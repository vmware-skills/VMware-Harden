"""Regression: bounded output to LLM/CLI, and a cap on advisor fan-out.

Two audit findings drive these tests:

1. `list_violations` used to have no LIMIT — every violation row (tens of
   thousands at scale) was serialized straight into the MCP/LLM context. It now
   returns an envelope capped at `limit` rows while reporting the true `total`.

2. `advise --all-critical` used to fan out one serial LLM call per critical
   violation with no cap. It now honors `--limit`.
"""
import json
import uuid
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vmware_harden.cli.main import app
from vmware_harden.store.twin import Twin


cli = CliRunner()

CANNED = json.dumps(
    {
        "summary": "fix",
        "execution_plan": {"steps": []},
        "impact_prediction": {
            "affects_running_workload": False,
            "requires_maintenance_window": False,
        },
        "confidence": 0.5,
        "human_review_required": True,
    }
)


def _seed_many(tmp_path: Path, count: int, severity: str = "high") -> Path:
    """Build a Twin whose latest snapshot has `count` violations."""
    db = tmp_path / "many.duckdb"
    twin = Twin(db)
    snap = twin.start_snapshot("v.lab")
    twin.conn.execute(
        "INSERT INTO nodes (id, type, target, name, attrs) "
        "VALUES (?, 'host', 'v.lab', 'esx', '{}')",
        ["v.lab:h-1"],
    )
    rows = [
        [
            str(uuid.uuid4()), snap, "b", f"r-{i:05d}", "v.lab:h-1",
            severity, "{}",
        ]
        for i in range(count)
    ]
    twin.conn.executemany(
        """INSERT INTO violation
           (id, snapshot_id, baseline_id, rule_id, node_id, severity, evidence)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        rows,
    )
    twin.finish_snapshot(snap)
    twin.close()
    return db


@pytest.mark.unit
def test_list_violations_is_bounded_but_reports_total(tmp_path: Path):
    db = _seed_many(tmp_path, count=250)
    from vmware_harden.mcp import tools as srv
    srv._DB_PATH = db

    out = srv.list_violations(limit=50)
    assert len(out["violations"]) <= 50
    assert len(out["violations"]) == 50
    assert out["total"] == 250  # true total is not hidden
    assert out["has_more"] is True
    assert out["limit"] == 50
    assert out["offset"] == 0


@pytest.mark.unit
def test_list_violations_offset_pages_through(tmp_path: Path):
    db = _seed_many(tmp_path, count=250)
    from vmware_harden.mcp import tools as srv
    srv._DB_PATH = db

    first = srv.list_violations(limit=100, offset=0)
    last = srv.list_violations(limit=100, offset=200)
    assert first["has_more"] is True
    assert len(last["violations"]) == 50  # 250 - 200
    assert last["has_more"] is False
    first_ids = {v["id"] for v in first["violations"]}
    last_ids = {v["id"] for v in last["violations"]}
    assert first_ids.isdisjoint(last_ids)  # no overlap across pages


@pytest.mark.unit
def test_advise_all_critical_respects_limit_cap(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    db = _seed_many(tmp_path, count=40, severity="critical")

    import vmware_harden.cli.advise as advise_mod
    from vmware_harden.advisor.llm import MockProvider
    monkeypatch.setattr(
        advise_mod, "_get_provider",
        lambda: MockProvider(canned_response=CANNED),
    )

    result = cli.invoke(app, ["advise", "--db", str(db), "--all-critical", "--limit", "5"])
    assert result.exit_code == 0
    # Message must disclose processed-vs-total so nothing is silently dropped.
    assert "5 of 40" in result.output

    # Only 5 suggestions were persisted (cap honored, no fan-out to 40 calls).
    twin = Twin(db)
    persisted = twin.conn.execute(
        "SELECT COUNT(*) FROM remediation"
    ).fetchone()[0]
    twin.close()
    assert persisted == 5
