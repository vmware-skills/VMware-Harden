"""Tests for `vmware-harden advise` CLI."""
import json
import uuid
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vmware_harden.cli.main import app
from vmware_harden.store.twin import Twin


cli = CliRunner()


CANNED = json.dumps({
    "summary": "fix",
    "execution_plan": {"steps": [{"step": 1, "mcp_tool": "x.y", "params": {}}]},
    "impact_prediction": {
        "affects_running_workload": False,
        "requires_maintenance_window": False,
    },
    "confidence": 0.9,
    "human_review_required": False,
})


def _seed_twin(tmp_path: Path, severity: str = "critical") -> tuple[str, str]:
    db = tmp_path / "t.duckdb"
    twin = Twin(db)
    snap = twin.start_snapshot("lab")
    twin.conn.execute(
        "INSERT INTO nodes (id, type, target, name, attrs) "
        "VALUES (?, 'host', 'lab', 'esx', ?)",
        ["lab:h-1", json.dumps({"ntp_enabled": False})],
    )
    vid = str(uuid.uuid4())
    twin.conn.execute(
        """INSERT INTO violation
           (id, snapshot_id, baseline_id, rule_id, node_id, severity, evidence)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        [vid, snap, "b", "r", "lab:h-1", severity, "{}"],
    )
    twin.finish_snapshot(snap)
    twin.close()
    return str(db), vid


@pytest.mark.unit
def test_advise_single_violation_uses_mock_when_no_key(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    db, vid = _seed_twin(tmp_path)

    import vmware_harden.cli.advise as advise_mod
    from vmware_harden.advisor.llm import MockProvider
    monkeypatch.setattr(advise_mod, "_get_provider",
                        lambda: MockProvider(canned_response=CANNED))

    result = cli.invoke(app, ["advise", "--db", db, "--violation-id", vid])
    assert result.exit_code == 0
    assert "fix" in result.output


@pytest.mark.unit
def test_advise_all_critical_processes_only_critical(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    db = tmp_path / "t.duckdb"
    twin = Twin(db)
    snap = twin.start_snapshot("lab")
    twin.conn.execute(
        "INSERT INTO nodes (id, type, target, name, attrs) "
        "VALUES (?, 'host', 'lab', 'esx', '{}')",
        ["lab:h-1"],
    )
    crit_id = str(uuid.uuid4())
    med_id = str(uuid.uuid4())
    twin.conn.execute(
        """INSERT INTO violation
           (id, snapshot_id, baseline_id, rule_id, node_id, severity, evidence)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        [crit_id, snap, "b", "r-c", "lab:h-1", "critical", "{}"],
    )
    twin.conn.execute(
        """INSERT INTO violation
           (id, snapshot_id, baseline_id, rule_id, node_id, severity, evidence)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        [med_id, snap, "b", "r-m", "lab:h-1", "medium", "{}"],
    )
    twin.finish_snapshot(snap)
    twin.close()

    import vmware_harden.cli.advise as advise_mod
    from vmware_harden.advisor.llm import MockProvider
    monkeypatch.setattr(advise_mod, "_get_provider",
                        lambda: MockProvider(canned_response=CANNED))

    result = cli.invoke(app, ["advise", "--db", str(db), "--all-critical"])
    assert result.exit_code == 0

    twin = Twin(db)
    crit_count = twin.conn.execute(
        "SELECT COUNT(*) FROM remediation WHERE violation_id = ?", [crit_id]
    ).fetchone()[0]
    med_count = twin.conn.execute(
        "SELECT COUNT(*) FROM remediation WHERE violation_id = ?", [med_id]
    ).fetchone()[0]
    assert crit_count == 1
    assert med_count == 0
    twin.close()


@pytest.mark.unit
def test_advise_all_critical_skips_failed_latest_snapshot(tmp_path, monkeypatch):
    """Regression (MEDIUM): after a failed/running scan, `advise --all-critical`
    must advise the last GOOD (completed) snapshot's criticals, not the empty
    failed snapshot. The old raw `ORDER BY scan_started_at DESC LIMIT 1` (no
    status filter) targeted the empty failed snapshot and said "no critical
    violations" while real criticals went unadvised. Must use
    twin.latest_snapshot() (completed_only=True)."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    db = tmp_path / "t.duckdb"
    twin = Twin(db)
    twin.conn.execute(
        "INSERT INTO nodes (id, type, target, name, attrs) "
        "VALUES (?, 'host', 'lab', 'esx', '{}')",
        ["lab:h-1"],
    )
    # Last GOOD scan: completed, has a critical violation.
    good_snap = twin.start_snapshot("lab")
    crit_id = str(uuid.uuid4())
    twin.conn.execute(
        """INSERT INTO violation
           (id, snapshot_id, baseline_id, rule_id, node_id, severity, evidence)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        [crit_id, good_snap, "b", "r-c", "lab:h-1", "critical", "{}"],
    )
    twin.finish_snapshot(good_snap, status="completed")
    # Newer scan crashed: status='failed', no violations recorded.
    bad_snap = twin.start_snapshot("lab")
    twin.finish_snapshot(bad_snap, status="failed")
    twin.close()

    import vmware_harden.cli.advise as advise_mod
    from vmware_harden.advisor.llm import MockProvider
    monkeypatch.setattr(advise_mod, "_get_provider",
                        lambda: MockProvider(canned_response=CANNED))

    result = cli.invoke(app, ["advise", "--db", str(db), "--all-critical"])
    assert result.exit_code == 0
    # The good snapshot's critical must have been advised (not reported clean).
    assert "No critical violations" not in result.output

    twin = Twin(db)
    crit_count = twin.conn.execute(
        "SELECT COUNT(*) FROM remediation WHERE violation_id = ?", [crit_id]
    ).fetchone()[0]
    assert crit_count == 1
    twin.close()


@pytest.mark.unit
def test_advise_no_args_shows_help_or_error(tmp_path):
    db, _ = _seed_twin(tmp_path)
    result = cli.invoke(app, ["advise", "--db", db])
    assert result.exit_code != 0 or "violation" in result.output.lower()


@pytest.mark.unit
def test_advise_warns_when_using_mock_no_key(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    db, vid = _seed_twin(tmp_path)
    result = cli.invoke(app, ["advise", "--db", db, "--violation-id", vid])
    combined = result.output + (result.stderr or "")
    assert ("ANTHROPIC_API_KEY" in combined) or ("mock" in combined.lower())
