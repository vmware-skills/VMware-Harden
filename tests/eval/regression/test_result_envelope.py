"""Regression: list tools state their completeness instead of implying it.

Source: VMware-AIops issue #31 (juanpf-ha). Running the family against a local
Llama 3.3 70B, the operator reported that "with long tool responses, it may
omit existing information or incorrectly state that no data was returned."

A bare ``list[dict]`` gives a model nothing to distinguish a complete answer
from page one, so it guesses — and a guess that reads "no data" looks like a
finding. Every list tool here now returns the family envelope from
``vmware_policy.paginated``, so ``returned``/``total``/``truncated`` are stated.

vmware-harden is DuckDB-backed, so its totals are real: ``list_drift_events``
counts the same predicate it selects (one probe of idx_change_event_snapshot),
and the two baseline tools return whole collections they had already loaded.
A known total is what lets a page that happens to fill ``limit`` be reported as
complete rather than conservatively flagged as possibly-truncated.
"""
import uuid
from pathlib import Path

import pytest

from vmware_harden.store.twin import Twin

ENVELOPE_KEYS = {"items", "returned", "limit", "total", "truncated", "hint"}


def _seed_drift(tmp_path: Path, count: int) -> Path:
    """Build a Twin whose latest snapshot holds `count` change events."""
    db = tmp_path / "drift.duckdb"
    twin = Twin(db)
    snap = twin.start_snapshot("v.lab")
    twin.conn.execute(
        "INSERT INTO nodes (id, type, target, name, attrs) "
        "VALUES (?, 'host', 'v.lab', 'esx', '{}')",
        ["v.lab:h-1"],
    )
    twin.conn.executemany(
        """INSERT INTO change_event
           (id, snapshot_id, node_id, field, old_value, new_value)
           VALUES (?, ?, ?, ?, ?, ?)""",
        [
            [str(uuid.uuid4()), snap, "v.lab:h-1", f"field_{i:05d}", "a", "b"]
            for i in range(count)
        ],
    )
    twin.finish_snapshot(snap)
    twin.close()
    return db


# ---------------------------------------------------------------------------
# Shape — every converted tool carries the whole contract
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_list_baselines_returns_the_envelope():
    from vmware_harden.mcp import tools as srv

    assert ENVELOPE_KEYS <= set(srv.list_baselines())


@pytest.mark.unit
def test_get_baseline_rules_returns_the_envelope():
    from vmware_harden.mcp import tools as srv

    out = srv.get_baseline_rules("cis-vmware-esxi-8.0-subset")
    assert ENVELOPE_KEYS <= set(out)


@pytest.mark.unit
def test_list_drift_events_returns_the_envelope(tmp_path: Path):
    from vmware_harden.mcp import tools as srv

    srv._DB_PATH = _seed_drift(tmp_path, count=3)
    assert ENVELOPE_KEYS <= set(srv.list_drift_events())


# ---------------------------------------------------------------------------
# Truncation — the question the model can no longer get wrong
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_full_page_is_flagged_truncated(tmp_path: Path):
    """250 events behind a limit of 50: say so rather than imply 50 is all."""
    from vmware_harden.mcp import tools as srv

    srv._DB_PATH = _seed_drift(tmp_path, count=250)
    out = srv.list_drift_events(limit=50)
    assert out["returned"] == 50
    assert out["total"] == 250
    assert out["truncated"] is True
    assert "250" in out["hint"]


@pytest.mark.unit
def test_short_result_is_not_truncated(tmp_path: Path):
    from vmware_harden.mcp import tools as srv

    srv._DB_PATH = _seed_drift(tmp_path, count=3)
    out = srv.list_drift_events(limit=50)
    assert out["returned"] == 3
    assert out["total"] == 3
    assert out["truncated"] is False
    assert out["hint"] is None


@pytest.mark.unit
def test_exactly_full_page_with_known_total_is_complete(tmp_path: Path):
    """The payoff of a real total: a page filled to the limit is not ambiguous.

    Without ``total`` the envelope would conservatively flag this truncated,
    costing the agent a redundant follow-up query.
    """
    from vmware_harden.mcp import tools as srv

    srv._DB_PATH = _seed_drift(tmp_path, count=50)
    out = srv.list_drift_events(limit=50)
    assert out["returned"] == 50
    assert out["truncated"] is False
    assert out["hint"] is None


@pytest.mark.unit
def test_empty_result_is_complete_not_truncated(tmp_path: Path):
    """No snapshot at all is a complete answer of zero rows, not a maybe."""
    from vmware_harden.mcp import tools as srv

    db = tmp_path / "empty.duckdb"
    Twin(db).close()
    srv._DB_PATH = db
    out = srv.list_drift_events()
    assert out["items"] == []
    assert out["total"] == 0
    assert out["truncated"] is False
    assert out["hint"] is None


# ---------------------------------------------------------------------------
# Unlimited tools — "truncated: false" is itself the information
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_baseline_tools_report_a_real_total_and_no_truncation():
    from vmware_harden.mcp import tools as srv

    baselines = srv.list_baselines()
    assert baselines["total"] == baselines["returned"]
    assert baselines["limit"] is None
    assert baselines["truncated"] is False

    rules = srv.get_baseline_rules("cis-vmware-esxi-8.0-subset")
    assert rules["returned"] == 20
    assert rules["total"] == 20
    assert rules["truncated"] is False
