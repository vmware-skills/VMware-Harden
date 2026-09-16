"""Persistence tests for diff_snapshots."""
from pathlib import Path

import pytest

from vmware_harden.drift.diff import diff_snapshots
from vmware_harden.store.twin import Twin


def _seed(twin: Twin, snap_id: str, node_id: str, state: dict, node_type: str = "host") -> None:
    """Seed a node the way a collector does: a `nodes` row AND a `node_state` row.

    Writing only `node_state` left the diff engine with node ids it could not
    type, and the engine carried an unconditional bypass for exactly that — a
    node of an uncollected type could slip past the type scoping in production
    to keep this fixture working (review, 2026-09-16).
    """
    twin.conn.execute(
        "INSERT INTO nodes (id, type, target, name, attrs) VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT (id) DO UPDATE SET type = excluded.type",
        [node_id, node_type, "v.lab", node_id, "{}"],
    )
    twin.write_node_state(snap_id, node_id, state)


@pytest.mark.unit
def test_diff_persist_writes_change_event_rows(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    snap_a = twin.start_snapshot("v.lab")
    snap_b = twin.start_snapshot("v.lab")
    _seed(twin, snap_a, "h-1", {"ntp_enabled": True, "build": 1})
    _seed(twin, snap_b, "h-1", {"ntp_enabled": False, "build": 1})
    _seed(twin, snap_b, "h-2", {"ntp_enabled": True, "build": 1})  # added

    events = diff_snapshots(twin, snap_a, snap_b, persist=True)
    assert len(events) >= 2  # config (ntp) + inventory (h-2 added)

    rows = twin.conn.execute(
        "SELECT snapshot_id, node_id, field, old_value, new_value "
        "FROM change_event WHERE snapshot_id = ? ORDER BY node_id, field",
        [snap_b],
    ).fetchall()
    assert len(rows) >= 2
    by_node = {(r[1], r[2]) for r in rows}
    assert ("h-1", "ntp_enabled") in by_node
    assert ("h-2", "_added") in by_node
    twin.close()


@pytest.mark.unit
def test_diff_persist_idempotent(tmp_path: Path):
    """Re-running diff with persist=True doesn't duplicate rows for same snap_b."""
    twin = Twin(tmp_path / "t.duckdb")
    snap_a = twin.start_snapshot("v.lab")
    snap_b = twin.start_snapshot("v.lab")
    _seed(twin, snap_a, "h-1", {"ntp_enabled": True})
    _seed(twin, snap_b, "h-1", {"ntp_enabled": False})

    diff_snapshots(twin, snap_a, snap_b, persist=True)
    diff_snapshots(twin, snap_a, snap_b, persist=True)

    count = twin.conn.execute(
        "SELECT COUNT(*) FROM change_event WHERE snapshot_id = ?", [snap_b]
    ).fetchone()[0]
    assert count == 1  # not 2
    twin.close()


@pytest.mark.unit
def test_diff_no_persist_default(tmp_path: Path):
    """persist defaults to False — no DB writes."""
    twin = Twin(tmp_path / "t.duckdb")
    snap_a = twin.start_snapshot("v.lab")
    snap_b = twin.start_snapshot("v.lab")
    _seed(twin, snap_a, "h-1", {"x": 1})
    _seed(twin, snap_b, "h-1", {"x": 2})

    diff_snapshots(twin, snap_a, snap_b)  # no persist arg

    count = twin.conn.execute(
        "SELECT COUNT(*) FROM change_event"
    ).fetchone()[0]
    assert count == 0
    twin.close()


@pytest.mark.unit
def test_diff_persist_returns_events_too(tmp_path: Path):
    """persist=True still returns the events list (not just side-effect)."""
    twin = Twin(tmp_path / "t.duckdb")
    snap_a = twin.start_snapshot("v.lab")
    snap_b = twin.start_snapshot("v.lab")
    _seed(twin, snap_a, "h-1", {"x": 1})
    _seed(twin, snap_b, "h-1", {"x": 2})

    events = diff_snapshots(twin, snap_a, snap_b, persist=True)
    assert len(events) == 1
    assert events[0].field == "x"
    twin.close()
