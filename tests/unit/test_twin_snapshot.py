"""Snapshot lifecycle and content-addressed state tests."""
from pathlib import Path

import pytest

from vmware_harden.store.twin import Twin


@pytest.mark.unit
def test_snapshot_lifecycle(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot(target="vcenter.lab.local")
    assert snap_id  # non-empty string

    twin.write_node_state(snap_id, "host-01", {"name": "esx01", "build": 12345})
    twin.finish_snapshot(snap_id, status="completed")

    rows = twin.conn.execute(
        "SELECT status, scan_finished_at FROM snapshots WHERE id = ?", [snap_id]
    ).fetchall()
    assert rows[0][0] == "completed"
    assert rows[0][1] is not None
    twin.close()


@pytest.mark.unit
def test_state_hash_dedup(tmp_path: Path):
    """Two writes of identical state produce the same hash."""
    twin = Twin(tmp_path / "t.duckdb")
    snap1 = twin.start_snapshot("v.lab")
    h1 = twin.write_node_state(snap1, "host-01", {"build": 12345})
    snap2 = twin.start_snapshot("v.lab")
    h2 = twin.write_node_state(snap2, "host-01", {"build": 12345})

    assert h1 == h2
    # Both rows present (one per snapshot) but with same hash
    distinct_hashes = twin.conn.execute(
        "SELECT DISTINCT state_hash FROM node_state WHERE node_id = 'host-01'"
    ).fetchall()
    assert len(distinct_hashes) == 1
    twin.close()


@pytest.mark.unit
def test_state_hash_changes_when_state_changes(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    snap1 = twin.start_snapshot("v.lab")
    h1 = twin.write_node_state(snap1, "host-01", {"build": 12345})
    snap2 = twin.start_snapshot("v.lab")
    h2 = twin.write_node_state(snap2, "host-01", {"build": 99999})

    assert h1 != h2
    twin.close()


@pytest.mark.unit
def test_finish_snapshot_default_status_is_completed(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")
    twin.finish_snapshot(snap_id)  # default status

    row = twin.conn.execute(
        "SELECT status FROM snapshots WHERE id = ?", [snap_id]
    ).fetchone()
    assert row[0] == "completed"
    twin.close()
