"""Snapshot diff engine tests."""
from pathlib import Path

import pytest

from vmware_harden.drift.diff import ChangeEvent, diff_snapshots
from vmware_harden.store.twin import Twin


def _seed_node_state(twin: Twin, snap_id: str, node_id: str, state: dict) -> None:
    twin.write_node_state(snap_id, node_id, state)


@pytest.mark.unit
def test_identical_snapshots_yield_no_events(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    snap_a = twin.start_snapshot("v.lab")
    snap_b = twin.start_snapshot("v.lab")
    _seed_node_state(twin, snap_a, "h-1", {"ntp_enabled": True})
    _seed_node_state(twin, snap_b, "h-1", {"ntp_enabled": True})

    events = diff_snapshots(twin, snap_a, snap_b)
    assert events == []
    twin.close()


@pytest.mark.unit
def test_added_node_emits_inventory_event(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    snap_a = twin.start_snapshot("v.lab")
    snap_b = twin.start_snapshot("v.lab")
    _seed_node_state(twin, snap_a, "h-1", {"ntp_enabled": True})
    _seed_node_state(twin, snap_b, "h-1", {"ntp_enabled": True})
    _seed_node_state(twin, snap_b, "h-2", {"ntp_enabled": True})  # new

    events = diff_snapshots(twin, snap_a, snap_b)
    assert len(events) == 1
    assert events[0].kind == "inventory"
    assert events[0].node_id == "h-2"
    assert events[0].field == "_added"
    assert events[0].old_value is None
    assert events[0].new_value is not None  # has the new state
    twin.close()


@pytest.mark.unit
def test_removed_node_emits_inventory_event(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    snap_a = twin.start_snapshot("v.lab")
    snap_b = twin.start_snapshot("v.lab")
    _seed_node_state(twin, snap_a, "h-1", {"ntp_enabled": True})
    _seed_node_state(twin, snap_a, "h-2", {"ntp_enabled": True})
    _seed_node_state(twin, snap_b, "h-1", {"ntp_enabled": True})  # h-2 missing

    events = diff_snapshots(twin, snap_a, snap_b)
    removed = [e for e in events if e.field == "_removed"]
    assert len(removed) == 1
    assert removed[0].node_id == "h-2"
    twin.close()


@pytest.mark.unit
def test_config_change_emits_field_event(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    snap_a = twin.start_snapshot("v.lab")
    snap_b = twin.start_snapshot("v.lab")
    _seed_node_state(twin, snap_a, "h-1", {"ntp_enabled": True, "build": 100})
    _seed_node_state(twin, snap_b, "h-1", {"ntp_enabled": False, "build": 100})

    events = diff_snapshots(twin, snap_a, snap_b)
    config_events = [e for e in events if e.kind == "config"]
    assert len(config_events) == 1
    e = config_events[0]
    assert e.node_id == "h-1"
    assert e.field == "ntp_enabled"
    assert e.old_value == "True"
    assert e.new_value == "False"
    twin.close()


@pytest.mark.unit
def test_multi_field_change_emits_multiple_events(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    snap_a = twin.start_snapshot("v.lab")
    snap_b = twin.start_snapshot("v.lab")
    _seed_node_state(twin, snap_a, "h-1", {"a": 1, "b": 2, "c": 3})
    _seed_node_state(twin, snap_b, "h-1", {"a": 1, "b": 99, "c": 100})  # b, c changed

    events = diff_snapshots(twin, snap_a, snap_b)
    fields_changed = {e.field for e in events if e.kind == "config"}
    assert fields_changed == {"b", "c"}
    twin.close()


@pytest.mark.unit
def test_field_added_in_new_state(tmp_path: Path):
    """If new state has a field old didn't, emit a config event with old=None."""
    twin = Twin(tmp_path / "t.duckdb")
    snap_a = twin.start_snapshot("v.lab")
    snap_b = twin.start_snapshot("v.lab")
    _seed_node_state(twin, snap_a, "h-1", {"a": 1})
    _seed_node_state(twin, snap_b, "h-1", {"a": 1, "new_field": "hello"})

    events = diff_snapshots(twin, snap_a, snap_b)
    config = [e for e in events if e.kind == "config" and e.field == "new_field"]
    assert len(config) == 1
    assert config[0].old_value is None
    assert config[0].new_value == "hello"
    twin.close()


@pytest.mark.unit
def test_field_removed_in_new_state(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    snap_a = twin.start_snapshot("v.lab")
    snap_b = twin.start_snapshot("v.lab")
    _seed_node_state(twin, snap_a, "h-1", {"a": 1, "old_field": "bye"})
    _seed_node_state(twin, snap_b, "h-1", {"a": 1})  # old_field gone

    events = diff_snapshots(twin, snap_a, snap_b)
    config = [e for e in events if e.kind == "config" and e.field == "old_field"]
    assert len(config) == 1
    assert config[0].old_value == "bye"
    assert config[0].new_value is None
    twin.close()
