"""Drift CLI subcommand tests."""
import json as _json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vmware_harden.cli.main import app
from vmware_harden.store.twin import Twin


cli = CliRunner()


def _seed_drift(tmp_path: Path, db: str) -> str:
    """Create a Twin with two snapshots and pre-baked change events for snap_b."""
    twin = Twin(Path(db))
    snap_a = twin.start_snapshot("v.lab")  # snap_a (id used purely for ordering)
    twin.finish_snapshot(snap_a)
    snap_b = twin.start_snapshot("v.lab")
    # Insert prebaked change_event rows for snap_b
    import uuid
    twin.conn.execute(
        "INSERT INTO change_event (id, snapshot_id, node_id, field, old_value, new_value) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        [str(uuid.uuid4()), snap_b, "h-1", "ntp_enabled", "True", "False"],
    )
    twin.conn.execute(
        "INSERT INTO change_event (id, snapshot_id, node_id, field, old_value, new_value) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        [str(uuid.uuid4()), snap_b, "h-2", "_added", None, '{"ntp": true}'],
    )
    twin.finish_snapshot(snap_b)  # only completed snapshots qualify as latest
    twin.close()
    return snap_b


@pytest.mark.unit
def test_drift_text_output(tmp_path: Path):
    db = str(tmp_path / "t.duckdb")
    _seed_drift(tmp_path, db)
    result = cli.invoke(app, ["drift", "--db", db])
    assert result.exit_code == 0
    assert "h-1" in result.output
    assert "ntp_enabled" in result.output
    assert "h-2" in result.output
    assert "_added" in result.output


@pytest.mark.unit
def test_drift_json_output(tmp_path: Path):
    db = str(tmp_path / "t.duckdb")
    _seed_drift(tmp_path, db)
    result = cli.invoke(app, ["drift", "--db", db, "--format", "json"])
    assert result.exit_code == 0
    payload = _json.loads(result.output)
    assert isinstance(payload, list)
    assert len(payload) == 2
    by_field = {(p["node_id"], p["field"]) for p in payload}
    assert ("h-1", "ntp_enabled") in by_field
    assert ("h-2", "_added") in by_field


@pytest.mark.unit
def test_drift_empty_twin_helpful_message(tmp_path: Path):
    db = str(tmp_path / "empty.duckdb")
    Twin(Path(db)).close()
    result = cli.invoke(app, ["drift", "--db", db])
    assert result.exit_code == 0
    assert "No drift" in result.output or "scans yet" in result.output


@pytest.mark.unit
def test_drift_help_runs():
    result = cli.invoke(app, ["drift", "--help"])
    assert result.exit_code == 0
    assert "drift" in result.output.lower()
