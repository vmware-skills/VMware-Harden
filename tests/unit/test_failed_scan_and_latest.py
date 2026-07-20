"""Regression tests for failed-scan handling, latest-snapshot semantics,
severity ordering, MCP input validation, and teaching errors.

Covers fix items #3, #4, #5, #7, #8, #9 of the 2026-06 hardening pass.
"""
import json
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from vmware_harden.store.twin import Twin

# ---------------------------------------------------------------------------
# #3 — Twin.latest_snapshot(completed_only=True)
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_latest_snapshot_none_when_empty(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    assert twin.latest_snapshot() is None
    twin.close()


@pytest.mark.unit
def test_latest_snapshot_skips_running_and_failed(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    snap_ok = twin.start_snapshot("lab")
    twin.finish_snapshot(snap_ok)
    snap_failed = twin.start_snapshot("lab")
    twin.finish_snapshot(snap_failed, status="failed")
    twin.start_snapshot("lab")  # left running

    latest = twin.latest_snapshot()
    assert latest is not None
    assert latest["id"] == snap_ok
    assert latest["status"] == "completed"

    # completed_only=False sees the newest snapshot regardless of status
    any_latest = twin.latest_snapshot(completed_only=False)
    assert any_latest["status"] == "running"
    twin.close()


# ---------------------------------------------------------------------------
# #3 — run_scan marks the snapshot failed and re-raises
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_failed_scan_marks_snapshot_failed(tmp_path: Path):
    from vmware_harden.cli.runner import run_scan

    db = str(tmp_path / "t.duckdb")
    with patch(
        "vmware_harden.collectors.hosts._fetch_hosts",
        side_effect=RuntimeError("vCenter unreachable"),
    ):
        with pytest.raises(RuntimeError):
            run_scan(target="lab", baseline="cis-vmware-esxi-8.0-subset", db=db)

    twin = Twin(Path(db))
    rows = twin.conn.execute("SELECT status FROM snapshots").fetchall()
    assert rows and all(r[0] == "failed" for r in rows)
    assert twin.latest_snapshot() is None  # failed scan never becomes "latest"
    twin.close()


@pytest.mark.unit
def test_scan_missing_dependency_teaching_error(tmp_path: Path):
    """#8 — ImportError of a collector dependency yields an actionable message.

    The type matters as much as the text. This used to raise ``RuntimeError``,
    which ``_safe_error`` deliberately refuses to pass through, so the whole
    instruction arrived at the agent as ``RuntimeError: operation failed.`` —
    see ``test_safe_error_passthrough`` for the wrapper half of this.
    """
    from vmware_harden.cli.runner import run_scan
    from vmware_harden.collectors.base import CollectorDependencyError

    db = str(tmp_path / "t.duckdb")
    with patch(
        "vmware_harden.collectors.hosts._fetch_hosts",
        side_effect=ModuleNotFoundError("No module named 'vmware_aiops'", name="vmware_aiops"),
    ):
        with pytest.raises(CollectorDependencyError) as exc:
            run_scan(target="lab", baseline="cis-vmware-esxi-8.0-subset", db=db)
    msg = str(exc.value)
    assert "vmware-aiops" in msg
    assert "uv tool install" in msg

    twin = Twin(Path(db))
    assert twin.latest_snapshot() is None
    twin.close()


# ---------------------------------------------------------------------------
# Shared seeding helper for ordering / MCP tests
# ---------------------------------------------------------------------------

def _seed_mixed_severities(tmp_path: Path) -> Path:
    db = tmp_path / "t.duckdb"
    twin = Twin(db)
    snap = twin.start_snapshot("lab")
    severities = ["low", "critical", "medium", "info", "high"]
    for i, sev in enumerate(severities):
        node = f"lab:h-{i}"
        twin.conn.execute(
            "INSERT INTO nodes (id, type, target, name, attrs) "
            "VALUES (?, 'host', 'lab', ?, '{}')",
            [node, f"esx{i}"],
        )
        twin.conn.execute(
            """INSERT INTO violation
               (id, snapshot_id, baseline_id, rule_id, node_id, severity, evidence)
               VALUES (?, ?, 'b', ?, ?, ?, '{}')""",
            [str(uuid.uuid4()), snap, f"r-{i}", node, sev],
        )
    twin.finish_snapshot(snap)
    twin.close()
    return db


# ---------------------------------------------------------------------------
# #4 — severity ranking: critical first everywhere
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_mcp_list_violations_orders_critical_first(tmp_path: Path):
    from vmware_harden.mcp import tools as srv

    db = _seed_mixed_severities(tmp_path)
    old = srv._DB_PATH
    srv._DB_PATH = db
    try:
        out = srv.list_violations()
    finally:
        srv._DB_PATH = old
    got = [v["severity"] for v in out["violations"]]
    assert got == ["critical", "high", "medium", "low", "info"]


@pytest.mark.unit
def test_report_orders_critical_first(tmp_path: Path, capsys):
    from vmware_harden.cli.runner import run_report

    db = _seed_mixed_severities(tmp_path)
    run_report(db=str(db), format="json")
    out = json.loads(capsys.readouterr().out)
    got = [v["severity"] for v in out]
    assert got == ["critical", "high", "medium", "low", "info"]


# ---------------------------------------------------------------------------
# #3 — report / MCP reads ignore non-completed "latest" snapshots
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_mcp_list_violations_ignores_running_snapshot(tmp_path: Path):
    from vmware_harden.mcp import tools as srv

    db = _seed_mixed_severities(tmp_path)
    twin = Twin(db)
    twin.start_snapshot("lab")  # newer, still running — must be ignored
    twin.close()

    old = srv._DB_PATH
    srv._DB_PATH = db
    try:
        out = srv.list_violations()
    finally:
        srv._DB_PATH = old
    assert len(out) == 5  # violations of the completed snapshot, not []


# ---------------------------------------------------------------------------
# #7 — invalid severity raises a teaching ValueError
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_mcp_list_violations_invalid_severity_teaching_error(tmp_path: Path):
    from vmware_harden.mcp import tools as srv

    with pytest.raises(ValueError) as exc:
        srv.list_violations(severity="sev1")
    msg = str(exc.value)
    for valid in ("critical", "high", "medium", "low", "info"):
        assert valid in msg


# ---------------------------------------------------------------------------
# #8 — read paths must not silently create the DB
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_mcp_resolve_db_missing_teaching_error(tmp_path: Path):
    from vmware_harden.mcp import tools as srv

    missing = tmp_path / "nope" / "twin.duckdb"
    old = srv._DB_PATH
    srv._DB_PATH = missing
    try:
        with pytest.raises(FileNotFoundError) as exc:
            srv.list_violations()
    finally:
        srv._DB_PATH = old
    assert "scan" in str(exc.value)
    assert not missing.exists()  # nothing was created


@pytest.mark.unit
def test_report_does_not_create_db(tmp_path: Path, capsys):
    from vmware_harden.cli.runner import run_report

    missing = tmp_path / "nope" / "twin.duckdb"
    run_report(db=str(missing), format="text")
    out = capsys.readouterr().out
    assert "No scans yet" in out
    assert not missing.exists()


# ---------------------------------------------------------------------------
# #5 — scan_target reports the snapshot id of ITS scan, not the global latest
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_scan_target_uses_returned_snapshot_id(tmp_path: Path):
    from vmware_harden.mcp import tools as srv

    db = tmp_path / "t.duckdb"

    def fake_run_scan(target: str, baseline: str, db: str) -> str:
        twin = Twin(Path(db))
        mine = twin.start_snapshot(target)
        twin.finish_snapshot(mine)
        # A concurrent scan of another target finishes after ours.
        other = twin.start_snapshot("other-vcenter")
        twin.finish_snapshot(other)
        twin.close()
        return mine

    old = srv._DB_PATH
    srv._DB_PATH = db
    try:
        with patch("vmware_harden.cli.runner.run_scan", side_effect=fake_run_scan):
            result = srv.scan_target(target="lab")
    finally:
        srv._DB_PATH = old

    twin = Twin(db)
    row = twin.conn.execute(
        "SELECT target FROM snapshots WHERE id = ?", [result["snapshot_id"]]
    ).fetchone()
    twin.close()
    assert row[0] == "lab"  # not the globally-latest "other-vcenter" snapshot


# ---------------------------------------------------------------------------
# #9 — hot-path indexes exist
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_schema_indexes_for_hot_paths(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    names = {
        r[0]
        for r in twin.conn.execute(
            "SELECT index_name FROM duckdb_indexes()"
        ).fetchall()
    }
    twin.close()
    assert "idx_change_event_node" in names
    assert "idx_remediation_violation" in names
