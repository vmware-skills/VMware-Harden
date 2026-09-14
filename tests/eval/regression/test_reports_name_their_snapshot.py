"""Regression — a report says which scan it reads, and when later scans failed.

Found 2026-09-14 on the lab: `vmware-harden scan --target home-vcenter` failed
twice (the collectors extra was missing). Both snapshots were correctly marked
'failed' and kept out of reports — and `vmware-harden report` then printed the
violations from the last scan that *had* completed, on 2026-08-30, with no
snapshot id, no date and no word that two newer scans had failed since. A user
who had just run a scan read fifteen-day-old results as the answer to it.

Every surface that reads "the latest completed snapshot" now names it and its
finish time, and says when later scans of the same target did not complete:
the text and JSON report, the drift view, and the list_violations /
list_drift_events MCP tools.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from vmware_harden.store.twin import Twin


def _seed(tmp_path: Path, statuses: list[tuple[str, str, str]]) -> tuple[Path, dict[str, str]]:
    """Snapshots as (label, target, status), started a day apart in that order."""
    db = tmp_path / "t.duckdb"
    twin = Twin(db)
    ids = {}
    try:
        for day, (label, target, status) in enumerate(statuses, start=1):
            snap = twin.start_snapshot(target)
            started = datetime(2026, 9, day, 9, 0)
            twin.conn.execute(
                "UPDATE snapshots SET scan_started_at = ? WHERE id = ?", [started, snap]
            )
            if status != "running":
                twin.finish_snapshot(snap, status=status)
                twin.conn.execute(
                    "UPDATE snapshots SET scan_finished_at = ? WHERE id = ?",
                    [started.replace(minute=5), snap],
                )
            ids[label] = snap
    finally:
        twin.close()
    return db, ids


@pytest.mark.unit
def test_standing_names_the_snapshot_and_counts_later_failures(tmp_path: Path):
    db, ids = _seed(tmp_path, [
        ("ok", "home-vcenter", "completed"),
        ("other-target-failed", "prod-vc", "failed"),
        ("f1", "home-vcenter", "failed"),
        ("f2", "home-vcenter", "failed"),
    ])
    twin = Twin(db)
    try:
        latest = twin.latest_snapshot()
        assert latest["id"] == ids["ok"]
        standing = twin.snapshot_standing(latest)
    finally:
        twin.close()
    assert standing["id"] == ids["ok"]
    assert standing["target"] == "home-vcenter"
    assert standing["finished_at"] == "2026-09-01 09:05 UTC"
    assert standing["later_unfinished"] == 2, "another target's failure was counted"
    note = standing["note"]
    assert "2 later scans of home-vcenter" in note
    assert "2026-09-04 09:00 UTC" in note and "failed" in note
    assert "2026-09-01 09:05 UTC" in note


@pytest.mark.unit
def test_standing_has_no_note_when_nothing_later_went_wrong(tmp_path: Path):
    db, _ = _seed(
        tmp_path, [("f0", "home-vcenter", "failed"), ("ok", "home-vcenter", "completed")]
    )
    twin = Twin(db)
    try:
        standing = twin.snapshot_standing(twin.latest_snapshot())
    finally:
        twin.close()
    assert standing["later_unfinished"] == 0
    assert standing["note"] is None


@pytest.mark.unit
def test_a_scan_still_running_is_named_as_running(tmp_path: Path):
    db, _ = _seed(tmp_path, [("ok", "lab", "completed"), ("r", "lab", "running")])
    twin = Twin(db)
    try:
        note = twin.snapshot_standing(twin.latest_snapshot())["note"]
    finally:
        twin.close()
    assert "1 later scan of lab" in note and "running" in note


@pytest.mark.unit
def test_text_report_names_the_snapshot_and_warns(tmp_path: Path, capsys):
    from vmware_harden.cli.runner import run_report

    db, ids = _seed(
        tmp_path, [("ok", "home-vcenter", "completed"), ("f", "home-vcenter", "failed")]
    )
    run_report(db=str(db), format="text")
    out = capsys.readouterr().out
    first = out.splitlines()[0]
    assert ids["ok"] in first and "home-vcenter" in first and "2026-09-01 09:05 UTC" in first
    assert "1 later scan of home-vcenter" in out


@pytest.mark.unit
def test_json_report_carries_the_snapshot(tmp_path: Path, capsys):
    from vmware_harden.cli.runner import run_report

    db, ids = _seed(
        tmp_path, [("ok", "home-vcenter", "completed"), ("f", "home-vcenter", "failed")]
    )
    run_report(db=str(db), format="json")
    payload = json.loads(capsys.readouterr().out)
    assert payload["snapshot"]["id"] == ids["ok"]
    assert payload["snapshot"]["later_unfinished"] == 1
    assert "violations" in payload and "coverage" in payload


@pytest.mark.unit
def test_mcp_tools_carry_the_snapshot(tmp_path: Path):
    from vmware_harden.mcp import tools as srv

    db, ids = _seed(
        tmp_path, [("ok", "home-vcenter", "completed"), ("f", "home-vcenter", "failed")]
    )
    old = srv._DB_PATH
    srv._DB_PATH = db
    try:
        listed = srv.list_violations()
        drift = srv.list_drift_events()
    finally:
        srv._DB_PATH = old
    for payload in (listed, drift):
        assert payload["snapshot"]["id"] == ids["ok"], payload
        assert payload["snapshot"]["later_unfinished"] == 1


@pytest.mark.unit
def test_drift_view_names_the_snapshot_and_warns(tmp_path: Path):
    from typer.testing import CliRunner

    from vmware_harden.cli.main import app

    db, ids = _seed(
        tmp_path, [("ok", "home-vcenter", "completed"), ("f", "home-vcenter", "failed")]
    )
    result = CliRunner().invoke(app, ["drift", "--db", str(db)])
    assert result.exit_code == 0, result.output
    assert ids["ok"] in result.output and "2026-09-01 09:05 UTC" in result.output
    assert "1 later scan of home-vcenter" in result.output
