"""Every surface that shows violations must also say how much was judged.

Recording outcomes in the database is only half the fix. While the report still
printed a bare "No violations." the scan engine already knew that 16 of 20 rules
had not run — the data was honest and the presentation was not, which is worse
than either end state because the warning had been silently withdrawn.

These pin the four surfaces (scan, report, MCP, web) against that regression.
"""
import json
from pathlib import Path

import pytest

from vmware_harden.checks.coverage import Coverage, coverage_for
from vmware_harden.cli.runner import run_report, run_scan
from vmware_harden.store.twin import Twin

#: Compliant on the two rules the collector can actually feed, so the only thing
#: left to report is how much of the baseline never ran.
_CLEAN_HOST = {
    "id": "h-1", "name": "esx-01",
    "esxi_build": 99999999, "syslog_remote_host": "syslog.lab",
}
_CIS = "cis-vmware-esxi-8.0-subset"


def _scan(tmp_path: Path, capsys, hosts=None) -> str:
    from unittest.mock import patch

    db = str(tmp_path / "t.duckdb")
    with patch("vmware_harden.collectors.hosts._fetch_hosts",
               return_value=hosts or [_CLEAN_HOST]):
        run_scan(target="prod", baseline=_CIS, db=db)
    capsys.readouterr()
    return db


# --- Coverage itself --------------------------------------------------------

@pytest.mark.unit
def test_untracked_snapshot_is_not_reported_as_complete():
    """A scan with no outcome rows does not know its coverage.

    ``complete`` derived from ``undetermined == 0`` alone returns True here,
    which would announce full coverage for a scan that measured none of it —
    the original false-compliance claim, one release later.
    """
    cov = Coverage()
    assert cov.tracked is False
    assert cov.complete is False
    assert "predates coverage tracking" in cov.summary_line()


@pytest.mark.unit
def test_complete_coverage_says_nothing():
    """No banner when every rule ran — a warning on every clean scan goes unread."""
    cov = Coverage(evaluated=20, undetermined=0)
    assert cov.complete is True
    assert cov.summary_line() == ""


@pytest.mark.unit
def test_partial_coverage_states_the_ratio_and_refuses_the_word_compliant():
    cov = Coverage(evaluated=4, undetermined=16)
    line = cov.summary_line()
    assert "16 of 20" in line
    assert "not compliant" in line


# --- CLI: scan and report ---------------------------------------------------

@pytest.mark.integration
def test_scan_output_reports_partial_coverage(tmp_path: Path, capsys):
    from unittest.mock import patch

    db = str(tmp_path / "t.duckdb")
    with patch("vmware_harden.collectors.hosts._fetch_hosts", return_value=[_CLEAN_HOST]):
        run_scan(target="prod", baseline=_CIS, db=db)
    out = capsys.readouterr().out
    assert "Found 0 violations" in out
    assert "16 of 20 rules could not be evaluated" in out


@pytest.mark.integration
def test_text_report_never_says_bare_no_violations_on_partial_coverage(
    tmp_path: Path, capsys
):
    """The three words that were the whole defect."""
    db = _scan(tmp_path, capsys)
    run_report(db=db, format="text")
    out = capsys.readouterr().out

    assert "No violations." not in out
    assert "No violations among the rules that could be evaluated." in out
    assert "Not evaluated:" in out
    assert "no collector writes host.ntp_enabled" in out


@pytest.mark.integration
def test_json_report_is_an_object_carrying_coverage(tmp_path: Path, capsys):
    """A bare list gives a script no way to see that nothing was checked."""
    db = _scan(tmp_path, capsys)
    run_report(db=db, format="json")
    payload = json.loads(capsys.readouterr().out)

    assert isinstance(payload, dict)
    assert payload["violations"] == []
    assert payload["coverage"]["evaluated"] == 4
    assert payload["coverage"]["undetermined"] == 16
    assert payload["coverage"]["complete"] is False
    blocked = {r["rule"] for r in payload["coverage"]["undetermined_rules"]}
    assert "cis-esxi-2.1.1" in blocked


# --- MCP --------------------------------------------------------------------

@pytest.mark.integration
def test_mcp_surfaces_coverage_next_to_the_violation_count(tmp_path: Path, capsys):
    """An agent reading `violations: 0` will tell the user the estate is clean."""
    from vmware_harden.mcp import tools as srv

    db = _scan(tmp_path, capsys)
    old = srv._DB_PATH
    srv._DB_PATH = Path(db)
    try:
        listed = srv.list_violations()
    finally:
        srv._DB_PATH = old

    assert listed["violations"] == []
    assert listed["coverage"]["undetermined"] == 16
    assert listed["coverage"]["complete"] is False
    assert "not compliant" in listed["note"]


# --- web --------------------------------------------------------------------

@pytest.mark.integration
def test_web_pages_state_coverage(tmp_path: Path, capsys):
    from fastapi.testclient import TestClient

    from vmware_harden.web.app import build_app

    db = _scan(tmp_path, capsys)
    client = TestClient(build_app(Path(db)))

    dashboard = client.get("/").text
    assert "could not be evaluated" in dashboard

    violations = client.get("/violations").text
    assert "not a clean bill of health" in violations
    assert "cis-esxi-2.1.1" in violations
    # and it must not claim the estate is compliant
    assert "the estate is compliant against every rule" not in violations


# --- the query --------------------------------------------------------------

@pytest.mark.unit
def test_coverage_for_reads_only_its_own_snapshot(tmp_path: Path, capsys):
    """Two scans in one database must not pool their outcomes."""
    from unittest.mock import patch

    db = str(tmp_path / "t.duckdb")
    with patch("vmware_harden.collectors.hosts._fetch_hosts", return_value=[_CLEAN_HOST]):
        run_scan(target="a", baseline=_CIS, db=db)
        run_scan(target="b", baseline=_CIS, db=db)
    capsys.readouterr()

    twin = Twin(Path(db))
    snaps = [r[0] for r in twin.conn.execute(
        "SELECT id FROM snapshots WHERE status = 'completed'"
    ).fetchall()]
    assert len(snaps) == 2
    for snap in snaps:
        assert coverage_for(twin, snap).total == 20
    twin.close()
