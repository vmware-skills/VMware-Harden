"""One collector failing must not throw away the rules the others can answer.

Lab, 2026-09-16: `scan_target(baseline="dengbao-2.0-level3-vmware")` died with
"Config file not found: ~/.vmware-nsx-security/config.yaml". That baseline's
applies_to lists dfw_rule, so the DFW collector ran, could not reach NSX, and
took the whole scan with it — no snapshot, and the 17 host/vm/datastore rules
never ran, on an estate where nothing about NSX was being asked.

The other half of the requirement is the one this family keeps relearning: the
rules that could NOT be collected for must read as unknown, never as compliant.
A scan that quietly evaluates a dfw rule against zero nodes reports "no
violations" for a firewall it never looked at.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from vmware_harden.cli.runner import run_scan
from vmware_harden.store.twin import Twin

HOSTS = [
    {
        "id": "host-1",
        "name": "esx-1",
        "esxi_version": "8.0.3",
        "esxi_build": 24280767,
        "ntp_enabled": True,
        "ntp_servers": ["10.0.0.1"],
        "ntp_service_policy": "on",
        "syslog_remote_host": "",
        "lockdown_mode": "normal",
    }
]
VMS = [{"id": "vm-1", "name": "test-llm"}]
DATASTORES = [{"id": "ds-1", "name": "datastore1"}]

NSX_MISSING = FileNotFoundError("Config file not found: ~/.vmware-nsx-security/config.yaml")


def _scan(db: str, baseline: str, *, dfw_error: Exception | None = NSX_MISSING):
    """Run a scan with vSphere mocked and the DFW collector optionally broken."""
    dfw = {"sections": [], "rules": []}
    with (
        patch("vmware_harden.collectors.hosts._fetch_hosts", return_value=HOSTS),
        patch("vmware_harden.collectors.vms._fetch_vms", return_value=VMS),
        patch(
            "vmware_harden.collectors.datastores._fetch_datastores",
            return_value=DATASTORES,
        ),
        patch(
            "vmware_harden.collectors.dfw._fetch_dfw",
            side_effect=dfw_error or None,
            return_value=None if dfw_error else dfw,
        ),
    ):
        return run_scan(target="lab", baseline=baseline, db=db)


def _outcomes(twin: Twin, snap_id: str) -> dict[str, tuple[str, str]]:
    rows = twin.conn.execute(
        "SELECT rule_id, outcome, COALESCE(reason, '') FROM rule_outcome WHERE snapshot_id = ?",
        [snap_id],
    ).fetchall()
    return {r[0]: (r[1], r[2]) for r in rows}


@pytest.mark.integration
class TestOneCollectorFails:
    @pytest.fixture
    def scanned(self, tmp_path: Path):
        db = str(tmp_path / "t.duckdb")
        snap_id = _scan(db, "dengbao-2.0-level3-vmware")
        twin = Twin(Path(db))
        yield snap_id, twin, db
        twin.close()

    def test_the_scan_completes(self, scanned):
        snap_id, twin, _ = scanned
        status = twin.conn.execute(
            "SELECT status FROM snapshots WHERE id = ?", [snap_id]
        ).fetchone()[0]
        assert status == "completed"

    def test_the_collectors_that_worked_still_landed(self, scanned):
        snap_id, twin, _ = scanned
        types = dict(
            twin.conn.execute(
                "SELECT n.type, COUNT(*) FROM nodes n JOIN node_state ns "
                "ON ns.node_id = n.id WHERE ns.snapshot_id = ? GROUP BY n.type",
                [snap_id],
            ).fetchall()
        )
        assert types.get("host") == 1
        assert types.get("vm") == 1
        assert types.get("datastore") == 1

    def test_rules_over_the_collected_types_were_evaluated(self, scanned):
        snap_id, twin, _ = scanned
        outcomes = _outcomes(twin, snap_id)
        assert any(o == "evaluated" for o, _ in outcomes.values())

    def test_rules_over_the_uncollected_type_are_undetermined_not_compliant(self, scanned):
        """The whole point: an uncollected firewall is unknown, not clean."""
        from vmware_harden.baselines.loader import load_builtin
        from vmware_harden.checks.evaluability import classify

        snap_id, twin, _ = scanned
        outcomes = _outcomes(twin, snap_id)
        # Selected by node type, from the baseline itself. An id prefix looked
        # like the same question and was not: `db-l3-net-3` is a *host* rule
        # about encrypted vMotion, undetermined for its own older reason.
        dfw_rule_ids = [
            rule.id
            for rule in load_builtin("dengbao-2.0-level3-vmware").rules
            if classify(rule).node_type == "dfw_rule"
        ]
        assert dfw_rule_ids, "no dfw rule in the baseline — the check would be vacuous"
        for rule_id in dfw_rule_ids:
            outcome, reason = outcomes[rule_id]
            assert outcome == "undetermined", f"{rule_id} read as {outcome}"
            assert "not collected" in reason, f"{rule_id}: {reason!r}"

    def test_the_snapshot_records_what_was_and_was_not_collected(self, scanned):
        snap_id, twin, _ = scanned
        covered, failed = twin.conn.execute(
            "SELECT covered_types, failed_collectors FROM snapshots WHERE id = ?",
            [snap_id],
        ).fetchone()
        assert sorted(json.loads(covered)) == ["datastore", "host", "vm"]
        entries = json.loads(failed)
        assert [e["node_types"] for e in entries] == [["dfw_rule"]]
        assert "vmware-nsx-security" in entries[0]["reason"]

    def test_coverage_is_not_reported_complete(self, scanned):
        from vmware_harden.checks.coverage import coverage_for

        snap_id, twin, _ = scanned
        cov = coverage_for(twin, snap_id)
        assert not cov.complete
        assert cov.undetermined > 0

    def test_the_mcp_result_names_the_collector_that_failed(self, tmp_path, monkeypatch):
        from vmware_harden.mcp import tools

        db = str(tmp_path / "mcp.duckdb")
        # Via `_DB_PATH`, the way build_server() hands it over. Setting an env
        # var passed here only because `scan_target` creates a missing database:
        # the read tools next to it refuse one, so the env var was never the
        # mechanism being exercised.
        monkeypatch.setattr(tools, "_DB_PATH", Path(db))
        with (
            patch("vmware_harden.collectors.hosts._fetch_hosts", return_value=HOSTS),
            patch("vmware_harden.collectors.vms._fetch_vms", return_value=VMS),
            patch(
                "vmware_harden.collectors.datastores._fetch_datastores",
                return_value=DATASTORES,
            ),
            patch("vmware_harden.collectors.dfw._fetch_dfw", side_effect=NSX_MISSING),
        ):
            result = tools.scan_target(target="lab", baseline="dengbao-2.0-level3-vmware")
        assert "error" not in result
        assert result["uncollected"], "the result must say a collector failed"
        assert "dfw_rule" in json.dumps(result["uncollected"])
        assert "not collected" in (result["note"] or "")


@pytest.mark.integration
def test_a_scan_whose_every_collector_fails_still_fails(tmp_path: Path):
    """Nothing was read: that is a failed scan, not a scan with gaps."""
    db = str(tmp_path / "t.duckdb")
    with patch("vmware_harden.collectors.hosts._fetch_hosts", side_effect=OSError("vCenter down")):
        with pytest.raises(OSError, match="vCenter down"):
            run_scan(target="lab", baseline="cis-vmware-esxi-8.0-subset", db=db)
    twin = Twin(Path(db))
    try:
        status = twin.conn.execute("SELECT status FROM snapshots").fetchone()[0]
        assert status == "failed"
    finally:
        twin.close()


@pytest.mark.integration
def test_a_remote_error_body_in_the_failure_reason_is_cut_and_stripped(tmp_path: Path):
    """The reason quotes the exception, and the exception can quote the remote.

    An NSX or vCenter error body travels verbatim into the exception text, so
    the recorded reason is the one string in a scan result a remote could
    author: family rule, control characters out and 500 characters at most
    (security review, 2026-09-16).
    """
    db = str(tmp_path / "t.duckdb")
    hostile = "\x1b]0;owned\x07\u200b\u202e refused: " + "A" * 900
    with (
        patch("vmware_harden.collectors.hosts._fetch_hosts", return_value=HOSTS),
        patch(
            "vmware_harden.collectors.vms._fetch_vms",
            side_effect=RuntimeError(hostile),
        ),
    ):
        snap_id = run_scan(target="lab", baseline="vsphere-scg-v8-subset", db=db)
    twin = Twin(Path(db))
    try:
        _, failed = twin.collection_record(snap_id)
        reasons = [e["reason"] for e in failed]
        assert reasons, "the failed collector must be recorded"
        for reason in reasons:
            assert len(reason) <= 500
            assert "\x1b" not in reason and "\x07" not in reason
            # Unicode format chars (zero-width, bidi override) are the
            # reason this must be the family sanitizer, not a local copy.
            assert "\u200b" not in reason and "\u202e" not in reason
        assert "refused" in " ".join(reasons)  # the useful part survives
    finally:
        twin.close()
