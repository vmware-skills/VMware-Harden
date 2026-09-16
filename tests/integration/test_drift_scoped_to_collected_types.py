"""Drift must not read "this baseline does not collect VMs" as "the VMs are gone".

Reported 2026-09-15: a scan with a baseline that collects no VMs, run after one
that did, reported all 12 VMs deleted. The prior snapshot is chosen by target
alone (never by baseline), and `node_state` holds only what that scan collected,
so every node type the new baseline does not cover looks removed.

`_removed` is the one drift event an operator acts on immediately, so it has to
mean a node that is actually gone. A type nobody looked at is unknown, and the
diff says which types it compared instead of guessing.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from vmware_harden.cli.runner import run_scan
from vmware_harden.drift.diff import diff_snapshots
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
VMS = [{"id": "vm-1", "name": "test-llm"}, {"id": "vm-2", "name": "vcsa"}]
DATASTORES = [{"id": "ds-1", "name": "datastore1"}]


def _scan(db: str, baseline: str, hosts=None):
    with (
        patch("vmware_harden.collectors.hosts._fetch_hosts", return_value=hosts or HOSTS),
        patch("vmware_harden.collectors.vms._fetch_vms", return_value=VMS),
        patch(
            "vmware_harden.collectors.datastores._fetch_datastores",
            return_value=DATASTORES,
        ),
        patch(
            "vmware_harden.collectors.dfw._fetch_dfw",
            side_effect=FileNotFoundError(
                "Config file not found: ~/.vmware-nsx-security/config.yaml"
            ),
        ),
    ):
        return run_scan(target="lab", baseline=baseline, db=db)


@pytest.mark.integration
class TestSwitchingBaselines:
    @pytest.fixture
    def two_scans(self, tmp_path: Path):
        db = str(tmp_path / "t.duckdb")
        first = _scan(db, "dengbao-2.0-level3-vmware")  # host + vm + datastore
        second = _scan(db, "cis-vmware-esxi-8.0-subset")  # host only
        twin = Twin(Path(db))
        yield first, second, twin
        twin.close()

    def test_uncollected_types_are_not_reported_removed(self, two_scans):
        first, second, twin = two_scans
        events = diff_snapshots(twin, first, second)
        removed = [e.node_id for e in events if e.field == "_removed"]
        assert removed == [], f"reported gone, but nobody looked: {removed}"

    def test_the_persisted_drift_has_no_removals_either(self, two_scans):
        """run_scan persists its own diff; the stored rows are what tools read."""
        _, second, twin = two_scans
        rows = twin.conn.execute(
            "SELECT node_id FROM change_event WHERE snapshot_id = ? AND field = '_removed'",
            [second],
        ).fetchall()
        assert rows == []

    def test_the_diff_says_which_types_it_compared(self, two_scans):
        from vmware_harden.drift.diff import diff_scope

        first, second, twin = two_scans
        scope = diff_scope(twin, first, second)
        assert scope.compared == ("host",)
        assert sorted(scope.not_compared) == ["datastore", "vm"]
        assert "vm" in scope.note and "not collected" in scope.note


@pytest.mark.integration
class TestRealChangesStillReported:
    def test_a_node_of_a_compared_type_that_really_went_away_is_reported(self, tmp_path: Path):
        db = str(tmp_path / "t.duckdb")
        two_hosts = [HOSTS[0], {**HOSTS[0], "id": "host-2", "name": "esx-2"}]
        first = _scan(db, "cis-vmware-esxi-8.0-subset", hosts=two_hosts)
        second = _scan(db, "cis-vmware-esxi-8.0-subset", hosts=[HOSTS[0]])
        twin = Twin(Path(db))
        try:
            events = diff_snapshots(twin, first, second)
            removed = [e.node_id for e in events if e.field == "_removed"]
            assert removed == ["lab:host-2"]
        finally:
            twin.close()

    def test_config_drift_on_a_compared_type_is_still_reported(self, tmp_path: Path):
        db = str(tmp_path / "t.duckdb")
        first = _scan(db, "cis-vmware-esxi-8.0-subset")
        changed = [{**HOSTS[0], "syslog_remote_host": "syslog.lab"}]
        second = _scan(db, "cis-vmware-esxi-8.0-subset", hosts=changed)
        twin = Twin(Path(db))
        try:
            fields = {e.field for e in diff_snapshots(twin, first, second)}
            assert "syslog_remote_host" in fields
        finally:
            twin.close()


@pytest.mark.integration
def test_a_type_collected_but_found_empty_is_still_compared(tmp_path: Path):
    """ "We looked for VMs and there were none" is a measurement, not a blind spot.

    Scoping by the rows a snapshot happens to hold would make the first VM to
    appear invisible, and — the direction that matters — the last VM to vanish
    too, because a snapshot with zero VM rows looks like one that never checked.
    The recorded covered_types is what separates them.
    """
    db = str(tmp_path / "t.duckdb")
    with (
        patch("vmware_harden.collectors.hosts._fetch_hosts", return_value=HOSTS),
        patch("vmware_harden.collectors.vms._fetch_vms", return_value=[]),
    ):
        first = run_scan(target="lab", baseline="vsphere-scg-v8-subset", db=db)  # host + vm
    with (
        patch("vmware_harden.collectors.hosts._fetch_hosts", return_value=HOSTS),
        patch("vmware_harden.collectors.vms._fetch_vms", return_value=[VMS[0]]),
    ):
        second = run_scan(target="lab", baseline="vsphere-scg-v8-subset", db=db)
    twin = Twin(Path(db))
    try:
        from vmware_harden.drift.diff import diff_scope

        assert "vm" in diff_scope(twin, first, second).compared
        # The type stays comparable — but nothing is claimed about vm-1 yet: the
        # base read zero rows, so "new" would rest on a read that measured
        # nothing. This asserted an addition until a review pointed that out,
        # while a second test file asserted the opposite for the same estate.
        added = [e.node_id for e in diff_snapshots(twin, first, second) if e.field == "_added"]
        assert added == []
    finally:
        twin.close()


@pytest.mark.integration
def test_a_snapshot_from_before_this_release_falls_back_to_what_it_holds(tmp_path: Path):
    """covered_types is NULL on old rows; the types it collected are still knowable."""
    from vmware_harden.drift.diff import diff_scope

    db = str(tmp_path / "t.duckdb")
    first = _scan(db, "dengbao-2.0-level3-vmware")
    second = _scan(db, "cis-vmware-esxi-8.0-subset")
    twin = Twin(Path(db))
    try:
        twin.conn.execute("UPDATE snapshots SET covered_types = NULL WHERE id = ?", [first])
        scope = diff_scope(twin, first, second)
        assert scope.compared == ("host",)
        assert sorted(scope.not_compared) == ["datastore", "vm"]
        assert diff_snapshots(twin, first, second) == [] or all(
            e.field != "_removed" for e in diff_snapshots(twin, first, second)
        )
    finally:
        twin.close()
