"""Which prior scan a type is compared against, and what to say when there is none.

Round two compared each node type against the most recent prior scan that
*collected* it. A third review found that a scan whose collector returned zero
rows qualifies as such a base — and since that scan's own removals were
deliberately left unconcluded, a deletion between the last real read and now
fell through both: reported by nobody, silently this time.

The other half is honesty about the search itself. The window of prior
snapshots is bounded, so "no base found" has two very different causes, and
calling the second one "first scan to collect" is a positive falsehood about a
type that may have been scanned for months.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from vmware_harden.cli.runner import run_scan
from vmware_harden.drift import diff as diff_mod
from vmware_harden.drift.diff import diff_since_prior
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
VM_1 = {"id": "vm-1", "name": "test-llm"}
VM_2 = {"id": "vm-2", "name": "vcsa"}

HOST_AND_VM = "vsphere-scg-v8-subset"
HOST_ONLY = "cis-vmware-esxi-8.0-subset"


def _scan(db: str, baseline: str, vms: list[dict] | None = None) -> str:
    with (
        patch("vmware_harden.collectors.hosts._fetch_hosts", return_value=HOSTS),
        patch("vmware_harden.collectors.vms._fetch_vms", return_value=list(vms or [])),
    ):
        return run_scan(target="lab", baseline=baseline, db=db)


def _events(twin: Twin, snap_id: str, field: str) -> list[str]:
    return [
        r[0]
        for r in twin.conn.execute(
            "SELECT node_id FROM change_event WHERE snapshot_id = ? AND field = ?",
            [snap_id, field],
        ).fetchall()
    ]


@pytest.mark.integration
class TestAZeroRowScanIsNeverABase:
    @pytest.fixture
    def three_scans(self, tmp_path: Path):
        db = str(tmp_path / "t.duckdb")
        first = _scan(db, HOST_AND_VM, vms=[VM_1, VM_2])
        _scan(db, HOST_AND_VM, vms=[])  # permission-filtered read: 0 rows
        third = _scan(db, HOST_AND_VM, vms=[VM_1])  # vm-2 genuinely deleted
        twin = Twin(Path(db))
        yield first, third, twin
        twin.close()

    def test_the_deletion_is_reported(self, three_scans):
        _, third, twin = three_scans
        assert _events(twin, third, "_removed") == ["lab:vm-2"]

    def test_the_survivor_is_not_reported_as_new(self, three_scans):
        """Comparing against the empty scan made every surviving VM an addition."""
        _, third, twin = three_scans
        assert _events(twin, third, "_added") == []

    def test_the_scope_names_the_scan_actually_compared_against(self, three_scans):
        first, third, twin = three_scans
        _, scope = diff_since_prior(twin, third)
        assert ("vm", first) in scope.compared


@pytest.mark.integration
class TestAnExhaustedSearchWindow:
    def test_is_not_reported_as_a_first_scan(self, tmp_path: Path, monkeypatch):
        """A type scanned long ago is not one nobody ever collected."""
        monkeypatch.setattr(diff_mod, "_BASE_SEARCH_LIMIT", 2)
        db = str(tmp_path / "t.duckdb")
        _scan(db, HOST_AND_VM, vms=[VM_1, VM_2])  # the only scan that saw VMs
        for _ in range(3):
            _scan(db, HOST_ONLY)  # pushes it out of the window
        last = _scan(db, HOST_AND_VM, vms=[VM_1])
        twin = Twin(Path(db))
        try:
            _, scope = diff_since_prior(twin, last)
            assert "vm" not in scope.first_seen, "claimed a first scan for an old type"
            assert "vm" in scope.no_base_in_window
            note = scope.note or ""
            # The label says what was searched and stops there. Round five
            # removed the wording this line used to assert ("the window ran
            # out … not the same as never having collected them"), which
            # implied an earlier collection just as falsely as `first_seen`
            # denied one.
            assert "cannot be told" in note
            assert "not the same as never" not in note
        finally:
            twin.close()

    def test_a_genuinely_new_type_is_still_called_first_seen(self, tmp_path: Path):
        db = str(tmp_path / "t.duckdb")
        first = _scan(db, HOST_AND_VM, vms=[VM_1])
        twin = Twin(Path(db))
        try:
            _, scope = diff_since_prior(twin, first)
            assert set(scope.first_seen) == {"host", "vm"}
            assert "First scan to collect" in (scope.note or "")
        finally:
            twin.close()


@pytest.mark.integration
def test_an_explicitly_empty_covered_list_is_not_unknown(tmp_path: Path):
    """`[]` says "this scan collected nothing"; None says "nobody recorded it".

    Collapsing the first into the second is how a recorded fact becomes a guess.
    """
    db = tmp_path / "t.duckdb"
    snap_id = _scan(str(db), HOST_ONLY)
    twin = Twin(db)
    try:
        twin.conn.execute("UPDATE snapshots SET covered_types = '[]' WHERE id = ?", [snap_id])
        assert diff_mod._collected_types(twin, snap_id) == set()
    finally:
        twin.close()
