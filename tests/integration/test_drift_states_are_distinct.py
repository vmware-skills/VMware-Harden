"""Three ways to have no comparison, and they must not be told as one another.

Fourth review of this code, 2026-09-16. Round three introduced a skip (a scan
that read zero rows is not a base) and then reported the consequence with the
wrong label: a type collected-but-empty last time came out as "First scan to
collect", a positive falsehood about an estate whose own snapshot records that
the type WAS collected. My own test pinned that wrong label.

The distinct states:

* never collected by any searched scan  → first_seen
* collected, but every candidate read zero rows → first_real_read
* collected for real, but further back than the searched window → no_base_in_window

The other half is what "collected" means. It was taken from the baseline's
`applies_to`, while collectors write what they write: DFWCollector writes
`dfw_section` rows for a baseline that lists only `dfw_rule`, so section drift —
a renamed or vanished firewall section — was compared by nobody and named by
nothing.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from vmware_harden.cli.runner import run_scan
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

HOST_AND_VM = "vsphere-scg-v8-subset"  # applies_to: host, vm
HOST_ONLY = "cis-vmware-esxi-8.0-subset"  # applies_to: host
WITH_DFW = "dengbao-2.0-level3-vmware"  # applies_to: host, vm, datastore, dfw_rule


def _scan(db: str, baseline: str, vms: list[dict] | None = None, dfw: dict | None = None):
    with (
        patch("vmware_harden.collectors.hosts._fetch_hosts", return_value=HOSTS),
        patch("vmware_harden.collectors.vms._fetch_vms", return_value=list(vms or [])),
        patch("vmware_harden.collectors.datastores._fetch_datastores", return_value=[]),
        patch(
            "vmware_harden.collectors.dfw._fetch_dfw",
            return_value=dfw or {"sections": [], "rules": []},
        ),
    ):
        return run_scan(target="lab", baseline=baseline, db=db)


@pytest.mark.integration
class TestTheFirstRealReadHasItsOwnName:
    @pytest.fixture
    def after_a_zero_row_read(self, tmp_path: Path):
        db = str(tmp_path / "t.duckdb")
        _scan(db, HOST_AND_VM, vms=[])  # collected vm, read nothing
        second = _scan(db, HOST_AND_VM, vms=[VM_1])
        twin = Twin(Path(db))
        yield second, twin
        twin.close()

    def test_it_is_not_called_a_first_collection(self, after_a_zero_row_read):
        """The prior snapshot's own covered_types records that vm was collected."""
        second, twin = after_a_zero_row_read
        _, scope = diff_since_prior(twin, second)
        assert "vm" not in scope.first_seen
        assert "vm" in scope.first_real_read

    def test_the_note_says_which_it_is(self, after_a_zero_row_read):
        second, twin = after_a_zero_row_read
        _, scope = diff_since_prior(twin, second)
        note = scope.note or ""
        assert "first" in note.lower() and "0 rows" in note
        assert "First scan to collect" not in note

    def test_a_type_no_scan_ever_collected_is_still_first_seen(self, tmp_path: Path):
        db = str(tmp_path / "t2.duckdb")
        _scan(db, HOST_ONLY)
        second = _scan(db, HOST_AND_VM, vms=[VM_1])
        twin = Twin(Path(db))
        try:
            _, scope = diff_since_prior(twin, second)
            assert "vm" in scope.first_seen
            assert "vm" not in scope.first_real_read
        finally:
            twin.close()


@pytest.mark.integration
class TestWhatCountsAsCollected:
    """Rows written, not the baseline's declaration."""

    @pytest.fixture
    def two_dfw_scans(self, tmp_path: Path):
        db = str(tmp_path / "t.duckdb")
        # Shaped the way the real `_fetch_dfw` returns them: it runs every record
        # through `_shape_dfw`, which stamps `name` from NSX's `display_name`.
        # Leaving `name` off made the collector fail on its own contract, and the
        # fixture — not the code — was the thing under test.
        first = _scan(
            db,
            WITH_DFW,
            dfw={
                "sections": [{"id": "s-1", "display_name": "web tier", "name": "web tier"}],
                "rules": [
                    {
                        "id": "r-1",
                        "display_name": "allow web",
                        "name": "allow web",
                        "action": "ALLOW",
                    }
                ],
            },
        )
        second = _scan(
            db,
            WITH_DFW,
            dfw={
                "sections": [
                    {"id": "s-1", "display_name": "web tier RENAMED", "name": "web tier RENAMED"}
                ],
                "rules": [
                    {
                        "id": "r-1",
                        "display_name": "allow web",
                        "name": "allow web",
                        "action": "DROP",
                    }
                ],
            },
        )
        twin = Twin(Path(db))
        yield first, second, twin
        twin.close()

    def test_a_type_the_collector_wrote_is_recorded_as_collected(self, two_dfw_scans):
        first, _, twin = two_dfw_scans
        covered, _ = twin.collection_record(first)
        assert "dfw_section" in covered, "written rows were not recorded as collected"

    def test_a_section_rename_is_reported(self, two_dfw_scans):
        """The rule change was reported and the section change was not — silently."""
        _, second, twin = two_dfw_scans
        fields = {
            (r[0], r[1])
            for r in twin.conn.execute(
                "SELECT node_id, field FROM change_event WHERE snapshot_id = ?", [second]
            ).fetchall()
        }
        assert ("lab:r-1", "action") in fields
        assert ("lab:s-1", "display_name") in fields

    def test_the_counts_cover_every_written_type(self, two_dfw_scans):
        first, _, twin = two_dfw_scans
        counts = twin.collected_counts(first) or {}
        assert counts.get("dfw_section") == 1
        assert counts.get("dfw_rule") == 1


@pytest.mark.integration
def test_both_engines_agree_about_a_zero_row_base(tmp_path: Path):
    """`diff_snapshots` kept the semantics round three reverted.

    Two test files asserted opposite outcomes for this estate and both passed,
    because one of them drove code no scan calls any more.
    """
    from vmware_harden.drift.diff import diff_snapshots

    db = str(tmp_path / "t.duckdb")
    first = _scan(db, HOST_AND_VM, vms=[])
    second = _scan(db, HOST_AND_VM, vms=[VM_1])
    twin = Twin(Path(db))
    try:
        per_type, _ = diff_since_prior(twin, second)
        pairwise = diff_snapshots(twin, first, second)
        assert [(e.node_id, e.field) for e in pairwise] == [(e.node_id, e.field) for e in per_type]
    finally:
        twin.close()


@pytest.mark.integration
def test_scans_sharing_a_start_timestamp_still_find_their_base(tmp_path: Path):
    """`scan_started_at <` dropped the base entirely; the old query keyed on id."""
    db = str(tmp_path / "t.duckdb")
    first = _scan(db, HOST_AND_VM, vms=[VM_1, VM_2])
    second = _scan(db, HOST_AND_VM, vms=[VM_1])  # vm-2 deleted
    twin = Twin(Path(db))
    try:
        stamp = twin.conn.execute(
            "SELECT scan_started_at FROM snapshots WHERE id = ?", [first]
        ).fetchone()[0]
        # Both timestamps, not just the start. Moving only `scan_started_at`
        # back invented a state the estate cannot be in — the earlier scan
        # finishing AFTER this one began — and a base must be an earlier
        # observation, so it was then correctly excluded. A real tie is two
        # scans that started in the same instant and both finished before the
        # next one started.
        twin.conn.execute(
            "UPDATE snapshots SET scan_started_at = ?, scan_finished_at = ? WHERE id = ?",
            [stamp, stamp, first],
        )
        twin.conn.execute("UPDATE snapshots SET scan_started_at = ? WHERE id = ?", [stamp, second])
        events, scope = diff_since_prior(twin, second)
        assert ("vm", first) in scope.compared
        assert [e.node_id for e in events if e.field == "_removed"] == ["lab:vm-2"]
    finally:
        twin.close()


@pytest.mark.integration
def test_a_candidate_that_finished_after_this_scan_began_is_not_a_base(tmp_path: Path):
    """The boundary of the rule above, one second the wrong side of it.

    `TestTheBaseIsAlwaysAnEarlierObservation` uses a 99-minute overlap; the
    off-by-an-instant case is the one a fast pair of scans actually produces.
    """
    db = str(tmp_path / "t.duckdb")
    first = _scan(db, HOST_AND_VM, vms=[VM_1, VM_2])
    second = _scan(db, HOST_AND_VM, vms=[VM_1])
    twin = Twin(Path(db))
    try:
        started = twin.conn.execute(
            "SELECT scan_started_at FROM snapshots WHERE id = ?", [second]
        ).fetchone()[0]
        twin.conn.execute(
            "UPDATE snapshots SET scan_finished_at = ? + INTERVAL 1 SECOND WHERE id = ?",
            [started, first],
        )
        _, scope = diff_since_prior(twin, second)
        assert first not in {b for _, b in scope.compared}
        assert "vm" in scope.no_base_in_window or "vm" in scope.first_seen
    finally:
        twin.close()


@pytest.mark.integration
def test_a_full_window_is_not_reported_as_exhausted(tmp_path: Path, monkeypatch):
    """With as many priors as the limit, "the window ran out" must be true to say."""
    from vmware_harden.drift import diff as diff_mod

    monkeypatch.setattr(diff_mod, "_BASE_SEARCH_LIMIT", 2)
    db = str(tmp_path / "t.duckdb")
    _scan(db, HOST_ONLY)
    _scan(db, HOST_ONLY)
    last = _scan(db, HOST_AND_VM, vms=[VM_1])
    twin = Twin(Path(db))
    try:
        _, scope = diff_since_prior(twin, last)
        # vm was never collected by anything, and exactly `limit` priors exist.
        assert "vm" in scope.first_seen
        assert "vm" not in scope.no_base_in_window
    finally:
        twin.close()


@pytest.mark.integration
def test_the_scope_reports_how_many_snapshots_it_searched(tmp_path: Path):
    """It reported the constant, so the bound in the note was never verified."""
    db = str(tmp_path / "t.duckdb")
    _scan(db, HOST_ONLY)
    _scan(db, HOST_ONLY)
    last = _scan(db, HOST_ONLY)
    twin = Twin(Path(db))
    try:
        _, scope = diff_since_prior(twin, last)
        assert scope.as_dict()["searched_snapshots"] == 2
        assert json.dumps(scope.as_dict())  # stays serialisable for the envelope
    finally:
        twin.close()
