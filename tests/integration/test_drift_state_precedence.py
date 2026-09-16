"""One reason per type, chosen by one table, and never two that contradict.

Fifth review of this code. Four rounds of patching the classification produced,
each time, a label that was false in some combination:

* a type this scan also read zero rows for was announced as the "first read with
  rows", while the same scan's counts said 0;
* a type no scan ever collected was announced as "the window ran out", which
  asserts an earlier collection that never happened.

Both are the failure this release exists to remove — an unmeasured thing stated
as a fact — so the states are pinned here as a table rather than as prose, and
the classifier is one function with one precedence.
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

HOST_AND_VM = "vsphere-scg-v8-subset"
HOST_ONLY = "cis-vmware-esxi-8.0-subset"


def _scan(db: str, baseline: str, vms: list[dict] | None = None) -> str:
    with (
        patch("vmware_harden.collectors.hosts._fetch_hosts", return_value=HOSTS),
        patch("vmware_harden.collectors.vms._fetch_vms", return_value=list(vms or [])),
    ):
        return run_scan(target="lab", baseline=baseline, db=db)


def _scope(db: str, snap_id: str):
    twin = Twin(Path(db))
    try:
        return diff_since_prior(twin, snap_id)[1]
    finally:
        twin.close()


@pytest.mark.integration
class TestOneReasonAtATime:
    def test_two_zero_row_scans_do_not_claim_a_first_read_with_rows(self, tmp_path: Path):
        """This scan read 0 rows too, so `unconcluded` is the whole story."""
        db = str(tmp_path / "t.duckdb")
        _scan(db, HOST_AND_VM, vms=[])
        second = _scan(db, HOST_AND_VM, vms=[])
        scope = _scope(db, second)
        assert "vm" in scope.unconcluded
        assert "vm" not in scope.first_real_read
        assert "First read with rows" not in (scope.note or "")

    def test_a_truncated_window_claims_neither_first_collection_nor_an_earlier_one(
        self, tmp_path: Path, monkeypatch
    ):
        """With scans left unread, both labels would assert the unmeasured.

        This test first demanded `first_seen`, which is a claim the code cannot
        support — an unread scan may have collected the type. The shipped label
        previously implied the opposite ("not the same as never having collected
        them"). Neither is knowable here, so the note says only what was searched.
        """
        monkeypatch.setattr(diff_mod, "_BASE_SEARCH_LIMIT", 1)
        db = str(tmp_path / "t.duckdb")
        _scan(db, HOST_ONLY)
        _scan(db, HOST_ONLY)
        last = _scan(db, HOST_AND_VM, vms=[VM_1])
        scope = _scope(db, last)
        assert "vm" not in scope.first_seen
        assert "vm" in scope.no_base_in_window
        note = scope.note or ""
        assert "cannot be told" in note
        assert "1 prior scans searched" in note

    def test_with_every_prior_scan_read_a_new_type_is_first_seen(self, tmp_path: Path):
        """Nothing was left unread, so "first collection" is a measured fact."""
        db = str(tmp_path / "t2.duckdb")
        _scan(db, HOST_ONLY)
        _scan(db, HOST_ONLY)
        last = _scan(db, HOST_AND_VM, vms=[VM_1])
        scope = _scope(db, last)
        assert "vm" in scope.first_seen
        assert "vm" not in scope.no_base_in_window
        assert "First scan to collect" in (scope.note or "")

    def test_a_type_pushed_out_of_the_window_still_blames_the_window(
        self, tmp_path: Path, monkeypatch
    ):
        """The other side of the same table: it WAS collected, just further back."""
        monkeypatch.setattr(diff_mod, "_BASE_SEARCH_LIMIT", 1)
        db = str(tmp_path / "t.duckdb")
        _scan(db, HOST_AND_VM, vms=[VM_1])
        _scan(db, HOST_ONLY)
        last = _scan(db, HOST_AND_VM, vms=[VM_1])
        scope = _scope(db, last)
        assert "vm" in scope.no_base_in_window
        assert "vm" not in scope.first_seen

    def test_a_type_this_scan_read_empty_is_not_called_a_first_collection(self, tmp_path: Path):
        """`unconcluded` and `first_seen` were both claimed for the same type."""
        db = str(tmp_path / "t3.duckdb")
        _scan(db, HOST_ONLY)
        second = _scan(db, HOST_AND_VM, vms=[])  # vm collected, 0 rows
        scope = _scope(db, second)
        assert "vm" in scope.unconcluded
        assert "vm" not in scope.first_seen
        assert "First scan to collect" not in (scope.note or "")

    def test_a_zero_row_read_after_a_real_one_is_unconcluded_and_nothing_else(self, tmp_path: Path):
        """A base exists, but an empty read has nothing to compare against it.

        This estate — prior scan with rows, this scan zero rows — put vm in
        `compared` AND `unconcluded` at once: a named comparison whose events
        were all silently dropped (independent review #7, 2026-09-16).
        """
        db = str(tmp_path / "t4.duckdb")
        _scan(db, HOST_AND_VM, vms=[VM_1])
        second = _scan(db, HOST_AND_VM, vms=[])
        scope = _scope(db, second)
        assert "vm" in scope.unconcluded
        assert "vm" not in {t for t, _ in scope.compared}
        assert "vm" not in scope.first_seen
        assert "vm" not in scope.first_real_read
        assert "vm" not in scope.no_base_in_window

    @pytest.mark.parametrize(
        "first_vms,second_vms",
        [
            ([], [VM_1]),  # zero-row read first, then a real one
            ([VM_1], []),  # a real read first, then a zero-row one — the
            # estate the invariant was violated in while this test passed
            # on the other one only (review #7).
        ],
    )
    def test_no_type_carries_two_reasons(self, tmp_path: Path, first_vms, second_vms):
        """Every labelled type appears in exactly one bucket — `unconcluded` too.

        It was left out of this check, so the invariant the name advertises was
        not the one being verified (form #4).
        """
        db = str(tmp_path / "t.duckdb")
        _scan(db, HOST_AND_VM, vms=first_vms)
        second = _scan(db, HOST_AND_VM, vms=second_vms)
        scope = _scope(db, second)
        buckets = {
            "first_seen": set(scope.first_seen),
            "first_real_read": set(scope.first_real_read),
            "no_base_in_window": set(scope.no_base_in_window),
            "unconcluded": set(scope.unconcluded),
            "compared": {t for t, _ in scope.compared},
        }
        seen: set[str] = set()
        for name, types in buckets.items():
            clash = seen & types
            assert not clash, f"{clash} is in {name} and another bucket too"
            seen |= types


@pytest.mark.integration
class TestTheClassifierIsOneTable:
    """The precedence lives in one function, so it can be asserted directly."""

    @pytest.mark.parametrize(
        "saw_type,zero_only,this_scan_empty,window_exhausted,expected",
        [
            # Nothing left unread, nothing ever collected: a measured first.
            (False, False, False, False, "first_seen"),
            # Scans left unread: say only what was searched — these were
            # `first_real_read` until a review showed the note then asserts
            # "the earlier scans returned 0 rows" about scans nobody read, and
            # swallows a real deletion.
            (False, False, False, True, "no_base_in_window"),
            (True, True, False, True, "no_base_in_window"),
            # Window fully read; every read of the type was empty.
            (True, True, False, False, "first_real_read"),
            # This scan read 0 rows: it concludes nothing either direction, so
            # `unconcluded` is the whole story — no matter what the window
            # holds. The two exhausted rows here were `no_base_in_window` until
            # a seventh review showed that put one type in two buckets.
            (True, True, True, False, None),
            (False, False, True, False, None),
            (True, True, True, True, None),
            (False, False, True, True, None),
        ],
    )
    def test_the_table(self, saw_type, zero_only, this_scan_empty, window_exhausted, expected):
        assert (
            diff_mod._classify_no_base(
                saw_type=saw_type,
                zero_only=zero_only,
                this_scan_empty=this_scan_empty,
                window_exhausted=window_exhausted,
            )
            == expected
        )


@pytest.mark.integration
class TestTheBaseIsAlwaysAnEarlierObservation:
    def test_a_scan_that_finished_later_is_never_the_base(self, tmp_path: Path):
        """Ordering by `scan_finished_at DESC` maximally preferred exactly that.

        Drift then measures this scan against a *later* look at the estate, so a
        node created after this scan reads as already present, and one deleted
        before it reads as still there.
        """
        db = str(tmp_path / "t.duckdb")
        early = _scan(db, HOST_AND_VM, vms=[VM_1])
        late = _scan(db, HOST_AND_VM, vms=[VM_1])
        current = _scan(db, HOST_AND_VM, vms=[VM_1])
        twin = Twin(Path(db))
        try:
            started = twin.conn.execute(
                "SELECT scan_started_at FROM snapshots WHERE id = ?", [current]
            ).fetchone()[0]
            # All three share a start; `late` finishes long after `current`.
            for snap in (early, late, current):
                twin.conn.execute(
                    "UPDATE snapshots SET scan_started_at = ? WHERE id = ?", [started, snap]
                )
            twin.conn.execute(
                "UPDATE snapshots SET scan_finished_at = scan_finished_at + INTERVAL 99 MINUTE "
                "WHERE id = ?",
                [late],
            )
            _, scope = diff_since_prior(twin, current)
            bases = {t: b for t, b in scope.compared}
            assert late not in bases.values(), "compared against a later observation"
        finally:
            twin.close()


@pytest.mark.integration
def test_scan_target_carries_the_drift_note(tmp_path: Path, monkeypatch):
    """The agent that ran the scan is the one acting on it.

    RELEASE_NOTES claimed the scan's own output reads the note; only
    list_drift_events did.
    """
    from vmware_harden.mcp import tools

    db = str(tmp_path / "t.duckdb")
    _scan(db, HOST_AND_VM, vms=[VM_1])
    monkeypatch.setattr(tools, "_DB_PATH", Path(db))
    with (
        patch("vmware_harden.collectors.hosts._fetch_hosts", return_value=HOSTS),
        patch("vmware_harden.collectors.vms._fetch_vms", return_value=[VM_1]),
    ):
        result = tools.scan_target(target="lab", baseline=HOST_ONLY)
    assert result["drift_scope"], "the scan result must carry what its drift could compare"
    assert "vm" in result["drift_scope"]["not_compared"]
    assert "Not compared" in (result["note"] or "")
