"""Scoping the diff must not hide a real deletion, or go quiet about what it skipped.

Independent review of the first fix, 2026-09-16, reproduced three ways it fell
short — each one a variant of the same rule: what a scan did not measure has to
be *said*, and what it did measure has to still be comparable.

1. The "not compared" note was derived from the collectors that FAILED. In the
   defect that prompted the fix no collector fails — the second baseline simply
   covers fewer node types — so both surfaces went silent about the VMs.
2. Drift only ever compares the immediately-prior snapshot, so a VM deleted
   across a narrower scan in between was reported by nobody, ever.
3. `covered_types` came from the baseline's `applies_to`, not from what the
   collector actually wrote, so a collector that answers with an empty list (a
   permission-filtered read is indistinguishable from an empty estate) still
   turned last scan's VMs into deletions.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

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
VM_1 = {"id": "vm-1", "name": "test-llm"}
VM_2 = {"id": "vm-2", "name": "vcsa"}

HOST_AND_VM = "vsphere-scg-v8-subset"  # applies_to: host, vm
HOST_ONLY = "cis-vmware-esxi-8.0-subset"  # applies_to: host


def _scan(db: str, baseline: str, vms: list[dict] | None = None):
    """A scan where every collector the baseline needs succeeds."""
    with (
        patch("vmware_harden.collectors.hosts._fetch_hosts", return_value=HOSTS),
        patch("vmware_harden.collectors.vms._fetch_vms", return_value=list(vms or [])),
    ):
        return run_scan(target="lab", baseline=baseline, db=db)


def _added_in(twin: Twin, snap_id: str) -> list[str]:
    return [
        r[0]
        for r in twin.conn.execute(
            "SELECT node_id FROM change_event WHERE snapshot_id = ? AND field = '_added'",
            [snap_id],
        ).fetchall()
    ]


def _removed(twin: Twin, snap_id: str) -> list[str]:
    return [
        r[0]
        for r in twin.conn.execute(
            "SELECT node_id FROM change_event WHERE snapshot_id = ? AND field = '_removed'",
            [snap_id],
        ).fetchall()
    ]


@pytest.mark.integration
class TestSayingWhatWasNotCompared:
    """No collector fails here. The narrower baseline is the whole story."""

    @pytest.fixture
    def narrowed(self, tmp_path: Path):
        db = str(tmp_path / "t.duckdb")
        _scan(db, HOST_AND_VM, vms=[VM_1, VM_2])
        second = _scan(db, HOST_ONLY)
        twin = Twin(Path(db))
        yield second, twin, db
        twin.close()

    def test_the_mcp_tool_says_vm_was_not_compared(self, narrowed, monkeypatch):
        from vmware_harden.mcp import tools

        _, _, db = narrowed
        # `_DB_PATH` is how build_server() hands the path to the tools; there is
        # no env var on this path, and the read tools refuse a missing file.
        monkeypatch.setattr(tools, "_DB_PATH", Path(db))
        result = tools.list_drift_events(limit=50)
        assert result["collected_types"] == ["host"]
        assert result["drift_note"], "an empty drift list needs its scope said out loud"
        assert "vm" in result["drift_note"]
        assert "not compared" in result["drift_note"].lower()

    def test_the_cli_says_it_too(self, narrowed):
        from vmware_harden.cli.drift import app

        _, _, db = narrowed
        out = CliRunner().invoke(app, ["--db", db], terminal_width=200)
        assert out.exit_code == 0, out.output
        assert "vm" in out.output
        assert "not compared" in out.output.lower()

    def test_the_json_format_says_it_too(self, narrowed):
        """An empty JSON list with no note is "nothing changed anywhere" again.

        The two NOTE lines were text-format only, so the machine-readable
        surface kept the exact hole this release closes (independent review
        #7, 2026-09-16). They go to stderr as `#` comments, like the standing
        warning already does, so stdout stays parseable JSON.
        """
        import json as _json

        from vmware_harden.cli.drift import app

        _, _, db = narrowed
        out = CliRunner().invoke(app, ["--db", db, "--format", "json"], terminal_width=200)
        assert out.exit_code == 0, out.output
        stdout_part = out.output.split("# ")[0]
        _json.loads(stdout_part)  # stdout alone is still valid JSON
        assert "not compared" in out.output.lower()
        assert "vm" in out.output


@pytest.mark.integration
def test_a_deletion_across_a_narrower_scan_is_still_reported(tmp_path: Path):
    """The narrower scan in the middle must not become a place deletions vanish.

    Compared against the most recent prior scan that actually collected VMs,
    which is the first one — not the host-only scan that never looked.
    """
    db = str(tmp_path / "t.duckdb")
    _scan(db, HOST_AND_VM, vms=[VM_1, VM_2])
    _scan(db, HOST_ONLY)
    third = _scan(db, HOST_AND_VM, vms=[VM_1])  # vm-2 genuinely deleted
    twin = Twin(Path(db))
    try:
        assert _removed(twin, third) == ["lab:vm-2"]
    finally:
        twin.close()


@pytest.mark.integration
class TestACollectorThatAnswersEmpty:
    """An empty answer is not a measurement of an empty estate."""

    @pytest.fixture
    def emptied(self, tmp_path: Path):
        db = str(tmp_path / "t.duckdb")
        _scan(db, HOST_AND_VM, vms=[VM_1, VM_2])
        second = _scan(db, HOST_AND_VM, vms=[])  # same baseline, zero rows back
        twin = Twin(Path(db))
        yield second, twin, db
        twin.close()

    def test_last_scans_vms_are_not_reported_deleted(self, emptied):
        second, twin, _ = emptied
        assert _removed(twin, second) == []

    def test_the_zero_row_read_is_recorded_and_said(self, emptied, monkeypatch):
        from vmware_harden.mcp import tools

        second, twin, db = emptied
        covered, _ = twin.collection_record(second)
        counts = json.loads(
            twin.conn.execute(
                "SELECT collected_counts FROM snapshots WHERE id = ?", [second]
            ).fetchone()[0]
        )
        assert "vm" in covered and counts["vm"] == 0
        monkeypatch.setattr(tools, "_DB_PATH", Path(db))
        note = tools.list_drift_events(limit=50)["drift_note"] or ""
        assert "vm" in note and "0" in note

    def test_the_first_real_read_claims_no_additions(self, tmp_path: Path):
        """A VM seen after a zero-row read is not known to be new.

        This test asserted the opposite until a review pointed out what the
        claim rests on: the only evidence for "new" would be a read that
        measured nothing. It may have been there all along, so the scope calls
        this the first reliable read of the type and claims no change.
        """
        from vmware_harden.drift.diff import diff_since_prior

        db = str(tmp_path / "t2.duckdb")
        _scan(db, HOST_AND_VM, vms=[])
        second = _scan(db, HOST_AND_VM, vms=[VM_1])
        twin = Twin(Path(db))
        try:
            assert _added_in(twin, second) == []
            _, scope = diff_since_prior(twin, second)
            # Not `first_seen`: the earlier snapshot records collecting vm. This
            # is the first read that returned anything (review, 2026-09-16).
            assert "vm" in scope.first_real_read
        finally:
            twin.close()

    def test_a_real_addition_against_a_real_read_is_reported(self, tmp_path: Path):
        """The direction stays live where the base actually read the type."""
        db = str(tmp_path / "t3.duckdb")
        _scan(db, HOST_AND_VM, vms=[VM_1])
        second = _scan(db, HOST_AND_VM, vms=[VM_1, VM_2])
        twin = Twin(Path(db))
        try:
            assert _added_in(twin, second) == ["lab:vm-2"]
        finally:
            twin.close()


@pytest.mark.integration
def test_a_missing_dependency_keeps_its_remedy_when_another_collector_works(tmp_path: Path):
    """The install command is the whole value of that error; a partial scan kept
    only "ModuleNotFoundError: No module named 'pyVim'"."""
    db = str(tmp_path / "t.duckdb")
    with (
        patch(
            "vmware_harden.collectors.hosts._fetch_hosts",
            side_effect=ModuleNotFoundError("No module named 'pyVim'", name="pyVim"),
        ),
        patch("vmware_harden.collectors.vms._fetch_vms", return_value=[VM_1]),
    ):
        snap_id = run_scan(target="lab", baseline=HOST_AND_VM, db=db)
    twin = Twin(Path(db))
    try:
        _, failed = twin.collection_record(snap_id)
        assert [entry["node_types"] for entry in failed] == [["host"]]
        assert "vmware-harden[collectors]" in failed[0]["reason"]
    finally:
        twin.close()


@pytest.mark.integration
def test_collection_record_on_a_database_without_the_columns(tmp_path: Path):
    """A pre-column database must read as "unknown", not raise.

    `checks/coverage.py` already guards its own query for the same reason: a
    read-only consumer cannot migrate the file it was handed.
    """
    db = tmp_path / "t.duckdb"
    twin = Twin(db)
    try:
        snap_id = _scan(str(db), HOST_ONLY)
        twin.conn.execute("ALTER TABLE snapshots DROP COLUMN covered_types")
        twin.conn.execute("ALTER TABLE snapshots DROP COLUMN failed_collectors")
        assert twin.collection_record(snap_id) == (None, [])
    finally:
        twin.close()
