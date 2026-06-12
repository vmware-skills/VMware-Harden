"""Regression: collectors and check runner batch their writes.

Pins the v1.5.x perf fix that collapsed per-node `BEGIN TRANSACTION ... COMMIT`
(one fsync per host/vm/datastore/dfw entry — thousands on a large estate) into
a single transaction per collector run, and likewise for CheckRunner's
violation inserts. We assert the transaction count is small and constant
(independent of inventory size), and that observable behavior is unchanged.
"""
from pathlib import Path
from unittest.mock import patch

import pytest

from vmware_harden.baselines.loader import load_builtin
from vmware_harden.checks.runner import CheckRunner
from vmware_harden.collectors.datastores import DatastoreCollector
from vmware_harden.collectors.dfw import DFWCollector
from vmware_harden.collectors.hosts import HostCollector
from vmware_harden.collectors.vms import VMCollector
from vmware_harden.store.twin import Twin


class _ConnSpy:
    """Wraps a DuckDB connection, counting BEGIN TRANSACTION statements.

    The native connection's ``execute`` attribute is read-only, so we can't
    monkeypatch it in place; wrap the whole connection and delegate.
    """

    def __init__(self, conn, counter: list[int]):
        self._conn = conn
        self._counter = counter

    def execute(self, sql, *args, **kwargs):
        if isinstance(sql, str) and sql.strip().upper().startswith("BEGIN"):
            self._counter[0] += 1
        return self._conn.execute(sql, *args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._conn, name)


def _count_begins(twin: Twin) -> list[int]:
    """Swap twin.conn for a spy, returning a mutable [count] of BEGINs."""
    counter = [0]
    twin.conn = _ConnSpy(twin.conn, counter)
    return counter


def _hosts(n: int) -> list[dict]:
    return [
        {"id": f"h-{i}", "name": f"esx{i}", "ntp_enabled": True, "build": 99999999}
        for i in range(n)
    ]


@pytest.mark.unit
def test_host_collector_uses_one_transaction_regardless_of_size(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    snap = twin.start_snapshot("v.lab")
    begins = _count_begins(twin)

    with patch("vmware_harden.collectors.hosts._fetch_hosts", return_value=_hosts(50)):
        n = HostCollector(twin).collect(snap, target="v.lab")

    assert n == 50
    # One transaction for the whole batch — NOT one per host.
    assert begins[0] == 1
    # Behavior unchanged: every node + node_state row was written.
    assert twin.conn.execute(
        "SELECT COUNT(*) FROM nodes WHERE type = 'host'"
    ).fetchone()[0] == 50
    assert twin.conn.execute(
        "SELECT COUNT(*) FROM node_state WHERE snapshot_id = ?", [snap]
    ).fetchone()[0] == 50
    twin.close()


@pytest.mark.unit
def test_vm_and_datastore_collectors_use_one_transaction(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    snap = twin.start_snapshot("v.lab")

    vms = [{"id": f"vm-{i}", "name": f"vm{i}"} for i in range(30)]
    begins = _count_begins(twin)
    with patch("vmware_harden.collectors.vms._fetch_vms", return_value=vms):
        VMCollector(twin).collect(snap, target="v.lab")
    assert begins[0] == 1

    dss = [{"id": f"ds-{i}", "name": f"ds{i}"} for i in range(20)]
    begins[0] = 0
    with patch(
        "vmware_harden.collectors.datastores._fetch_datastores", return_value=dss
    ):
        DatastoreCollector(twin).collect(snap, target="v.lab")
    assert begins[0] == 1
    twin.close()


@pytest.mark.unit
def test_dfw_collector_uses_one_transaction_for_sections_and_rules(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    snap = twin.start_snapshot("v.lab")
    data = {
        "sections": [{"id": f"sec-{i}", "name": f"sec{i}"} for i in range(5)],
        "rules": [{"id": f"rule-{i}", "name": f"rule{i}"} for i in range(15)],
    }
    begins = _count_begins(twin)
    with patch("vmware_harden.collectors.dfw._fetch_dfw", return_value=data):
        n = DFWCollector(twin).collect(snap, target="v.lab")
    assert n == 20
    # Sections + rules share ONE transaction now.
    assert begins[0] == 1
    twin.close()


@pytest.mark.unit
def test_check_runner_persists_violations_in_one_transaction(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    snap = twin.start_snapshot("v.lab")
    # Seed several non-compliant hosts so the baseline fires many violations.
    with patch(
        "vmware_harden.collectors.hosts._fetch_hosts",
        return_value=[
            {"id": f"h-{i}", "name": f"esx{i}", "ntp_enabled": False, "build": 1}
            for i in range(10)
        ],
    ):
        HostCollector(twin).collect(snap, target="v.lab")

    baseline = load_builtin("cis-vmware-esxi-8.0-subset")
    begins = _count_begins(twin)
    violations = CheckRunner(twin).run_baseline(snap, baseline)

    assert violations  # something fired
    # All inserts land in a single transaction, not one per violation.
    assert begins[0] == 1
    persisted = twin.conn.execute(
        "SELECT COUNT(*) FROM violation WHERE snapshot_id = ?", [snap]
    ).fetchone()[0]
    assert persisted == len(violations)
    twin.close()


@pytest.mark.unit
def test_drift_counts_unchanged_after_batched_persist(tmp_path: Path):
    """diff_snapshots(persist=True) must produce identical change_event counts
    to the pure compute path after the executemany batching."""
    from vmware_harden.drift.diff import diff_snapshots

    twin = Twin(tmp_path / "t.duckdb")

    snap_a = twin.start_snapshot("v.lab")
    with patch(
        "vmware_harden.collectors.hosts._fetch_hosts",
        return_value=[
            {"id": "h-1", "name": "esx1", "ntp_enabled": True},
            {"id": "h-2", "name": "esx2", "ntp_enabled": True},
        ],
    ):
        HostCollector(twin).collect(snap_a, target="v.lab")
    twin.finish_snapshot(snap_a)

    snap_b = twin.start_snapshot("v.lab")
    with patch(
        "vmware_harden.collectors.hosts._fetch_hosts",
        return_value=[
            {"id": "h-1", "name": "esx1", "ntp_enabled": False},  # config drift
            {"id": "h-3", "name": "esx3", "ntp_enabled": True},  # added; h-2 removed
        ],
    ):
        HostCollector(twin).collect(snap_b, target="v.lab")
    twin.finish_snapshot(snap_b)

    pure = diff_snapshots(twin, snap_a, snap_b, persist=False)
    persisted = diff_snapshots(twin, snap_a, snap_b, persist=True)

    assert len(pure) == len(persisted)
    db_count = twin.conn.execute(
        "SELECT COUNT(*) FROM change_event WHERE snapshot_id = ?", [snap_b]
    ).fetchone()[0]
    assert db_count == len(pure)
    twin.close()
