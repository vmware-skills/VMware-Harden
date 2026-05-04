"""HostCollector unit tests with mocked _fetch_hosts."""
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from vmware_harden.collectors.hosts import HostCollector
from vmware_harden.store.twin import Twin


FAKE_HOSTS = [
    {
        "id": "host-01",
        "name": "esx01.lab",
        "esxi_version": "8.0.2",
        "build": 23305546,
        "ntp_enabled": True,
        "ntp_servers": ["10.0.0.1"],
    },
    {
        "id": "host-02",
        "name": "esx02.lab",
        "esxi_version": "8.0.2",
        "build": 23305546,
        "ntp_enabled": False,
        "ntp_servers": [],
    },
]


@pytest.mark.unit
def test_host_collector_writes_to_twin(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")

    with patch("vmware_harden.collectors.hosts._fetch_hosts", return_value=FAKE_HOSTS):
        n = HostCollector(twin).collect(snap_id, target="v.lab")

    assert n == 2
    nodes = twin.conn.execute(
        "SELECT id, type, name FROM nodes WHERE type = 'host' ORDER BY id"
    ).fetchall()
    assert [r[0] for r in nodes] == ["host-01", "host-02"]
    assert [r[1] for r in nodes] == ["host", "host"]
    assert [r[2] for r in nodes] == ["esx01.lab", "esx02.lab"]
    twin.close()


@pytest.mark.unit
def test_host_collector_writes_node_state(tmp_path: Path):
    """node_state should contain the full host dict for each snapshot."""
    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")

    with patch("vmware_harden.collectors.hosts._fetch_hosts", return_value=FAKE_HOSTS):
        HostCollector(twin).collect(snap_id, target="v.lab")

    rows = twin.conn.execute(
        "SELECT node_id, state_json FROM node_state "
        "WHERE snapshot_id = ? ORDER BY node_id",
        [snap_id],
    ).fetchall()
    assert len(rows) == 2
    state_01 = json.loads(rows[0][1])
    assert state_01["ntp_enabled"] is True
    assert state_01["build"] == 23305546
    twin.close()


@pytest.mark.unit
def test_host_collector_idempotent_on_repeat_collect(tmp_path: Path):
    """Calling collect twice with same data must not duplicate nodes."""
    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")

    with patch("vmware_harden.collectors.hosts._fetch_hosts", return_value=FAKE_HOSTS):
        HostCollector(twin).collect(snap_id, target="v.lab")
        HostCollector(twin).collect(snap_id, target="v.lab")

    count = twin.conn.execute("SELECT COUNT(*) FROM nodes WHERE type = 'host'").fetchone()[0]
    assert count == 2
    twin.close()


@pytest.mark.unit
def test_host_collector_updates_attrs_on_revisit(tmp_path: Path):
    """When same host shows up with new attrs, nodes.attrs should reflect latest."""
    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")

    with patch("vmware_harden.collectors.hosts._fetch_hosts", return_value=FAKE_HOSTS):
        HostCollector(twin).collect(snap_id, target="v.lab")

    updated = [{**FAKE_HOSTS[1], "ntp_enabled": True, "ntp_servers": ["10.0.0.99"]}]
    snap_id2 = twin.start_snapshot("v.lab")
    with patch("vmware_harden.collectors.hosts._fetch_hosts", return_value=updated):
        HostCollector(twin).collect(snap_id2, target="v.lab")

    row = twin.conn.execute(
        "SELECT attrs FROM nodes WHERE id = 'host-02'"
    ).fetchone()
    assert json.loads(row[0])["ntp_enabled"] is True
    twin.close()
