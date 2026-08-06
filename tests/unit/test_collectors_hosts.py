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
    assert [r[0] for r in nodes] == ["v.lab:host-01", "v.lab:host-02"]
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
        "SELECT attrs FROM nodes WHERE id = 'v.lab:host-02'"
    ).fetchone()
    assert json.loads(row[0])["ntp_enabled"] is True
    twin.close()


@pytest.mark.unit
def test_host_collector_raises_on_malformed_host(tmp_path: Path):
    """Missing required 'id' or 'name' raises CollectorError with context."""
    from vmware_harden.collectors.base import CollectorError

    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")

    bad = [{"name": "esx-bad", "build": 1}]  # missing 'id'
    with patch("vmware_harden.collectors.hosts._fetch_hosts", return_value=bad):
        with pytest.raises(CollectorError, match="missing required field"):
            HostCollector(twin).collect(snap_id, target="v.lab")
    twin.close()


class _Opt:
    """Minimal stand-in for a pyVmomi OptionValue (.key/.value)."""

    def __init__(self, key, value):
        self.key = key
        self.value = value


@pytest.mark.unit
def test_advanced_settings_reducer_maps_only_stig_keys():
    """The pure reducer converts ESXi OptionValues to the STIG snake_case attrs
    the baseline SQL reads, and ignores everything else."""
    from vmware_harden.collectors.hosts import _advanced_settings_to_attrs

    options = [
        _Opt("Security.AccountLockFailures", 5),
        _Opt("DCUI.Access", "root,ops"),
        _Opt("Net.BlockGuestBPDU", 1),
        _Opt("Config.HostAgent.plugins.solo.enableMob", True),
        _Opt("Some.Unrelated.Setting", "ignored"),
    ]
    attrs = _advanced_settings_to_attrs(options)
    assert attrs == {
        "account_lock_failures": 5,
        "dcui_access": "root,ops",
        "block_guest_bpdu": 1,
        "mob_enabled": True,
    }
    # "Some.Unrelated.Setting" must not leak into the record.
    assert "ignored" not in attrs.values()


@pytest.mark.unit
def test_advanced_settings_reducer_is_defensive():
    """A None list or a malformed entry (no .key) must not raise — a partial
    host config cannot be allowed to abort the whole collection."""
    from vmware_harden.collectors.hosts import _advanced_settings_to_attrs

    assert _advanced_settings_to_attrs(None) == {}
    assert _advanced_settings_to_attrs([object(), _Opt("DCUI.Access", "root")]) == {
        "dcui_access": "root"
    }


@pytest.mark.unit
def test_shape_host_merges_advanced_settings():
    """_shape_host folds the collected advanced settings into the record so the
    STIG SQL can read them; without the merge every STIG rule matches 0 rows."""
    from vmware_harden.collectors.hosts import _shape_host

    rec = _shape_host(
        {"name": "esx01.lab", "esxi_version": "9.0.0"},
        {"dcui_access": "root", "account_lock_failures": 3},
    )
    assert rec["id"] == "esx01.lab"
    assert rec["dcui_access"] == "root"  # merged advanced setting is present
    assert rec["account_lock_failures"] == 3
    assert rec["esxi_version"] == "9.0.0"  # base record preserved
    # Backwards-compatible single-arg call still works (advanced optional).
    assert _shape_host({"name": "esx02.lab"})["id"] == "esx02.lab"
