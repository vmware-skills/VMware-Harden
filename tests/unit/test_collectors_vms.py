"""VMCollector unit tests with mocked _fetch_vms."""
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from vmware_harden.collectors.vms import VMCollector
from vmware_harden.store.twin import Twin


FAKE_VMS = [
    {
        "id": "vm-100",
        "name": "web-01",
        "host_id": "host-01",
        "power_state": "poweredOn",
        "tools_running": True,
        "secure_boot": True,
        "encryption_enabled": False,
        "tags": ["PCI"],
    },
    {
        "id": "vm-101",
        "name": "db-01",
        "host_id": "host-02",
        "power_state": "poweredOn",
        "tools_running": False,
        "secure_boot": False,
        "encryption_enabled": False,
        "tags": [],
    },
]


@pytest.mark.unit
def test_vm_collector_writes_to_twin(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")
    with patch("vmware_harden.collectors.vms._fetch_vms", return_value=FAKE_VMS):
        n = VMCollector(twin).collect(snap_id, target="v.lab")
    assert n == 2
    rows = twin.conn.execute(
        "SELECT id, type, name, target FROM nodes WHERE type='vm' ORDER BY id"
    ).fetchall()
    ids = {r[0] for r in rows}
    assert ids == {"v.lab:vm-100", "v.lab:vm-101"}
    types = {r[1] for r in rows}
    assert types == {"vm"}
    targets = {r[3] for r in rows}
    assert targets == {"v.lab"}
    twin.close()


@pytest.mark.unit
def test_vm_collector_persists_full_attrs(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")
    with patch("vmware_harden.collectors.vms._fetch_vms", return_value=FAKE_VMS):
        VMCollector(twin).collect(snap_id, target="v.lab")
    row = twin.conn.execute(
        "SELECT attrs FROM nodes WHERE id = 'v.lab:vm-100'"
    ).fetchone()
    attrs = json.loads(row[0])
    assert attrs["secure_boot"] is True
    assert attrs["tags"] == ["PCI"]
    assert attrs["host_id"] == "host-01"
    twin.close()


@pytest.mark.unit
def test_vm_collector_raises_on_malformed(tmp_path: Path):
    from vmware_harden.collectors.base import CollectorError
    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")
    bad = [{"name": "no-id"}]  # missing 'id'
    with patch("vmware_harden.collectors.vms._fetch_vms", return_value=bad):
        with pytest.raises(CollectorError, match="missing required field"):
            VMCollector(twin).collect(snap_id, target="v.lab")
    twin.close()


@pytest.mark.unit
def test_vm_collector_node_state_persisted(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")
    with patch("vmware_harden.collectors.vms._fetch_vms", return_value=FAKE_VMS):
        VMCollector(twin).collect(snap_id, target="v.lab")
    rows = twin.conn.execute(
        "SELECT COUNT(*) FROM node_state WHERE snapshot_id = ?", [snap_id]
    ).fetchone()
    assert rows[0] == 2
    twin.close()
