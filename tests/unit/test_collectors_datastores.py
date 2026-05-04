"""DatastoreCollector unit tests."""
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from vmware_harden.collectors.datastores import DatastoreCollector
from vmware_harden.store.twin import Twin


FAKE_DATASTORES = [
    {
        "id": "ds-100",
        "name": "san-vmfs-01",
        "type": "vmfs",
        "capacity_gb": 1000,
        "free_gb": 400,
        "encryption_enabled": True,
        "ssd": True,
    },
    {
        "id": "ds-101",
        "name": "vsan-default",
        "type": "vsan",
        "capacity_gb": 10000,
        "free_gb": 6000,
        "encryption_enabled": False,
        "ssd": True,
    },
]


@pytest.mark.unit
def test_datastore_collector_writes_to_twin(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    snap = twin.start_snapshot("v.lab")
    with patch(
        "vmware_harden.collectors.datastores._fetch_datastores",
        return_value=FAKE_DATASTORES,
    ):
        n = DatastoreCollector(twin).collect(snap, target="v.lab")
    assert n == 2
    rows = twin.conn.execute(
        "SELECT id, type, name, target FROM nodes WHERE type='datastore' ORDER BY id"
    ).fetchall()
    ids = {r[0] for r in rows}
    assert ids == {"v.lab:ds-100", "v.lab:ds-101"}
    assert {r[1] for r in rows} == {"datastore"}
    twin.close()


@pytest.mark.unit
def test_datastore_collector_persists_attrs(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    snap = twin.start_snapshot("v.lab")
    with patch(
        "vmware_harden.collectors.datastores._fetch_datastores",
        return_value=FAKE_DATASTORES,
    ):
        DatastoreCollector(twin).collect(snap, target="v.lab")
    row = twin.conn.execute(
        "SELECT attrs FROM nodes WHERE id = 'v.lab:ds-101'"
    ).fetchone()
    attrs = json.loads(row[0])
    assert attrs["type"] == "vsan"
    assert attrs["encryption_enabled"] is False
    assert attrs["capacity_gb"] == 10000
    twin.close()


@pytest.mark.unit
def test_datastore_collector_raises_on_malformed(tmp_path: Path):
    from vmware_harden.collectors.base import CollectorError
    twin = Twin(tmp_path / "t.duckdb")
    snap = twin.start_snapshot("v.lab")
    bad = [{"name": "no-id"}]
    with patch(
        "vmware_harden.collectors.datastores._fetch_datastores",
        return_value=bad,
    ):
        with pytest.raises(CollectorError, match="missing required field"):
            DatastoreCollector(twin).collect(snap, target="v.lab")
    twin.close()
