"""Multi-vCenter Twin: identical MoRefs from different targets must coexist."""
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from vmware_harden.collectors.hosts import HostCollector
from vmware_harden.store.twin import Twin


@pytest.mark.unit
def test_two_targets_same_morefid_dont_collide(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    hosts_a = [
        {"id": "host-01", "name": "esx01-a", "ntp_enabled": True, "build": 1}
    ]
    hosts_b = [
        {"id": "host-01", "name": "esx01-b", "ntp_enabled": False, "build": 1}
    ]

    with patch("vmware_harden.collectors.hosts._fetch_hosts", return_value=hosts_a):
        snap_a = twin.start_snapshot("vc-a.lab")
        HostCollector(twin).collect(snap_a, target="vc-a.lab")
    with patch("vmware_harden.collectors.hosts._fetch_hosts", return_value=hosts_b):
        snap_b = twin.start_snapshot("vc-b.lab")
        HostCollector(twin).collect(snap_b, target="vc-b.lab")

    rows = twin.conn.execute(
        "SELECT id, name, target FROM nodes WHERE type='host' ORDER BY id"
    ).fetchall()
    assert len(rows) == 2
    targets = {r[2] for r in rows}
    assert targets == {"vc-a.lab", "vc-b.lab"}
    ids = {r[0] for r in rows}
    assert ids == {"vc-a.lab:host-01", "vc-b.lab:host-01"}
    twin.close()


@pytest.mark.unit
def test_target_column_persisted_per_node(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    hosts = [
        {"id": "h-1", "name": "esx", "ntp_enabled": True, "build": 1},
    ]
    with patch("vmware_harden.collectors.hosts._fetch_hosts", return_value=hosts):
        snap = twin.start_snapshot("my-vc")
        HostCollector(twin).collect(snap, target="my-vc")
    row = twin.conn.execute(
        "SELECT target FROM nodes WHERE id = 'my-vc:h-1'"
    ).fetchone()
    assert row[0] == "my-vc"
    twin.close()
