"""The collector reshape helpers stamp the id/name the Twin requires.

The live fetch path (connect + call the sibling inventory function) can only be
exercised against a real vCenter/NSX and is covered by ``test_lab_scan.py``.
What IS verifiable offline is the pure transformation each collector applies to
a sibling record: unwrapping the family envelope and stamping ``id``/``name``.

These pin that logic. A record leaving a reshape helper without both keys would
raise ``CollectorError`` in ``_persist_groups`` (base.py) at scan time, so this
catches an id/name regression at its source rather than against a live estate.
Written after 1.8.7 repaired the collectors' fabricated import paths.
"""
import pytest

from vmware_harden.collectors.datastores import _shape_datastore
from vmware_harden.collectors.dfw import _PAGE, _drain, _shape_dfw
from vmware_harden.collectors.hosts import _shape_host
from vmware_harden.collectors.vms import _shape_vm


@pytest.mark.unit
class TestReshapeStampsIdAndName:
    """Every reshaped record must carry both ``id`` and ``name`` and keep the
    full sibling payload the baselines read."""

    def test_host_id_is_its_name(self):
        rec = _shape_host({"name": "esx01.lab", "esxi_version": "8.0.3"})
        assert rec["id"] == "esx01.lab"
        assert rec["name"] == "esx01.lab"
        assert rec["esxi_version"] == "8.0.3"  # full record preserved

    def test_vm_id_is_uuid(self):
        rec = _shape_vm(
            {"name": "web-01", "uuid": "564d-abcd", "power_state": "poweredOn"}
        )
        assert rec["id"] == "564d-abcd"
        assert rec["name"] == "web-01"
        assert rec["power_state"] == "poweredOn"

    def test_vm_without_uuid_falls_back_to_name(self):
        # Both a literal "N/A" (aiops' sentinel) and an absent key fall back.
        for rec_in in ({"name": "web-01", "uuid": "N/A"}, {"name": "web-01"}):
            rec = _shape_vm(rec_in)
            assert rec["id"] == "web-01", rec_in
            assert rec["name"] == "web-01", rec_in

    def test_datastore_id_is_its_name(self):
        rec = _shape_datastore({"name": "ds-ssd-01", "type": "VMFS", "total_gb": 1024})
        assert rec["id"] == "ds-ssd-01"
        assert rec["name"] == "ds-ssd-01"
        assert rec["total_gb"] == 1024

    def test_dfw_maps_display_name_to_name_and_keeps_id(self):
        rec = _shape_dfw({"id": "pol-1", "display_name": "App Tier", "action": "ALLOW"})
        assert rec["id"] == "pol-1"  # NSX already supplies a stable id
        assert rec["name"] == "App Tier"  # display_name -> name
        assert rec["action"] == "ALLOW"


@pytest.mark.unit
class TestDrainPagesEverything:
    """A compliance scan must not stop at the API's default page size."""

    def test_stops_on_short_final_page(self):
        full = [{"i": n} for n in range(_PAGE)]
        pages = {0: {"items": full}, _PAGE: {"items": [{"i": _PAGE}]}}
        assert len(_drain(lambda off: pages[off])) == _PAGE + 1

    def test_stops_on_empty_trailing_page(self):
        full = [{"i": n} for n in range(_PAGE)]
        pages = {0: {"items": full}, _PAGE: {"items": []}}
        assert len(_drain(lambda off: pages[off])) == _PAGE

    def test_single_short_page_needs_no_second_request(self):
        calls = []

        def fetch(off):
            calls.append(off)
            return {"items": [{"a": 1}, {"a": 2}]}

        assert _drain(fetch) == [{"a": 1}, {"a": 2}]
        assert calls == [0], "a short first page must not trigger a second fetch"

    def test_empty_result(self):
        assert _drain(lambda off: {"items": []}) == []
