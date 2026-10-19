"""vCenter component record for advisory matching."""

from types import SimpleNamespace

from vmware_harden.collectors.vcenter import shape_about


def _about(**kw):
    base = dict(
        apiType="VirtualCenter",
        version="8.0.3",
        build="24853646",
        fullName="VMware vCenter Server 8.0.3 build-24853646",
        instanceUuid="uuid-1",
    )
    base.update(kw)
    return SimpleNamespace(**base)


def test_vcenter_target_yields_one_record_with_version_and_build():
    [rec] = shape_about(_about(), "vc.lab")
    assert rec["id"] == "uuid-1"
    assert rec["name"] == "vc.lab"
    assert rec["vcenter_version"] == "8.0.3"
    assert rec["vcenter_build"] == "24853646"


def test_standalone_esxi_target_yields_no_vcenter_record():
    # The host collector covers a standalone ESXi; there is no vCenter to judge.
    assert shape_about(_about(apiType="HostAgent"), "esx.lab") == []


def test_unreadable_build_is_omitted_not_defaulted():
    [rec] = shape_about(_about(build=None, version=""), "vc.lab")
    assert "vcenter_build" not in rec
    assert "vcenter_version" not in rec


def test_missing_instance_uuid_falls_back_to_target_name():
    [rec] = shape_about(_about(instanceUuid=None), "vc.lab")
    assert rec["id"] == "vc.lab"
