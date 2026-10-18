"""Collector batches B1-B3/B5 and the VM facts, driven by shapes a real lab returned.

Every fixture below copies what a vCenter 8.0.3 (managing ESXi 8.0.3 hosts
192.168.1.117/.118) and the standalone ESXi 8.0.3 at .118 actually answered on
2026-10-18 — field names, types and values, including what was *absent*. The
earlier fixtures in this suite invented ``lockdown_mode: "normal"`` and
``"VMwareCertified"``; the API says ``lockdownDisabled`` and ``partner``. A rule
written against an invented value cannot fire on a real host, and a test written
against the same invention cannot notice (BACKLOG P0 [H-4]).

The rule threaded through every case: what the API did not answer stays absent,
and an absent fact is "not evaluated" for that host — never compliant, and never
a violation nobody measured.
"""

from __future__ import annotations

import json
import types
from pathlib import Path

import pytest

from vmware_harden.baselines.loader import load_builtin
from vmware_harden.checks.coverage import coverage_for
from vmware_harden.checks.runner import CheckRunner
from vmware_harden.collectors.host_security import queried_attrs, security_attrs
from vmware_harden.collectors.hosts import _shape_host
from vmware_harden.collectors.vms import _vm_security_attrs
from vmware_harden.store.twin import Twin

NS = types.SimpleNamespace


def _opt(key, value):
    return NS(key=key, value=value)


#: ``config.option`` entries the lab hosts returned (only the ones read here).
_LAB_OPTIONS = [
    _opt("Syslog.global.logDir", "[] /scratch/log"),
    _opt("ScratchConfig.CurrentScratchLocation",
         "/vmfs/volumes/684fa75b-603d28d5-ac66-48210b335794"),
    _opt("UserVars.ESXiVPsDisabledProtocols", "sslv3,tlsv1,tlsv1.1"),
    _opt("Syslog.global.auditRecord.storageCapacity", 4),
]


def _sec(allow, mac, forged):
    return NS(allowPromiscuous=allow, macChanges=mac, forgedTransmits=forged)


def _pg(name, vlan, computed):
    return NS(spec=NS(name=name, vswitchName="vSwitch0", vlanId=vlan,
                      policy=NS(security=NS(allowPromiscuous=None, macChanges=None,
                                            forgedTransmits=None))),
              computedPolicy=NS(security=computed))


#: config.network on .118: one vSwitch, and a nested-lab port group that
#: overrides all three security policies to accept.
_NETWORK_118 = NS(
    vswitch=[NS(name="vSwitch0", spec=NS(policy=NS(security=_sec(False, False, False))))],
    portgroup=[
        _pg("OLVM-Nested", 0, _sec(True, True, True)),
        _pg("VM Network", 0, _sec(False, False, False)),
        _pg("Management Network", 0, _sec(False, False, False)),
    ],
    vnic=[NS(device="vmk0", key="key-vim.host.VirtualNic-vmk0",
             portgroup="Management Network", spec=NS(distributedVirtualPort=None))],
)

#: .117: the same, without the nested-lab port group.
_NETWORK_117 = NS(
    vswitch=_NETWORK_118.vswitch,
    portgroup=_NETWORK_118.portgroup[1:],
    vnic=_NETWORK_118.vnic,
)

_VNIC_MANAGER = NS(netConfig=[
    NS(nicType="management", selectedVnic=["management.key-vim.host.VirtualNic-vmk0"]),
    NS(nicType="vmotion", selectedVnic=[]),
])

_AUTH = NS(authConfig=[
    NS(enabled=True),  # LocalAuthenticationInfo: no joinedDomain field at all
    NS(enabled=False, joinedDomain=None, domainMembershipStatus=None),
])


class _AccessManager:
    def __init__(self, users):
        self._users = users

    def QueryLockdownExceptions(self):  # noqa: N802 — pyVmomi's name
        if isinstance(self._users, Exception):
            raise self._users
        return self._users


class _ImageManager:
    def __init__(self, level):
        self._level = level

    def HostImageConfigGetAcceptance(self):  # noqa: N802 — pyVmomi's name
        if isinstance(self._level, Exception):
            raise self._level
        return self._level


def _vcenter_props(network=_NETWORK_118) -> dict:
    """One host as vCenter 8.0.3 answered for it."""
    return {
        "runtime.connectionState": "connected",
        "config.lockdownMode": "lockdownDisabled",
        "config.product.version": "8.0.3",
        "config.option": _LAB_OPTIONS,
        "capability.uefiSecureBoot": False,
        "summary.tpmAttestation": NS(status="notAccepted",
                                     message=NS(key="vim.vmware.tpm.error.internalFailure")),
        "config.authenticationManagerInfo": _AUTH,
        "config.featureCapability": [
            NS(key="cpuid.mwait", value="1"), NS(key="cpuid.nx", value="1"),
        ],
        "config.network": network,
        "config.virtualNicManagerInfo": _VNIC_MANAGER,
        "configManager.hostAccessManager": _AccessManager([]),
        "configManager.imageConfigManager": _ImageManager("partner"),
    }


def _esxi_props() -> dict:
    """The same machine asked directly: no TPM attestation summary at all."""
    props = _vcenter_props()
    del props["summary.tpmAttestation"]
    return props


def _attrs(props: dict) -> dict:
    return {**security_attrs(props), **queried_attrs(props)}


# --- the reducers ------------------------------------------------------------

@pytest.mark.unit
def test_the_lab_host_reduces_to_what_it_really_is():
    assert _attrs(_vcenter_props()) == {
        "lockdown_mode": "lockdownDisabled",
        "lockdown_mode_enabled": False,
        "lockdown_exceptions_count": 0,
        "persistent_logs": True,
        "tls_min_version": "1.2",
        "secure_boot_enabled": False,
        "host_tpm_attested": False,
        "nx_enabled": True,
        "ad_joined": False,
        "standard_vswitch_count": 1,
        "vswitch_promiscuous_mode": "accept",
        "forged_transmits": "accept",
        "mac_address_changes": "accept",
        "mgmt_vlan_tagged": False,
        "image_profile_acceptance": "partner",
    }


@pytest.mark.unit
def test_a_port_group_override_is_what_makes_the_host_accept():
    """.117 has no overriding port group; every effective policy rejects."""
    a = _attrs(_vcenter_props(network=_NETWORK_117))
    assert (a["vswitch_promiscuous_mode"], a["forged_transmits"], a["mac_address_changes"]) == (
        "reject", "reject", "reject")


@pytest.mark.unit
def test_a_standalone_esxi_has_no_attestation_and_says_nothing_about_it():
    assert "host_tpm_attested" not in _attrs(_esxi_props())


@pytest.mark.unit
@pytest.mark.parametrize("missing", [
    "config.lockdownMode", "capability.uefiSecureBoot", "config.featureCapability",
    "config.authenticationManagerInfo", "config.network", "config.option",
])
def test_an_unanswered_property_writes_nothing(missing):
    props = _vcenter_props()
    del props[missing]
    a = _attrs(props)
    owned = {
        "config.lockdownMode": {"lockdown_mode", "lockdown_mode_enabled"},
        "capability.uefiSecureBoot": {"secure_boot_enabled"},
        "config.featureCapability": {"nx_enabled"},
        "config.authenticationManagerInfo": {"ad_joined"},
        "config.network": {"standard_vswitch_count", "vswitch_promiscuous_mode",
                           "forged_transmits", "mac_address_changes", "mgmt_vlan_tagged"},
        "config.option": {"persistent_logs", "tls_min_version"},
    }[missing]
    assert not owned & set(a), f"{owned & set(a)} written without {missing}"


@pytest.mark.unit
def test_failed_queries_omit_their_fact_and_nothing_else():
    props = _vcenter_props()
    props["configManager.hostAccessManager"] = _AccessManager(RuntimeError("NoPermission"))
    props["configManager.imageConfigManager"] = _ImageManager(RuntimeError("NotSupported"))
    a = _attrs(props)
    assert "lockdown_exceptions_count" not in a
    assert "image_profile_acceptance" not in a
    assert a["lockdown_mode"] == "lockdownDisabled"


@pytest.mark.unit
def test_a_disconnected_host_is_not_queried():
    props = _vcenter_props()
    props["runtime.connectionState"] = "notResponding"
    props["configManager.hostAccessManager"] = _AccessManager(AssertionError("called"))
    assert queried_attrs(props) == {}


@pytest.mark.unit
def test_an_unknown_acceptance_level_is_not_stored():
    props = _vcenter_props()
    props["configManager.imageConfigManager"] = _ImageManager("CommunitySupported")
    assert "image_profile_acceptance" not in queried_attrs(props)


@pytest.mark.unit
@pytest.mark.parametrize(("log_dir", "scratch", "expected"), [
    ("[] /scratch/log", "/vmfs/volumes/abc", True),
    ("[] /scratch/log", "/tmp/scratch", False),
    ("[datastore1] logs", None, True),
    ("[] /vmfs/volumes/abc/log", None, True),
    ("[] /tmp/log", None, False),
    ("[] /scratch/log", None, None),       # scratch unknown: undecided
    ("[] /var/log", None, None),            # not a form we can judge
    ("", "/vmfs/volumes/abc", None),
])
def test_persistent_logs(log_dir, scratch, expected):
    options = [_opt("Syslog.global.logDir", log_dir)]
    if scratch is not None:
        options.append(_opt("ScratchConfig.CurrentScratchLocation", scratch))
    a = security_attrs({"config.option": options})
    assert a.get("persistent_logs") is expected


@pytest.mark.unit
@pytest.mark.parametrize(("disabled", "version", "expected"), [
    ("sslv3,tlsv1,tlsv1.1", "8.0.3", "1.2"),     # the lab's answer
    ("sslv3,tlsv1,tlsv1.1", None, "1.2"),
    ("tlsv1,tlsv1.1,tlsv1.2", "8.0.3", "1.3"),
    ("sslv3,tlsv1", "7.0.3", "1.1"),
    ("sslv3", "7.0.3", "1.0"),
    ("", "7.0.3", "1.0"),
    # a weak answer is only believed where the option is known to decide it
    ("sslv3,tlsv1", "8.0.3", None),
    ("", "8.0.3", None),
    ("sslv3", None, None),
    ("sslv3,tlsv1,tlsv1.1,tlsv1.2,tlsv1.3", "8.0.3", None),
    ("sslv3,tlsv1,dtls1", "8.0.3", None),        # unknown token: do not guess
])
def test_tls_min_version(disabled, version, expected):
    props = {"config.option": [_opt("UserVars.ESXiVPsDisabledProtocols", disabled)]}
    if version is not None:
        props["config.product.version"] = version
    assert security_attrs(props).get("tls_min_version") == expected


@pytest.mark.unit
def test_a_management_vmknic_on_a_distributed_switch_is_undecided():
    net = NS(vswitch=[], portgroup=[], vnic=[NS(
        key="key-vim.host.VirtualNic-vmk0", portgroup="",
        spec=NS(distributedVirtualPort=NS(portgroupKey="dvportgroup-1")))])
    a = security_attrs({"config.network": net, "config.virtualNicManagerInfo": _VNIC_MANAGER})
    assert "mgmt_vlan_tagged" not in a
    assert a["standard_vswitch_count"] == 0
    assert "vswitch_promiscuous_mode" not in a, "no standard vSwitch is not 'reject'"


@pytest.mark.unit
def test_a_tagged_management_port_group_is_tagged():
    net = NS(vswitch=_NETWORK_117.vswitch,
             portgroup=[_pg("Management Network", 120, _sec(False, False, False))],
             vnic=_NETWORK_117.vnic)
    a = security_attrs({"config.network": net, "config.virtualNicManagerInfo": _VNIC_MANAGER})
    assert a["mgmt_vlan_tagged"] is True


@pytest.mark.unit
def test_a_trunk_vlan_on_the_management_port_group_is_undecided():
    """4095 is guest tagging; a vmknic does not tag its own frames (review MED)."""
    net = NS(vswitch=_NETWORK_117.vswitch,
             portgroup=[_pg("Management Network", 4095, _sec(False, False, False))],
             vnic=_NETWORK_117.vnic)
    a = security_attrs({"config.network": net, "config.virtualNicManagerInfo": _VNIC_MANAGER})
    assert "mgmt_vlan_tagged" not in a


@pytest.mark.unit
def test_a_selected_management_vmknic_that_is_not_listed_leaves_it_undecided():
    """vmk1 is selected for management but absent from config.network.vnic.

    Judging on vmk0 alone would call the host tagged on partial evidence.
    """
    vnm = NS(netConfig=[NS(nicType="management", selectedVnic=[
        "management.key-vim.host.VirtualNic-vmk0", "management.key-vim.host.VirtualNic-vmk1"])])
    net = NS(vswitch=_NETWORK_117.vswitch,
             portgroup=[_pg("Management Network", 120, _sec(False, False, False))],
             vnic=_NETWORK_117.vnic)
    assert "mgmt_vlan_tagged" not in security_attrs(
        {"config.network": net, "config.virtualNicManagerInfo": vnm})


@pytest.mark.unit
def test_an_accepted_attestation_is_attested():
    props = _vcenter_props()
    props["summary.tpmAttestation"] = NS(status="accepted", message=None)
    assert security_attrs(props)["host_tpm_attested"] is True


@pytest.mark.unit
def test_two_vms_sharing_a_bios_uuid_get_no_security_facts(monkeypatch):
    """A copied VM keeps config.uuid; facts could belong to either VM."""
    import sys

    from vmware_harden.collectors import vms

    rows = [
        (object(), {"config.uuid": "u-1", "runtime.connectionState": "connected",
                    "config.bootOptions": NS(efiSecureBootEnabled=True),
                    "config.version": "vmx-21"}),
        (object(), {"config.uuid": "u-1", "runtime.connectionState": "connected",
                    "config.bootOptions": NS(efiSecureBootEnabled=False),
                    "config.version": "vmx-11"}),
        (object(), {"config.uuid": "u-2", "runtime.connectionState": "connected",
                    "config.bootOptions": NS(efiSecureBootEnabled=True),
                    "config.version": "vmx-21"}),
    ]
    fake = types.ModuleType("vmware_aiops.ops.inventory")
    fake._collect = lambda si, types_, paths: rows
    fake.vim = NS(VirtualMachine=object)
    monkeypatch.setitem(sys.modules, "vmware_aiops.ops.inventory", fake)
    got = vms._fetch_vm_security(si=None)
    assert "u-1" not in got
    assert got["u-2"] == {"secure_boot": True, "hw_version_int": 21}


@pytest.mark.unit
def test_an_unread_policy_value_cannot_make_a_host_reject():
    net = NS(vswitch=[NS(spec=NS(policy=NS(security=_sec(False, None, False))))], portgroup=[])
    a = security_attrs({"config.network": net})
    assert "mac_address_changes" not in a
    assert a["vswitch_promiscuous_mode"] == "reject"


@pytest.mark.unit
def test_an_ad_joined_host_is_joined():
    auth = NS(authConfig=[NS(enabled=True, joinedDomain="corp.lab",
                             domainMembershipStatus="ok")])
    assert security_attrs({"config.authenticationManagerInfo": auth})["ad_joined"] is True


@pytest.mark.unit
def test_no_active_directory_store_means_undecided():
    auth = NS(authConfig=[NS(enabled=True)])
    assert "ad_joined" not in security_attrs({"config.authenticationManagerInfo": auth})


# --- VMs (lab shapes: an EFI VM, a BIOS VM at vmx-11) --------------------------

@pytest.mark.unit
@pytest.mark.parametrize(("props", "expected"), [
    ({"runtime.connectionState": "connected",
      "config.bootOptions": NS(efiSecureBootEnabled=True), "config.version": "vmx-21"},
     {"secure_boot": True, "hw_version_int": 21}),
    ({"runtime.connectionState": "connected",
      "config.bootOptions": NS(efiSecureBootEnabled=False), "config.version": "vmx-11"},
     {"secure_boot": False, "hw_version_int": 11}),
    ({"runtime.connectionState": "connected", "config.version": "vmx-xx"}, {}),
    ({"runtime.connectionState": "orphaned",
      "config.bootOptions": NS(efiSecureBootEnabled=False), "config.version": "vmx-11"}, {}),
])
def test_vm_security_attrs(props, expected):
    assert _vm_security_attrs(props) == expected


# --- end to end through the real baselines -----------------------------------

def _host(twin, snap, host_id, attrs):
    twin.conn.execute(
        "INSERT INTO nodes (id, type, target, name, attrs) VALUES (?, 'host', 'lab', ?, ?)",
        [host_id, host_id, json.dumps(attrs)],
    )
    twin.write_node_state(snap, host_id, attrs)


def _lab_record(props, name):
    base = {"name": name, "connection_state": "connected", "esxi_build": "24280767"}
    return _shape_host(base, _attrs(props))


@pytest.mark.integration
def test_scg_judges_the_lab_hosts_and_leaves_the_unanswerable_undetermined(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    snap = twin.start_snapshot("lab")
    _host(twin, snap, "192.168.1.118", _lab_record(_vcenter_props(), "192.168.1.118"))
    _host(twin, snap, "esxi-direct", _lab_record(_esxi_props(), "esxi-direct"))
    CheckRunner(twin).run_baseline(snap, load_builtin("vsphere-scg-v8-subset"))

    fired = set(twin.conn.execute(
        "SELECT rule_id || '@' || node_id FROM violation WHERE snapshot_id = ?", [snap],
    ).fetchall())
    fired = {f for (f,) in fired}
    for rule in ("scg-host-2", "scg-host-5", "scg-net-1", "scg-net-2", "scg-net-3"):
        expected_host = {f"{rule}@192.168.1.118"}
        if rule == "scg-host-5":
            expected_host = set()  # TLS 1.2 minimum is compliant
        assert {f for f in fired if f.startswith(rule + "@192")} == expected_host, rule
    # vCenter answered the attestation (notAccepted) -> a real finding.
    assert "scg-host-1@192.168.1.118" in fired
    # The standalone host could not answer it -> neither a pass nor a finding.
    assert "scg-host-1@esxi-direct" not in fired
    cov = coverage_for(twin, snap, rule_limit=1000)
    gaps = {(r, n) for r, n, _ in cov.undetermined_node_checks}
    assert ("scg-host-1", "esxi-direct") in gaps
    assert not cov.complete
    twin.close()


@pytest.mark.integration
@pytest.mark.parametrize("baseline_id", [
    "bsi-itgs-basisabsicherung-vmware", "eu-nis2-vmware", "pci-dss-4.0-vmware",
])
def test_a_host_that_answered_nothing_is_undetermined_not_violating(tmp_path, baseline_id):
    """These rules used to read ``attr IS NULL OR …`` — absence was a violation.

    With a collector writing the attribute, absence on one host means that host
    could not be read. It is a gap, reported as such, not a finding.
    """
    twin = Twin(tmp_path / "t.duckdb")
    snap = twin.start_snapshot("lab")
    _host(twin, snap, "h-silent", {"name": "h-silent", "connection_state": "connected"})
    CheckRunner(twin).run_baseline(snap, load_builtin(baseline_id))
    activated = {
        "bsi-itgs-basisabsicherung-vmware": {
            "bsi-itgs-malware-1", "bsi-itgs-malware-2", "bsi-itgs-server-1",
            "bsi-itgs-server-3", "bsi-itgs-server-7"},
        "eu-nis2-vmware": {"nis2-ac-1", "nis2-sc-1"},
        "pci-dss-4.0-vmware": {"pci-r7-1", "pci-r8-2"},
    }[baseline_id]
    fired = {r for (r,) in twin.conn.execute(
        "SELECT rule_id FROM violation WHERE snapshot_id = ?", [snap]).fetchall()}
    assert not fired & activated, f"absence reported as a violation: {fired & activated}"
    gaps = {r for r, _n, _m in coverage_for(twin, snap, rule_limit=1000).undetermined_node_checks}
    assert activated <= gaps
    twin.close()


@pytest.mark.unit
def test_a_failed_vm_security_pass_keeps_the_inventory_and_omits_its_facts(monkeypatch):
    """The second pass is extra evidence; its failure must not cost the VMs."""
    import sys

    from vmware_harden.collectors import vms

    class _Mgr:
        @classmethod
        def from_config(cls):
            return cls()

        def connect(self, target):
            return object()

        def disconnect_all(self):
            pass

    conn = types.ModuleType("vmware_aiops.connection")
    conn.ConnectionManager = _Mgr
    inv = types.ModuleType("vmware_aiops.ops.inventory")
    inv.list_vms = lambda si, compact_threshold: {"vms": [
        {"name": "web-01", "uuid": "u-1", "tools_status": "guestToolsRunning"}]}
    monkeypatch.setitem(sys.modules, "vmware_aiops.connection", conn)
    monkeypatch.setitem(sys.modules, "vmware_aiops.ops.inventory", inv)

    def _boom(si):
        raise RuntimeError("InvalidProperty")

    monkeypatch.setattr(vms, "_fetch_vm_security", _boom)
    got = vms._fetch_vms("lab")
    assert [v["name"] for v in got] == ["web-01"]
    assert "secure_boot" not in got[0] and "hw_version_int" not in got[0]
