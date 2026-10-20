"""Five pending facts re-specified as things vSphere can answer (user decision 2026-10-20).

Twelve builtin rules read five facts no collector could ever write, because
vSphere does not hold them in that form:

* ``audit_retention_days`` — ESXi bounds audit records by size, not days. Now:
  audit record storage enabled, at least 100 MiB (the ESXi 8 STIG value), on
  persistent storage. Days are kept on the log server, which a host scan cannot
  read.
* ``encrypted_vmotion`` — a per-VM setting (``config.migrateEncryption``), not a
  host one. Now a VM rule, and only ``required`` complies (``opportunistic``
  falls back to clear text when the far side cannot encrypt).
* ``mgmt_vmk_isolated`` — had no measurable definition. Now: every management
  vmknic sits on a VLAN-tagged standard port group, and no VM on that host is
  attached to a port group carrying the same VLAN (or the 4095 trunk).
* ``default_admin_disabled`` — ESXi's root cannot be disabled. PCI 2.2.2 allows a
  vendor account that is used if its use is restricted, so: lockdown mode on and
  SSH neither running nor set to start.
* ``datastore_encryption`` — no host-level fact. Now per VM: the VM home
  (``config.keyId``) and every virtual disk carry a key.

Unknown stays unknown throughout: an unread fact is absent, and an absent fact
is a gap, never a pass and never a finding.
"""

from __future__ import annotations

import json
import types
from pathlib import Path

import pytest

from vmware_harden.baselines.loader import load_builtin
from vmware_harden.checks.coverage import coverage_for
from vmware_harden.checks.evaluability import classify
from vmware_harden.checks.runner import CheckRunner
from vmware_harden.collectors.host_security import (
    host_vm_networks,
    mgmt_isolation_attrs,
    security_attrs,
    vm_networks_by_host,
)
from vmware_harden.collectors.vms import _vm_security_attrs
from vmware_harden.store.twin import Twin

NS = types.SimpleNamespace

# --- audit records -------------------------------------------------------------


def _opt(key, value):
    return NS(key=key, value=value)


def _audit_options(enable=True, capacity=4, directory="[] /scratch/auditLog",
                   scratch="/vmfs/volumes/684fa75b-603d28d5-ac66-48210b335794"):
    opts = []
    if enable is not None:
        opts.append(_opt("Syslog.global.auditRecord.storageEnable", enable))
    if capacity is not None:
        opts.append(_opt("Syslog.global.auditRecord.storageCapacity", capacity))
    if directory is not None:
        opts.append(_opt("Syslog.global.auditRecord.storageDirectory", directory))
    if scratch is not None:
        opts.append(_opt("ScratchConfig.CurrentScratchLocation", scratch))
    return opts


_AUDIT_KEYS = {"audit_record_storage_enabled", "audit_record_storage_capacity_mib",
               "audit_record_storage_persistent"}


@pytest.mark.unit
def test_the_lab_default_reduces_to_what_it_is():
    a = security_attrs({"config.option": _audit_options()})
    assert {k: a[k] for k in _AUDIT_KEYS} == {
        "audit_record_storage_enabled": True,
        "audit_record_storage_capacity_mib": 4,
        "audit_record_storage_persistent": True,
    }


@pytest.mark.unit
@pytest.mark.parametrize(("kwargs", "absent"), [
    ({"enable": None}, "audit_record_storage_enabled"),
    ({"enable": "true"}, "audit_record_storage_enabled"),       # not the API's type
    ({"capacity": None}, "audit_record_storage_capacity_mib"),
    ({"capacity": True}, "audit_record_storage_capacity_mib"),  # bool is an int in Python
    ({"capacity": -1}, "audit_record_storage_capacity_mib"),
    ({"directory": None}, "audit_record_storage_persistent"),
    ({"scratch": None}, "audit_record_storage_persistent"),     # /scratch unresolved
])
def test_an_unread_audit_setting_is_absent_not_defaulted(kwargs, absent):
    assert absent not in security_attrs({"config.option": _audit_options(**kwargs)})


@pytest.mark.unit
@pytest.mark.parametrize(("directory", "scratch", "expected"), [
    ("[] /scratch/auditLog", "/tmp/scratch", False),
    ("[datastore1] auditLog", None, True),
    ("[] /tmp/auditLog", None, False),
])
def test_audit_record_persistence(directory, scratch, expected):
    a = security_attrs({"config.option": _audit_options(directory=directory, scratch=scratch)})
    assert a["audit_record_storage_persistent"] is expected


# --- management isolation --------------------------------------------------------


def _pg(name, vlan, vm_port=False):
    ports = [NS(type="host"), *([NS(type="virtualMachine")] if vm_port else [])]
    return NS(spec=NS(name=name, vlanId=vlan), port=ports)


_VMK0 = NS(key="key-vim.host.VirtualNic-vmk0", portgroup="Management Network",
           spec=NS(distributedVirtualPort=None))
_VNIC_MANAGER = NS(netConfig=[
    NS(nicType="management", selectedVnic=["management.key-vim.host.VirtualNic-vmk0"]),
])


def _net(mgmt_vlan, *others, vnic=_VMK0):
    return NS(portgroup=[_pg("Management Network", mgmt_vlan), *others], vnic=[vnic])


def _isolated(network, vm_nets):
    return mgmt_isolation_attrs(network, _VNIC_MANAGER, vm_nets).get("mgmt_vmk_isolated")


@pytest.mark.unit
def test_the_lab_untagged_management_network_is_not_isolated():
    # .117/.118: vmk0 on "Management Network", VLAN 0, beside "VM Network", VLAN 0.
    net = _net(0, _pg("VM Network", 0))
    assert _isolated(net, frozenset({"VM Network"})) is False
    # Untagged is not isolated whatever the VMs are doing, even unread.
    assert _isolated(net, None) is False


@pytest.mark.unit
@pytest.mark.parametrize(("others", "vm_nets", "expected"), [
    ([_pg("VM Network", 0)], frozenset({"VM Network"}), True),
    ([_pg("Apps", 120)], frozenset(), True),                 # same VLAN, no VM on it
    ([_pg("Apps", 120)], frozenset({"Apps"}), False),        # a VM shares the VLAN
    ([_pg("Trunk", 4095)], frozenset({"Trunk"}), False),     # a trunk carries it too
    ([], frozenset({"Management Network"}), False),          # a VM on the mgmt group
    ([_pg("VM Network", 0)], None, None),                    # VM side unread
])
def test_a_tagged_management_network(others, vm_nets, expected):
    assert _isolated(_net(120, *others), vm_nets) is expected


@pytest.mark.unit
@pytest.mark.parametrize("vm_nets", [None, frozenset()])
def test_a_running_vm_in_the_port_list_is_enough_for_a_no(vm_nets):
    """Host config, not inventory: a restricted account sees it too (narrow review H1)."""
    assert _isolated(_net(120, _pg("Apps", 120, vm_port=True)), vm_nets) is False
    assert _isolated(_net(120, _pg("Trunk", 4095, vm_port=True)), vm_nets) is False


@pytest.mark.unit
def test_a_running_vm_on_another_vlan_is_no_evidence():
    assert _isolated(_net(120, _pg("VM Network", 0, vm_port=True)), None) is None


@pytest.mark.unit
def test_a_vm_network_this_host_has_no_port_group_for_is_undecided():
    """An NSX segment, or anything else not one of this host's standard port groups.

    Its VLAN is not something this pass read, so it cannot be ruled out as the
    management VLAN (review M1, 2026-10-20).
    """
    assert _isolated(_net(120, _pg("VM Network", 0)), frozenset({"seg-mgmt"})) is None


@pytest.mark.unit
def test_a_vm_on_a_distributed_port_group_leaves_it_undecided():
    # Its VLAN lives on the distributed port group, which this pass does not read.
    by_host, _read = vm_networks_by_host(
        [("vm-1", {"runtime.host": NS(_moId="host-1"), "network": [NS(_moId="dvportgroup-7")]})],
        {"dvportgroup-7": (True, "DPG-Apps")},
    )
    assert _isolated(_net(120), by_host.get("host-1")) is None


@pytest.mark.unit
@pytest.mark.parametrize("network", [
    _net(4095),                                              # trunk on the vmknic itself
    _net(120, vnic=NS(key=_VMK0.key, portgroup="", spec=NS(
        distributedVirtualPort=NS(portgroupKey="dvportgroup-1")))),
    NS(portgroup=[_pg("Management Network", 120)], vnic=[]),  # selected vmknic not listed
])
def test_an_unreadable_management_vmknic_is_undecided(network):
    assert _isolated(network, frozenset()) is None


@pytest.mark.unit
def test_vm_networks_are_grouped_by_the_host_running_the_vm():
    rows = [
        ("vm-1", {"runtime.host": NS(_moId="host-1"), "network": [NS(_moId="network-1")]}),
        ("vm-2", {"runtime.host": NS(_moId="host-1"), "network": [NS(_moId="network-2")]}),
        ("vm-3", {"runtime.host": NS(_moId="host-2"), "network": []}),   # no NIC, read
        ("vm-4", {"runtime.host": None, "network": [NS(_moId="network-2")]}),  # orphaned
        ("vm-5", {"runtime.host": NS(_moId="host-2")}),                  # network unread
    ]
    kinds = {"network-1": (False, "VM Network"), "network-2": (False, "Apps")}
    by_host, read = vm_networks_by_host(rows, kinds)
    assert by_host == {"host-1": frozenset({"VM Network", "Apps"}), "host-2": frozenset()}
    assert read == {"vm-1", "vm-2", "vm-3"}


@pytest.mark.unit
def test_a_vm_whose_networks_were_not_read_leaves_its_host_undecided():
    """Narrow review M-a: an unread property is not "no networks"."""
    rows = [("vm-1", {"runtime.host": NS(_moId="host-1")})]
    by_host, read = vm_networks_by_host(rows, {})
    assert host_vm_networks("host-1", [NS(_moId="vm-1")], by_host, read) is None


@pytest.mark.unit
def test_an_unknown_network_makes_that_host_undecided():
    rows = [("vm-1", {"runtime.host": NS(_moId="host-1"), "network": [NS(_moId="network-9")]})]
    assert vm_networks_by_host(rows, {})[0] == {"host-1": None}


@pytest.mark.unit
def test_a_template_carries_no_traffic_and_does_not_share_a_vlan():
    rows = [("vm-1", {"runtime.host": NS(_moId="host-1"), "network": [NS(_moId="network-1")],
                      "config.template": True})]
    assert vm_networks_by_host(rows, {"network-1": (False, "Apps")})[0] == {
        "host-1": frozenset()}


_BY_HOST = {"host-1": frozenset({"VM Network"})}


@pytest.mark.unit
@pytest.mark.parametrize(("host_vms", "seen", "by_host", "expected"), [
    ([NS(_moId="vm-1")], {"vm-1"}, _BY_HOST, frozenset({"VM Network"})),
    ([], set(), {}, frozenset()),                      # a host with no VM at all
    # review H1: a VM the account cannot see is not "no VM"
    ([NS(_moId="vm-1"), NS(_moId="vm-2")], {"vm-1"}, _BY_HOST, None),
    ([NS(_moId="vm-1")], set(), {}, None),
    (None, {"vm-1"}, _BY_HOST, None),                  # host.vm unread
    ([NS(_moId="vm-1")], {"vm-1"}, None, None),        # the VM pass failed
])
def test_a_host_is_only_judged_on_every_vm_it_runs(host_vms, seen, by_host, expected):
    assert host_vm_networks("host-1", host_vms, by_host, seen) == expected


# --- VM facts --------------------------------------------------------------------


def _vm(**extra):
    return {"runtime.connectionState": "connected", "config.version": "vmx-21",
            "config.bootOptions": NS(efiSecureBootEnabled=True), **extra}


@pytest.mark.unit
@pytest.mark.parametrize(("props", "expected"), [
    (_vm(**{"config.migrateEncryption": "required"}), "required"),
    (_vm(**{"config.migrateEncryption": "opportunistic"}), "opportunistic"),
    (_vm(**{"config.migrateEncryption": "disabled"}), "disabled"),
    (_vm(**{"config.migrateEncryption": "sometimes"}), None),
    (_vm(), None),
])
def test_migrate_encryption(props, expected):
    assert _vm_security_attrs(props).get("migrate_encryption") == expected


def _disk(key_id):
    return NS(capacityInKB=1024, backing=NS(fileName="[ds] vm/vm.vmdk", keyId=key_id))


_CDROM = NS(backing=NS(fileName="[ds] iso/x.iso"))
_KEY = NS(keyId="k")


_TYPES = {"datastore-1": "vmfs", "datastore-9": "vsan"}


def _enc(vm_key, disks, datastores=("datastore-1",), types=_TYPES):
    props = _vm(**{"config.hardware.device": [*disks, _CDROM]})
    if datastores is not None:
        props["datastore"] = [NS(_moId=d) for d in datastores]
    if vm_key:
        props["config.keyId"] = _KEY
    return _vm_security_attrs(props, types).get("encryption_enabled")


@pytest.mark.unit
@pytest.mark.parametrize(("vm_key", "disks", "expected"), [
    (True, [_disk(_KEY), _disk(_KEY)], True),
    (True, [], True),                       # no disk to leave in clear text
    # review H3: a vTPM VM has its home encrypted and its disks in clear text
    (True, [_disk(_KEY), _disk(None)], False),
    (False, [_disk(None)], False),
])
def test_encryption_means_the_vm_home_and_every_disk(vm_key, disks, expected):
    assert _enc(vm_key, disks) is expected


@pytest.mark.unit
def test_encryption_is_not_judged_without_the_config_or_the_device_list():
    unread = _vm(**{"config.hardware.device": []})
    del unread["config.version"]
    assert "encryption_enabled" not in _vm_security_attrs(unread)
    assert "encryption_enabled" not in _vm_security_attrs(_vm(**{"config.keyId": _KEY}))


@pytest.mark.unit
@pytest.mark.parametrize(("datastores", "types"), [
    (["datastore-9"], _TYPES),                 # on vSAN (review M3)
    (["datastore-1", "datastore-9"], _TYPES),
    (["datastore-1"], None),                   # the datastore pass failed
    (["datastore-7"], _TYPES),                 # a datastore that pass did not read (M-b)
    (None, _TYPES),                            # the VM's datastore list unread (M-b)
    ([], _TYPES),
])
def test_a_clear_vm_is_only_a_violation_when_known_to_be_off_vsan(datastores, types):
    """vSAN data-at-rest encryption may cover it, and that is not read."""
    assert _enc(False, [_disk(None)], datastores, types) is None


@pytest.mark.unit
def test_a_clear_vm_on_read_vmfs_is_a_violation_and_an_encrypted_one_is_fine_anywhere():
    assert _enc(False, [_disk(None)]) is False
    assert _enc(True, [_disk(_KEY)], ["datastore-9"], None) is True


@pytest.mark.unit
def test_a_disconnected_vm_gives_no_encryption_facts():
    props = _vm(**{"config.migrateEncryption": "required", "config.keyId": _KEY,
                   "config.hardware.device": []})
    props["runtime.connectionState"] = "inaccessible"
    assert _vm_security_attrs(props) == {}


# --- the twelve rules, through the real baselines ---------------------------------

REDEFINED: dict[tuple[str, str], str] = {
    ("cis-vmware-esxi-8.0-subset", "cis-esxi-3.1.3"): "host",
    ("cis-vmware-esxi-8.0-subset", "cis-esxi-4.1.1"): "host",
    ("cis-vmware-esxi-8.0-subset", "cis-esxi-7.1.2"): "vm",
    ("dengbao-2.0-level3-vmware", "db-l3-net-3"): "vm",
    ("dengbao-2.0-level3-vmware", "db-l3-host-6"): "host",
    ("eu-nis2-vmware", "nis2-ir-1"): "host",
    ("eu-nis2-vmware", "nis2-ir-3"): "vm",
    ("eu-nis2-vmware", "nis2-net-2"): "host",
    ("eu-nis2-vmware", "nis2-net-3"): "vm",
    ("pci-dss-4.0-vmware", "pci-r2-1"): "host",
    ("pci-dss-4.0-vmware", "pci-r10-2"): "host",
    ("vsphere-scg-v8-subset", "scg-enc-2"): "vm",
}

_GOOD_HOST = {
    "audit_record_storage_enabled": True,
    "audit_record_storage_capacity_mib": 100,
    "audit_record_storage_persistent": True,
    "mgmt_vmk_isolated": True,
    "lockdown_mode_enabled": True,
    "ssh_enabled": False,
    "ssh_running": False,
}
_GOOD_VM = {"migrate_encryption": "required", "encryption_enabled": True}


def _rule(baseline_id, rule_id):
    [rule] = [r for r in load_builtin(baseline_id).rules if r.id == rule_id]
    return rule


@pytest.mark.unit
@pytest.mark.parametrize(("baseline_id", "rule_id"), sorted(REDEFINED))
def test_every_redefined_rule_can_now_judge(baseline_id, rule_id):
    ev = classify(_rule(baseline_id, rule_id))
    assert ev.evaluable, ev.reason
    assert ev.node_type == REDEFINED[(baseline_id, rule_id)]


def _scan(tmp_path: Path, baseline_id: str, nodes: dict[str, tuple[str, dict]]):
    twin = Twin(tmp_path / "t.duckdb")
    snap = twin.start_snapshot("lab")
    for node_id, (node_type, attrs) in nodes.items():
        record = {"name": node_id, "connection_state": "connected", **attrs}
        twin.conn.execute(
            "INSERT INTO nodes (id, type, target, name, attrs) VALUES (?, ?, 'lab', ?, ?)",
            [node_id, node_type, node_id, json.dumps(record)],
        )
        twin.write_node_state(snap, node_id, record)
    CheckRunner(twin).run_baseline(snap, load_builtin(baseline_id))
    fired = {(r, n) for r, n in twin.conn.execute(
        "SELECT rule_id, node_id FROM violation WHERE snapshot_id = ?", [snap]).fetchall()}
    cov = coverage_for(twin, snap, rule_limit=1000)
    gaps = {(r, n) for r, n, _ in cov.undetermined_node_checks}
    twin.close()
    return fired, gaps


def _variant(base: dict, **change) -> dict:
    return {**base, **change}


#: One violating variant per condition each rule checks.
_HOST_BREAKS: dict[str, list[dict]] = {
    "audit": [{"audit_record_storage_enabled": False},
              {"audit_record_storage_capacity_mib": 99},
              {"audit_record_storage_persistent": False}],
    "mgmt": [{"mgmt_vmk_isolated": False}],
    "admin": [{"lockdown_mode_enabled": False}, {"ssh_enabled": True}, {"ssh_running": True}],
}
_RULE_KIND = {
    "cis-esxi-3.1.3": "audit", "db-l3-host-6": "audit", "nis2-ir-1": "audit",
    "pci-r10-2": "audit", "cis-esxi-4.1.1": "mgmt", "nis2-net-2": "mgmt",
    "pci-r2-1": "admin",
}
_KIND_ATTRS = {
    "audit": ("audit_record_storage_enabled", "audit_record_storage_capacity_mib",
              "audit_record_storage_persistent"),
    "mgmt": ("mgmt_vmk_isolated",),
    "admin": ("lockdown_mode_enabled", "ssh_enabled", "ssh_running"),
}


@pytest.mark.integration
@pytest.mark.parametrize(("baseline_id", "rule_id"),
                         sorted(k for k, v in REDEFINED.items() if v == "host"))
def test_host_rules_fire_on_each_broken_condition_and_only_there(tmp_path, baseline_id, rule_id):
    kind = _RULE_KIND[rule_id]
    nodes = {"good": ("host", _GOOD_HOST)}
    # Each attribute the rule reads, missing on its own (review L4).
    silent = [f"silent-{a}" for a in _KIND_ATTRS[kind]]
    for attr, node_id in zip(_KIND_ATTRS[kind], silent, strict=True):
        nodes[node_id] = ("host", {k: v for k, v in _GOOD_HOST.items() if k != attr})
    for i, change in enumerate(_HOST_BREAKS[kind]):
        nodes[f"bad-{i}"] = ("host", _variant(_GOOD_HOST, **change))
    fired, gaps = _scan(tmp_path, baseline_id, nodes)
    mine = {n for r, n in fired if r == rule_id}
    assert mine == {f"bad-{i}" for i in range(len(_HOST_BREAKS[kind]))}
    for node_id in silent:
        assert (rule_id, node_id) in gaps, f"{node_id}: an unread fact must be a gap, not a pass"
    assert (rule_id, "good") not in gaps


@pytest.mark.integration
def test_the_capacity_threshold_is_inclusive(tmp_path):
    fired, _ = _scan(tmp_path, "cis-vmware-esxi-8.0-subset", {
        "at": ("host", _GOOD_HOST),
        "below": ("host", _variant(_GOOD_HOST, audit_record_storage_capacity_mib=99)),
    })
    assert {n for r, n in fired if r == "cis-esxi-3.1.3"} == {"below"}


@pytest.mark.integration
@pytest.mark.parametrize(("baseline_id", "rule_id"),
                         sorted(k for k, v in REDEFINED.items() if v == "vm"))
def test_vm_rules(tmp_path, baseline_id, rule_id):
    attr = "encryption_enabled" if rule_id == "nis2-ir-3" else "migrate_encryption"
    broken = [{"encryption_enabled": False}] if attr == "encryption_enabled" else [
        {"migrate_encryption": "opportunistic"},  # user decision: required only
        {"migrate_encryption": "disabled"},
    ]
    nodes = {"vm-good": ("vm", _GOOD_VM),
             "vm-silent": ("vm", {k: v for k, v in _GOOD_VM.items() if k != attr})}
    for i, change in enumerate(broken):
        nodes[f"vm-bad-{i}"] = ("vm", _variant(_GOOD_VM, **change))
    fired, gaps = _scan(tmp_path, baseline_id, nodes)
    assert {n for r, n in fired if r == rule_id} == {f"vm-bad-{i}" for i in range(len(broken))}
    assert (rule_id, "vm-silent") in gaps
    assert (rule_id, "vm-good") not in gaps


# --- the collector wiring ------------------------------------------------------------


def _fake_vim():
    class Network:
        def __init__(self, mo_id):
            self._moId = mo_id

    class DistributedVirtualPortgroup(Network):
        pass

    class OpaqueNetwork(Network):
        pass

    return NS(Network=Network, OpaqueNetwork=OpaqueNetwork, VirtualMachine=object(),
              HostSystem=object(), dvs=NS(DistributedVirtualPortgroup=DistributedVirtualPortgroup))


@pytest.mark.unit
def test_only_a_plain_standard_network_counts_as_a_port_group():
    from vmware_harden.collectors.hosts import _fetch_vm_networks

    vim = _fake_vim()
    nets = [(vim.Network("network-1"), {"name": "VM Network"}),
            (vim.dvs.DistributedVirtualPortgroup("dvportgroup-1"), {"name": "DPG"}),
            (vim.OpaqueNetwork("network-o"), {"name": "seg"})]
    vms = [(NS(_moId=f"vm-{n}"),
            {"runtime.host": NS(_moId=f"host-{n}"), "network": [NS(_moId=net)]})
           for n, net in (("1", "network-1"), ("2", "dvportgroup-1"), ("3", "network-o"))]

    def collect(si, types_, paths):
        return nets if types_[0] is vim.Network else vms

    by_host, seen = _fetch_vm_networks(None, collect, vim)
    assert by_host == {"host-1": frozenset({"VM Network"}), "host-2": None, "host-3": None}
    assert seen == {"vm-1", "vm-2", "vm-3"}


@pytest.mark.unit
def test_a_failed_vm_network_pass_is_none_and_keeps_the_host_facts():
    from vmware_harden.collectors.hosts import _fetch_vm_networks

    def collect(si, types_, paths):
        return [(NS(_moId="vm-1"), {"runtime.host": NS(_moId="host-1"), "network": 7})]

    vim = _fake_vim()

    def boom_or_vms(si, types_, paths):
        if types_[0] is vim.Network:
            return []
        return collect(si, types_, paths)

    # A non-iterable network list must be contained, not raised (review L1).
    assert _fetch_vm_networks(None, boom_or_vms, vim) is None
