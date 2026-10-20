"""Host security facts for collector batches B1-B3 and B5.

Pure reducers over one host's PropertyCollector result, plus the two facts that
only a per-host method call answers. Every value here was checked against a live
vCenter 8.0.3 and a standalone ESXi 8.0.3 before it was written (2026-10-18);
the shapes those hosts returned are pinned in
``tests/eval/regression/test_host_security_real_shapes.py``.

One rule governs everything below, the same one ``_service_and_time_attrs``
follows: **a fact that could not be read is omitted, never defaulted.** An
absent key leaves its rules "not evaluated" for that host, which is the honest
answer. A default would be a verdict about something nobody measured.
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)

#: Property paths this module reads, fetched in the host collector's single
#: batched PropertyCollector pass (踩坑 #31). ``config.option`` is already in
#: that pass for the STIG settings and is reused here.
HOST_SECURITY_PATHS: tuple[str, ...] = (
    "runtime.connectionState",
    "config.lockdownMode",
    "config.product.version",
    "capability.uefiSecureBoot",
    "summary.tpmAttestation",
    "config.authenticationManagerInfo",
    "config.featureCapability",
    "config.network",
    "config.virtualNicManagerInfo",
    "configManager.hostAccessManager",
    "configManager.imageConfigManager",
)

#: ``HostAccessManager.LockdownMode`` — the API form is stored as-is so a rule
#: compares against exactly what vSphere says.
LOCKDOWN_MODES: tuple[str, ...] = ("lockdownDisabled", "lockdownNormal", "lockdownStrict")

#: ``HostImageConfigManager.AcceptanceLevel`` (API form, not the esxcli
#: ``CommunitySupported`` spelling).
ACCEPTANCE_LEVELS: tuple[str, ...] = (
    "vmware_certified", "vmware_accepted", "partner", "community",
)

#: Lowest TLS version the host's reverse proxy still accepts.
TLS_VERSIONS: tuple[str, ...] = ("1.0", "1.1", "1.2", "1.3")

#: Standard-vSwitch security policy, aggregated across every vSwitch and the
#: effective (computed) policy of every port group on it.
VSWITCH_POLICY_VALUES: tuple[str, ...] = ("accept", "reject")

#: ``UserVars.ESXiVPsDisabledProtocols`` token -> the TLS version it disables.
#: ``sslv3`` is deliberately not a tier: whether an ESXi build can speak SSLv3 at
#: all is not something this option tells us, so leaving it out of the list
#: must not make us claim the host accepts it.
_TLS_TOKENS: dict[str, str] = {
    "tlsv1": "1.0",
    "tlsv1.1": "1.1",
    "tlsv1.2": "1.2",
    "tlsv1.3": "1.3",
}
_KNOWN_TLS_TOKENS = frozenset(_TLS_TOKENS) | {"sslv3"}

#: Every key this module can write.
PRODUCIBLE_SECURITY_ATTRS: frozenset[str] = frozenset(
    {
        "lockdown_mode",
        "lockdown_mode_enabled",
        "lockdown_exceptions_count",
        "persistent_logs",
        "secure_boot_enabled",
        "host_tpm_attested",
        "image_profile_acceptance",
        "nx_enabled",
        "tls_min_version",
        "ad_joined",
        "vswitch_promiscuous_mode",
        "forged_transmits",
        "mac_address_changes",
        "standard_vswitch_count",
        "mgmt_vlan_tagged",
        "mgmt_vmk_isolated",
        "audit_record_storage_enabled",
        "audit_record_storage_capacity_mib",
        "audit_record_storage_persistent",
    }
)


def _options(props: dict) -> dict[str, object]:
    return {
        getattr(o, "key", None): getattr(o, "value", None)
        for o in props.get("config.option") or []
    }


def _lockdown(props: dict) -> dict:
    mode = props.get("config.lockdownMode")
    if mode not in LOCKDOWN_MODES:
        return {}
    return {"lockdown_mode": mode, "lockdown_mode_enabled": mode != "lockdownDisabled"}


#: The ESXi ramdisk. A path *on the remote host* compared against, never opened
#: here — so not an insecure temp file (bandit B108 does not know that).
_RAMDISK = "/tmp"  # nosec B108
_VMFS = "/vmfs/volumes"


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def _is_persistent(directory: object, options: dict[str, object]) -> bool | None:
    """Is a ``[datastore] path`` directory setting on persistent storage?

    An empty datastore name means a path on the host's own filesystem, usually
    under ``/scratch`` — and ``/scratch`` is persistent only if
    ``ScratchConfig.CurrentScratchLocation`` points into ``/vmfs/volumes``
    rather than the ramdisk under ``/tmp``. Anything else is not decided here.
    """
    if not isinstance(directory, str) or not directory.startswith("["):
        return None
    datastore, _, path = directory[1:].partition("]")
    path = path.strip()
    if datastore.strip() or _under(path, _VMFS):
        return True
    if _under(path, _RAMDISK):
        return False
    if _under(path, "/scratch"):
        scratch = options.get("ScratchConfig.CurrentScratchLocation")
        if isinstance(scratch, str) and _under(scratch, _VMFS):
            return True
        if isinstance(scratch, str) and _under(scratch, _RAMDISK):
            return False
    return None


def _persistent_logs(options: dict[str, object]) -> dict:
    """Is the local log directory (``Syslog.global.logDir``) on persistent storage?"""
    persistent = _is_persistent(options.get("Syslog.global.logDir"), options)
    return {} if persistent is None else {"persistent_logs": persistent}


def _audit_record(options: dict[str, object]) -> dict:
    """The local audit record store: on or off, how big, and whether it survives a reboot.

    ESXi bounds audit records by size (MiB), not by age — there is no retention
    days setting to read, and how many days a log server keeps is not visible
    from the host. These three are what the host does answer. Each is written
    only in the type the API returns: ``storageCapacity`` arrives as an int (the
    lab's 8.0.3 hosts said 4), and a bool is refused even though Python counts
    it as one.
    """
    attrs: dict = {}
    enabled = options.get("Syslog.global.auditRecord.storageEnable")
    if isinstance(enabled, bool):
        attrs["audit_record_storage_enabled"] = enabled
    capacity = options.get("Syslog.global.auditRecord.storageCapacity")
    if isinstance(capacity, int) and not isinstance(capacity, bool) and capacity >= 0:
        attrs["audit_record_storage_capacity_mib"] = capacity
    persistent = _is_persistent(
        options.get("Syslog.global.auditRecord.storageDirectory"), options)
    if persistent is not None:
        attrs["audit_record_storage_persistent"] = persistent
    return attrs


def _major_version(version: object) -> int | None:
    head = str(version).split(".", 1)[0] if version is not None else ""
    return int(head) if head.isdigit() else None


def _tls_min_version(options: dict[str, object], product_version: object) -> dict:
    """Lowest TLS version the reverse proxy / VPS services accept, per the option.

    Only a result of 1.2 or above is trusted unconditionally — that is what the
    lab's 8.0.3 hosts reported, and port 443 refused TLS 1.0/1.1 handshakes to
    match. A *lower* result means the option leaves 1.0/1.1 enabled; on 7.x that
    is what the services do, but on 8.x the option may not be what decides it,
    so a sub-1.2 answer is kept only when the host is known to be older than 8.
    Anything unknown is left out rather than reported as a weak protocol.
    """
    raw = options.get("UserVars.ESXiVPsDisabledProtocols")
    if not isinstance(raw, str):
        return {}
    disabled = {t.strip().lower() for t in raw.split(",") if t.strip()}
    if not disabled <= _KNOWN_TLS_TOKENS:
        return {}  # a token we do not understand: do not guess what it disables
    for token, version in _TLS_TOKENS.items():
        if token not in disabled:
            if version in ("1.0", "1.1"):
                major = _major_version(product_version)
                if major is None or major >= 8:
                    return {}
            return {"tls_min_version": version}
    return {}


def _platform(props: dict) -> dict:
    attrs: dict = {}
    secure_boot = props.get("capability.uefiSecureBoot")
    if isinstance(secure_boot, bool):
        attrs["secure_boot_enabled"] = secure_boot
    # vCenter-only. A standalone ESXi does not have the property at all, and a
    # host with no report has no status: both stay absent.
    status = getattr(props.get("summary.tpmAttestation"), "status", None)
    if status in ("accepted", "notAccepted"):
        attrs["host_tpm_attested"] = status == "accepted"
    for feature in props.get("config.featureCapability") or []:
        if getattr(feature, "key", None) == "cpuid.nx":
            value = getattr(feature, "value", None)
            if value in ("0", "1"):
                attrs["nx_enabled"] = value == "1"
    return attrs


def _ad_joined(props: dict) -> dict:
    auth = props.get("config.authenticationManagerInfo")
    for store in getattr(auth, "authConfig", None) or []:
        # Duck-typed on the field only the AD store has; LocalAuthenticationInfo
        # carries ``enabled`` but never ``joinedDomain``.
        if hasattr(store, "joinedDomain") and hasattr(store, "domainMembershipStatus"):
            return {"ad_joined": bool(getattr(store, "joinedDomain", None))}
    return {}


def _aggregate_policy(values: list[object]) -> str | None:
    """'accept' if anything allows it, 'reject' only if everything was read and rejects."""
    if any(v is True for v in values):
        return "accept"
    if values and all(v is False for v in values):
        return "reject"
    return None


def _vswitch_security(network: object) -> dict:
    vswitches = getattr(network, "vswitch", None)
    if vswitches is None:
        return {}
    attrs: dict = {"standard_vswitch_count": len(vswitches)}
    if not vswitches:
        # No standard vSwitch: the policy questions have no subject. Absent,
        # not "reject" — the rule asked about something that is not there.
        return attrs
    policies: list[object] = []
    for vs in vswitches:
        policy = getattr(getattr(vs, "spec", None), "policy", None)
        policies.append(getattr(policy, "security", None))
    for pg in getattr(network, "portgroup", None) or []:
        policies.append(getattr(getattr(pg, "computedPolicy", None), "security", None))
    for key, field in (
        ("vswitch_promiscuous_mode", "allowPromiscuous"),
        ("forged_transmits", "forgedTransmits"),
        ("mac_address_changes", "macChanges"),
    ):
        verdict = _aggregate_policy([getattr(p, field, None) for p in policies])
        if verdict is not None:
            attrs[key] = verdict
    return attrs


def _mgmt_vlans(network: object, vnic_manager: object) -> list[int] | None:
    """The VLAN of every management vmknic, or ``None`` when any one is unreadable.

    A management vmknic on a distributed switch takes its VLAN from the
    distributed port group, which this pass does not read — so the whole fact
    is left undecided rather than judged on the vmknics it could see.
    """
    selected: set[str] = set()
    for cfg in getattr(vnic_manager, "netConfig", None) or []:
        if getattr(cfg, "nicType", None) == "management":
            prefix = "management."
            selected.update(
                s[len(prefix):] if s.startswith(prefix) else s
                for s in (getattr(cfg, "selectedVnic", None) or [])
            )
    if not selected or network is None:
        return None
    vlans = _portgroup_vlans(network)
    found: list[int] = []
    for vnic in getattr(network, "vnic", None) or []:
        if getattr(vnic, "key", None) not in selected:
            continue
        if getattr(getattr(vnic, "spec", None), "distributedVirtualPort", None) is not None:
            return None
        vlan = vlans.get(getattr(vnic, "portgroup", None))
        # 0 is untagged; 1-4094 is a VLAN the vmknic's traffic is tagged with.
        # 4095 is the trunk (guest-tagging) setting: a vmknic does not tag its
        # own frames, so it is neither — undecided rather than "tagged".
        if not isinstance(vlan, int) or not 0 <= vlan <= 4094:
            return None
        found.append(vlan)
    if len(found) != len(selected):
        return None
    return found


def _portgroup_vlans(network: object) -> dict[object, object]:
    specs = [getattr(pg, "spec", None) for pg in getattr(network, "portgroup", None) or []]
    return {getattr(spec, "name", None): getattr(spec, "vlanId", None) for spec in specs}


def _mgmt_vlan_tagged(network: object, vnic_manager: object) -> dict:
    """Are all management vmknics on a VLAN-tagged standard port group?"""
    vlans = _mgmt_vlans(network, vnic_manager)
    return {} if vlans is None else {"mgmt_vlan_tagged": all(v != 0 for v in vlans)}


#: The standard port group VLAN that carries every VLAN to its VMs.
_TRUNK_VLAN = 4095


def mgmt_isolation_attrs(
    network: object, vnic_manager: object, vm_networks: frozenset[str] | None
) -> dict:
    """Is management traffic on a VLAN of its own on this host?

    Isolated means every management vmknic is on a tagged VLAN, and no VM on
    this host is attached to a standard port group carrying that VLAN — the same
    VLAN ID, or the 4095 trunk that carries them all. ``vm_networks`` is the set
    of network names the host's VMs use (:func:`host_vm_networks`), ``None``
    when that is not known.

    The check is host-local: a VM on another host sharing this VLAN is not seen
    here. An untagged management vmknic is not isolated whatever the VMs do, so
    that answer needs no VM data.

    Two sources say whether a VM shares the VLAN. The port groups' own port
    lists (host configuration: a ``virtualMachine`` port) show every powered-on
    VM, whatever the account may see — enough on their own for a "no". A "yes"
    also needs ``vm_networks``, the VM pass, which covers powered-off VMs too
    but only those the account can see; :func:`host_vm_networks` refuses a host
    whose own VM list it did not fully read, but if vCenter filters that list
    for a restricted account as well, a hidden powered-off VM is not seen
    (unverified, 2026-10-20). Without ``vm_networks``, or with a VM network that
    is not one of this host's standard port groups (an NSX segment, say, whose
    VLAN is not read), a "yes" is left undecided.
    """
    vlans = _mgmt_vlans(network, vnic_manager)
    if vlans is None:
        return {}
    if any(v == 0 for v in vlans):
        return {"mgmt_vmk_isolated": False}
    portgroups = _portgroup_vlans(network)
    shared = {
        name for name, vlan in portgroups.items()
        if vlan in vlans or vlan == _TRUNK_VLAN
    }
    if _vm_ports_on(network, shared):
        return {"mgmt_vmk_isolated": False}
    if vm_networks is None or not vm_networks <= set(portgroups):
        return {}
    return {"mgmt_vmk_isolated": not shared & vm_networks}


def _vm_ports_on(network: object, names: set) -> bool:
    """Does any of these standard port groups have a VM port in use right now?"""
    for pg in getattr(network, "portgroup", None) or []:
        if getattr(getattr(pg, "spec", None), "name", None) not in names:
            continue
        if any(getattr(port, "type", None) == "virtualMachine"
               for port in getattr(pg, "port", None) or []):
            return True
    return False


def vm_networks_by_host(
    vm_rows: list[tuple[str, dict]], network_kinds: dict[str, tuple[bool, str]]
) -> tuple[dict[str, frozenset[str] | None], set[str]]:
    """Network names the VMs on each host use, and which VMs were fully read.

    ``vm_rows`` are ``(vm moId, properties)`` with ``runtime.host``, ``network``
    and ``config.template``; ``network_kinds`` maps a network moId to
    ``(not_a_standard_port_group, name)``. A host with a VM on a distributed
    port group, an NSX segment, or a network not in that map, is ``None``: that
    VM's VLAN is not something this pass read. A template carries no traffic,
    so its networks are not counted.

    A VM counts as read only when both ``runtime.host`` and ``network`` came
    back — PropertyCollector leaves an unreadable property out, which must not
    pass for "no networks". Whether every VM on a host was read is
    :func:`host_vm_networks`' question.
    """
    names: dict[str, set[str]] = {}
    undecided: set[str] = set()
    read: set[str] = set()
    for vm_id, props in vm_rows:
        host_id = getattr(props.get("runtime.host"), "_moId", None)
        if host_id is None or props.get("network") is None:
            continue
        read.add(vm_id)
        used = names.setdefault(host_id, set())
        if props.get("config.template") is True:
            continue
        for net in props.get("network") or []:
            kind = network_kinds.get(getattr(net, "_moId", None))
            if kind is None or kind[0]:
                undecided.add(host_id)
            else:
                used.add(kind[1])
    by_host = {h: None if h in undecided else frozenset(n) for h, n in names.items()}
    return by_host, read


def host_vm_networks(
    host_id: str,
    host_vms: list | None,
    by_host: dict[str, frozenset[str] | None] | None,
    seen_vm_ids: set[str],
) -> frozenset[str] | None:
    """One host's VM network names, or ``None`` unless every VM on it was read.

    The VM pass returns only the VMs the account can see, and says nothing about
    the rest — so a host whose VMs are all hidden would otherwise look like a
    host with no VMs, and pass. ``host_vms`` is the host's own ``vm`` list; every
    VM in it must be among ``seen_vm_ids``. ``by_host`` ``None`` means the VM
    pass failed.
    """
    if by_host is None or host_vms is None:
        return None
    ids = {getattr(vm, "_moId", None) for vm in host_vms}
    if None in ids or not ids <= seen_vm_ids:
        return None
    return by_host.get(host_id, frozenset())


def security_attrs(props: dict) -> dict:
    """Reduce one host's batched properties to the B1-B3/B5 attributes."""
    options = _options(props)
    network = props.get("config.network")
    return {
        **_lockdown(props),
        **_persistent_logs(options),
        **_audit_record(options),
        **_tls_min_version(options, props.get("config.product.version")),
        **_platform(props),
        **_ad_joined(props),
        **_vswitch_security(network),
        **_mgmt_vlan_tagged(network, props.get("config.virtualNicManagerInfo")),
    }


def queried_attrs(props: dict) -> dict:
    """The two facts no property holds, each one read-only call per host.

    ``HostAccessManager.QueryLockdownExceptions`` and
    ``HostImageConfigManager.HostImageConfigGetAcceptance`` are queries: they
    change nothing. A host vCenter is not connected to is skipped — the call
    would only time out, and the record is dropped as unmeasured anyway. Any
    failure omits that one fact.
    """
    if props.get("runtime.connectionState") != "connected":
        return {}
    attrs: dict = {}
    access = props.get("configManager.hostAccessManager")
    if access is not None:
        try:
            users = access.QueryLockdownExceptions()
        except Exception as exc:  # noqa: BLE001 — unreadable means absent, by design
            log.debug("QueryLockdownExceptions failed: %s", type(exc).__name__)
            users = None
        if users is not None:
            attrs["lockdown_exceptions_count"] = len(list(users))
    image = props.get("configManager.imageConfigManager")
    if image is not None:
        try:
            level = image.HostImageConfigGetAcceptance()
        except Exception as exc:  # noqa: BLE001 — unreadable means absent, by design
            log.debug("HostImageConfigGetAcceptance failed: %s", type(exc).__name__)
            level = None
        if level in ACCEPTANCE_LEVELS:
            attrs["image_profile_acceptance"] = level
    return attrs
