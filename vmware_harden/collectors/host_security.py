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


def _persistent_logs(options: dict[str, object]) -> dict:
    """Is the local log directory on persistent storage?

    ``Syslog.global.logDir`` is ``[datastore] path``. An empty datastore name
    means a path on the host's own filesystem, usually ``/scratch/log`` — and
    ``/scratch`` is persistent only if ``ScratchConfig.CurrentScratchLocation``
    points into ``/vmfs/volumes`` rather than the ramdisk under ``/tmp``.
    Anything else is not decided here.
    """
    log_dir = options.get("Syslog.global.logDir")
    if not isinstance(log_dir, str) or not log_dir.startswith("["):
        return {}
    datastore, _, path = log_dir[1:].partition("]")
    path = path.strip()
    if datastore.strip():
        return {"persistent_logs": True}
    if _under(path, _VMFS):
        return {"persistent_logs": True}
    if _under(path, _RAMDISK):
        return {"persistent_logs": False}
    if _under(path, "/scratch"):
        scratch = options.get("ScratchConfig.CurrentScratchLocation")
        if isinstance(scratch, str) and _under(scratch, _VMFS):
            return {"persistent_logs": True}
        if isinstance(scratch, str) and _under(scratch, _RAMDISK):
            return {"persistent_logs": False}
    return {}


def _tls_min_version(options: dict[str, object]) -> dict:
    raw = options.get("UserVars.ESXiVPsDisabledProtocols")
    if not isinstance(raw, str):
        return {}
    disabled = {t.strip().lower() for t in raw.split(",") if t.strip()}
    if not disabled <= _KNOWN_TLS_TOKENS:
        return {}  # a token we do not understand: do not guess what it disables
    for token, version in _TLS_TOKENS.items():
        if token not in disabled:
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


def _mgmt_vlan_tagged(network: object, vnic_manager: object) -> dict:
    """Are all management vmknics on a VLAN-tagged standard port group?

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
        return {}
    specs = [getattr(pg, "spec", None) for pg in getattr(network, "portgroup", None) or []]
    vlans = {getattr(spec, "name", None): getattr(spec, "vlanId", None) for spec in specs}
    tagged: list[bool] = []
    for vnic in getattr(network, "vnic", None) or []:
        if getattr(vnic, "key", None) not in selected:
            continue
        if getattr(getattr(vnic, "spec", None), "distributedVirtualPort", None) is not None:
            return {}
        vlan = vlans.get(getattr(vnic, "portgroup", None))
        if not isinstance(vlan, int):
            return {}
        tagged.append(vlan != 0)
    if len(tagged) != len(selected):
        return {}
    return {"mgmt_vlan_tagged": all(tagged)}


def security_attrs(props: dict) -> dict:
    """Reduce one host's batched properties to the B1-B3/B5 attributes."""
    options = _options(props)
    network = props.get("config.network")
    return {
        **_lockdown(props),
        **_persistent_logs(options),
        **_tls_min_version(options),
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
