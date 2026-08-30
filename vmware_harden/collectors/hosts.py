"""Host inventory collector. Pulls ESXi host data via vmware-aiops."""
from vmware_harden.collectors.base import Collector

#: ESXi advanced-setting name -> the snake_case ``nodes.attrs`` key the STIG
#: baseline SQL reads. Single source of truth for what the host collector can
#: produce for the vsphere-stig-v9-subset rules. The regression test asserts
#: every ``$.key`` that baseline cites is a value here (doc-vs-code parity,
#: 形态 #6): a rule reading a key no collector populates would silently match
#: zero rows and report false compliance.
STIG_ADVANCED_SETTING_ATTRS: dict[str, str] = {
    "Security.AccountLockFailures": "account_lock_failures",
    "Security.AccountUnlockTime": "account_unlock_time",
    "Security.PasswordQualityControl": "password_quality_control",
    "Security.PasswordHistory": "password_history",
    "DCUI.Access": "dcui_access",
    "UserVars.ESXiShellInteractiveTimeOut": "shell_timeout_seconds",
    "UserVars.ESXiShellTimeOut": "esxi_shell_timeout_seconds",
    "UserVars.DcuiTimeOut": "dcui_timeout_seconds",
    "Config.HostAgent.plugins.solo.enableMob": "mob_enabled",
    "UserVars.SuppressShellWarning": "suppress_shell_warning",
    "Net.BlockGuestBPDU": "block_guest_bpdu",
    "Syslog.global.logHost": "syslog_remote_host",
}

#: Keys ``_service_and_time_attrs`` can populate. Declared beside the advanced
#: settings so the collector's full output surface is readable in one place.
_SERVICE_TIME_ATTRS: frozenset[str] = frozenset(
    {
        "ntp_enabled",
        "ntp_service_policy_on",
        "ntp_servers",
        "ssh_running",
        "ssh_enabled",
        "firewall_enabled",
    }
)

#: Base inventory keys ``vmware_aiops.ops.inventory.list_hosts`` always returns.
_BASE_HOST_ATTRS: frozenset[str] = frozenset(
    {
        "name",
        "connection_state",
        "power_state",
        "cpu_cores",
        "cpu_threads",
        "memory_gb",
        "esxi_version",
        "esxi_build",
        "vm_count",
        "uptime_seconds",
    }
)

#: Every ``nodes.attrs`` key the host collector can populate = base inventory +
#: the STIG advanced settings + the service/time/firewall facts + the stamped
#: ``id``. The parity regression asserts no builtin baseline SQL reads a host key
#: outside this set — and, read the other way, this set is what the "could not be
#: evaluated" report subtracts from, so growing it is how that report shrinks.
PRODUCIBLE_HOST_ATTRS: frozenset[str] = (
    _BASE_HOST_ATTRS
    | frozenset(STIG_ADVANCED_SETTING_ATTRS.values())
    | _SERVICE_TIME_ATTRS
    | {"id"}
)


def _advanced_settings_to_attrs(options: object) -> dict:
    """Reduce a host's advanced ``OptionValue`` list to the STIG attrs keys.

    ``options`` is an iterable of objects exposing ``.key`` (the ESXi advanced
    setting name, e.g. ``Security.AccountLockFailures``) and ``.value``. Only the
    settings the STIG baseline reads are kept; everything else is ignored so the
    record stays small. Defensive: a ``None`` list or an entry missing ``.key``
    is skipped rather than raising — a partial host config must not abort the
    whole collection.

    Pure and offline-testable — the network fetch that produces ``options`` is
    the real-hardware-gated part (see ``_fetch_advanced_settings``).
    """
    attrs: dict = {}
    for opt in options or []:
        key = getattr(opt, "key", None)
        attr = STIG_ADVANCED_SETTING_ATTRS.get(key)
        if attr is not None:
            attrs[attr] = getattr(opt, "value", None)
    return attrs


#: ESXi service key -> the ``nodes.attrs`` keys it answers. `running` and
#: `policy` are separate facts: a service can be running with policy "off"
#: (started by hand, gone after reboot), which several baselines fail on.
_SERVICE_ATTRS: dict[str, tuple[str, str]] = {
    "ntpd": ("ntp_enabled", "ntp_service_policy_on"),
    "TSM-SSH": ("ssh_running", "ssh_enabled"),
}

#: ESXi service policy values that mean "starts on its own". `automatic` starts
#: the service with its firewall port, so it is not "off".
_POLICY_ON = frozenset({"on", "automatic"})


def _service_and_time_attrs(props: dict) -> dict:
    """Reduce one host's service/time/firewall properties to baseline attrs.

    Answers six keys the baselines already declare in ``baselines/vocabulary.py``
    and that nothing wrote: a real scan reported "no collector writes
    host.ntp_enabled" and five siblings, so the design existed and the collector
    did not.

    **A fact that could not be read is omitted, never defaulted.** ESXi reports
    the services it has; a build without ntpd simply omits it, and writing
    ``ntp_enabled: false`` there would report a compliance failure for something
    nobody measured — the exact defect v1.9.0 was released to remove. An absent
    key leaves its rules "not evaluated", which is the honest answer.

    ``ntp_servers`` is the one place empty means something: time sync configured
    with nothing to sync to is a finding, so ``[]`` is recorded and only an
    unreadable ``dateTimeInfo`` is omitted.
    """
    attrs: dict = {}

    service_info = props.get("config.service")
    for svc in getattr(service_info, "service", None) or []:
        names = _SERVICE_ATTRS.get(getattr(svc, "key", None))
        if names is None:
            continue
        running_key, policy_key = names
        running = getattr(svc, "running", None)
        if running is not None:
            attrs[running_key] = bool(running)
        policy = getattr(svc, "policy", None)
        if policy is not None:
            attrs[policy_key] = str(policy).lower() in _POLICY_ON

    dt = props.get("config.dateTimeInfo")
    servers = getattr(getattr(dt, "ntpConfig", None), "server", None)
    if servers is not None:
        attrs["ntp_servers"] = list(servers)

    firewall = props.get("config.firewall")
    default_policy = getattr(firewall, "defaultPolicy", None)
    blocked = getattr(default_policy, "incomingBlocked", None)
    if blocked is not None:
        attrs["firewall_enabled"] = bool(blocked)

    return attrs


def _fetch_advanced_settings(si: object) -> dict[str, dict]:
    """Fetch each host's STIG-relevant advanced settings, keyed by host name.

    REAL-HARDWARE-GATED: this path is only exercised against a live
    vCenter/ESXi, so no test here covers it. It was verified by hand on
    2026-08-13 against a standalone ESXi 8.0.3 (build 24280767): all 12 attrs in
    STIG_ADVANCED_SETTING_ATTRS came back populated. ESXi 9.x — what the STIG
    baseline actually targets — and vCenter-managed multi-host inventories
    remain unverified. One batched PropertyCollector pass
    pulls every host's ``config.option`` (its full advanced-setting list)
    alongside its name — a single server-side call for the whole fleet rather
    than an ``OptionManager.QueryOptions`` round-trip per host (踩坑 #31). The
    pure reducer ``_advanced_settings_to_attrs`` is unit-tested; this wrapper is
    covered only on real hardware.
    """
    # ``vim`` and ``_collect`` both come from vmware-aiops (its inventory module
    # does ``from pyVmomi import vim``), so harden's only declared collector
    # dependency stays vmware-aiops — no direct pyVmomi distribution to declare.
    from vmware_aiops.ops.inventory import _collect, vim

    # One pass for everything: the advanced settings AND the service/time/
    # firewall properties. Two passes would double the round trips for facts
    # that arrive from the same managed object (踩坑 #31).
    paths = [
        "name",
        "config.option",
        "config.service",
        "config.dateTimeInfo",
        "config.firewall",
    ]
    settings: dict[str, dict] = {}
    for _obj, props in _collect(si, [vim.HostSystem], paths):
        name = props.get("name", "")
        settings[name] = {
            **_advanced_settings_to_attrs(props.get("config.option")),
            **_service_and_time_attrs(props),
        }
    return settings


def _fetch_hosts(target: str) -> list[dict]:
    """Fetch ESXi host inventory for ``target``. Patched in tests.

    Connects with vmware-aiops' own ``ConnectionManager`` (reusing its
    ``~/.vmware-aiops/config.yaml``), lists hosts, enriches each with the STIG
    advanced settings, and stamps each record with the ``id``/``name`` the Twin
    requires. Lazy-imported so vmware-aiops stays an optional collector
    dependency (declared under the ``collectors`` extra).
    """
    from vmware_aiops.connection import ConnectionManager
    from vmware_aiops.ops.inventory import list_hosts

    mgr = ConnectionManager.from_config()
    try:
        si = mgr.connect(target)
        hosts = list_hosts(si)
        advanced = _fetch_advanced_settings(si)
    finally:
        mgr.disconnect_all()
    return [_shape_host(host, advanced.get(host.get("name", ""), {})) for host in hosts]


def _shape_host(host: dict, advanced: dict | None = None) -> dict:
    """Stamp a host record with a stable ``id`` and merge advanced settings.

    An ESXi host's name is its FQDN/IP, unique within a vCenter inventory, so it
    doubles as the stable identity the Twin namespaces per target. The full
    sibling record (esxi_version, cpu, memory, …) is preserved for the baselines,
    with the STIG advanced settings (``advanced``) merged in when collected.
    """
    return {**host, **(advanced or {}), "id": host.get("name", "")}


class HostCollector(Collector):
    """Collect ESXi host inventory and write to Twin."""

    def collect(self, snapshot_id: str, target: str) -> int:
        hosts = _fetch_hosts(target)
        return self._persist_groups(snapshot_id, target, [(hosts, "host", "host")])
