"""VM inventory collector. Pulls VM data via vmware-aiops."""
from vmware_harden.collectors.base import Collector

#: Every ``nodes.attrs`` key this collector can populate: the keys
#: ``vmware_aiops.ops.inventory.list_vms`` builds into each entry, plus the
#: ``id`` stamped by :func:`_shape_vm`. Single source of truth for the baseline
#: contract test — a rule reading a key outside this set matches zero rows and
#: reports false compliance (doc-vs-code parity, 形态 #6).
PRODUCIBLE_VM_ATTRS: frozenset[str] = frozenset(
    {
        "name",
        "power_state",
        "cpu",
        "memory_mb",
        "guest_os",
        "ip_address",
        "host",
        "uuid",
        "tools_status",
        "id",
        "secure_boot",
        "hw_version_int",
    }
)

#: Properties read for the per-VM security facts, in one batched pass.
_VM_SECURITY_PATHS: tuple[str, ...] = (
    "config.uuid", "config.bootOptions", "config.version", "runtime.connectionState",
)


def _vm_security_attrs(props: dict) -> dict:
    """Reduce one VM's batched properties to ``secure_boot`` / ``hw_version_int``.

    ``efiSecureBootEnabled`` is reported ``False`` for a BIOS-firmware VM, which
    is the truth: such a VM cannot secure-boot. An unreadable ``bootOptions``
    leaves the key absent. ``config.version`` is ``vmx-NN``; anything else is not
    parsed into a number.

    A VM vCenter does not report as ``connected`` (its host is unreachable, or
    the VM is orphaned/inaccessible) yields nothing: what vCenter answers for it
    is a cached copy, not a reading.
    """
    if props.get("runtime.connectionState") != "connected":
        return {}
    attrs: dict = {}
    secure_boot = getattr(props.get("config.bootOptions"), "efiSecureBootEnabled", None)
    if isinstance(secure_boot, bool):
        attrs["secure_boot"] = secure_boot
    version = props.get("config.version")
    if isinstance(version, str) and version.startswith("vmx-") and version[4:].isdigit():
        attrs["hw_version_int"] = int(version[4:])
    return attrs


def _fetch_vm_security(si: object) -> dict[str, dict]:
    """Security facts per ``config.uuid`` for every VM. REAL-HARDWARE-GATED.

    A ``config.uuid`` shared by two VMs (a copied VM keeps it) is dropped: the
    facts could belong to either, and attaching them to the wrong one is a
    finding nobody measured.
    """
    from vmware_aiops.ops.inventory import _collect, vim

    by_uuid: dict[str, dict] = {}
    seen_twice: set[str] = set()
    for _obj, props in _collect(si, [vim.VirtualMachine], list(_VM_SECURITY_PATHS)):
        uuid = props.get("config.uuid")
        if not uuid:
            continue
        if uuid in by_uuid:
            seen_twice.add(uuid)
        by_uuid[uuid] = _vm_security_attrs(props)
    return {u: a for u, a in by_uuid.items() if u not in seen_twice}


def _fetch_vms(target: str) -> list[dict]:
    """Fetch VM inventory for ``target``. Patched in tests.

    ``list_vms`` auto-compacts a large estate and drops ``uuid`` in that mode —
    but ``uuid`` is the stable id the Twin persists by, so the compaction is
    defeated with a very high ``compact_threshold`` to keep every field. Lazy-
    imported so vmware-aiops stays an optional collector dependency.
    """
    from vmware_aiops.connection import ConnectionManager
    from vmware_aiops.ops.inventory import list_vms

    mgr = ConnectionManager.from_config()
    try:
        si = mgr.connect(target)
        envelope = list_vms(si, compact_threshold=10**9)
        security = _fetch_vm_security(si)
    finally:
        mgr.disconnect_all()
    return [
        _shape_vm(vm, security.get(vm.get("uuid", ""), {}))
        for vm in envelope.get("vms", [])
    ]


def _shape_vm(vm: dict, security: dict | None = None) -> dict:
    """Stamp a VM record with a stable ``id``.

    ``config.uuid`` is the stable identity; a VM that reports none ("N/A")
    falls back to its name so the record still satisfies the Twin's id contract.
    The full sibling record is preserved for the baselines.
    """
    uuid = vm.get("uuid")
    vm_id = uuid if uuid and uuid != "N/A" else vm.get("name", "")
    return {**vm, **(security or {}), "id": vm_id}


class VMCollector(Collector):
    """Collect VM inventory and write to Twin."""

    def collect(self, snapshot_id: str, target: str) -> int:
        vms = _fetch_vms(target)
        return self._persist_groups(snapshot_id, target, [(vms, "vm", "VM")])
