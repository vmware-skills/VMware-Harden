"""VM inventory collector. Pulls VM data via vmware-aiops."""
import logging

from vmware_harden.collectors.base import Collector

log = logging.getLogger(__name__)

#: Every ``nodes.attrs`` key this collector can populate: the keys
#: ``vmware_aiops.ops.inventory.list_vms`` builds into each entry, plus the
#: ``id`` stamped by :func:`_shape_vm`, plus the security facts of the second
#: pass (:data:`_VM_SECURITY_ATTRS`). Single source of truth for the baseline
#: contract test — a rule reading a key outside this set matches zero rows and
#: reports false compliance (doc-vs-code parity, 形态 #6).
_VM_SECURITY_ATTRS: frozenset[str] = frozenset(
    {"secure_boot", "hw_version_int", "migrate_encryption", "encryption_enabled"}
)

#: ``VirtualMachineConfigSpecEncryptedVMotionModes``, the API form.
MIGRATE_ENCRYPTION_MODES: tuple[str, ...] = ("disabled", "opportunistic", "required")

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
    }
) | _VM_SECURITY_ATTRS

#: Properties read for the per-VM security facts, in one batched pass.
_VM_SECURITY_PATHS: tuple[str, ...] = (
    "config.uuid", "config.bootOptions", "config.version", "runtime.connectionState",
    "config.migrateEncryption", "config.keyId", "config.hardware.device", "datastore",
)


def _vm_security_attrs(props: dict, datastore_types: dict[str, str] | None = None) -> dict:
    """Reduce one VM's batched properties to its security facts.

    ``efiSecureBootEnabled`` is reported ``False`` for a BIOS-firmware VM, which
    is the truth: such a VM cannot secure-boot. An unreadable ``bootOptions``
    leaves the key absent. ``config.version`` is ``vmx-NN``; anything else is not
    parsed into a number.

    ``encryption_enabled`` needs the VM home *and* every virtual disk encrypted
    (``config.keyId`` and each disk backing's ``keyId``): a vTPM VM has its home
    encrypted and its disks in clear text. It is only judged when the config was
    read (a well-formed ``config.version``) and the device list arrived. An RDM
    or PMem disk has no key to carry, so a VM with one is not fully encrypted.

    "Not encrypted" also needs to know the VM is on no vSAN datastore, whose
    data-at-rest encryption may cover it and is not read: ``datastore_types``
    maps every datastore the datastore pass read to its type (``None`` when the
    pass failed), and the VM's own ``datastore`` list must have come back with
    every entry in that map and none of them vSAN. Otherwise the fact is left
    undecided. ``migrateEncryption`` is stored in the API's own enum form; any
    other value is not stored.

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
        attrs.update(_encryption(props, datastore_types))
    mode = props.get("config.migrateEncryption")
    if mode in MIGRATE_ENCRYPTION_MODES:
        attrs["migrate_encryption"] = mode
    return attrs


def _encryption(props: dict, datastore_types: dict[str, str] | None) -> dict:
    devices = props.get("config.hardware.device")
    if devices is None:
        return {}
    # Duck-typed on the field only a virtual disk has: a CD-ROM's ISO backing
    # has a fileName too, but no capacity.
    disks = [d for d in devices if hasattr(d, "capacityInKB")]
    encrypted = props.get("config.keyId") is not None and all(
        getattr(getattr(d, "backing", None), "keyId", None) is not None for d in disks
    )
    if not encrypted:
        on = [getattr(ds, "_moId", None) for ds in props.get("datastore") or []]
        if datastore_types is None or not on:
            return {}
        if any(datastore_types.get(ds) in (None, "vsan") for ds in on):
            return {}
    return {"encryption_enabled": encrypted}


def _fetch_vm_security(si: object) -> dict[str, dict]:
    """Security facts per ``config.uuid`` for every VM. REAL-HARDWARE-GATED.

    A ``config.uuid`` shared by two VMs (a copied VM keeps it) is dropped: the
    facts could belong to either, and attaching them to the wrong one is a
    finding nobody measured.
    """
    from vmware_aiops.ops.inventory import _collect, vim

    try:
        # A datastore whose type did not come back is left out, so a VM on it
        # is undecided rather than judged as off vSAN.
        types: dict[str, str] | None = {
            getattr(obj, "_moId", None): str(props["summary.type"]).lower()
            for obj, props in _collect(si, [vim.Datastore], ["summary.type"])
            if props.get("summary.type") is not None
        }
    except Exception as exc:  # noqa: BLE001 — only the unencrypted verdict depends on it
        log.warning("datastore pass failed (%s); unencrypted VMs will be reported "
                    "not evaluated", type(exc).__name__)
        types = None
    by_uuid: dict[str, dict] = {}
    seen_twice: set[str] = set()
    for _obj, props in _collect(si, [vim.VirtualMachine], list(_VM_SECURITY_PATHS)):
        uuid = props.get("config.uuid")
        if not uuid:
            continue
        if uuid in by_uuid:
            seen_twice.add(uuid)
        by_uuid[uuid] = _vm_security_attrs(props, types)
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
        try:
            security = _fetch_vm_security(si)
        except Exception as exc:  # noqa: BLE001 — the inventory still stands
            # The second pass failing must not cost the VMs the first pass did
            # read. Its two facts go missing on every VM, which the engine
            # reports as per-VM gaps — not as passes.
            log.warning("VM security pass failed (%s); its facts will be reported "
                        "not evaluated", type(exc).__name__)
            security = {}
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
