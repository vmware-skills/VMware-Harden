"""VM inventory collector. Pulls VM data via vmware-aiops."""
from vmware_harden.collectors.base import Collector


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
    finally:
        mgr.disconnect_all()
    return [_shape_vm(vm) for vm in envelope.get("vms", [])]


def _shape_vm(vm: dict) -> dict:
    """Stamp a VM record with a stable ``id``.

    ``config.uuid`` is the stable identity; a VM that reports none ("N/A")
    falls back to its name so the record still satisfies the Twin's id contract.
    The full sibling record is preserved for the baselines.
    """
    uuid = vm.get("uuid")
    vm_id = uuid if uuid and uuid != "N/A" else vm.get("name", "")
    return {**vm, "id": vm_id}


class VMCollector(Collector):
    """Collect VM inventory and write to Twin."""

    def collect(self, snapshot_id: str, target: str) -> int:
        vms = _fetch_vms(target)
        return self._persist_groups(snapshot_id, target, [(vms, "vm", "VM")])
