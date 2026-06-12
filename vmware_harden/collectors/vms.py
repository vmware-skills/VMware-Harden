"""VM inventory collector. Pulls VM data via vmware_aiops."""
from vmware_harden.collectors.base import Collector


def _fetch_vms(target: str) -> list[dict]:
    """Fetch VM inventory from vCenter. Patched in tests.

    Production wrapper around vmware_aiops; lazy-imports to avoid hard
    dependency at test time.
    """
    from vmware_aiops.ops.vm_inventory import list_vms

    return list_vms(target)


class VMCollector(Collector):
    """Collect VM inventory and write to Twin."""

    def collect(self, snapshot_id: str, target: str) -> int:
        vms = _fetch_vms(target)
        return self._persist_groups(snapshot_id, target, [(vms, "vm", "VM")])
