"""Host inventory collector. Pulls ESXi host data via vmware_aiops."""
from vmware_harden.collectors.base import Collector


def _fetch_hosts(target: str) -> list[dict]:
    """Fetch host inventory from vCenter. Patched in tests.

    Production wrapper around vmware_aiops; lazy-imports to avoid hard
    dependency at test time.
    """
    from vmware_aiops.ops.host_inventory import list_hosts

    return list_hosts(target)


class HostCollector(Collector):
    """Collect ESXi host inventory and write to Twin."""

    def collect(self, snapshot_id: str, target: str) -> int:
        hosts = _fetch_hosts(target)
        return self._persist_groups(
            snapshot_id, target, [(hosts, "host", "host")]
        )
