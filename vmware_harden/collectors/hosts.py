"""Host inventory collector. Pulls ESXi host data via vmware-aiops."""
from vmware_harden.collectors.base import Collector


def _fetch_hosts(target: str) -> list[dict]:
    """Fetch ESXi host inventory for ``target``. Patched in tests.

    Connects with vmware-aiops' own ``ConnectionManager`` (reusing its
    ``~/.vmware-aiops/config.yaml``), lists hosts, and stamps each record with
    the ``id``/``name`` the Twin requires. Lazy-imported so vmware-aiops stays
    an optional collector dependency (declared under the ``collectors`` extra).
    """
    from vmware_aiops.connection import ConnectionManager
    from vmware_aiops.ops.inventory import list_hosts

    mgr = ConnectionManager.from_config()
    try:
        si = mgr.connect(target)
        hosts = list_hosts(si)
    finally:
        mgr.disconnect_all()
    return [_shape_host(host) for host in hosts]


def _shape_host(host: dict) -> dict:
    """Stamp a host record with a stable ``id``.

    An ESXi host's name is its FQDN/IP, unique within a vCenter inventory, so it
    doubles as the stable identity the Twin namespaces per target. The full
    sibling record (esxi_version, cpu, memory, …) is preserved for the baselines.
    """
    return {**host, "id": host.get("name", "")}


class HostCollector(Collector):
    """Collect ESXi host inventory and write to Twin."""

    def collect(self, snapshot_id: str, target: str) -> int:
        hosts = _fetch_hosts(target)
        return self._persist_groups(snapshot_id, target, [(hosts, "host", "host")])
