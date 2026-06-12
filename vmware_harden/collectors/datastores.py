"""Datastore inventory collector. Pulls datastore data via vmware_storage."""
from vmware_harden.collectors.base import Collector


def _fetch_datastores(target: str) -> list[dict]:
    """Fetch datastore inventory from vCenter. Patched in tests.

    Production wrapper around vmware_storage; lazy-imports to avoid hard
    dependency at test time.
    """
    from vmware_storage.ops.datastore_inventory import list_datastores

    return list_datastores(target)


class DatastoreCollector(Collector):
    """Collect datastore inventory and write to Twin."""

    def collect(self, snapshot_id: str, target: str) -> int:
        datastores = _fetch_datastores(target)
        return self._persist_groups(
            snapshot_id, target, [(datastores, "datastore", "datastore")]
        )
