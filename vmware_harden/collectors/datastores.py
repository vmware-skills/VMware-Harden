"""Datastore inventory collector. Pulls datastore data via vmware-storage."""
from vmware_harden.collectors.base import Collector

#: Every ``nodes.attrs`` key this collector can populate: the keys
#: ``vmware_storage.ops.inventory.list_datastores`` builds into each entry, plus
#: the ``id`` stamped by :func:`_shape_datastore`. ``vm_count`` is absent on
#: purpose — it is opt-in upstream (``include_vm_count=True``) and this collector
#: does not ask for it. Single source of truth for the baseline contract test.
PRODUCIBLE_DATASTORE_ATTRS: frozenset[str] = frozenset(
    {
        "name",
        "type",
        "free_gb",
        "used_gb",
        "total_gb",
        "usage_pct",
        "accessible",
        "url",
        "id",
    }
)


def _fetch_datastores(target: str) -> list[dict]:
    """Fetch datastore inventory for ``target``. Patched in tests.

    Connects with vmware-storage's own ``ConnectionManager`` and reads the
    family list envelope (every datastore, un-truncated), stamping each record
    with the ``id``/``name`` the Twin requires. Lazy-imported so vmware-storage
    stays an optional collector dependency.
    """
    from vmware_storage.connection import ConnectionManager
    from vmware_storage.ops.inventory import list_datastores

    mgr = ConnectionManager.from_config()
    try:
        si = mgr.connect(target)
        envelope = list_datastores(si)
    finally:
        mgr.disconnect_all()
    return [_shape_datastore(ds) for ds in envelope.get("items", [])]


def _shape_datastore(datastore: dict) -> dict:
    """Stamp a datastore record with a stable ``id``.

    A datastore's name is unique within a vCenter, so it doubles as the stable
    identity the Twin namespaces per target. The full sibling record (capacity,
    type, usage, …) is preserved for the baselines.
    """
    return {**datastore, "id": datastore.get("name", "")}


class DatastoreCollector(Collector):
    """Collect datastore inventory and write to Twin."""

    def collect(self, snapshot_id: str, target: str) -> int:
        datastores = _fetch_datastores(target)
        return self._persist_groups(
            snapshot_id, target, [(datastores, "datastore", "datastore")]
        )
