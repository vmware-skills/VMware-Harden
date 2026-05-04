"""Datastore inventory collector. Pulls datastore data via vmware_storage."""
import json
from datetime import datetime, timezone

from vmware_harden.collectors.base import Collector, CollectorError


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
        # DuckDB rejects CURRENT_TIMESTAMP in ON CONFLICT SET (BinderException);
        # bind `now` once and reference via excluded.* — see schema.py note.
        now = datetime.now(timezone.utc)
        for d in datastores:
            try:
                moref = d["id"]
                node_name = d["name"]
            except KeyError as e:
                raise CollectorError(
                    f"DatastoreCollector: datastore record missing required field {e}; "
                    f"target={target}, record={d!r}"
                ) from e
            # Namespace by target so identical MoRefs from different vCenters
            # don't collide in a multi-target Twin.
            node_id = f"{target}:{moref}"

            self.twin.conn.execute("BEGIN TRANSACTION")
            try:
                self.twin.conn.execute(
                    """INSERT INTO nodes (id, type, target, name, attrs, last_seen_at)
                       VALUES (?, 'datastore', ?, ?, ?, ?)
                       ON CONFLICT (id) DO UPDATE SET
                           target = excluded.target,
                           name = excluded.name,
                           attrs = excluded.attrs,
                           last_seen_at = excluded.last_seen_at""",
                    [node_id, target, node_name, json.dumps(d), now],
                )
                self.twin.write_node_state(snapshot_id, node_id, d)
                self.twin.conn.execute("COMMIT")
            except Exception:
                self.twin.conn.execute("ROLLBACK")
                raise
        return len(datastores)
