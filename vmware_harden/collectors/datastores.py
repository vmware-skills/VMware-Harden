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
        node_rows: list[list] = []
        state_rows: list[tuple[str, dict]] = []
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
            node_rows.append([node_id, target, node_name, json.dumps(d), now])
            state_rows.append((node_id, d))

        # One transaction + executemany for the whole batch: a large inventory
        # used to issue one commit per node (thousands of fsyncs).
        self.twin.conn.execute("BEGIN TRANSACTION")
        try:
            if node_rows:
                self.twin.conn.executemany(
                    """INSERT INTO nodes (id, type, target, name, attrs, last_seen_at)
                       VALUES (?, 'datastore', ?, ?, ?, ?)
                       ON CONFLICT (id) DO UPDATE SET
                           target = excluded.target,
                           name = excluded.name,
                           attrs = excluded.attrs,
                           last_seen_at = excluded.last_seen_at""",
                    node_rows,
                )
            self.twin.write_node_states(snapshot_id, state_rows)
            self.twin.conn.execute("COMMIT")
        except Exception:
            self.twin.conn.execute("ROLLBACK")
            raise
        return len(datastores)
