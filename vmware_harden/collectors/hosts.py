"""Host inventory collector. Pulls ESXi host data via vmware_aiops."""
# TODO(planning): currently assumes single-target Twin. If multi-vCenter
# Twins are added, namespace IDs as f"{target}:{h['id']}" or add a
# target column to nodes. Raised in Task 4 code review.
import json
from datetime import datetime, timezone

from vmware_harden.collectors.base import Collector, CollectorError


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
        # DuckDB rejects CURRENT_TIMESTAMP in ON CONFLICT SET (BinderException);
        # bind `now` once and reference via excluded.* — see schema.py note.
        now = datetime.now(timezone.utc)
        for h in hosts:
            try:
                node_id = h["id"]
                node_name = h["name"]
            except KeyError as e:
                raise CollectorError(
                    f"HostCollector: host record missing required field {e}; "
                    f"target={target}, record={h!r}"
                ) from e

            self.twin.conn.execute("BEGIN TRANSACTION")
            try:
                self.twin.conn.execute(
                    """INSERT INTO nodes (id, type, name, attrs, last_seen_at)
                       VALUES (?, 'host', ?, ?, ?)
                       ON CONFLICT (id) DO UPDATE SET
                           name = excluded.name,
                           attrs = excluded.attrs,
                           last_seen_at = excluded.last_seen_at""",
                    [node_id, node_name, json.dumps(h), now],
                )
                self.twin.write_node_state(snapshot_id, node_id, h)
                self.twin.conn.execute("COMMIT")
            except Exception:
                self.twin.conn.execute("ROLLBACK")
                raise
        return len(hosts)
