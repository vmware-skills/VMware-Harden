"""Host inventory collector. Pulls ESXi host data via vmware_aiops."""
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
        node_rows: list[list] = []
        state_rows: list[tuple[str, dict]] = []
        for h in hosts:
            try:
                moref = h["id"]
                node_name = h["name"]
            except KeyError as e:
                raise CollectorError(
                    f"HostCollector: host record missing required field {e}; "
                    f"target={target}, record={h!r}"
                ) from e
            # Namespace by target so identical MoRefs from different vCenters
            # don't collide in a multi-target Twin.
            node_id = f"{target}:{moref}"
            node_rows.append([node_id, target, node_name, json.dumps(h), now])
            state_rows.append((node_id, h))

        # One transaction + executemany for the whole batch: a large inventory
        # used to issue one commit per node (thousands of fsyncs).
        self.twin.conn.execute("BEGIN TRANSACTION")
        try:
            if node_rows:
                self.twin.conn.executemany(
                    """INSERT INTO nodes (id, type, target, name, attrs, last_seen_at)
                       VALUES (?, 'host', ?, ?, ?, ?)
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
        return len(hosts)
