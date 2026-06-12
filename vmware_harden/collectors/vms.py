"""VM inventory collector. Pulls VM data via vmware_aiops."""
import json
from datetime import datetime, timezone

from vmware_harden.collectors.base import Collector, CollectorError


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
        # DuckDB rejects CURRENT_TIMESTAMP in ON CONFLICT SET (BinderException);
        # bind `now` once and reference via excluded.* — see schema.py note.
        now = datetime.now(timezone.utc)
        node_rows: list[list] = []
        state_rows: list[tuple[str, dict]] = []
        for v in vms:
            try:
                moref = v["id"]
                node_name = v["name"]
            except KeyError as e:
                raise CollectorError(
                    f"VMCollector: VM record missing required field {e}; "
                    f"target={target}, record={v!r}"
                ) from e
            # Namespace by target so identical MoRefs from different vCenters
            # don't collide in a multi-target Twin.
            node_id = f"{target}:{moref}"
            node_rows.append([node_id, target, node_name, json.dumps(v), now])
            state_rows.append((node_id, v))

        # One transaction + executemany for the whole batch: a large inventory
        # used to issue one commit per node (thousands of fsyncs).
        self.twin.conn.execute("BEGIN TRANSACTION")
        try:
            if node_rows:
                self.twin.conn.executemany(
                    """INSERT INTO nodes (id, type, target, name, attrs, last_seen_at)
                       VALUES (?, 'vm', ?, ?, ?, ?)
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
        return len(vms)
