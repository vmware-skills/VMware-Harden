"""Base collector class. Concrete collectors implement collect()."""
import json
from datetime import datetime, timezone

from vmware_harden.store.twin import Twin


class Collector:
    """Abstract base for inventory collectors."""

    def __init__(self, twin: Twin):
        self.twin = twin

    def collect(self, snapshot_id: str, target: str) -> int:
        """Fetch and write inventory for the given snapshot. Returns count written."""
        raise NotImplementedError

    def _persist_groups(
        self,
        snapshot_id: str,
        target: str,
        groups: list[tuple[list[dict], str, str]],
    ) -> int:
        """Map record groups to node/state rows and batch-persist them.

        ``groups`` is a list of ``(records, node_type, label)`` tuples, letting a
        single collector emit several node types in one transaction (DFW emits
        sections + rules). ``label`` is the human-readable record kind used in
        CollectorError messages. Each record must carry ``id`` and ``name``.

        All rows land in ONE transaction + executemany — a large inventory used
        to issue one commit per node (thousands of fsyncs). Returns the total
        number of records persisted.
        """
        # DuckDB rejects CURRENT_TIMESTAMP in ON CONFLICT SET (BinderException);
        # bind `now` once and reference via excluded.* — see schema.py note.
        now = datetime.now(timezone.utc)
        node_rows: list[list] = []
        state_rows: list[tuple[str, dict]] = []
        total = 0
        for records, node_type, label in groups:
            for rec in records:
                try:
                    moref = rec["id"]
                    node_name = rec["name"]
                except KeyError as e:
                    raise CollectorError(
                        f"{type(self).__name__}: {label} record missing required "
                        f"field {e}; target={target}, record={rec!r}. Every "
                        "collected record must carry both 'id' and 'name' — a "
                        "record without them usually means the vCenter API "
                        "returned a partial object. Check the target's "
                        "connectivity and permissions with `vmware-harden "
                        f"doctor`, then re-run `vmware-harden scan --target "
                        f"{target}`."
                    ) from e
                # Namespace by target so identical MoRefs from different vCenters
                # don't collide in a multi-target Twin.
                node_id = f"{target}:{moref}"
                node_rows.append(
                    [node_id, node_type, target, node_name, json.dumps(rec), now]
                )
                state_rows.append((node_id, rec))
            total += len(records)

        self.twin.conn.execute("BEGIN TRANSACTION")
        try:
            if node_rows:
                self.twin.conn.executemany(
                    """INSERT INTO nodes (id, type, target, name, attrs, last_seen_at)
                       VALUES (?, ?, ?, ?, ?, ?)
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
        return total


class CollectorError(Exception):
    """Raised when a collector encounters malformed inventory data."""
