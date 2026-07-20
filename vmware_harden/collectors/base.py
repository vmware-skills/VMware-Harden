"""Base collector class. Concrete collectors implement collect()."""
import json
from datetime import datetime, timezone

from vmware_harden.store.twin import Twin

#: Characters of a collected record's repr that fit in a CollectorError before
#: the MCP wrapper's 500-char cap starts eating the message. The diagnosis and
#: the remedy together run ~350 characters, and a real ESXi host record reprs at
#: ~480 on its own — interpolating it unbounded pushed the remedy past the cap
#: every time, so the agent received a truncated dict dump and no next step.
_MAX_RECORD_REPR = 120


def _short_repr(value: object, limit: int = _MAX_RECORD_REPR) -> str:
    """Repr ``value``, truncated to ``limit`` with a visible marker.

    The marker matters: ``sanitize()`` truncates silently, so a cut message
    reads as a complete one. An explicit ellipsis tells the reader that the
    record continues rather than that it ended there.
    """
    text = repr(value)
    return text if len(text) <= limit else text[:limit] + "…(truncated)"


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
                    # Remedy before evidence, evidence bounded. This message
                    # reaches the agent through _safe_error's 500-char cap, and
                    # the record repr is the one part whose length this code
                    # does not control — put it last so a cut loses the
                    # expendable half.
                    raise CollectorError(
                        f"{type(self).__name__}: {label} record missing required "
                        f"field {e}. Every collected record must carry both 'id' "
                        "and 'name' — a record without them usually means the "
                        "vCenter API returned a partial object. Check the "
                        "target's connectivity and permissions with "
                        "`vmware-harden doctor`, then re-run `vmware-harden scan "
                        f"--target {target}`. Offending record: "
                        f"{_short_repr(rec)}"
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


class CollectorDependencyError(Exception):
    """Raised when a collector's package dependency is not installed.

    Separate from :class:`CollectorError`, which means "the data was wrong";
    this one means "the collector could not run at all". It lives here rather
    than at its raise site in ``cli/runner.py`` because the MCP server's
    ``_domain_errors()`` already imports this module — homing it in ``cli``
    would put typer and every collector on the error path, so a failed tool
    call could fail again while building its own error message.
    """
