"""Snapshot diff engine.

Compares two snapshots in the same Twin and emits ChangeEvents:
- inventory drift (nodes added/removed)
- config drift (same node, different state — field-level diff)

Pure compute by default; opt-in persistence via persist=True (Task 13).
"""
import json
import uuid
from dataclasses import dataclass
from typing import Any, Literal

from vmware_harden.store.twin import Twin

ChangeKind = Literal["inventory", "config"]


@dataclass(frozen=True)
class ChangeEvent:
    """A single detected change between two snapshots."""

    kind: ChangeKind
    node_id: str
    field: str  # "_added" / "_removed" for inventory; attr name for config
    old_value: str | None  # str-encoded for storage; None means "didn't exist"
    new_value: str | None


def _load_states(twin: Twin, snapshot_id: str) -> dict[str, dict]:
    """Return {node_id: state_dict} for all rows in node_state for that snapshot."""
    rows = twin.conn.execute(
        "SELECT node_id, state_json FROM node_state WHERE snapshot_id = ?",
        [snapshot_id],
    ).fetchall()
    return {r[0]: json.loads(r[1]) for r in rows}


def _stringify(v: Any) -> str:
    """Stable string repr for storage in change_event.old/new_value."""
    return str(v)


def _dict_field_diff(
    node_id: str, old: dict, new: dict
) -> list[ChangeEvent]:
    """Field-level diff. Each differing key emits one config ChangeEvent."""
    events: list[ChangeEvent] = []
    keys = set(old.keys()) | set(new.keys())
    for key in sorted(keys):
        if key not in old:
            events.append(
                ChangeEvent(
                    kind="config",
                    node_id=node_id,
                    field=key,
                    old_value=None,
                    new_value=_stringify(new[key]),
                )
            )
        elif key not in new:
            events.append(
                ChangeEvent(
                    kind="config",
                    node_id=node_id,
                    field=key,
                    old_value=_stringify(old[key]),
                    new_value=None,
                )
            )
        elif old[key] != new[key]:
            events.append(
                ChangeEvent(
                    kind="config",
                    node_id=node_id,
                    field=key,
                    old_value=_stringify(old[key]),
                    new_value=_stringify(new[key]),
                )
            )
    return events


def _compute_events(twin: Twin, snap_a: str, snap_b: str) -> list[ChangeEvent]:
    """Pure diff between two snapshots; no persistence."""
    states_a = _load_states(twin, snap_a)
    states_b = _load_states(twin, snap_b)

    events: list[ChangeEvent] = []
    all_nodes = set(states_a) | set(states_b)
    for node_id in sorted(all_nodes):
        if node_id not in states_a:
            events.append(
                ChangeEvent(
                    kind="inventory",
                    node_id=node_id,
                    field="_added",
                    old_value=None,
                    new_value=json.dumps(states_b[node_id], sort_keys=True),
                )
            )
        elif node_id not in states_b:
            events.append(
                ChangeEvent(
                    kind="inventory",
                    node_id=node_id,
                    field="_removed",
                    old_value=json.dumps(states_a[node_id], sort_keys=True),
                    new_value=None,
                )
            )
        else:
            events.extend(
                _dict_field_diff(node_id, states_a[node_id], states_b[node_id])
            )
    return events


def _persist_events(twin: Twin, snap_b: str, events: list[ChangeEvent]) -> None:
    """Write events to change_event idempotently for snap_b.

    Uses DELETE + INSERT in a single transaction: clear any prior rows for
    snap_b first, then insert all current events. Diff is deterministic for
    a fixed (snap_a, snap_b) pair, so this is correct and simpler than
    per-row UPSERT.
    """
    twin.conn.execute("BEGIN TRANSACTION")
    try:
        twin.conn.execute(
            "DELETE FROM change_event WHERE snapshot_id = ?", [snap_b]
        )
        if events:
            twin.conn.executemany(
                """INSERT INTO change_event
                   (id, snapshot_id, node_id, field, old_value, new_value)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                [
                    [
                        str(uuid.uuid4()),
                        snap_b,
                        e.node_id,
                        e.field,
                        e.old_value,
                        e.new_value,
                    ]
                    for e in events
                ],
            )
        twin.conn.execute("COMMIT")
    except Exception:
        twin.conn.execute("ROLLBACK")
        raise


def diff_snapshots(
    twin: Twin, snap_a: str, snap_b: str, persist: bool = False
) -> list[ChangeEvent]:
    """Diff two snapshots; return list of ChangeEvents (sorted by node_id, field).

    If ``persist=True``, idempotently write events to the ``change_event``
    table keyed on snap_b (re-runs replace prior rows for that snapshot).
    """
    events = _compute_events(twin, snap_a, snap_b)
    if persist:
        _persist_events(twin, snap_b, events)
    return events
