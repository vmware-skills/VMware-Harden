"""Snapshot diff engine.

Compares two snapshots in the same Twin and emits ChangeEvents:
- inventory drift (nodes added/removed)
- config drift (same node, different state — field-level diff)

Pure function — no persistence. Task 13 adds optional persistence.
"""
import json
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


def diff_snapshots(
    twin: Twin, snap_a: str, snap_b: str
) -> list[ChangeEvent]:
    """Diff two snapshots; return list of ChangeEvents (sorted by node_id, field)."""
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
