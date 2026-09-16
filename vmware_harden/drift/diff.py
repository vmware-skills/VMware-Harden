"""Snapshot diff engine.

Compares two snapshots in the same Twin and emits ChangeEvents:
- inventory drift (nodes added/removed)
- config drift (same node, different state — field-level diff)

Pure compute by default; opt-in persistence via persist=True (Task 13).
"""
import json
import uuid
from collections.abc import Callable
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


@dataclass(frozen=True)
class DiffScope:
    """Which node types two snapshots can be compared over, and which they cannot."""

    compared: tuple[str, ...]
    not_compared: tuple[str, ...]
    note: str | None


def _types_present(twin: Twin, snapshot_id: str) -> set[str]:
    """Node types this snapshot actually holds rows for."""
    return set(_node_types_of(twin, snapshot_id).values())


def _collected_types(twin: Twin, snapshot_id: str) -> set[str]:
    """Types the scan set out to collect; the types it holds when that is unknown.

    The recorded list is preferred because it includes a type the scan collected
    and found empty — a baseline that covers VMs and finds none must still be
    able to report a VM that later disappears. Falling back to the rows is for
    snapshots taken before the column existed.
    """
    try:
        covered, _ = twin.collection_record(snapshot_id)
    except Exception:  # noqa: BLE001 — a pre-column database is read-only-safe
        covered = None
    # `covered is not None`, not `if covered`: an empty list is a recorded fact
    # ("this scan collected nothing"), and collapsing it into the unknown case
    # turns that fact back into a guess about the rows it happens to hold.
    return set(covered) if covered is not None else _types_present(twin, snapshot_id)


def _zero_row_types(twin: Twin, snapshot_id: str) -> set[str]:
    """Types this scan collected and got zero rows back for.

    An empty answer from a collector is not a measurement of an empty estate: a
    permission-filtered read looks identical.

    Neither direction is concluded for such a type: a deletion would rest on a
    read that measured nothing, and so would an addition — "new" requires a
    reliable earlier read showing the node absent. An attempt to keep additions
    live was reverted for exactly that reason.

    A snapshot with no recorded counts (written before the column) yields the
    empty set: unknown, and unknown must not silence a real deletion.
    """
    counts = twin.collected_counts(snapshot_id)
    if not counts:
        return set()
    covered, _ = twin.collection_record(snapshot_id)
    return {t for t in (covered or ()) if counts.get(t, None) == 0}


def _classify_no_base(
    *, saw_type: bool, zero_only: bool, this_scan_empty: bool, window_exhausted: bool
) -> str | None:
    """Why a type has no base, as one decision with one precedence.

    Four rounds of patching this classification inline produced, each time, a
    label that was false in some combination — a type this scan also read zero
    rows for announced as "the first read with rows", and a type no scan ever
    collected announced as "the window ran out". The precedence lives here, in
    one place, and is asserted as a table.

    Returns None when no label belongs: the type is already reported as
    ``unconcluded``, which says everything there is to say.
    """
    if this_scan_empty:
        # This scan read 0 rows of the type, so it concludes nothing about the
        # estate in either direction — no matter what the window holds.
        # `unconcluded` already says that, and every other label would add a
        # claim on top of it: "first scan to collect" was reported for a type
        # the same scan recorded collecting, and "no base in window" for a type
        # a base could not have helped (each label appearing alongside
        # `unconcluded` also put one type in two buckets — review 7,
        # 2026-09-16).
        return None
    if window_exhausted:
        # Scans were left unread, so nothing stronger can be said — not "first
        # collection" (an unread scan may contradict it) and not "every earlier
        # read was empty" either, which is what `first_real_read` asserts. This
        # branch ranked BELOW that one until a review reproduced the sentence
        # "the earlier scans … returned 0 rows" about a scan that had returned
        # two, with a real deletion lost behind it. Among types this scan
        # actually read, exhaustion outranks everything: it is the one thing
        # actually known.
        return "no_base_in_window"
    if saw_type and zero_only:
        # The whole window was read and every read of this type was empty, so
        # this is the first read with anything in it — not the first collection.
        return "first_real_read"
    # Every prior scan was read and none collected it: first collection, known.
    return "first_seen"


#: How far back to look for a scan that collected a given node type. Bounded
#: because the search reads each candidate, and unbounded history on a busy
#: estate would make every scan pay for every scan before it. Reaching the bound
#: without a base is reported as itself — `no_base_in_window`, which claims
#: nothing about the estate. Every label that does make such a claim ("first
#: scan to collect", "every earlier read was empty") is reserved for a window
#: that was read to the end; each was shipped here once and each was false in
#: some case (independent reviews, 2026-09-16).
_BASE_SEARCH_LIMIT = 100


def _base_for_type(
    twin: Twin,
    snapshot_id: str,
    node_type: str,
    *,
    covered_of: Callable[[str], set[str]],
    counts_of: Callable[[str], dict],
    candidates: list[str] | None = None,
    window_exhausted: bool = False,
) -> tuple[str | None, str | None]:
    """Return ``(base_snapshot_id, None)``, or ``(None, reason)``.

    ``reason`` comes from :func:`_classify_no_base` and is itself None when no
    label belongs — the type is already reported as ``unconcluded``.

    A scan that collected the type but got **zero rows** is skipped and the walk
    continues. Neither direction can be concluded from a read that measured
    nothing:

    * a deletion basing on it is how a node deleted between the last real read
      and now escapes both scans — the hole this file exists to close, re-opened
      one release later and silent instead of noisy;
    * and an addition basing on it says "new" about a node that was there all
      along, which is how the surviving VM got reported as added.

    Both were found by independent review on 2026-09-16, the second one after I
    tried to treat the directions differently.
    """
    row = twin.snapshot_row(snapshot_id)
    if row is None:
        # No such snapshot: nothing is known about it, so no label — "first
        # collection" would be a claim about an estate this code never saw.
        return None, None
    saw_type = False
    if candidates is None:
        candidates = twin.completed_snapshots_before(
            row["target"],
            row["scan_started_at"],
            limit=_BASE_SEARCH_LIMIT,
            exclude_id=snapshot_id,
        )
    zero_row_only = False
    for candidate in candidates:
        if node_type not in covered_of(candidate):
            continue
        saw_type = True
        if counts_of(candidate).get(node_type, None) == 0:
            # Collected, answered nothing. Not a measurement either direction can
            # be concluded from, so keep walking for one that is — but remember
            # that the type WAS collected, or the caller reports a first
            # collection for a type the earlier snapshot records collecting.
            zero_row_only = True
            continue
        return candidate, None
    return None, _classify_no_base(
        saw_type=saw_type,
        zero_only=zero_row_only,
        # Always False here: a type this scan read zero rows for is skipped by
        # the caller before any base is searched for — `unconcluded` is its
        # whole story and no label belongs (see `diff_since_prior`).
        this_scan_empty=False,
        # Only the walk knows whether this type was ever seen; a global "the
        # page was truncated" blamed the window for types nobody collected.
        # Passed through unmodified. Suppressing it when the type had been seen
        # (`and not saw_type`) is what hid the exhaustion from the classifier
        # and produced the false "every earlier read was empty" — the guard
        # caused the blocker it claimed to prevent (review, 2026-09-16).
        window_exhausted=window_exhausted,
    )


@dataclass(frozen=True)
class DriftScope:
    """What a scan's drift compared, against what, and what it could not conclude."""

    #: ``(node_type, base_snapshot_id)`` — the scan each type was compared against.
    compared: tuple[tuple[str, str], ...] = ()
    #: Types an earlier scan collected and this one did not: nobody looked.
    not_compared: tuple[str, ...] = ()
    #: Types this scan collected but got zero rows for: nothing concluded in
    #: either direction, and no comparison was made.
    unconcluded: tuple[str, ...] = ()
    #: Types no earlier scan of this target ever collected.
    first_seen: tuple[str, ...] = ()
    #: Types an earlier scan collected but only ever with zero rows: this is the
    #: first read with anything in it, which is not the first collection.
    first_real_read: tuple[str, ...] = ()
    #: Types whose last real read is further back than the search window: a
    #: statement about the search, not about the estate.
    no_base_in_window: tuple[str, ...] = ()
    #: How many prior snapshots this diff actually looked at.
    searched: int = 0

    @property
    def note(self) -> str | None:
        parts = []
        if self.not_compared:
            parts.append(
                f"Not compared: {', '.join(self.not_compared)} — this scan did not "
                f"collect them, so whether those nodes changed, or are still there, "
                f"is unknown."
            )
        if self.unconcluded:
            parts.append(
                f"Collected but 0 rows returned: {', '.join(self.unconcluded)} — an "
                f"empty answer is not proof of an empty estate, so removals of those "
                f"were not concluded."
            )
        if self.first_real_read:
            parts.append(
                f"First read with rows for: {', '.join(self.first_real_read)} — the "
                f"earlier scans collected them and returned 0 rows, so there is "
                f"nothing to compare against and no change is claimed."
            )
        if self.no_base_in_window:
            parts.append(
                f"No base found for {', '.join(self.no_base_in_window)} in the "
                f"{self.searched} prior scans searched of this target (limit "
                f"{_BASE_SEARCH_LIMIT}), and older scans were not read — so whether "
                f"they were never collected or last collected further back cannot be "
                f"told from here."
            )
        if self.first_seen:
            parts.append(f"First scan to collect: {', '.join(self.first_seen)}.")
        return " ".join(parts) or None

    def as_dict(self) -> dict:
        return {
            "compared": [{"node_type": t, "base_snapshot_id": b} for t, b in self.compared],
            "not_compared": list(self.not_compared),
            "unconcluded": list(self.unconcluded),
            "first_seen": list(self.first_seen),
            "first_real_read": list(self.first_real_read),
            "no_base_in_window": list(self.no_base_in_window),
            # What was searched, not the ceiling: reporting the constant made the
            # bound in the note unverifiable (independent review, 2026-09-16).
            "searched_snapshots": self.searched,
            "search_limit": _BASE_SEARCH_LIMIT,
            "note": self.note,
        }


def diff_since_prior(twin: Twin, snapshot_id: str) -> tuple[list[ChangeEvent], DriftScope]:
    """Diff each node type against the most recent prior scan that collected it.

    One base snapshot for the whole diff was what made a narrower scan a hole
    deletions fell into: scan 1 collects VMs, scan 2 does not, scan 3 collects
    them again with one genuinely gone — compared only against scan 2, that
    deletion was reported by nobody, ever (independent review, 2026-09-16).
    """
    row = twin.snapshot_row(snapshot_id)
    if row is None:
        return [], DriftScope()

    # One read per snapshot per call. Without the caches this walked the
    # candidate list once for the union and again per node type — 202 queries a
    # scan, each a `nodes⋈node_state` JOIN on a pre-column database.
    covered_cache: dict[str, set[str]] = {}
    counts_cache: dict[str, dict] = {}

    def covered_of(snap: str) -> set[str]:
        if snap not in covered_cache:
            covered_cache[snap] = _collected_types(twin, snap)
        return covered_cache[snap]

    def counts_of(snap: str) -> dict:
        if snap not in counts_cache:
            counts_cache[snap] = twin.collected_counts(snap) or {}
        return counts_cache[snap]

    now_types = covered_of(snapshot_id)
    zero_rows = _zero_row_types(twin, snapshot_id)
    candidates = twin.completed_snapshots_before(
        row["target"],
        row["scan_started_at"],
        limit=_BASE_SEARCH_LIMIT,
        exclude_id=snapshot_id,
    )
    total_priors = twin.count_completed_snapshots_before(
        row["target"], row["scan_started_at"], exclude_id=snapshot_id
    )
    window_exhausted = total_priors > len(candidates)
    # Bounded by the same window that is searched for a base: a type named here
    # is one this scan skipped and a *searched* scan collected, so the claim and
    # the evidence for it have the same reach.
    ever_collected: set[str] = set()
    for candidate in candidates:
        ever_collected |= covered_of(candidate)

    states_now = _load_states(twin, snapshot_id)
    types_now = _node_types_of(twin, snapshot_id)
    events: list[ChangeEvent] = []
    compared: list[tuple[str, str]] = []
    first_seen: list[str] = []
    first_real_read: list[str] = []
    no_base_in_window: list[str] = []

    states_cache: dict[str, dict[str, dict]] = {snapshot_id: states_now}
    types_cache: dict[str, dict[str, str]] = {snapshot_id: types_now}

    def _of_type(snap: str, node_type: str) -> dict[str, dict]:
        # Cached per snapshot, not per (snapshot, type): the base's states were
        # reloaded for every node type it held.
        if snap not in states_cache:
            states_cache[snap] = _load_states(twin, snap)
            types_cache[snap] = _node_types_of(twin, snap)
        types = types_cache[snap]
        return {nid: st for nid, st in states_cache[snap].items() if types.get(nid) == node_type}

    no_base: dict[str, list[str]] = {
        "first_seen": first_seen,
        "first_real_read": first_real_read,
        "no_base_in_window": no_base_in_window,
    }
    for node_type in sorted(now_types):
        if node_type in zero_rows:
            # An empty read concludes nothing in either direction, so there is
            # no comparison to make and no base worth searching for.
            # `unconcluded` is the whole story; a `compared` entry here named a
            # comparison whose events were all silently dropped, and put the
            # type in two buckets at once (independent review, 2026-09-16).
            continue
        base, reason = _base_for_type(
            twin, snapshot_id, node_type,
            covered_of=covered_of, counts_of=counts_of, candidates=candidates,
            window_exhausted=window_exhausted,
        )
        if base is None:
            if reason is not None:
                no_base[reason].append(node_type)
            continue
        compared.append((node_type, base))
        events.extend(
            _events_between(
                _of_type(base, node_type),
                _of_type(snapshot_id, node_type),
            )
        )

    return (
        sorted(events, key=lambda e: (e.node_id, e.field)),
        DriftScope(
            compared=tuple(compared),
            not_compared=tuple(sorted(ever_collected - now_types)),
            unconcluded=tuple(sorted(zero_rows)),
            first_seen=tuple(first_seen),
            first_real_read=tuple(first_real_read),
            no_base_in_window=tuple(no_base_in_window),
            searched=len(candidates),
        ),
    )


def _node_types_of(twin: Twin, snapshot_id: str) -> dict[str, str]:
    """``{node_id: type}`` for the nodes one snapshot holds."""
    rows = twin.conn.execute(
        "SELECT n.id, n.type FROM nodes n JOIN node_state ns ON ns.node_id = n.id "
        "WHERE ns.snapshot_id = ?",
        [snapshot_id],
    ).fetchall()
    return {r[0]: r[1] for r in rows}


def _events_between(
    states_a: dict[str, dict], states_b: dict[str, dict]
) -> list[ChangeEvent]:
    """Added / removed / field-level events between two sets of node states."""
    events: list[ChangeEvent] = []
    for node_id in sorted(set(states_a) | set(states_b)):
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
            events.extend(_dict_field_diff(node_id, states_a[node_id], states_b[node_id]))
    return events


def diff_scope(twin: Twin, snap_a: str, snap_b: str) -> DiffScope:
    """The node types both snapshots collected, and the ones only one of them did.

    A type only one side collected cannot be diffed: absent rows on the other
    side mean "nobody looked", not "the nodes are gone". Reporting them as
    removals told a lab its 12 VMs had been deleted when the second scan simply
    used a baseline that collects no VMs (2026-09-15).
    """
    a, b = _collected_types(twin, snap_a), _collected_types(twin, snap_b)
    compared = tuple(sorted(a & b))
    not_compared = tuple(sorted(a ^ b))
    note = None
    if not_compared:
        note = (
            f"Not compared: {', '.join(not_compared)} — not collected by both "
            f"scans, so whether those nodes changed is unknown. Compared: "
            f"{', '.join(compared) or 'nothing'}."
        )
    return DiffScope(compared=compared, not_compared=not_compared, note=note)


def _node_type_map(twin: Twin, snap_a: str, snap_b: str) -> dict[str, str]:
    """``{node_id: type}`` for every node either snapshot holds."""
    return {**_node_types_of(twin, snap_a), **_node_types_of(twin, snap_b)}


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

    # Only types both scans collected. A node whose type one side never looked
    # at is not comparable in either direction, and calling it removed is the
    # family's "not measured read as a fact" failure in the one event an
    # operator acts on immediately.
    scope = diff_scope(twin, snap_a, snap_b)
    node_types = _node_type_map(twin, snap_a, snap_b)
    comparable = set(scope.compared)

    zero_rows = _zero_row_types(twin, snap_b)
    # The same rule the per-type walk applies: a base that read zero rows of a
    # type is no evidence that what appears now is new. Without this the two
    # engines disagreed about the same estate, and two test files asserted
    # opposite outcomes — both passing, because one drove the dead one
    # (independent review, 2026-09-16).
    zero_rows_base = _zero_row_types(twin, snap_a)
    events: list[ChangeEvent] = []
    all_nodes = {
        node_id
        for node_id in set(states_a) | set(states_b)
        if node_types.get(node_id, None) in comparable
    }
    for node_id in sorted(all_nodes):
        if node_id not in states_a:
            if node_types.get(node_id) in zero_rows_base:
                continue
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
            if node_types.get(node_id) in zero_rows:
                # The collector answered "nothing" for this type. That is not a
                # measurement that the nodes are gone.
                continue
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


def persist_events(twin: Twin, snapshot_id: str, events: list[ChangeEvent]) -> None:
    """Public wrapper: write one snapshot's drift events, replacing any prior rows."""
    _persist_events(twin, snapshot_id, events)


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
