"""Which nodes a rule actually judged, and which it only appeared to.

:mod:`vmware_harden.checks.evaluability` asks whether a rule *can* judge —
whether some collector writes every attribute it reads. That is a statement
about the build, and it is answered before the rule runs.

It does not answer whether the data arrived. A rule reading
``password_quality_control`` is evaluable because the host collector fetches
that advanced setting; on a host where the fetch came back empty — permission
denied, the setting absent on that ESXi build, PropertyCollector unable to read
``config.option`` — the attribute is missing on that one host, the rule's
``WHERE`` matches no row for it, and no row is what the engine reports as a
pass. That is the same false-compliance shape 1.9.0 removed at rule level,
surviving one level down at node level.

So after an evaluable rule runs, this module asks the narrower question of every
node in the rule's scope: *did the values this rule reads exist on you?* Nodes
where they did not are recorded as gaps rather than counted as compliant.

Two things are deliberately not gaps:

* **A node the rule flagged.** Its verdict is established — it is violating —
  and no missing attribute can unestablish it. Only a node the rule said
  nothing about is ambiguous, so only those are examined.
* **An empty string.** ``syslog_remote_host = ''`` is a real, collected value
  meaning "no remote syslog configured", which is exactly what several rules
  exist to catch. Treating it as absent would suppress the finding.
"""

import json
from dataclasses import dataclass

#: What ``vmware_aiops.ops.inventory.list_hosts`` returns in place of a property
#: it could not read (host unreachable, insufficient privilege). It reaches
#: ``nodes.attrs`` as this literal string, so a rule comparing against it sees a
#: value that is not the host's configuration — it is the absence of one.
#:
#: This is why the baselines use ``TRY_CAST``: ``CAST('N/A' AS BIGINT)`` raises
#: and takes the whole scan down. ``TRY_CAST`` yields NULL instead, the rule
#: matches nothing, and without this module that host quietly passes.
UNREADABLE_SENTINEL = "N/A"


@dataclass(frozen=True)
class NodeScope:
    """What one rule was able to judge across the nodes it was scoped to."""

    #: Nodes of the rule's node type present in this snapshot.
    in_scope: int = 0
    #: ``(node_id, missing_attributes)`` for the in-scope nodes the rule could
    #: not judge, in stable node order.
    gaps: tuple[tuple[str, tuple[str, ...]], ...] = ()

    @property
    def undetermined(self) -> int:
        return len(self.gaps)

    @property
    def evaluated(self) -> int:
        """Nodes this rule genuinely reached a verdict on."""
        return self.in_scope - self.undetermined


def missing_attributes(attrs: dict, cited: set[str]) -> tuple[str, ...]:
    """The cited attributes that hold no readable value on one node.

    Missing means the key is absent, its value is JSON ``null``, or it is the
    unreadable sentinel. Any other value — including ``''`` and ``0`` — is data
    the rule can judge on.
    """
    return tuple(
        attr
        for attr in sorted(cited)
        if attrs.get(attr) is None or attrs.get(attr) == UNREADABLE_SENTINEL
    )


def scope_for_rule(
    nodes: list[tuple[str, dict]],
    cited: set[str],
    judged_node_ids: set[str],
) -> NodeScope:
    """Split a rule's in-scope nodes into judged and undetermined.

    ``nodes`` is ``(node_id, attrs)`` for every node of the rule's node type in
    the snapshot; ``cited`` the attributes its SQL reads; ``judged_node_ids``
    the nodes it flagged.

    A rule citing no attributes at all — the estate-wide absence checks, which
    assert over the existence of rows rather than the contents of one — has
    nothing that can be missing per node, so it reports no gaps.
    """
    if not cited:
        return NodeScope(in_scope=len(nodes))
    gaps: list[tuple[str, tuple[str, ...]]] = []
    for node_id, attrs in nodes:
        if node_id in judged_node_ids:
            continue
        missing = missing_attributes(attrs, cited)
        if missing:
            gaps.append((node_id, missing))
    return NodeScope(in_scope=len(nodes), gaps=tuple(sorted(gaps)))


def load_snapshot_nodes(twin, snapshot_id: str) -> dict[str, list[tuple[str, dict]]]:
    """``{node_type: [(node_id, attrs), ...]}`` for nodes observed in a snapshot.

    Reads ``nodes.attrs``, not ``node_state.state_json``, because ``nodes.attrs``
    is what the rule SQL itself queries. Judging data presence against a
    different copy of it would let the two disagree, which is how a node gets
    reported as judged by a value the rule never saw.

    Loaded once per scan and shared across rules: the alternative is a query per
    rule, and a full baseline fires hundreds.
    """
    rows = twin.conn.execute(
        "SELECT n.type, n.id, n.attrs FROM nodes n "
        "JOIN node_state ns ON ns.node_id = n.id "
        "WHERE ns.snapshot_id = ?",
        [snapshot_id],
    ).fetchall()
    by_type: dict[str, list[tuple[str, dict]]] = {}
    for node_type, node_id, attrs_json in rows:
        try:
            attrs = json.loads(attrs_json) if attrs_json else {}
        except (TypeError, ValueError):
            # Unparseable attrs means every attribute is missing on this node,
            # which is the honest reading and the safe one: it becomes a gap
            # rather than a pass.
            attrs = {}
        if not isinstance(attrs, dict):
            attrs = {}
        by_type.setdefault(node_type, []).append((node_id, attrs))
    return by_type
