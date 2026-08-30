"""How much of a baseline a scan actually judged.

A violation count alone cannot answer "is this estate compliant?" — it only says
what the rules that ran found. When most rules could not run, "0 violations" and
"compliant" are different claims, and reporting the first as the second is how a
scan certifies an estate it never inspected.

Every surface that shows violations (CLI scan, report, web dashboard, MCP tools)
reads coverage from here rather than counting rows itself, so they cannot drift
into disagreeing about the same snapshot.
"""

from dataclasses import dataclass, field

import duckdb


@dataclass(frozen=True)
class Coverage:
    """Per-snapshot tally of which rules were able to judge."""

    evaluated: int = 0
    undetermined: int = 0
    #: ``(rule_id, reason)`` for rules that were not run, in stable id order —
    #: there is no severity here, because a rule that did not run has no finding
    #: to rank. Capped; see :attr:`undetermined_rules_truncated`.
    undetermined_rules: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    #: True when :attr:`undetermined_rules` is a page rather than the whole list.
    #:
    #: The count in :attr:`undetermined` is always complete, so the summary line
    #: stays honest either way — but a reader shown "16 of 20 could not be
    #: evaluated" beside a list of one would reasonably conclude the other
    #: fifteen were fine. Reachable by scanning one snapshot against several
    #: baselines.
    undetermined_rules_truncated: bool = False

    # --- the node dimension ------------------------------------------------
    # A rule can clear the vocabulary check and still judge nothing about a
    # particular host, because the value it reads arrived empty there. The
    # counts below are (rule, node) judgements, not nodes: one host missing one
    # attribute that four rules read is four judgements not made.

    #: (rule, node) pairs where the rule reached a verdict.
    node_checks_evaluated: int = 0
    #: (rule, node) pairs where the data the rule reads was missing on the node.
    node_checks_undetermined: int = 0
    #: ``(rule_id, node_id, missing_attributes)`` for those pairs, capped.
    undetermined_node_checks: tuple[tuple[str, str, str], ...] = field(
        default_factory=tuple
    )
    #: True when :attr:`undetermined_node_checks` is a page rather than the lot.
    undetermined_node_checks_truncated: bool = False
    #: Distinct nodes appearing in the gaps — the "how many hosts" figure, which
    #: is what a reader wants and what the judgement counts above are not.
    nodes_affected: int = 0
    #: Rules that ran, found no violation, and had no node of their type to look
    #: at. Their "0 violations" is vacuous: the most complete form of the same
    #: missing-data problem, usually a collector that returned nothing.
    rules_without_targets: tuple[str, ...] = field(default_factory=tuple)
    #: False for snapshots scanned before per-node outcomes were recorded — a
    #: 1.9.0 database, where no gaps found means none were ever looked for.
    node_tracked: bool = False
    #: ``(node_id, why)`` for nodes whose collector said nothing in the record
    #: was read off the thing itself. They account for a run of gap lines that
    #: otherwise look like eight unrelated problems, so they are reported once,
    #: ahead of those lines, with the single reason behind all of them.
    unmeasured_nodes: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    @property
    def total(self) -> int:
        return self.evaluated + self.undetermined

    @property
    def node_checks_total(self) -> int:
        return self.node_checks_evaluated + self.node_checks_undetermined

    @property
    def tracked(self) -> bool:
        """False for snapshots taken before outcomes were recorded."""
        return self.total > 0

    @property
    def complete(self) -> bool:
        """True only when the scan judged every rule, on every node it covers.

        Requires ``tracked``. Without outcome rows there is nothing to conclude,
        and returning True there would announce full coverage for a scan that
        never measured any — the original false-compliance claim, one release
        later and harder to spot.

        The node clauses are part of the same guarantee, not an extra: a scan
        where every rule ran but four hosts had no readable data is not one that
        checked the estate, and this property is what every surface consults
        before it prints a bare "No violations."

        ``node_tracked`` is required rather than assumed. Without it the node
        counts are zero because nothing was measured, not because nothing was
        missing, and treating that as full coverage would make an unavailable
        measurement read as a clean one — which is the whole failure this class
        exists to prevent, arriving through the back door.
        """
        return (
            self.tracked
            and self.undetermined == 0
            and self.node_tracked
            and self.node_checks_undetermined == 0
            and not self.rules_without_targets
        )

    def summary_line(self) -> str:
        """A short paragraph for a human, empty when there is nothing to warn about.

        Deliberately empty when coverage is complete: a banner on every clean
        scan trains people to skip it, and then it goes unread on the scan that
        matters.
        """
        if not self.tracked:
            return (
                "This snapshot predates coverage tracking — how many of its "
                "rules could actually be evaluated is unknown. Re-scan to find out."
            )
        parts: list[str] = []
        if not self.node_tracked:
            parts.append(
                "This snapshot records which rules could be evaluated but not "
                "which nodes each rule could judge — it was scanned by a "
                "release before that was measured. Re-scan to find out."
            )
        if self.undetermined:
            parts.append(
                f"{self.undetermined} of {self.total} rules could not be "
                f"evaluated — no collector provides the data they check, so "
                f"their result is unknown, not compliant."
            )
        if self.rules_without_targets:
            parts.append(
                f"{len(self.rules_without_targets)} rule(s) ran but found no "
                f"node of the type they check, so they judged nothing: "
                f"{', '.join(self.rules_without_targets)}."
            )
        if self.unmeasured_nodes:
            parts.append(
                f"{len(self.unmeasured_nodes)} node(s) supplied no measurement "
                f"at all — nothing about them was read off the thing itself, so "
                f"no rule judged them in either direction: "
                f"{', '.join(f'{n} ({why})' for n, why in self.unmeasured_nodes)}."
            )
        if self.node_checks_undetermined:
            parts.append(
                f"{self.node_checks_undetermined} of {self.node_checks_total} "
                f"per-node checks could not be made across "
                f"{self.nodes_affected} node(s): the rules ran, but the values "
                f"they read were missing on those nodes, so those nodes are "
                f"unknown rather than compliant."
            )
        return " ".join(parts)

    def as_dict(self) -> dict:
        return {
            "evaluated": self.evaluated,
            "undetermined": self.undetermined,
            "total": self.total,
            "tracked": self.tracked,
            "complete": self.complete,
            "undetermined_rules": [
                {"rule": rule_id, "reason": reason}
                for rule_id, reason in self.undetermined_rules
            ],
            "undetermined_rules_truncated": self.undetermined_rules_truncated,
            "node_checks_evaluated": self.node_checks_evaluated,
            "node_checks_undetermined": self.node_checks_undetermined,
            "node_checks_total": self.node_checks_total,
            "nodes_affected": self.nodes_affected,
            "node_tracked": self.node_tracked,
            "undetermined_node_checks": [
                {"rule": rule_id, "node": node_id, "missing": missing}
                for rule_id, node_id, missing in self.undetermined_node_checks
            ],
            "undetermined_node_checks_truncated": (
                self.undetermined_node_checks_truncated
            ),
            "rules_without_targets": list(self.rules_without_targets),
            "unmeasured_nodes": [
                {"node": node_id, "why": why} for node_id, why in self.unmeasured_nodes
            ],
        }


def coverage_for(twin, snapshot_id: str, *, rule_limit: int = 100) -> Coverage:
    """Tally rule outcomes for one snapshot.

    Returns an empty :class:`Coverage` for snapshots taken before outcomes were
    recorded. That is reported as ``total == 0`` rather than as full coverage —
    an older scan genuinely does not know how much it judged, and claiming it was
    complete would put the original false-compliance claim back, one release
    later and harder to see.
    """
    try:
        counts = dict(
            twin.conn.execute(
                "SELECT outcome, COUNT(*) FROM rule_outcome WHERE snapshot_id = ? "
                "GROUP BY outcome",
                [snapshot_id],
            ).fetchall()
        )
        rules = twin.conn.execute(
            "SELECT rule_id, reason FROM rule_outcome "
            "WHERE snapshot_id = ? AND outcome = 'undetermined' "
            "ORDER BY rule_id LIMIT ?",
            # One extra row is the cheapest way to know the list was cut without
            # a second COUNT — the surplus is dropped below.
            [snapshot_id, rule_limit + 1],
        ).fetchall()
    except duckdb.CatalogException:
        # The table does not exist: a database created before 1.9.0, opened
        # read-only. `Twin.open_readonly` skips schema init because DDL is a
        # write, so the web dashboard cannot self-heal the way the CLI does —
        # and every page that shows violations would 500 on a user's existing
        # database the moment they upgrade, before they run a new scan.
        #
        # A missing table is exactly what `tracked=False` describes: coverage
        # was never measured. Returning that is both accurate and the same
        # answer the CLI gives for such a snapshot.
        return Coverage()
    truncated = len(rules) > rule_limit
    node = _node_coverage(twin, snapshot_id, rule_limit=rule_limit)
    return Coverage(
        evaluated=counts.get("evaluated", 0),
        undetermined=counts.get("undetermined", 0),
        undetermined_rules=tuple((r[0], r[1] or "") for r in rules[:rule_limit]),
        undetermined_rules_truncated=truncated,
        **node,
    )


def _node_coverage(twin, snapshot_id: str, *, rule_limit: int) -> dict:
    """The per-node half of a snapshot's coverage.

    Separate query and separate failure handling from the rule-level tally
    because the two can be present independently: a database written by 1.9.0
    has rule outcomes but no node columns and no gap table, and a read-only
    consumer (the web dashboard) cannot migrate it. Losing the rule-level
    coverage because the node half is unavailable would trade one honest answer
    for none.
    """
    empty = {"node_tracked": False}
    try:
        row = twin.conn.execute(
            "SELECT SUM(nodes_in_scope), SUM(nodes_undetermined), "
            "       COUNT(nodes_in_scope) "
            "FROM rule_outcome WHERE snapshot_id = ? AND outcome = 'evaluated'",
            [snapshot_id],
        ).fetchone()
        # A rule that ran, matched nothing, and had nothing of its type to look
        # at asserted compliance over an empty set. `NOT EXISTS` rather than a
        # join: an absence check ("no host has X") legitimately fires on an
        # estate with zero hosts, and it has judged something.
        vacuous = twin.conn.execute(
            "SELECT rule_id FROM rule_outcome o "
            "WHERE o.snapshot_id = ? AND o.outcome = 'evaluated' "
            "  AND o.nodes_in_scope = 0 "
            "  AND NOT EXISTS (SELECT 1 FROM violation v "
            "                  WHERE v.snapshot_id = o.snapshot_id "
            "                    AND v.rule_id = o.rule_id) "
            "ORDER BY rule_id",
            [snapshot_id],
        ).fetchall()
        gaps = twin.conn.execute(
            "SELECT rule_id, node_id, missing_attributes FROM rule_node_gap "
            "WHERE snapshot_id = ? ORDER BY node_id, rule_id LIMIT ?",
            [snapshot_id, rule_limit + 1],
        ).fetchall()
        affected = twin.conn.execute(
            "SELECT COUNT(DISTINCT node_id) FROM rule_node_gap "
            "WHERE snapshot_id = ?",
            [snapshot_id],
        ).fetchone()
        # Nodes the collector declared unmeasured. Read from `nodes.attrs`, the
        # same copy the rules query, so the report cannot disagree with what was
        # judged. `connection_state` is the reason for the case this was built
        # for; a collector marking a node unmeasured for some other reason still
        # gets listed, just without one.
        unmeasured = twin.conn.execute(
            "SELECT n.id, json_extract_string(n.attrs, '$.connection_state') "
            "FROM nodes n JOIN node_state ns ON ns.node_id = n.id "
            "WHERE ns.snapshot_id = ? "
            "  AND json_extract_string(n.attrs, '$.measured') = 'false' "
            "ORDER BY n.id",
            [snapshot_id],
        ).fetchall()
    except (duckdb.CatalogException, duckdb.BinderException):
        # CatalogException: the gap table is absent. BinderException: the table
        # is there but `rule_outcome` predates the node columns. Both mean the
        # same thing — this snapshot was never measured per node — and both are
        # reachable on a read-only 1.9.0 database that the reader cannot migrate.
        return empty

    in_scope, undetermined, measured = (row or (None, None, 0))
    if not measured:
        # Rows exist but every `nodes_in_scope` is NULL: outcomes written by
        # 1.9.0, which recorded no node dimension. Reporting 0 gaps here would
        # state that nothing was missing, when in truth nothing was checked.
        return empty
    undetermined = int(undetermined or 0)
    truncated = len(gaps) > rule_limit
    return {
        "node_tracked": True,
        "node_checks_evaluated": int(in_scope or 0) - undetermined,
        "node_checks_undetermined": undetermined,
        "undetermined_node_checks": tuple(
            (g[0], g[1], g[2] or "") for g in gaps[:rule_limit]
        ),
        "undetermined_node_checks_truncated": truncated,
        "nodes_affected": int(affected[0]) if affected else 0,
        "rules_without_targets": tuple(r[0] for r in vacuous),
        "unmeasured_nodes": tuple(
            (u[0], f"connection_state={u[1]}" if u[1] else "reason not recorded")
            for u in unmeasured
        ),
    }
