"""Compliance check runner.

Iterates baseline rules, executes each rule's check against the Twin,
and persists violations.
"""
import json
import uuid

from vmware_harden.baselines.model import Baseline, QueryCheck
from vmware_harden.checks.evaluability import classify
from vmware_harden.checks.nodescope import (
    load_snapshot_nodes,
    missing_attributes,
    scope_for_rule,
    unmeasured_node_ids,
)
from vmware_harden.checks.query import execute_query_check
from vmware_harden.store.twin import Twin


class CheckRunner:
    """Run a Baseline against a Twin snapshot, producing violations."""

    def __init__(self, twin: Twin):
        self.twin = twin

    def run_baseline(self, snapshot_id: str, baseline: Baseline) -> list[dict]:
        """Run all rules; return list of violation dicts; persist to violation table."""
        violations: list[dict] = []
        # Rule SQL runs verbatim against the cumulative `nodes` table, which
        # holds every target ever scanned plus decommissioned nodes. Scope
        # matches to nodes actually observed in THIS snapshot (node_state
        # rows), so violations are never attributed across targets/scans.
        snapshot_node_ids: set[str] = {
            r[0]
            for r in self.twin.conn.execute(
                "SELECT node_id FROM node_state WHERE snapshot_id = ?",
                [snapshot_id],
            ).fetchall()
        }
        # Absence-check rules (e.g. "default-deny firewall missing") emit a
        # SYNTHETIC CONSTANT id via `SELECT '<rule-id>' AS id ... WHERE NOT
        # EXISTS(...)`. That literal is never a scanned node, so a plain
        # set-membership filter would drop the most severe estate-wide gaps.
        # Only drop a row when its node_id is a REAL node (exists in the
        # cumulative `nodes` table) belonging to a DIFFERENT snapshot.
        # Synthetic literals are absent from `nodes` and therefore survive.
        #
        # NOTE (growth): this materializes every node id ever scanned into a
        # Python set, so it grows with estate history, not with the current
        # scan. It is intentionally left as-is: correctness of the
        # synthetic-vs-real distinction (and thus the decommission/estate-gap
        # detection) depends on membership against the FULL cumulative `nodes`
        # table. Do not narrow this to the current snapshot without preserving
        # that distinction. If it ever becomes a memory concern, replace the
        # set with a per-candidate `SELECT 1 FROM nodes WHERE id = ?` existence
        # check (indexed PK) rather than dropping the full-table scope.
        real_node_ids: set[str] = {
            r[0] for r in self.twin.conn.execute("SELECT id FROM nodes").fetchall()
        }
        # Node attributes for this snapshot, keyed by node type. Loaded once and
        # shared by every rule's per-node gap analysis below.
        nodes_by_type = load_snapshot_nodes(self.twin, snapshot_id)
        # Nodes whose collector said the record is not a measurement (an ESXi
        # host vCenter cannot reach, whose configuration it answers from cache).
        # A rule must not raise a finding against one of them, in either
        # direction: the stale values are not observations, and their absence is
        # not a configuration. Both mistakes were live at once against a VCF 9.1
        # estate on 2026-08-30 — 8 HIGH violations off cached settings, plus a
        # "no remote syslog" violation for a host whose syslog setting simply
        # was not there to read.
        unmeasured = unmeasured_node_ids(nodes_by_type)
        attrs_by_node = {
            node_id: attrs
            for nodes in nodes_by_type.values()
            for node_id, attrs in nodes
        }
        insert_rows: list[list] = []
        outcome_rows: list[list] = []
        gap_rows: list[list] = []
        for rule in baseline.rules:
            if isinstance(rule.check, QueryCheck):
                # Refuse before executing. A rule reading an uncollected key
                # matches zero rows, and zero rows here would be reported as
                # "no violations" — asserting compliance the scan never
                # established. Recorded as undetermined instead.
                verdict = classify(rule)
                if not verdict.evaluable:
                    outcome_rows.append(
                        [
                            str(uuid.uuid4()), snapshot_id, baseline.id, rule.id,
                            "undetermined", verdict.reason or None, None, None,
                        ]
                    )
                    continue
                rows = execute_query_check(self.twin, rule.check)
                rule_violating_nodes: set[str] = set()
                for row in rows:
                    node_id = row.get("id") or row.get("node_id")
                    if node_id is None:
                        continue
                    if node_id not in snapshot_node_ids and node_id in real_node_ids:
                        continue
                    # An unmeasured node can still be judged — but only by a
                    # rule every one of whose attributes it actually carries.
                    # "This host is not responding" is a real finding about a
                    # host nobody measured; "this host has no remote syslog" is
                    # not. The distinction is which values the rule read, so it
                    # is drawn from those rather than from the node type.
                    if node_id in unmeasured and missing_attributes(
                        attrs_by_node.get(node_id, {}), set(verdict.attributes)
                    ):
                        continue
                    # Carry rule metadata in evidence so consumers (web
                    # dashboard category chart) don't need a rule lookup.
                    evidence = {**row, "category": rule.category, "title": rule.title}
                    v = {
                        "id": str(uuid.uuid4()),
                        "snapshot_id": snapshot_id,
                        "baseline_id": baseline.id,
                        "rule_id": rule.id,
                        "node_id": node_id,
                        "severity": rule.severity,
                        "evidence": evidence,
                    }
                    violations.append(v)
                    rule_violating_nodes.add(node_id)
                    insert_rows.append(
                        [
                            v["id"], snapshot_id, baseline.id, rule.id,
                            node_id, rule.severity, json.dumps(evidence, default=str),
                        ]
                    )

                # The rule could judge in principle. Now record which nodes it
                # judged in fact — an ACTIVE attribute can still arrive empty on
                # a given host, and there the rule's silence means "unknown",
                # not "compliant".
                scope = scope_for_rule(
                    nodes_by_type.get(verdict.node_type, []),
                    set(verdict.attributes),
                    rule_violating_nodes,
                )
                outcome_rows.append(
                    [
                        str(uuid.uuid4()), snapshot_id, baseline.id, rule.id,
                        "evaluated", None, scope.in_scope, scope.undetermined,
                    ]
                )
                for node_id, missing in scope.gaps:
                    gap_rows.append(
                        [
                            str(uuid.uuid4()), snapshot_id, baseline.id, rule.id,
                            node_id, ", ".join(missing),
                        ]
                    )
            # ScriptCheck and any unknown check types are silently skipped
            # (loader gates against ScriptCheck; this is defensive).

        # Persist violations and per-rule outcomes in one transaction +
        # executemany rather than row-by-row (a full baseline can fire hundreds
        # of rules). Both go in the same transaction: a scan that recorded
        # violations but lost its outcome rows would look fully evaluated, which
        # is the failure this whole mechanism exists to prevent.
        if insert_rows or outcome_rows or gap_rows:
            self.twin.conn.execute("BEGIN TRANSACTION")
            try:
                # Outcomes are replaced, not appended. Violations may duplicate
                # on a re-run (pinned MVP behaviour — the list just grows), but
                # coverage is a denominator: a second run of the same baseline
                # against the same snapshot would report "32 of 40 rules could
                # not be evaluated" off a doubled tally, which is a fabricated
                # ratio rather than a longer list. Gaps are a tally on the same
                # footing, so they are replaced too.
                self.twin.conn.execute(
                    "DELETE FROM rule_outcome WHERE snapshot_id = ? AND baseline_id = ?",
                    [snapshot_id, baseline.id],
                )
                self.twin.conn.execute(
                    "DELETE FROM rule_node_gap WHERE snapshot_id = ? AND baseline_id = ?",
                    [snapshot_id, baseline.id],
                )
                if insert_rows:
                    self.twin.conn.executemany(
                        """INSERT INTO violation
                           (id, snapshot_id, baseline_id, rule_id, node_id,
                            severity, evidence)
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        insert_rows,
                    )
                if outcome_rows:
                    self.twin.conn.executemany(
                        """INSERT INTO rule_outcome
                           (id, snapshot_id, baseline_id, rule_id, outcome,
                            reason, nodes_in_scope, nodes_undetermined)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                        outcome_rows,
                    )
                if gap_rows:
                    self.twin.conn.executemany(
                        """INSERT INTO rule_node_gap
                           (id, snapshot_id, baseline_id, rule_id, node_id,
                            missing_attributes)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        gap_rows,
                    )
                self.twin.conn.execute("COMMIT")
            except Exception:
                self.twin.conn.execute("ROLLBACK")
                raise
        return violations
