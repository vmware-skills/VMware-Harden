"""Compliance check runner.

Iterates baseline rules, executes each rule's check against the Twin,
and persists violations.
"""
import json
import uuid

from vmware_harden.baselines.model import Baseline, QueryCheck
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
        real_node_ids: set[str] = {
            r[0] for r in self.twin.conn.execute("SELECT id FROM nodes").fetchall()
        }
        for rule in baseline.rules:
            if isinstance(rule.check, QueryCheck):
                rows = execute_query_check(self.twin, rule.check)
                for row in rows:
                    node_id = row.get("id") or row.get("node_id")
                    if node_id is None:
                        continue
                    if node_id not in snapshot_node_ids and node_id in real_node_ids:
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
                    self.twin.conn.execute(
                        """INSERT INTO violation
                           (id, snapshot_id, baseline_id, rule_id, node_id,
                            severity, evidence)
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        [
                            v["id"], snapshot_id, baseline.id, rule.id,
                            node_id, rule.severity, json.dumps(evidence, default=str),
                        ],
                    )
            # ScriptCheck and any unknown check types are silently skipped
            # (loader gates against ScriptCheck; this is defensive).
        return violations
