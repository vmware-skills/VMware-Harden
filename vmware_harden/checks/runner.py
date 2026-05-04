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
        for rule in baseline.rules:
            if isinstance(rule.check, QueryCheck):
                rows = execute_query_check(self.twin, rule.check)
                for row in rows:
                    node_id = row.get("id") or row.get("node_id")
                    if node_id is None:
                        continue
                    v = {
                        "id": str(uuid.uuid4()),
                        "snapshot_id": snapshot_id,
                        "baseline_id": baseline.id,
                        "rule_id": rule.id,
                        "node_id": node_id,
                        "severity": rule.severity,
                        "evidence": row,
                    }
                    violations.append(v)
                    self.twin.conn.execute(
                        """INSERT INTO violation
                           (id, snapshot_id, baseline_id, rule_id, node_id,
                            severity, evidence)
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        [
                            v["id"], snapshot_id, baseline.id, rule.id,
                            node_id, rule.severity, json.dumps(row),
                        ],
                    )
            # ScriptCheck and any unknown check types are silently skipped
            # (loader gates against ScriptCheck; this is defensive).
        return violations
