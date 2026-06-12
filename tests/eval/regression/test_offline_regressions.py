"""Offline regression evals — run in normal CI without a live lab.

The other files in this directory (test_lab_scan.py) are gated on
VMWARE_HARDEN_LAB_TARGET, so they are effectively never exercised in CI. These
evals seed an in-memory/temp DuckDB twin with fixtures and pin already-fixed
behaviors so a regression is caught on every run:

  * absence-check synthetic-id survives the snapshot-scoping filter (the
    v1.5.36 data-loss fix — estate-wide "control entirely missing" gaps)
  * a failed snapshot never becomes the "latest" used by reports/MCP
  * severity ranking always puts 'critical' first (SEVERITY_RANK_SQL)
  * the remediation approval gate is OR-combined (any failing gate forces
    review — CLAUDE.md pitfall #30 truth table)

No VMWARE_HARDEN_LAB_TARGET, no network, no vCenter required.
"""
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from vmware_harden.baselines.loader import load_builtin
from vmware_harden.checks.runner import CheckRunner
from vmware_harden.store.schema import SEVERITY_RANK_SQL
from vmware_harden.store.twin import Twin


def _seed_host(twin: Twin, snap_id: str, host_id: str, attrs: dict) -> None:
    import json

    twin.conn.execute(
        "INSERT INTO nodes (id, type, target, name, attrs) "
        "VALUES (?, 'host', 'v.lab', ?, ?)",
        [host_id, host_id, json.dumps(attrs)],
    )
    twin.write_node_state(snap_id, host_id, attrs)


# ---------------------------------------------------------------------------
# absence-check synthetic id survives snapshot scoping (v1.5.36 data-loss fix)
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_absence_check_synthetic_id_not_dropped(tmp_path: Path):
    """An empty-DFW estate must still report the CRITICAL default-deny-missing
    violation. Its node_id is a synthetic literal (never in node_state); the
    scoping filter must NOT drop it."""
    twin = Twin(tmp_path / "t.duckdb")
    snap = twin.start_snapshot("v.lab")
    _seed_host(twin, snap, "host-a1", {"ntp_enabled": True, "build": 99999999})

    baseline = load_builtin("pci-dss-4.0-vmware")
    violations = CheckRunner(twin).run_baseline(snap, baseline)

    pairs = {(v["rule_id"], v["node_id"]) for v in violations}
    assert ("pci-r1-2", "pci-default-deny-missing") in pairs
    crit = next(v for v in violations if v["node_id"] == "pci-default-deny-missing")
    assert crit["severity"] == "critical"
    twin.close()


# ---------------------------------------------------------------------------
# a failed (or running) snapshot never becomes the "latest"
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_failed_snapshot_is_not_latest(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    good = twin.start_snapshot("v.lab")
    twin.finish_snapshot(good)
    bad = twin.start_snapshot("v.lab")
    twin.finish_snapshot(bad, status="failed")
    twin.start_snapshot("v.lab")  # left running

    latest = twin.latest_snapshot()
    assert latest is not None
    assert latest["id"] == good  # newest *completed*, not the failed/running one
    assert latest["status"] == "completed"
    twin.close()


# ---------------------------------------------------------------------------
# severity ranking puts critical first (SEVERITY_RANK_SQL)
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_severity_rank_orders_critical_first(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    snap = twin.start_snapshot("v.lab")
    for sev in ["low", "critical", "info", "high", "medium"]:
        twin.conn.execute(
            """INSERT INTO violation
               (id, snapshot_id, baseline_id, rule_id, node_id, severity, evidence)
               VALUES (?, ?, 'b', 'r', 'n', ?, '{}')""",
            [str(uuid.uuid4()), snap, sev],
        )
    ordered = [
        r[0]
        for r in twin.conn.execute(
            f"SELECT severity FROM violation WHERE snapshot_id = ? "
            f"ORDER BY {SEVERITY_RANK_SQL.format(col='severity')}",  # nosec B608 - constant
            [snap],
        ).fetchall()
    ]
    assert ordered == ["critical", "high", "medium", "low", "info"]
    twin.close()


# ---------------------------------------------------------------------------
# approval gate is OR-combined: any failing gate forces human review
# ---------------------------------------------------------------------------

def _suggestion(confidence: float, human_review_required: bool):
    from vmware_harden.baselines.model import (
        ExecutionPlan,
        ImpactPrediction,
        Suggestion,
    )

    return Suggestion(
        summary="s",
        execution_plan=ExecutionPlan(steps=[]),
        impact_prediction=ImpactPrediction(
            affects_running_workload=False, requires_maintenance_window=False
        ),
        confidence=confidence,
        human_review_required=human_review_required,
    )


def _seed_violation(twin: Twin, baseline_id: str, rule_id: str, severity: str) -> str:
    snap = twin.start_snapshot("v.lab")
    vid = str(uuid.uuid4())
    twin.conn.execute(
        """INSERT INTO violation
           (id, snapshot_id, baseline_id, rule_id, node_id, severity, evidence)
           VALUES (?, ?, ?, ?, 'n', ?, '{}')""",
        [vid, snap, baseline_id, rule_id, severity],
    )
    return vid


@pytest.mark.unit
@pytest.mark.parametrize(
    "policy_review, confidence, llm_review, expected",
    [
        # All gates pass (policy off, high confidence, LLM ok) → no review.
        (False, 0.95, False, False),
        # Policy demands review → review (even with high confidence + LLM ok).
        (True, 0.95, False, True),
        # Confidence below the rule's min_confidence → review.
        (False, 0.10, False, True),
        # LLM itself flags human_review_required → review.
        (False, 0.95, True, True),
    ],
)
def test_review_gate_is_or_combined(
    tmp_path: Path, policy_review, confidence, llm_review, expected
):
    """Truth table for cli/apply._review_required: a single failing gate must
    force review (OR), never be overridden by another passing gate."""
    import yaml

    from vmware_harden.cli.apply import _review_required

    # Build a tiny custom baseline so review_policy is resolvable. We monkey
    # the loader to return it by id.
    raw = {
        "id": "off-gate-test",
        "name": "Gate test",
        "version": "1.0.0",
        "applies_to": ["host"],
        "rules": [
            {
                "id": "gr-1",
                "title": "t",
                "severity": "medium",
                "category": "c",
                "check": {"type": "query", "sql": "SELECT id FROM nodes"},
                "remediation": {"summary": "x"},
                "review_policy": {
                    "human_review_required": policy_review,
                    "min_confidence": 0.8,
                },
            }
        ],
    }
    from vmware_harden.baselines.model import Baseline

    baseline = Baseline(**yaml.safe_load(yaml.safe_dump(raw)))

    twin = Twin(tmp_path / "t.duckdb")
    vid = _seed_violation(twin, "off-gate-test", "gr-1", "medium")

    # _review_required does a function-local `from ...loader import load_builtin`,
    # so patch the loader module's symbol, not cli.apply's namespace.
    with patch(
        "vmware_harden.baselines.loader.load_builtin", return_value=baseline
    ):
        got = _review_required(twin, vid, _suggestion(confidence, llm_review))
    twin.close()
    assert got is expected
