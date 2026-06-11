"""Tests for `vmware-harden apply` CLI."""
import uuid
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vmware_harden.baselines.model import (
    ExecutionPlan, ExecutionStep, ImpactPrediction, Suggestion,
)
from vmware_harden.cli.main import app
from vmware_harden.store.twin import Twin


cli = CliRunner()


def _seed(
    tmp_path: Path, *, human_review: bool = False, severity: str = "low"
) -> tuple[str, str]:
    db = tmp_path / "t.duckdb"
    twin = Twin(db)
    snap = twin.start_snapshot("lab")
    twin.conn.execute(
        "INSERT INTO nodes (id, type, target, name, attrs) "
        "VALUES (?, 'host', 'lab', 'esx', '{}')",
        ["lab:h-1"],
    )
    vid = str(uuid.uuid4())
    twin.conn.execute(
        """INSERT INTO violation
           (id, snapshot_id, baseline_id, rule_id, node_id, severity, evidence)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        [vid, snap, "b", "r", "lab:h-1", severity, "{}"],
    )
    sugg = Suggestion(
        summary="Configure NTP",
        execution_plan=ExecutionPlan(steps=[
            ExecutionStep(step=1, mcp_tool="x.y", params={})
        ]),
        impact_prediction=ImpactPrediction(
            affects_running_workload=False,
            requires_maintenance_window=False,
        ),
        confidence=0.9,
        human_review_required=human_review,
    )
    twin.save_suggestion(vid, sugg)
    twin.finish_snapshot(snap)
    twin.close()
    return str(db), vid


@pytest.mark.unit
def test_apply_low_review_auto_submits(tmp_path: Path):
    db, vid = _seed(tmp_path, human_review=False)
    result = cli.invoke(app, ["apply", "--db", db, "--violation-id", vid])
    assert result.exit_code == 0
    assert "mock-pilot-" in result.output  # task id printed

    # task_id persisted on the remediation row
    twin = Twin(Path(db))
    row = twin.conn.execute(
        "SELECT pilot_task_id FROM remediation WHERE violation_id = ?",
        [vid],
    ).fetchone()
    assert row[0].startswith("mock-pilot-")
    twin.close()


@pytest.mark.unit
def test_apply_human_review_required_prompts(tmp_path: Path):
    db, vid = _seed(tmp_path, human_review=True)
    # User declines
    result = cli.invoke(
        app, ["apply", "--db", db, "--violation-id", vid], input="n\n"
    )
    assert "review" in result.output.lower() or "approve" in result.output.lower()
    # Should not have submitted
    twin = Twin(Path(db))
    row = twin.conn.execute(
        "SELECT pilot_task_id FROM remediation WHERE violation_id = ?",
        [vid],
    ).fetchone()
    assert row[0] is None
    twin.close()


@pytest.mark.unit
def test_apply_human_review_with_auto_approve_skips_prompt(tmp_path: Path):
    db, vid = _seed(tmp_path, human_review=True)
    result = cli.invoke(
        app,
        ["apply", "--db", db, "--violation-id", vid, "--auto-approve"],
    )
    assert result.exit_code == 0
    assert "mock-pilot-" in result.output


@pytest.mark.unit
def test_apply_unknown_violation(tmp_path: Path):
    db, _ = _seed(tmp_path)
    result = cli.invoke(
        app,
        ["apply", "--db", db, "--violation-id", "does-not-exist"],
    )
    assert result.exit_code != 0
    assert "not found" in result.output.lower() or "does-not-exist" in result.output


def _make_suggestion(confidence: float, human_review: bool) -> Suggestion:
    return Suggestion(
        summary="s",
        execution_plan=ExecutionPlan(steps=[]),
        impact_prediction=ImpactPrediction(
            affects_running_workload=False,
            requires_maintenance_window=False,
        ),
        confidence=confidence,
        human_review_required=human_review,
    )


def _twin_with_violation(tmp_path: Path, severity: str) -> tuple[Twin, str]:
    twin = Twin(tmp_path / "rr.duckdb")
    snap = twin.start_snapshot("lab")
    vid = str(uuid.uuid4())
    twin.conn.execute(
        """INSERT INTO violation
           (id, snapshot_id, baseline_id, rule_id, node_id, severity, evidence)
           VALUES (?, ?, 'bl', 'rule-1', 'n-1', ?, '{}')""",
        [vid, snap, severity],
    )
    return twin, vid


def _fake_baseline(policy_review: bool, min_confidence: float):
    from vmware_harden.baselines.model import Baseline, Remediation, ReviewPolicy, Rule

    return Baseline(
        id="bl", name="bl", version="1.0", applies_to=["host"],
        rules=[
            Rule(
                id="rule-1", title="t", severity="medium", category="c",
                check={"type": "query", "sql": "SELECT 1"},
                remediation=Remediation(summary="x"),
                review_policy=ReviewPolicy(
                    human_review_required=policy_review,
                    min_confidence=min_confidence,
                ),
            )
        ],
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    ("policy_review", "confidence", "llm_review", "expected"),
    [
        # Truth table (#2): gate fires if ANY of the three conditions holds.
        (False, 0.9, False, False),  # all gates pass → no review
        (True, 0.9, False, True),    # rule policy demands review
        (False, 0.7, False, True),   # confidence below min_confidence (0.8)
        (False, 0.9, True, True),    # LLM itself asks for review
        (True, 0.7, True, True),     # all three
    ],
)
def test_review_required_truth_table(
    tmp_path: Path, monkeypatch, policy_review, confidence, llm_review, expected
):
    import vmware_harden.baselines.loader as loader_mod
    from vmware_harden.cli import apply as apply_mod

    baseline = _fake_baseline(policy_review, min_confidence=0.8)
    monkeypatch.setattr(loader_mod, "load_builtin", lambda name: baseline)

    twin, vid = _twin_with_violation(tmp_path, severity="medium")
    sugg = _make_suggestion(confidence, llm_review)
    assert apply_mod._review_required(twin, vid, sugg) is expected
    twin.close()


@pytest.mark.unit
@pytest.mark.parametrize(
    ("severity", "llm_review", "expected"),
    [
        # Rule unresolvable → severity-based conservative default.
        ("critical", False, True),
        ("high", False, True),
        ("medium", False, False),
        ("low", False, False),
        ("low", True, True),  # LLM flag still forces review
    ],
)
def test_review_required_unresolvable_rule_defaults_by_severity(
    tmp_path: Path, monkeypatch, severity, llm_review, expected
):
    import vmware_harden.baselines.loader as loader_mod
    from vmware_harden.cli import apply as apply_mod

    def _boom(name):
        raise FileNotFoundError(name)

    monkeypatch.setattr(loader_mod, "load_builtin", _boom)

    twin, vid = _twin_with_violation(tmp_path, severity=severity)
    sugg = _make_suggestion(0.95, llm_review)
    assert apply_mod._review_required(twin, vid, sugg) is expected
    twin.close()
