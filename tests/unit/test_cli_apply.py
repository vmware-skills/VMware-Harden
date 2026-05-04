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


def _seed(tmp_path: Path, *, human_review: bool = False) -> tuple[str, str]:
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
        [vid, snap, "b", "r", "lab:h-1", "high", "{}"],
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
