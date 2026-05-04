"""Twin.save_suggestion / get_suggestion tests."""
import json
import uuid
from pathlib import Path

import pytest

from vmware_harden.baselines.model import (
    ExecutionPlan,
    ExecutionStep,
    ImpactPrediction,
    Suggestion,
)
from vmware_harden.store.twin import Twin


def _make_suggestion() -> Suggestion:
    return Suggestion(
        summary="Configure NTP",
        execution_plan=ExecutionPlan(steps=[
            ExecutionStep(step=1, mcp_tool="x.y", params={"a": 1})
        ]),
        impact_prediction=ImpactPrediction(
            affects_running_workload=False,
            requires_maintenance_window=False,
        ),
        confidence=0.9,
        human_review_required=False,
    )


def _seed_violation(twin: Twin) -> str:
    snap = twin.start_snapshot("lab")
    vid = str(uuid.uuid4())
    twin.conn.execute(
        """INSERT INTO violation
           (id, snapshot_id, baseline_id, rule_id, node_id, severity, evidence)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        [vid, snap, "b", "r", "n", "low", "{}"],
    )
    return vid


@pytest.mark.unit
def test_save_suggestion_creates_row(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    vid = _seed_violation(twin)
    rid = twin.save_suggestion(vid, _make_suggestion())
    assert rid

    row = twin.conn.execute(
        "SELECT violation_id, confidence FROM remediation WHERE id = ?", [rid]
    ).fetchone()
    assert row[0] == vid
    assert row[1] == 0.9
    twin.close()


@pytest.mark.unit
def test_get_suggestion_roundtrip(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    vid = _seed_violation(twin)
    twin.save_suggestion(vid, _make_suggestion())

    s = twin.get_suggestion(vid)
    assert s is not None
    assert s.summary == "Configure NTP"
    assert s.confidence == 0.9
    assert s.execution_plan.steps[0].mcp_tool == "x.y"
    twin.close()


@pytest.mark.unit
def test_get_suggestion_returns_none_when_missing(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    vid = _seed_violation(twin)
    assert twin.get_suggestion(vid) is None
    twin.close()


@pytest.mark.unit
def test_save_suggestion_idempotent_replaces(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    vid = _seed_violation(twin)

    twin.save_suggestion(vid, _make_suggestion())
    new = _make_suggestion().model_copy(update={"summary": "REPLACED"})
    twin.save_suggestion(vid, new)

    rows = twin.conn.execute(
        "SELECT COUNT(*) FROM remediation WHERE violation_id = ?", [vid]
    ).fetchone()
    assert rows[0] == 1  # not 2

    s = twin.get_suggestion(vid)
    assert s.summary == "REPLACED"
    twin.close()
