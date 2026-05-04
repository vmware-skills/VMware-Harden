"""Pydantic models for runtime Suggestion (LLM advisor output)."""
import pytest
from pydantic import ValidationError

from vmware_harden.baselines.model import (
    ExecutionPlan,
    ExecutionStep,
    ImpactPrediction,
    Suggestion,
)


@pytest.mark.unit
def test_minimal_execution_step():
    s = ExecutionStep(
        step=1,
        mcp_tool="vmware_aiops.host_ntp_configure",
        params={"servers": ["ntp1"]},
    )
    assert s.step == 1
    assert s.mcp_tool == "vmware_aiops.host_ntp_configure"


@pytest.mark.unit
def test_execution_plan_orders_steps():
    plan = ExecutionPlan(
        steps=[
            ExecutionStep(step=1, mcp_tool="a.b", params={}),
            ExecutionStep(step=2, mcp_tool="c.d", params={}),
        ],
    )
    assert [s.step for s in plan.steps] == [1, 2]


@pytest.mark.unit
def test_impact_prediction_defaults():
    ip = ImpactPrediction(
        affects_running_workload=False,
        requires_maintenance_window=False,
    )
    assert ip.estimated_duration is None
    assert ip.rollback_plan is None


@pytest.mark.unit
def test_full_suggestion():
    raw = {
        "summary": "Configure NTP on 2 hosts",
        "execution_plan": {
            "steps": [
                {"step": 1, "mcp_tool": "vmware_aiops.host_ntp_configure",
                 "params": {"servers": ["ntp1.corp"]}},
            ],
        },
        "impact_prediction": {
            "affects_running_workload": False,
            "requires_maintenance_window": False,
            "estimated_duration": "2 minutes per host",
            "rollback_plan": "host_ntp_configure with empty servers list",
        },
        "confidence": 0.95,
        "human_review_required": False,
    }
    s = Suggestion(**raw)
    assert s.confidence == 0.95
    assert s.human_review_required is False
    assert len(s.execution_plan.steps) == 1
    assert s.impact_prediction.estimated_duration == "2 minutes per host"


@pytest.mark.unit
def test_confidence_must_be_in_range():
    with pytest.raises(ValidationError):
        Suggestion(
            summary="x",
            execution_plan=ExecutionPlan(steps=[]),
            impact_prediction=ImpactPrediction(
                affects_running_workload=False,
                requires_maintenance_window=False,
            ),
            confidence=1.5,  # invalid
            human_review_required=False,
        )


@pytest.mark.unit
def test_extra_field_rejected():
    """extra='forbid' on Suggestion."""
    with pytest.raises(ValidationError):
        Suggestion(
            summary="x",
            execution_plan=ExecutionPlan(steps=[]),
            impact_prediction=ImpactPrediction(
                affects_running_workload=False,
                requires_maintenance_window=False,
            ),
            confidence=0.5,
            human_review_required=False,
            bogus_field="x",  # not in schema
        )
