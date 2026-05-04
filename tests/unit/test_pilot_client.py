"""Pilot client tests (MockPilotClient only; real client wired but mocked)."""
import pytest

from vmware_harden.baselines.model import (
    ExecutionPlan, ExecutionStep, ImpactPrediction, Suggestion,
)
from vmware_harden.pilot.client import (
    MockPilotClient,
    PilotClient,
    PilotSubmissionError,
)


def _make_suggestion() -> Suggestion:
    return Suggestion(
        summary="Configure NTP",
        execution_plan=ExecutionPlan(
            steps=[ExecutionStep(step=1, mcp_tool="vmware_aiops.host_ntp_configure",
                                  params={"servers": ["ntp1"]})]
        ),
        impact_prediction=ImpactPrediction(
            affects_running_workload=False,
            requires_maintenance_window=False,
        ),
        confidence=0.9,
        human_review_required=False,
    )


@pytest.mark.unit
def test_mock_pilot_returns_task_id():
    client = MockPilotClient()
    tid = client.submit_remediation(_make_suggestion())
    assert tid.startswith("mock-pilot-")


@pytest.mark.unit
def test_mock_pilot_records_calls():
    client = MockPilotClient()
    client.submit_remediation(_make_suggestion())
    client.submit_remediation(_make_suggestion())
    assert len(client.submitted) == 2


@pytest.mark.unit
def test_mock_pilot_can_be_configured_to_raise():
    client = MockPilotClient(raise_on_submit=True)
    with pytest.raises(PilotSubmissionError):
        client.submit_remediation(_make_suggestion())


@pytest.mark.unit
def test_protocol_satisfied_by_mock():
    """MockPilotClient is structurally a PilotClient."""
    client: PilotClient = MockPilotClient()
    assert client.submit_remediation(_make_suggestion()).startswith("mock-")


@pytest.mark.lab
def test_real_pilot_client_against_installed_pilot():
    """If vmware-pilot is installed, RealPilotClient constructs and is callable."""
    pytest.importorskip("vmware_pilot")
    from vmware_harden.pilot.client import RealPilotClient

    client = RealPilotClient()
    # Construction should not crash; full submit requires a dispatch + workflow
    # context which is exercised in lab environments only.
    assert client is not None
