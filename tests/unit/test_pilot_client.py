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


# ── RealPilotClient honesty (fix: no-dispatch must never noop-execute) ──


def _pilot_store(tmp_path):
    pilot_models = pytest.importorskip("vmware_pilot.models")
    return pilot_models.WorkflowStore(tmp_path / "wf.db")


@pytest.mark.unit
def test_real_client_without_dispatch_persists_pending_and_executes_nothing(tmp_path):
    """Regression: `apply --pilot real` used to noop-execute remediations and
    report a COMPLETED workflow. Without a dispatcher, the workflow must be
    persisted PENDING with every step untouched."""
    pytest.importorskip("vmware_pilot")
    from vmware_harden.pilot.client import RealPilotClient

    store = _pilot_store(tmp_path)
    client = RealPilotClient(store=store)  # no dispatch
    task_id = client.submit_remediation(_make_suggestion())

    wf = store.load(task_id)
    assert wf is not None
    assert wf.state.value == "pending"
    assert all(s.status == "pending" for s in wf.steps)
    # Result of a step must never claim noop success
    assert all(s.result is None for s in wf.steps)
    # Guidance recorded for the caller
    assert any(e["action"] == "submitted_pending_dispatch" for e in wf.audit_log)


@pytest.mark.unit
def test_real_client_with_dispatch_actually_executes(tmp_path):
    pytest.importorskip("vmware_pilot")
    from vmware_harden.pilot.client import RealPilotClient

    calls = []

    def dispatch(skill, tool, params):
        calls.append((skill, tool, params))
        return {"ok": True}

    store = _pilot_store(tmp_path)
    client = RealPilotClient(dispatch=dispatch, store=store)
    task_id = client.submit_remediation(_make_suggestion())

    assert calls == [("aiops", "host_ntp_configure", {"servers": ["ntp1"]})]
    wf = store.load(task_id)
    assert wf.state.value == "completed"
    assert all(s.status == "success" for s in wf.steps)


@pytest.mark.unit
def test_real_client_with_dispatch_pauses_at_approval_gate(tmp_path):
    pytest.importorskip("vmware_pilot")
    from vmware_harden.pilot.client import RealPilotClient

    suggestion = Suggestion(
        summary="Configure NTP",
        execution_plan=ExecutionPlan(
            steps=[ExecutionStep(step=1, mcp_tool="vmware_aiops.host_ntp_configure",
                                  params={"servers": ["ntp1"]})]
        ),
        impact_prediction=ImpactPrediction(
            affects_running_workload=True,
            requires_maintenance_window=True,
        ),
        confidence=0.9,
        human_review_required=True,
    )

    calls = []
    store = _pilot_store(tmp_path)
    client = RealPilotClient(
        dispatch=lambda s, t, p: calls.append((s, t)) or {"ok": True},
        store=store,
    )
    task_id = client.submit_remediation(suggestion)

    wf = store.load(task_id)
    assert wf.state.value == "awaiting_approval"
    # The approval gate is first — nothing dispatched yet.
    assert calls == []
    assert wf.steps[0].action == "require_approval"
    assert wf.steps[1].status == "pending"
