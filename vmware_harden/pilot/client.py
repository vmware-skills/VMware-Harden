"""Pilot client interface.

vmware-harden never directly executes writes. Instead, when a Suggestion is
approved, harden submits it to vmware-pilot which handles the workflow with
its own audit + approval gates.

Two implementations:
- `RealPilotClient` — wraps vmware-pilot when available (lazy import).
- `MockPilotClient` — for tests + offline use; records calls; can simulate
  failures.
"""
from datetime import datetime, timezone
from typing import Any, Callable, Protocol
from uuid import uuid4

from vmware_harden.baselines.model import Suggestion


class PilotSubmissionError(Exception):
    """Raised when pilot rejects or cannot accept a remediation."""


class PilotClient(Protocol):
    """Minimal pilot client interface."""

    def submit_remediation(self, suggestion: Suggestion) -> str:
        """Submit a Suggestion to pilot. Returns the pilot task id."""
        ...


class MockPilotClient:
    """In-memory pilot client. Records every submission; configurable to fail."""

    def __init__(self, raise_on_submit: bool = False):
        self.submitted: list[Suggestion] = []
        self.raise_on_submit = raise_on_submit

    def submit_remediation(self, suggestion: Suggestion) -> str:
        if self.raise_on_submit:
            raise PilotSubmissionError("MockPilotClient configured to raise")
        self.submitted.append(suggestion)
        return f"mock-pilot-{uuid4().hex[:8]}"


# Type alias for the dispatch function pilot calls per step.
DispatchFn = Callable[[str, str, dict[str, Any]], Any]


class RealPilotClient:
    """Pilot integration via vmware_pilot.executor.WorkflowExecutor.

    Builds a Workflow from the Suggestion's execution_plan and submits it to
    pilot's workflow store. Behavior depends on whether a dispatch callable
    was supplied:

    - WITH ``dispatch``: the workflow is executed through pilot's executor up
      to the first approval checkpoint; steps genuinely run via the dispatcher.
    - WITHOUT ``dispatch``: NOTHING is executed. The workflow is persisted in
      state PENDING and the returned task id (== workflow.id) is the handle
      for the calling agent to drive it via pilot's MCP tools
      (``run_workflow`` / ``approve`` / ``get_workflow_status``), performing
      each pending step's skill/tool call itself. This client never fakes
      execution: a remediation can only complete when its steps actually ran.

    Lazy-imports vmware_pilot so harden runs without it; raises
    PilotSubmissionError with an install hint when the dep is missing.
    """

    def __init__(self, dispatch: DispatchFn | None = None, store: Any = None):
        # Caller can supply a DispatchFn (skill, tool, params) -> result that
        # invokes sibling MCP tools. Without it, submit_remediation only
        # persists the workflow (PENDING) — it never noop-"executes" steps.
        self._dispatch = dispatch
        # Optional vmware_pilot.models.WorkflowStore (mainly for tests);
        # defaults to pilot's standard store (~/.vmware/workflows.db).
        self._store = store

    def submit_remediation(self, suggestion: Suggestion) -> str:
        try:
            from vmware_pilot.executor import WorkflowExecutor
            from vmware_pilot.models import (
                Workflow,
                WorkflowState,
                WorkflowStep,
                WorkflowStore,
                new_workflow_id,
            )
        except ImportError as e:
            raise PilotSubmissionError(
                "vmware-pilot is not installed. Install it with "
                "`uv tool install vmware-pilot` and retry, or use "
                "MockPilotClient for testing."
            ) from e

        # Translate Suggestion → Workflow.
        steps: list[Any] = []
        if suggestion.human_review_required:
            steps.append(
                WorkflowStep(
                    index=len(steps),
                    action="require_approval",
                    skill="harden",
                    tool="approval_gate",
                    params={"summary": suggestion.summary},
                )
            )
        for s in suggestion.execution_plan.steps:
            steps.append(
                WorkflowStep(
                    index=len(steps),
                    action="execute",
                    skill=_infer_skill_from_tool(s.mcp_tool),
                    tool=_strip_skill_prefix(s.mcp_tool),
                    params=dict(s.params),
                )
            )

        now = datetime.now(tz=timezone.utc).isoformat()
        workflow = Workflow(
            id=new_workflow_id(),
            workflow_type="harden-remediation",
            state=WorkflowState.PENDING,
            steps=steps,
            params={
                "summary": suggestion.summary[:200],
                "human_review_required": suggestion.human_review_required,
            },
            created_at=now,
            updated_at=now,
        )

        store = self._store if self._store is not None else WorkflowStore()

        if self._dispatch is None:
            # No dispatcher → do NOT execute anything (pilot's noop path
            # would otherwise record fictional successes). Persist the
            # workflow PENDING; the caller drives it via pilot's MCP tools
            # (run_workflow / approve), performing each step itself.
            workflow.log(
                "submitted_pending_dispatch",
                "Submitted by vmware-harden without a dispatcher: steps are "
                "NOT executed. Drive this workflow via pilot's MCP "
                "run_workflow/approve tools and perform the returned "
                "pending_dispatch steps, or resubmit with a dispatch callable.",
            )
            try:
                store.save(workflow)
            except Exception as e:
                raise PilotSubmissionError(f"pilot.store failed: {e}") from e
            return workflow.id

        executor = WorkflowExecutor(store=store, dispatch=self._dispatch)
        try:
            executor.run_until_checkpoint(workflow)
        except Exception as e:
            raise PilotSubmissionError(f"pilot.executor failed: {e}") from e
        return workflow.id


def _infer_skill_from_tool(mcp_tool: str) -> str:
    """`vmware_aiops.host_ntp_configure` → 'aiops'.

    Falls back to 'unknown' for non-namespaced tools.
    """
    if "." in mcp_tool:
        ns = mcp_tool.split(".", 1)[0]
        if ns.startswith("vmware_"):
            return ns.replace("vmware_", "", 1)
    return "unknown"


def _strip_skill_prefix(mcp_tool: str) -> str:
    """`vmware_aiops.host_ntp_configure` → 'host_ntp_configure'."""
    if "." in mcp_tool:
        return mcp_tool.split(".", 1)[1]
    return mcp_tool
