"""Pilot client interface.

vmware-harden never directly executes writes. Instead, when a Suggestion is
approved, harden submits it to vmware-pilot which handles the workflow with
its own audit + approval gates.

Two implementations:
- `RealPilotClient` — wraps vmware-pilot when available (lazy import).
- `MockPilotClient` — for tests + offline use; records calls; can simulate
  failures.
"""
from typing import Protocol
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


class RealPilotClient:
    """Thin wrapper around vmware-pilot. Lazy-imports to keep the family loose.

    Note: as of v1.0, the Pilot integration is functional but the actual
    pilot API call site may need adjustment based on Pilot v1.x evolution.
    Default execution mode goes through Pilot's standard workflow with its
    own approval gates — vmware-harden never bypasses pilot's safeguards.
    """

    def submit_remediation(self, suggestion: Suggestion) -> str:
        try:
            from vmware_pilot.workflow import submit  # type: ignore[import-not-found]
        except ImportError as e:
            raise PilotSubmissionError(
                "vmware-pilot is not installed. Install it and retry, or "
                "use --pilot mock for testing."
            ) from e
        try:
            return submit(suggestion.model_dump())  # type: ignore[no-any-return]
        except Exception as e:
            raise PilotSubmissionError(f"pilot.submit failed: {e}") from e
