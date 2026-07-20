"""A teaching message the agent never sees is not a teaching message.

``_safe_error`` reduces unrecognised exceptions to ``"<Class>: operation
failed."`` so raw vCenter text and filesystem paths cannot leak. The allowlist
it checked against named only builtins, so every exception this skill defines
for its own domain — ``AdvisorError``, ``PilotSubmissionError`` — reached the
agent as its class name with the message stripped off.

Nothing pointed at this. The CLI prints those messages in full, and the
error-quality eval reads the message at the raise site rather than what
survives the wrapper, so both surfaces agreed the text was fine while the MCP
surface was throwing it away. Seven authored messages — the advisor's three
"copy an exact violation id" / "your provider returned markdown fences"
diagnoses and the pilot client's four submission failures, which distinguish
"nothing was submitted" from "it ran part-way, do not resubmit blindly" —
arrived as ``AdvisorError: operation failed.``

These types exist precisely to carry a corrected next step, so the rule is the
inverse of the original: a domain exception this package defines passes
through, and only genuinely unplanned exceptions are reduced.

``RuntimeError`` is not in the allowlist and must not be added. It is Python's
generic catch-all: allowing it would pass any library's raw text through as if
this package had authored it, which is the leak the wrapper exists to stop.
"""

from __future__ import annotations

import pytest

from vmware_harden.advisor.advisor import AdvisorError
from vmware_harden.collectors.base import CollectorError
from vmware_harden.mcp_server.server import _safe_error
from vmware_harden.pilot.client import PilotSubmissionError

TEACHING = (
    "violation not found: 'v-99'. Run list_violations and copy an exact value "
    "from a row's 'id' field."
)


@pytest.mark.parametrize("exc_type", [AdvisorError, CollectorError, PilotSubmissionError])
def test_domain_exceptions_keep_their_message(exc_type):
    assert _safe_error(exc_type(TEACHING), "get_remediation") == TEACHING


@pytest.mark.parametrize(
    "exc_type",
    [FileNotFoundError, ValueError, KeyError, NotImplementedError, PermissionError],
)
def test_validation_errors_still_pass_through(exc_type):
    """These are what the loader and the tool layer raise to correct a caller."""
    assert "v-99" in _safe_error(exc_type(TEACHING), "list_violations")


def test_unplanned_exceptions_are_still_reduced():
    """The redaction this allowlist exists for has to keep working."""
    out = _safe_error(RuntimeError("https://admin:hunter2@vc.internal/api/x"), "scan_target")
    assert out == "RuntimeError: operation failed."
    assert "hunter2" not in out


def test_runtime_error_is_not_a_teaching_error():
    """RuntimeError is the generic catch-all — allowlisting it reopens the leak.

    ``cli/runner.py`` raises one with an authored message, which is a real cost:
    that site wants a domain exception of its own, not a hole here.
    """
    assert _safe_error(RuntimeError(TEACHING), "scan_target") == "RuntimeError: operation failed."


def test_message_is_still_truncated():
    """Length capping is the other half of the guard.

    500 here, not the family's 300: these messages interpolate two absolute
    baseline paths before reaching the remedy, and 300 cut the remedy off.
    """
    out = _safe_error(AdvisorError("x" * 900), "get_remediation")
    assert len(out) <= 500
    assert len(out) > 300
