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

import socket
import ssl

import pytest

from vmware_harden.advisor.advisor import AdvisorError
from vmware_harden.collectors.base import CollectorDependencyError, CollectorError
from vmware_harden.mcp_server.server import _safe_error
from vmware_harden.pilot.client import PilotSubmissionError

TEACHING = (
    "violation not found: 'v-99'. Run list_violations and copy an exact value "
    "from a row's 'id' field."
)


@pytest.mark.parametrize(
    "exc_type",
    [AdvisorError, CollectorDependencyError, CollectorError, PilotSubmissionError],
)
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

    ``cli/runner.py`` used to raise one with an authored message, which was a
    real cost: the whole "install it with uv tool install …" instruction arrived
    as ``RuntimeError: operation failed.``. That site now raises
    ``CollectorDependencyError`` instead — the domain exception this comment
    asked for — so the message survives without widening the allowlist.
    """
    assert _safe_error(RuntimeError(TEACHING), "scan_target") == "RuntimeError: operation failed."


def test_missing_collector_dependency_reaches_the_agent():
    """The install instruction is the entire value of that error.

    Pairs with ``test_scan_missing_dependency_teaching_error``, which pins the
    type at the raise site; this pins that the type survives the MCP wrapper.
    """
    msg = (
        "vmware-aiops not installed — install it with `uv tool install "
        "vmware-aiops` (collector dependency for baseline 'cis-vmware-esxi-8.0-subset')."
    )
    assert _safe_error(CollectorDependencyError(msg), "scan_target") == msg


# ---------------------------------------------------------------------------
# OSError breadth: why the allowlist is type-based and must stay narrow
# ---------------------------------------------------------------------------
#
# The family briefly allowlisted bare ``OSError`` so one skill's
# missing-credential message could pass through. ``isinstance`` does not know
# who authored a message, so that entry also passed every TLS, DNS and socket
# failure — text this package never wrote, carrying hostnames and certificate
# subjects. This skill raises no OSError of its own, so there is nothing here
# for such an entry to admit except other libraries' text. These pin that.

def test_tls_failure_does_not_leak_the_certificate_subject():
    exc = ssl.SSLCertVerificationError(
        "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self signed "
        "certificate (_ssl.c:1006), subject CN=vc-prod-01.corp.internal"
    )
    out = _safe_error(exc, "scan_target")
    assert out == "SSLCertVerificationError: operation failed."
    assert "vc-prod-01.corp.internal" not in out


def test_dns_failure_does_not_leak_the_hostname():
    exc = socket.gaierror(-2, "Name or service not known: vc-prod-01.corp.internal")
    out = _safe_error(exc, "scan_target")
    assert out == "gaierror: operation failed."
    assert "vc-prod-01.corp.internal" not in out


def test_the_collector_remedy_survives_the_cap():
    """Regression: the remedy used to be truncated away by its own evidence.

    ``_persist_groups`` interpolated the offending record — ~480 characters for
    a real ESXi host — ahead of the remedy, so everything the agent could act on
    fell past the 500-char cap. Remedy first, evidence last and bounded.
    """
    from vmware_harden.collectors.base import Collector

    fat_record = {f"field_{i}": f"value-{i}" * 4 for i in range(60)}
    assert len(repr(fat_record)) > 1500, "record must be big enough to overflow"

    # twin is never touched: the KeyError fires before the transaction opens.
    collector = Collector(twin=None)
    with pytest.raises(CollectorError) as exc:
        collector._persist_groups(
            "snap-1", "vc-prod-01.corp.example.com", [([fat_record], "host", "host")]
        )

    out = _safe_error(exc.value, "scan_target")
    assert len(out) <= 500
    assert "vmware-harden doctor" in out, "the remedy must survive the cap"
    assert "--target vc-prod-01.corp.example.com" in out
    assert "…(truncated)" in out, "a cut record must announce itself"


def test_message_is_still_truncated():
    """Length capping is the other half of the guard.

    500 here, not the family's 300: these messages interpolate two absolute
    baseline paths before reaching the remedy, and 300 cut the remedy off.
    """
    out = _safe_error(AdvisorError("x" * 900), "get_remediation")
    assert len(out) <= 500
    assert len(out) > 300
