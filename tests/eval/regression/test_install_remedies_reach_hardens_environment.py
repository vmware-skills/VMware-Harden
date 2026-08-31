"""An install instruction that fails when followed is worse than none.

Real-hardware finding, 2026-08-30. On a clean install, `vmware-harden scan`
died with "vmware-aiops not installed — install it with `uv tool install
vmware-aiops`". The tester ran exactly that. The scan failed again, identically.

The reason is `uv tool install`'s whole point: it gives each tool its own
isolated environment. Installing vmware-aiops creates a *second* environment
containing vmware-aiops, and harden — importing from the first — still cannot
see it. Verified in a sandboxed UV_TOOL_DIR on 2026-08-30: after `uv tool
install vmware-harden` followed by `uv tool install vmware-aiops`, harden's
site-packages contains no vmware_aiops. After `uv tool install
"vmware-harden[collectors]"` it does, and no --force is needed to upgrade an
existing install in place.

So this file does not ask whether a remedy is *worded* well. It asks whether
the command in it lands the package where the importing code will look:

* every `uv tool install/upgrade` a remedy prints must name **vmware-harden**,
  because that is the only environment whose imports matter;
* the extra it names must exist in pyproject.toml and must actually contain the
  distribution the message is about — a link to a fact rather than to a habit
  (recurring shape #6: a documented string with no mechanical relationship to
  the code drifts silently).

The messages are collected by running the failure paths that emit them, not by
grepping the source, so a remedy that moves to another module stays covered.
"""

from __future__ import annotations

import importlib.metadata
import re
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

#: Module → the distribution that provides it, and where harden declares it.
#: ``None`` means a required dependency: it arrives with harden itself, so the
#: remedy is to reinstall harden rather than to add an extra.
_PROVENANCE = {
    "vmware_aiops": ("vmware-aiops", "collectors"),
    "vmware_storage": ("vmware-storage", "collectors"),
    "vmware_nsx_security": ("vmware-nsx-security", "collectors"),
    "vmware_pilot": ("vmware-pilot", "remediation"),
    "vmware_policy": ("vmware-policy", None),
}

#: `uv tool install …`, `uv tool upgrade …`, `uv pip install …`, `pip install …`
#: up to the end of the line or the closing backtick.
_COMMAND = re.compile(r"(?:uv )?(?:tool |pip )?(?:install|upgrade)[^`\n.]*")


def _extras() -> dict[str, list[str]]:
    """Extra name → the distributions it installs, read from built metadata.

    Metadata rather than pyproject.toml, for the reason the sibling file
    ``test_collector_imports_resolve.py`` gives: ``tomllib`` is 3.11+ while
    this project supports 3.10, and metadata is what a user actually receives.
    ``uv run`` re-syncs before pytest, so it still tracks edits to pyproject.
    """
    out: dict[str, list[str]] = {}
    for spec in importlib.metadata.requires("vmware-harden") or []:
        marker = re.search(r"""extra\s*==\s*['"]([^'"]+)['"]""", spec)
        if marker is None:
            continue
        dist = re.split(r"[<>=!~\[;\s(]", spec, maxsplit=1)[0].strip()
        out.setdefault(marker.group(1), []).append(dist.lower().replace("_", "-"))
    assert out, (
        "no extras found in vmware-harden's metadata — the parse is broken, "
        "and every check built on it would pass vacuously"
    )
    return out


def _isolating_commands(text: str) -> list[str]:
    """The commands that create or replace a *tool* environment."""
    return [c for c in _COMMAND.findall(text) if "uv tool" in c or c.startswith("tool ")]


def _assert_remedy_is_runnable(message: str, module: str) -> None:
    dist, extra = _PROVENANCE[module]

    commands = _COMMAND.findall(message)
    assert commands, (
        f"the message about missing {dist!r} names no install command at all, "
        f"so a reader is told what broke and not how to fix it:\n  {message}"
    )

    for cmd in _isolating_commands(message):
        assert "vmware-harden" in cmd, (
            f"remedy for missing {dist!r} says `{cmd.strip()}`. `uv tool "
            "install` builds an isolated environment per tool, so this "
            "installs the package somewhere vmware-harden cannot import it "
            "from — following the instruction reproduces the same failure. "
            'Name harden itself: uv tool install "vmware-harden[<extra>]".'
        )

    if extra is None:
        # A required dependency. Nothing to add — the install is incomplete.
        assert "vmware-harden" in message, (
            f"{dist!r} ships with vmware-harden as a required dependency, so "
            "the remedy is to reinstall harden, not to install it separately:"
            f"\n  {message}"
        )
        return

    extras = _extras()
    assert extra in extras, f"test is stale: pyproject declares no {extra!r} extra"
    assert dist in extras[extra], (
        f"pyproject's {extra!r} extra does not contain {dist!r}, so the remedy "
        f"below would install the wrong set:\n  {message}"
    )
    assert f"vmware-harden[{extra}]" in message or f"--with {dist}" in message, (
        f"remedy for missing {dist!r} must name a target that delivers it into "
        f'harden\'s environment — uv tool install "vmware-harden[{extra}]" '
        f"(or `uv tool install vmware-harden --with {dist}`). Got:\n  {message}"
    )


@pytest.fixture
def blocked(monkeypatch):
    """Make named modules unimportable, the way a clean install has them.

    ``None`` in ``sys.modules`` is the interpreter's own "this import is
    halted" marker: both ``import x`` and ``importlib.import_module("x")``
    raise ImportError, and submodules of it fail too. Closer to the real
    absence than patching one import site.
    """

    def _block(*modules: str) -> None:
        for name in modules:
            for loaded in [n for n in sys.modules if n == name or n.startswith(f"{name}.")]:
                monkeypatch.delitem(sys.modules, loaded, raising=False)
            monkeypatch.setitem(sys.modules, name, None)

    return _block


# ---------------------------------------------------------------------------
# The doctor: the remedy every other message points at
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("module", sorted(_PROVENANCE))
def test_doctor_module_hint_is_runnable(blocked, module: str) -> None:
    from vmware_harden import doctor as doc

    blocked(module)
    dist = _PROVENANCE[module][0]
    results = doc.run_diagnostics()
    hits = [r for r in results if r.name == dist or dist in r.detail]
    assert hits, f"doctor reports nothing about missing {dist!r}: {results}"
    for r in hits:
        _assert_remedy_is_runnable(r.detail, module)


@pytest.mark.unit
def test_doctor_does_not_report_all_checks_passed_while_a_collector_is_missing(
    blocked,
) -> None:
    """Without vmware-aiops no scan can run — that is not "all checks passed".

    The summary line is the only part of the output a hurried reader takes
    away, and "All checks passed (2 warning(s))" contradicts itself in seven
    words. The exit code stays 0: the warnings are real states, not failures.
    """
    from typer.testing import CliRunner

    from vmware_harden.cli.main import app

    blocked("vmware_aiops")
    result = CliRunner().invoke(app, ["doctor"])
    assert "All checks passed" not in result.output, (
        "the doctor called it a pass while the package every scan imports was "
        f"missing:\n{result.output}"
    )
    assert "vmware-harden[collectors]" in result.output


@pytest.mark.unit
def test_doctor_still_says_all_checks_passed_when_nothing_is_wrong() -> None:
    """Control: the sentence must not simply have been deleted.

    "This text is absent" is satisfied by removing the text for every input,
    which would leave a healthy environment with no verdict at all. Driven off
    a synthetic result list rather than this machine's real one, because a real
    one on a developer laptop almost always carries a warning (no API key), and
    a control that skips is not a control.
    """
    from unittest.mock import patch as _patch

    from typer.testing import CliRunner

    from vmware_harden.cli.main import app
    from vmware_harden.doctor import DiagnosticResult

    clean = [DiagnosticResult("Python version", "ok", "Python 3.12.0")]
    with _patch("vmware_harden.cli.doctor.run_diagnostics", return_value=clean):
        result = CliRunner().invoke(app, ["doctor"])
    assert "All checks passed" in result.output
    assert result.exit_code == 0

    warned = [*clean, DiagnosticResult("vmware-aiops", "warn", "not importable")]
    with _patch("vmware_harden.cli.doctor.run_diagnostics", return_value=warned):
        result = CliRunner().invoke(app, ["doctor"])
    assert "All checks passed" not in result.output
    assert "1 warning(s)" in result.output
    assert result.exit_code == 0, "a warning is a state to report, not a failure"


# ---------------------------------------------------------------------------
# The two runtime failures that quote an install command of their own
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_scan_dependency_error_remedy_is_runnable(tmp_path: Path) -> None:
    from vmware_harden.cli.runner import run_scan
    from vmware_harden.collectors.base import CollectorDependencyError

    with patch(
        "vmware_harden.collectors.hosts._fetch_hosts",
        side_effect=ModuleNotFoundError(
            "No module named 'vmware_aiops'", name="vmware_aiops"
        ),
    ):
        with pytest.raises(CollectorDependencyError) as exc:
            run_scan(
                target="lab",
                baseline="cis-vmware-esxi-8.0-subset",
                db=str(tmp_path / "t.duckdb"),
            )
    _assert_remedy_is_runnable(str(exc.value), "vmware_aiops")


@pytest.mark.unit
def test_scan_dependency_error_survives_the_mcp_truncation_cap(tmp_path: Path) -> None:
    """The whole message has to fit, with a realistic target name in it.

    ``mcp_server.server._safe_error`` puts this text through ``sanitize(…, 500)``
    before the agent sees it, and truncation is silent — a cut message reads as
    a complete one. Two of the substrings are the caller's (a vCenter FQDN and
    a baseline id), so a message that fits with "lab" can still lose its tail
    on a real estate.
    """
    from vmware_policy import sanitize

    from vmware_harden.cli.runner import run_scan
    from vmware_harden.collectors.base import CollectorDependencyError

    target = "vcsa-prod-01.datacenter-west.example.com"
    with patch(
        "vmware_harden.collectors.hosts._fetch_hosts",
        side_effect=ModuleNotFoundError(
            "No module named 'vmware_aiops'", name="vmware_aiops"
        ),
    ):
        with pytest.raises(CollectorDependencyError) as exc:
            run_scan(
                target=target,
                baseline="cis-vmware-esxi-8.0-subset",
                db=str(tmp_path / "t.duckdb"),
            )
    message = str(exc.value)
    assert sanitize(message, 500) == message, (
        f"the message is {len(message)} characters and is cut at 500 before "
        "reaching the agent; the part that survives must be the whole of it"
    )


@pytest.mark.unit
def test_pilot_submission_error_remedy_is_runnable(blocked) -> None:
    from vmware_harden.pilot.client import PilotSubmissionError, RealPilotClient

    blocked("vmware_pilot")
    with pytest.raises(PilotSubmissionError) as exc:
        RealPilotClient().submit_remediation(_suggestion())
    _assert_remedy_is_runnable(str(exc.value), "vmware_pilot")


def _suggestion():
    from vmware_harden.baselines.model import (
        ExecutionPlan,
        ExecutionStep,
        ImpactPrediction,
        Suggestion,
    )

    return Suggestion(
        summary="Configure NTP",
        execution_plan=ExecutionPlan(
            steps=[
                ExecutionStep(
                    step=1,
                    mcp_tool="vmware_aiops.host_ntp_configure",
                    params={"servers": ["ntp1"]},
                )
            ]
        ),
        impact_prediction=ImpactPrediction(
            affects_running_workload=False,
            requires_maintenance_window=False,
        ),
        confidence=0.9,
        human_review_required=False,
    )


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(
    "doc",
    [
        "README.md",
        "README-CN.md",
        "skills/vmware-harden/SKILL.md",
        "skills/vmware-harden/references/setup-guide.md",
    ],
)
def test_the_install_docs_offer_the_command_that_makes_a_scan_work(doc: str) -> None:
    """Each entry-point document must name the extra, character for character.

    The tester's first stop was the README Quickstart: `uv tool install
    vmware-harden`, then `vmware-harden scan --target …`, which cannot work —
    the collectors are behind an extra. Comparing against
    ``install_extra(COLLECTORS_EXTRA)`` rather than a copied literal is the
    point: rename the extra and these documents fail rather than drift
    (recurring shape #6).
    """
    from vmware_harden.install import COLLECTORS_EXTRA, install_extra

    root = Path(__file__).resolve().parents[3]
    path = root / doc
    assert path.exists(), f"{doc} does not exist — this check verifies nothing"
    assert install_extra(COLLECTORS_EXTRA) in path.read_text(encoding="utf-8"), (
        f"{doc} never shows `{install_extra(COLLECTORS_EXTRA)}`, so a reader "
        "who follows it installs harden without the collectors every scan "
        "needs and the first scan fails"
    )


@pytest.mark.unit
def test_the_checker_rejects_the_instruction_that_was_shipped() -> None:
    """Positive control: the exact text the tester followed must be caught.

    Without this, a checker that accepted everything would report the whole
    file green (recurring shape #1).
    """
    with pytest.raises(AssertionError, match="isolated environment"):
        _assert_remedy_is_runnable(
            "vmware-aiops not installed — install it with `uv tool install "
            "vmware-aiops` and re-run the scan.",
            "vmware_aiops",
        )


@pytest.mark.unit
def test_the_checker_rejects_an_extra_that_does_not_carry_the_package() -> None:
    """Naming harden is not enough: the extra has to contain the package."""
    with pytest.raises(AssertionError, match="must name a target that delivers"):
        _assert_remedy_is_runnable(
            'run `uv tool install "vmware-harden[remediation]"`', "vmware_aiops"
        )


@pytest.mark.unit
def test_the_collectors_extra_carries_every_collector_distribution() -> None:
    """The mechanical link the remedy text depends on."""
    extras = _extras()
    assert set(extras["collectors"]) == {
        dist for dist, extra in _PROVENANCE.values() if extra == "collectors"
    }
