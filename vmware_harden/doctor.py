"""Environment diagnostics for vmware-harden."""
from __future__ import annotations

import importlib
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

Status = Literal["ok", "warn", "error", "info"]


@dataclass(frozen=True)
class DiagnosticResult:
    name: str
    status: Status
    detail: str


def _check_python_version() -> DiagnosticResult:
    v = sys.version_info
    if (v.major, v.minor) < (3, 10):
        return DiagnosticResult(
            "Python version", "error", f"Python {v.major}.{v.minor} < 3.10 required"
        )
    return DiagnosticResult(
        "Python version", "ok", f"Python {v.major}.{v.minor}.{v.micro}"
    )


def _check_twin_db() -> DiagnosticResult:
    path = Path(os.path.expanduser("~/.vmware-harden/twin.duckdb"))
    if not path.exists():
        return DiagnosticResult(
            "Twin DB",
            "warn",
            f"missing at {path}; run `vmware-harden scan --target <vc>`",
        )
    return DiagnosticResult("Twin DB", "ok", str(path))


def _check_module(
    modname: str,
    label: str,
    *,
    severity: Status = "warn",
    absent_hint: str = "",
) -> DiagnosticResult:
    try:
        importlib.import_module(modname)
        return DiagnosticResult(label, "ok", f"{modname} available")
    except ImportError:
        hint = absent_hint or f"install with `uv tool install {modname.replace('_', '-')}`"
        return DiagnosticResult(label, severity, hint)


def _check_baselines() -> DiagnosticResult:
    from vmware_harden.baselines.loader import list_builtins

    names = list_builtins()
    if len(names) < 4:
        return DiagnosticResult(
            "Built-in baselines",
            "error",
            f"only {len(names)} found, expected >=4",
        )
    return DiagnosticResult("Built-in baselines", "ok", f"{len(names)} loaded")


def _check_anthropic_key() -> DiagnosticResult:
    if os.getenv("ANTHROPIC_API_KEY"):
        return DiagnosticResult("ANTHROPIC_API_KEY", "ok", "set — real Advisor")
    return DiagnosticResult(
        "ANTHROPIC_API_KEY",
        "warn",
        "unset — Advisor will use MockProvider",
    )


def _check_read_only() -> DiagnosticResult:
    """Report the resolved read-only state and where it came from.

    Never an error — read-only being on is a posture, not a fault. It is here
    because an operator who set the switch had no way to confirm it took: the
    only signal was a line in the MCP server's start-up log, and this skill
    does not even log that (it has nothing to withhold, so the gate's empty
    result is silent).

    ``config_flag`` is ``None`` because vmware-harden has no config loader —
    the environment variables are the only switch. That matches the
    ``apply_read_only_gate(server, "vmware-harden", config_flag=None)`` call in
    ``vmware_harden/mcp_server/server.py``; a doctor that disagrees with the gate it reports
    on is worse than no doctor.
    """
    from vmware_policy.readonly import read_only_status

    status = read_only_status("vmware-harden", None)
    if not status.recognised:
        return DiagnosticResult(
            "Read-only mode",
            "warn",
            f"{status.source}={status.raw!r} is not a recognised value. It resolves "
            f"to ON (fail-closed) — probably not what was intended. "
            f"Use true or false.",
        )
    if status.enabled:
        return DiagnosticResult(
            "Read-only mode",
            "ok",
            f"ON (from {status.source}) — no write tools exist here; "
            f"the gate verifies that at start-up",
        )
    return DiagnosticResult(
        "Read-only mode",
        "ok",
        f"off (from {status.source}) — nothing to withhold; all 6 tools are reads",
    )


def _check_audit_db_writable() -> DiagnosticResult:
    path = Path(os.path.expanduser("~/.vmware/audit.db")).parent
    if path.exists() and os.access(path, os.W_OK):
        return DiagnosticResult("Audit DB dir", "ok", str(path))
    if not path.exists():
        return DiagnosticResult(
            "Audit DB dir",
            "warn",
            f"{path} not yet created (created on first MCP tool call)",
        )
    return DiagnosticResult("Audit DB dir", "error", f"{path} not writable")


def run_diagnostics() -> list[DiagnosticResult]:
    return [
        _check_python_version(),
        _check_twin_db(),
        _check_baselines(),
        _check_module(
            "vmware_aiops",
            "vmware-aiops",
            absent_hint="install: `uv tool install vmware-aiops` (host/VM collectors)",
        ),
        _check_module(
            "vmware_storage",
            "vmware-storage",
            absent_hint="install: `uv tool install vmware-storage` (datastore collector)",
        ),
        _check_module(
            "vmware_nsx_security",
            "vmware-nsx-security",
            absent_hint="install: `uv tool install vmware-nsx-security` (DFW collector)",
        ),
        _check_module(
            "vmware_policy",
            "vmware-policy",
            severity="error",
            absent_hint="install: `uv tool install vmware-policy` (REQUIRED — audit decorator)",
        ),
        _check_anthropic_key(),
        _check_module(
            "vmware_pilot",
            "vmware-pilot",
            severity="info",
            absent_hint="optional — `vmware-harden apply --pilot real` requires it",
        ),
        _check_audit_db_writable(),
        _check_read_only(),
    ]
