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


def _check_scan_targets(target: str | None = None) -> list[DiagnosticResult]:
    """Can this skill actually reach and log into the vCenter(s) it scans?

    Seven places in this repo offer ``vmware-harden doctor`` as the remedy, and
    several of them are reached by a scan that failed on connectivity,
    credentials or a wrong target name — none of which the doctor could see. It
    printed "All checks passed" and the user went round again (2026-08-30).

    The indirection is what made it easy to miss: harden owns no credentials. It
    borrows vmware-aiops' ConnectionManager and its ``~/.vmware-aiops/
    config.yaml``, so *which* vCenter a scan will reach, and whether it will get
    in, are questions about a config file this repo never opens.

    Every configured target is tried, not just the default. A user with five
    targets and three wrong passwords was told everything passed, because the
    check that existed elsewhere in the family only ever authenticated the
    first one.

    Args:
        target: Check only this target. Given after a failure on one vCenter,
            it avoids spending a connection attempt — and a timeout — on every
            other one.
    """
    try:
        from vmware_aiops.config import load_config
        from vmware_aiops.connection import ConnectionManager
    except ImportError as exc:
        # A legitimate state: the collectors are an optional extra. But "could
        # not check" must not be rendered the same as "checked, fine" — that is
        # the whole defect, arriving one level up (形态 #1).
        return [
            DiagnosticResult(
                "Scan targets",
                "warn",
                f"could not check — vmware-aiops is not importable ({exc}); "
                f"scanning needs it. Install with `uv tool install vmware-aiops`, "
                f"then re-run doctor.",
            )
        ]

    try:
        config = load_config()
    except Exception as exc:
        return [
            DiagnosticResult(
                "Scan targets",
                "error",
                f"vmware-aiops config unreadable: {exc}. Scans read their "
                f"targets and credentials from it — run `vmware-aiops init`.",
            )
        ]

    names = [t.name for t in getattr(config, "targets", ()) or ()]
    if not names:
        return [
            DiagnosticResult(
                "Scan targets",
                "warn",
                "no target is configured in the vmware-aiops config, so "
                "`vmware-harden scan --target <name>` has nothing to reach. "
                "Run `vmware-aiops init`.",
            )
        ]
    if target is not None and target not in names:
        return [
            DiagnosticResult(
                "Scan targets",
                "error",
                f"no target named {target!r}. Configured: {', '.join(names)}.",
            )
        ]

    scope = [target] if target is not None else names
    results = [
        DiagnosticResult(
            "Scan targets", "ok", f"{len(names)} configured: {', '.join(names)}"
        )
    ]
    mgr = ConnectionManager.from_config(config)
    try:
        for name in scope:
            try:
                si = mgr.connect(name)
                version = si.content.about.version
                results.append(
                    DiagnosticResult(f"Scan target ({name})", "ok", f"reachable, v{version}")
                )
            except Exception as exc:
                # Reported per target rather than aborting: one bad credential
                # must not hide the state of the other four.
                results.append(
                    DiagnosticResult(
                        f"Scan target ({name})",
                        "error",
                        f"{exc} — check the host, and the password in "
                        f"~/.vmware-aiops/.env.",
                    )
                )
    finally:
        # Best effort: a doctor that raises while tidying up reports nothing at
        # all, which is worse than a leaked session in a one-shot command.
        try:
            mgr.disconnect_all()
        except Exception:  # noqa: BLE001 - see above
            pass
    return results


def run_diagnostics(target: str | None = None) -> list[DiagnosticResult]:
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
        *_check_scan_targets(target),
    ]
