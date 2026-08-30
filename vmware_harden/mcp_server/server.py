"""vmware-harden MCP server entry point.

Tools are defined in vmware_harden.mcp.tools (so audit logs see skill=harden).
This module wires them into a FastMCP server and provides the stdio entry point.
"""
import logging
import os
import ssl
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP
from vmware_policy import sanitize, set_environment_resolver

from vmware_harden import __version__
from vmware_harden.mcp import stig as t_stig
from vmware_harden.mcp import tools as t

logger = logging.getLogger("mcp_server")


# ---------------------------------------------------------------------------
# Environment declaration
# ---------------------------------------------------------------------------

#: What this skill reports as the environment of everything it touches.
#:
#: Policy rules scope by environment, and the baseline treats a target that
#: declares none as unknown — today that warns on state-changing operations,
#: and the next major release refuses them. Every other skill answers this from
#: its own config, where an operator labels each target ``production`` /
#: ``staging`` / ``lab``.
#:
#: vmware-harden has no such config, and cannot grow one honestly: it is backed
#: by a local DuckDB twin, not by a connection to a managed estate. Requiring a
#: declaration it has no place to make would leave it permanently warning and
#: eventually permanently blocked.
#:
#: A constant is correct here rather than a workaround, because the claim it
#: makes is true: the only thing this skill writes is its own local store.
#: ``scan_target`` is the sole state-changing tool, and its state change is the
#: snapshot it records in the twin DB — its vCenter interaction is read-only
#: collection. No tool in this skill mutates a remote VMware estate, so there
#: is no production change for an environment-scoped rule to protect.
LOCAL_ENVIRONMENT = "local"

#: Client-facing behaviour hints, matching the rest of the family. Every tool
#: here is [READ]: nothing mutates a remote VMware estate, and repeating any of
#: them yields the same answer. These drive MCP client UI (e.g. whether a call
#: needs a confirmation prompt).
#:
#: ``openWorldHint`` is set per tool rather than copied family-wide: five of
#: these six read local baseline YAML or the local twin DB and touch no network
#: at all, which is a closed world. Only scan_target reaches a vCenter.
_READ_LOCAL = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}
_READ_REMOTE = {**_READ_LOCAL, "openWorldHint": True}


#: Per-tool recovery hints returned alongside a caught error. Each names
#: something the caller can actually run — a tool on this surface, or this
#: skill's CLI — because the underlying exception text alone leaves a weak model
#: with a diagnosis and no next step.
_HINT_BASELINES = (
    "Baselines are parsed from local YAML only. Check that "
    "~/.vmware-harden/baselines/ is readable with `vmware-harden doctor`."
)
_HINT_VIOLATIONS = (
    "Run scan_target first if no scan has been recorded; otherwise check the "
    "twin DB at ~/.vmware-harden/twin.duckdb with `vmware-harden doctor`."
)
_HINT_REMEDIATION = (
    "Pass an exact 'id' from list_violations. If no suggestion exists yet, "
    "generate one with `vmware-harden advise --violation-id <id>`."
)
_HINT_DRIFT = (
    "Drift needs two scans of the same target — run scan_target again, then "
    "retry. Check the twin DB with `vmware-harden doctor`."
)
_HINT_BASELINE_RULES = (
    "Run list_baselines (or `vmware-harden baseline list`) and copy an exact "
    "baseline id."
)
_HINT_SCAN = (
    "Verify the target name and vCenter credentials with `vmware-harden doctor "
    "--target <name>` — it lists the configured targets and logs into each one, "
    "so a wrong name or a bad password shows up there. Copy a valid baseline id "
    "from list_baselines."
)
_HINT_STIG = (
    "STIG controls are parsed from the local vsphere-stig-v9-subset baseline "
    "YAML. Check that ~/.vmware-harden/baselines/ is readable with "
    "`vmware-harden doctor`."
)

#: Builtin exception types this package raises on purpose, whose messages it
#: authors and therefore trusts to reach the agent verbatim. Anything else is
#: masked: raw vCenter response bodies and filesystem paths must not leak into
#: the model's context.
#:
#: ``RuntimeError`` is deliberately absent. It is Python's generic catch-all, so
#: allowing it through would pass any library's raw text as if this package had
#: written it. ``cli/runner.py`` used to raise one with an authored message,
#: which the mask then swallowed; that site now raises
#: ``CollectorDependencyError`` — a domain exception of its own, listed below,
#: rather than a hole here.
#:
#: Bare ``OSError`` is absent too, and must stay absent. The family briefly
#: allowed it so one missing-credential message could pass; the tuple is
#: type-based, so that also passed ``ssl.SSLCertVerificationError`` (certificate
#: subject and hostname), ``socket.gaierror`` (the name that failed to resolve)
#: and every ``ConnectionError`` subclass carrying a full URL — none of it
#: authored here. This skill raises no ``OSError`` of its own, so there is
#: nothing for such an entry to let through except other libraries' text. The
#: narrower ``FileNotFoundError`` / ``PermissionError`` entries below predate
#: that and stay: both are raised here with authored messages.
_TEACHING_ERRORS = (
    FileNotFoundError,
    ValueError,
    KeyError,
    NotImplementedError,
    PermissionError,
    ConnectionError,
)


def _domain_errors() -> tuple[type[Exception], ...]:
    """Exception types this package defines to carry a corrected next step.

    Imported at call time, not module scope: a failing tool is the only moment
    these are needed, and the advisor pulls in pydantic while the pilot client
    reaches for vmware-pilot — neither belongs on the server's import path.

    ``web.app.DatabaseBusyError`` is absent on purpose. It is unreachable from
    this surface (no tool imports the dashboard, which would drag FastAPI and
    Jinja2 in with it), and its message is ``str(duckdb_error)`` — upstream text
    rather than authored text, which is the category this allowlist exists to
    withhold.
    """
    from vmware_harden.advisor.advisor import AdvisorError
    from vmware_harden.collectors.base import CollectorDependencyError, CollectorError
    from vmware_harden.pilot.client import PilotSubmissionError

    return (AdvisorError, CollectorDependencyError, CollectorError, PilotSubmissionError)


#: Types that satisfy the allowlist by inheritance without this package having
#: authored a word of their message. Checked first, so inheritance cannot vote
#: them back in.
#:
#: ``ssl.SSLCertVerificationError`` is the one that matters:
#: CPython declares it ``SSLCertVerificationError(SSLError, ValueError)``, so it
#: is an ``OSError`` *and* a ``ValueError``. Dropping bare ``OSError`` from an
#: allowlist therefore does not stop it — any allowlist naming ``ValueError``
#: still passes the certificate subject and the server hostname through
#: verbatim. A self-signed vCenter certificate is this family's most common
#: connection failure, and ``scan_target`` reaches a vCenter, so this is a live
#: path here rather than a hypothetical one.
_NEVER_TEACHING = (ssl.SSLError,)


def _safe_error(exc: Exception, tool: str) -> str:
    """Return an agent-safe error string; log full detail server-side only."""
    logger.error("Tool %s failed", tool, exc_info=True)

    if isinstance(exc, _NEVER_TEACHING):
        return f"{type(exc).__name__}: operation failed."
    if isinstance(exc, (*_TEACHING_ERRORS, *_domain_errors())):
        # 500, not the 300 used elsewhere in the family: these messages
        # interpolate two absolute baseline paths before reaching the remedy,
        # and truncating at 300 cut the remedy off mid-word — the one part of
        # the message the model actually needs.
        return sanitize(str(exc), 500)
    return f"{type(exc).__name__}: operation failed."


def _environment_for(target: Optional[str]) -> str:
    """Report the environment for policy scoping. Always ``local`` — see above."""
    return LOCAL_ENVIRONMENT


# Registered at import time rather than inside build_server(): the resolver is
# process-global state in vmware_policy, not per-server-instance, and every
# build_server() call would otherwise re-register the same constant.
set_environment_resolver(_environment_for)


def build_server(db_path: str | Path = "~/.vmware-harden/twin.duckdb") -> FastMCP:
    """Construct and configure the MCP server."""
    t._DB_PATH = Path(os.path.expanduser(str(db_path)))
    server = FastMCP("vmware-harden")

    # FastMCP takes no version argument and leaves the lowlevel server's at
    # None, which makes `initialize` answer with the MCP SDK's version rather
    # than ours. Set it so a client can tell which release it is talking to.
    server._mcp_server.version = __version__

    @server.tool(name="list_baselines", annotations=_READ_LOCAL)
    def _list_baselines_impl() -> dict:
        """[READ] List all available compliance baselines: built-in (CIS ESXi 8.0,
        vSphere SCG v8, PCI-DSS 4.0, DengBao 2.0 L3, EU NIS2, BSI ITGS) plus any
        user-imported YAML baselines from ~/.vmware-harden/baselines/. Takes no
        parameters. Returns the family list envelope {items, returned, limit,
        total, truncated, hint}; each item is {id, name, version, applies_to
        (node types covered), rule_count}, and entries that fail to load carry an
        'error' field instead. Every baseline is listed, so truncated is always
        false and total is exact — this is the complete set, not a page of it.
        Read-only — parses local baseline YAML only, no database or network
        access. Start here to discover valid baseline ids for get_baseline_rules
        and scan_target."""
        try:
            return t.list_baselines()
        except Exception as e:
            return {"error": _safe_error(e, "list_baselines"), "hint": _HINT_BASELINES}

    @server.tool(name="list_violations", annotations=_READ_LOCAL)
    def _list_violations_impl(
        severity: Optional[str] = None, limit: int = 50, offset: int = 0
    ) -> dict:
        """[READ] List compliance violations recorded by the most recent scan
        snapshot in the local twin DB (~/.vmware-harden/twin.duckdb).
        Returns an envelope {violations: [...], total, limit, offset,
        has_more, coverage, note}; each violation is {id, rule_id, node_id,
        severity, baseline_id, evidence}, sorted severity-descending then rule_id.
        `total` is the full matching count (unbounded by limit) so nothing is
        hidden — page by raising offset while has_more is true. AN EMPTY LIST IS
        NOT A COMPLIANCE VERDICT: rules whose data no collector gathers are not
        executed and count as undetermined, never as passing. Read `coverage`
        {evaluated, undetermined, total, tracked, complete, undetermined_rules}
        before summarising — when complete is false, say how many rules were
        evaluated out of how many and do not call the estate compliant or clean;
        when tracked is false the snapshot predates coverage tracking, so re-scan
        rather than assume. `note` states the same in one sentence, or null when
        coverage is complete. Empty envelope (total 0) when no scan exists — run
        scan_target first. Read-only local DB query, no network calls. Pass a
        row's 'id' to get_remediation for a fix plan.

        Args:
            severity: Return only violations of exactly this severity. One of
                'critical', 'high', 'medium', 'low', 'info' — lowercase, matched
                exactly; anything else is refused with a ValueError naming the
                five. Omit to return every severity (the default).
            limit: Maximum rows in this page, must be >= 1 (default 50). It
                bounds the rows serialized, not the 'total' count, so a small
                limit never hides how much there is.
            offset: Rows to skip before the page starts, must be >= 0 (default
                0 = first page). Page by raising it by 'limit' while the
                envelope's has_more is true.
        """
        try:
            return t.list_violations(severity, limit=limit, offset=offset)
        except Exception as e:
            return {"error": _safe_error(e, "list_violations"), "hint": _HINT_VIOLATIONS}

    @server.tool(name="get_remediation", annotations=_READ_LOCAL)
    def _get_remediation_impl(violation_id: str) -> Optional[dict]:
        """[READ] Fetch the persisted LLM-generated remediation Suggestion for one
        violation. Returns {summary, execution_plan.steps,
        impact_prediction (workload impact, maintenance window, rollback plan),
        confidence (0.0-1.0), human_review_required}, or None when no advisor
        suggestion has been generated for that violation yet (generate one via
        the vmware-harden CLI advisor). Read-only lookup in the local twin DB
        (~/.vmware-harden/twin.duckdb); no network calls and nothing is executed
        — suggestions are advisory only.

        Args:
            violation_id: The 'id' field of a row returned by list_violations
                (the violation's own id, not its rule_id or node_id). An id with
                no stored suggestion returns None rather than an error, so None
                means "not generated yet", not "not found".
        """
        try:
            return t.get_remediation(violation_id)
        except Exception as e:
            return {"error": _safe_error(e, "get_remediation"), "hint": _HINT_REMEDIATION}

    @server.tool(name="list_drift_events", annotations=_READ_LOCAL)
    def _list_drift_events_impl(limit: int = 50) -> dict:
        """[READ] List configuration drift events from the most recent scan
        snapshot — fields whose values changed since the prior scan of the same
        target. Returns the family list envelope
        {items, returned, limit, total, truncated, hint}; each item is {node_id,
        field, old_value, new_value, detected_at}. total is the snapshot's exact
        change-event count, so truncated tells you definitively whether rows were
        left behind — raise limit when it is true. Returns an empty envelope
        (total 0) when no snapshot exists or there was no prior snapshot to diff
        against (a target must be scanned at least twice). Read-only query of the
        local twin DB (~/.vmware-harden/twin.duckdb); no network calls. Use for
        change tracking; use list_violations for compliance failures.

        Args:
            limit: Maximum rows returned, ordered by node_id then field (default
                50). There is no offset or cursor here — this tool cannot page,
                so when the envelope's 'truncated' is true the only way to see
                the rest is to re-call with a larger limit.
        """
        try:
            return t.list_drift_events(limit)
        except Exception as e:
            return {"error": _safe_error(e, "list_drift_events"), "hint": _HINT_DRIFT}

    @server.tool(name="get_baseline_rules", annotations=_READ_LOCAL)
    def _get_baseline_rules_impl(baseline_id: str) -> dict:
        """[READ] Return every rule in one compliance baseline.
        Returns the family list envelope {items, returned, limit, total,
        truncated, hint}; each item is {id, title, severity, category}, where
        severity is one of 'critical', 'high', 'medium', 'low', 'info'. The whole
        baseline is returned, so truncated is always false and total is the exact
        rule count. Read-only — parses local baseline YAML only, no database or
        network access. Use after list_baselines to preview what scan_target will
        check; use list_violations for actual scan findings.

        Args:
            baseline_id: A baseline id exactly as returned by list_baselines —
                e.g. 'cis-vmware-esxi-8.0-subset', 'vsphere-stig-v9-subset' —
                not the baseline's display name. Unknown ids raise a not-found
                error; re-run list_baselines for the valid set, which includes
                any YAML you dropped in ~/.vmware-harden/baselines/.
        """
        try:
            return t.get_baseline_rules(baseline_id)
        except Exception as e:
            return {
                "error": _safe_error(e, "get_baseline_rules"),
                "hint": _HINT_BASELINE_RULES,
            }

    @server.tool(name="scan_target", annotations=_READ_REMOTE)
    def _scan_target_impl(
        target: str, baseline: str = "cis-vmware-esxi-8.0-subset"
    ) -> dict:
        """[READ] Run a compliance scan of a vCenter target against a baseline and
        persist results locally. Makes read-only vCenter API calls (inventory collection only — never modifies
        VMware infrastructure) and writes a new snapshot, violations, and drift
        events (vs the prior scan of the same target) to the local twin DB
        (~/.vmware-harden/twin.duckdb). Returns summary counts {snapshot_id,
        target, baseline, hosts, violations, coverage, note}; inspect details via
        list_violations and list_drift_events. `violations` is meaningful only
        together with `coverage`: rules whose data no collector gathers are not
        executed and count as undetermined, never as passing, so violations=0 is
        not by itself evidence of compliance. When coverage.complete is false,
        report how many rules were evaluated out of how many instead of calling
        the estate compliant. May take minutes on large inventories.

        Args:
            target: A vCenter target name as configured in vmware-aiops
                (~/.vmware-aiops/config.yaml) — this skill has no target config
                of its own and borrows aiops' connection manager. Use the
                config's target key, not a hostname or IP.
            baseline: A baseline id from list_baselines (default
                'cis-vmware-esxi-8.0-subset'). Which baseline you pick decides
                which rules can reach a verdict at all: a baseline whose rules
                need data no collector gathers reports them as undetermined,
                which is why coverage must be read alongside the violation count.
        """
        try:
            return t.scan_target(target, baseline)
        except Exception as e:
            return {"error": _safe_error(e, "scan_target"), "hint": _HINT_SCAN}

    @server.tool(name="list_stig_controls", annotations=_READ_LOCAL)
    def _list_stig_controls_impl(limit: int = 50, offset: int = 0) -> dict:
        """[READ] List the built-in vSphere 9 / VCF 9 STIG-aligned host baseline's
        controls (baseline id 'vsphere-stig-v9-subset').
        Returns the family list envelope {items, returned, limit,
        total, truncated, hint}; each item is {id, title, severity (one of
        critical/high/medium/low/info), category, advanced_setting} where
        advanced_setting names the ESXi advanced setting the control governs
        (e.g. 'Security.AccountLockFailures'). total is the exact catalog size, so
        truncated tells you definitively whether to raise offset. Read-only —
        parses local baseline YAML only, no database, network, or compliance API
        (VCF Operations ACC/SPM has none). Use scan_target with baseline
        'vsphere-stig-v9-subset' to evaluate these controls against a target; use
        describe_stig_content_sync for how this catalog is kept in sync.

        Args:
            limit: Maximum rows in this page, must be >= 1 (default 50). The
                whole catalog is loaded and paged locally, so 'total' stays
                exact whatever you pass.
            offset: Rows to skip before the page starts, must be >= 0 (default
                0 = first page). Raise it by 'limit' while 'truncated' is true.
        """
        try:
            return t_stig.list_stig_controls(limit=limit, offset=offset)
        except Exception as e:
            return {"error": _safe_error(e, "list_stig_controls"), "hint": _HINT_STIG}

    @server.tool(name="describe_stig_content_sync", annotations=_READ_LOCAL)
    def _describe_stig_content_sync_impl() -> dict:
        """[READ] Explain harden's vSphere STIG integration and route continuous
        enforcement. Takes no parameters. Returns {compliance_api_available (always
        false — VCF Operations ACC/SPM exposes no public compliance REST API),
        why_no_api, content_sources (the open-source MITRE InSpec/Cinc STIG repos
        harden syncs against), mechanism (how upstream controls become harden
        rules), routing_note (use VCF Operations SPM/ACC UI for fleet-wide
        continuous enforcement; harden is the API-scriptable point-in-time
        scanner), importer_status}. Read-only, local static content — no database,
        network, or API call. Call this before assuming a compliance endpoint
        exists; use list_stig_controls to see the actual controls."""
        try:
            return t_stig.describe_stig_content_sync()
        except Exception as e:
            return {
                "error": _safe_error(e, "describe_stig_content_sync"),
                "hint": _HINT_STIG,
            }

    return server


def main() -> None:
    """Entry point for `vmware-harden-mcp` (stdio transport)."""
    server = build_server()
    server.run()


if __name__ == "__main__":
    main()
