"""vmware-harden MCP server entry point.

Tools are defined in vmware_harden.mcp.tools (so audit logs see skill=harden).
This module wires them into a FastMCP server and provides the stdio entry point.
"""
import os
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

from vmware_harden.mcp import tools as t


def build_server(db_path: str | Path = "~/.vmware-harden/twin.duckdb") -> FastMCP:
    """Construct and configure the MCP server."""
    t._DB_PATH = Path(os.path.expanduser(str(db_path)))
    server = FastMCP("vmware-harden")

    @server.tool(name="list_baselines")
    def _list_baselines_impl() -> list[dict]:
        """[READ] List all available compliance baselines: built-in (CIS ESXi 8.0,
        vSphere SCG v8, PCI-DSS 4.0, DengBao 2.0 L3, EU NIS2, BSI ITGS) plus any
        user-imported YAML baselines from ~/.vmware-harden/baselines/. Takes no
        parameters. Returns one entry per baseline: {id, name, version, applies_to
        (node types covered), rule_count}; entries that fail to load carry an
        'error' field instead. Read-only — parses local baseline YAML only, no
        database or network access. Start here to discover valid baseline ids for
        get_baseline_rules and scan_target."""
        return t.list_baselines()

    @server.tool(name="list_violations")
    def _list_violations_impl(
        severity: Optional[str] = None, limit: int = 50, offset: int = 0
    ) -> dict:
        """[READ] List compliance violations recorded by the most recent scan
        snapshot in the local twin DB (~/.vmware-harden/twin.duckdb). severity
        (optional string): filter to exactly one of 'critical', 'high', 'medium',
        'low', 'info'; omit to return all severities. limit (optional int, default
        50): max rows returned; offset (optional int, default 0): rows to skip for
        paging. Returns an envelope {violations: [...], total, limit, offset,
        has_more}; each violation is {id, rule_id, node_id, severity, baseline_id,
        evidence}, sorted severity-descending then rule_id. `total` is the full
        matching count (unbounded by limit) so nothing is hidden — page by raising
        offset while has_more is true. Empty envelope (total 0) when no scan exists
        — run scan_target first. Read-only local DB query, no network calls. Pass a
        row's 'id' to get_remediation for a fix plan."""
        return t.list_violations(severity, limit=limit, offset=offset)

    @server.tool(name="get_remediation")
    def _get_remediation_impl(violation_id: str) -> Optional[dict]:
        """[READ] Fetch the persisted LLM-generated remediation Suggestion for one
        violation. violation_id (required string): the 'id' field of a row
        returned by list_violations. Returns {summary, execution_plan.steps,
        impact_prediction (workload impact, maintenance window, rollback plan),
        confidence (0.0-1.0), human_review_required}, or None when no advisor
        suggestion has been generated for that violation yet (generate one via
        the vmware-harden CLI advisor). Read-only lookup in the local twin DB
        (~/.vmware-harden/twin.duckdb); no network calls and nothing is executed
        — suggestions are advisory only."""
        return t.get_remediation(violation_id)

    @server.tool(name="list_drift_events")
    def _list_drift_events_impl(limit: int = 50) -> list[dict]:
        """[READ] List configuration drift events from the most recent scan
        snapshot — fields whose values changed since the prior scan of the same
        target. limit (optional int, default 50): maximum rows returned, ordered
        by node_id then field; no offset/cursor. Each event is {node_id, field,
        old_value, new_value, detected_at}. Returns [] when no snapshot exists or
        there was no prior snapshot to diff against (a target must be scanned at
        least twice). Read-only query of the local twin DB
        (~/.vmware-harden/twin.duckdb); no network calls. Use for change
        tracking; use list_violations for compliance failures."""
        return t.list_drift_events(limit)

    @server.tool(name="get_baseline_rules")
    def _get_baseline_rules_impl(baseline_id: str) -> list[dict]:
        """[READ] Return every rule in one compliance baseline. baseline_id
        (required string): a baseline id exactly as returned by list_baselines,
        e.g. 'cis-vmware-esxi-8.0-subset'; unknown ids raise a not-found error.
        Returns a list of {id, title, severity, category} per rule, where
        severity is one of 'critical', 'high', 'medium', 'low', 'info'.
        Read-only — parses local baseline YAML only, no database or network
        access. Use after list_baselines to preview what scan_target will check;
        use list_violations for actual scan findings."""
        return t.get_baseline_rules(baseline_id)

    @server.tool(name="scan_target")
    def _scan_target_impl(
        target: str, baseline: str = "cis-vmware-esxi-8.0-subset"
    ) -> dict:
        """[READ] Run a compliance scan of a vCenter target against a baseline and
        persist results locally. target (required string): a vCenter target name
        as configured in vmware-aiops. baseline (optional string, default
        'cis-vmware-esxi-8.0-subset'): a baseline id from list_baselines. Makes
        read-only vCenter API calls (inventory collection only — never modifies
        VMware infrastructure) and writes a new snapshot, violations, and drift
        events (vs the prior scan of the same target) to the local twin DB
        (~/.vmware-harden/twin.duckdb). Returns summary counts {snapshot_id,
        target, baseline, hosts, violations}; inspect details via list_violations
        and list_drift_events. May take minutes on large inventories."""
        return t.scan_target(target, baseline)

    return server


def main() -> None:
    """Entry point for `vmware-harden-mcp` (stdio transport)."""
    server = build_server()
    server.run()


if __name__ == "__main__":
    main()
