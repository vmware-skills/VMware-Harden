"""vmware-harden MCP server entry point.

Tools are defined in vmware_harden.mcp.tools (so audit logs see skill=harden).
This module wires them into a FastMCP server and provides the stdio entry point.
"""
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from vmware_harden.mcp import tools as t


def build_server(db_path: str | Path = "~/.vmware-harden/twin.duckdb") -> FastMCP:
    """Construct and configure the MCP server."""
    t._DB_PATH = Path(os.path.expanduser(str(db_path)))
    server = FastMCP("vmware-harden")

    @server.tool(name="list_baselines")
    def _list_baselines_impl() -> list[dict]:
        """[READ] List built-in and user-imported compliance baselines."""
        return t.list_baselines()

    @server.tool(name="list_violations")
    def _list_violations_impl(severity: str | None = None) -> list[dict]:
        """[READ] Latest snapshot's violations, optionally filtered by severity."""
        return t.list_violations(severity)

    @server.tool(name="get_remediation")
    def _get_remediation_impl(violation_id: str) -> dict | None:
        """[READ] Get the persisted Suggestion for a violation, or None."""
        return t.get_remediation(violation_id)

    @server.tool(name="list_drift_events")
    def _list_drift_events_impl(limit: int = 50) -> list[dict]:
        """[READ] Latest snapshot's change events."""
        return t.list_drift_events(limit)

    @server.tool(name="get_baseline_rules")
    def _get_baseline_rules_impl(baseline_id: str) -> list[dict]:
        """[READ] Return all rules of a given baseline."""
        return t.get_baseline_rules(baseline_id)

    @server.tool(name="scan_target")
    def _scan_target_impl(
        target: str, baseline: str = "cis-vmware-esxi-8.0-subset"
    ) -> dict:
        """[READ] Run a scan for `target` against `baseline`."""
        return t.scan_target(target, baseline)

    return server


def main() -> None:
    """Entry point for `vmware-harden-mcp` (stdio transport)."""
    server = build_server()
    server.run()


if __name__ == "__main__":
    main()
