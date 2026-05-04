"""vmware-harden MCP server (FastMCP-based).

Exposes read-only tools over MCP stdio so AI agents can query the Twin,
run baselines, and fetch remediation suggestions.

Entry point: `vmware-harden-mcp` (declared in pyproject.toml).
"""
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# Module-level state — set by build_server() so tools can read it
_DB_PATH: Path | None = None


def list_baselines() -> list[dict]:
    """List built-in and user-imported baselines.

    Returns: list of {id, name, version, applies_to, rule_count}.
    """
    from vmware_harden.baselines.loader import list_builtins, load_builtin

    out: list[dict] = []
    for name in list_builtins():
        try:
            b = load_builtin(name)
            out.append(
                {
                    "id": b.id,
                    "name": b.name,
                    "version": b.version,
                    "applies_to": list(b.applies_to),
                    "rule_count": len(b.rules),
                }
            )
        except Exception as e:
            out.append({"id": name, "error": f"failed to load: {e}"})
    return out


def build_server(db_path: str | Path = "~/.vmware-harden/twin.duckdb") -> FastMCP:
    """Construct and configure the MCP server."""
    global _DB_PATH
    _DB_PATH = Path(os.path.expanduser(str(db_path)))

    server = FastMCP("vmware-harden")

    @server.tool(name="list_baselines")
    def _list_baselines_impl() -> list[dict]:
        """[READ] List built-in and user-imported compliance baselines.

        Returns one entry per baseline with id, name, version, applies_to
        (node types this baseline targets), and rule_count.
        """
        return list_baselines()

    return server


def main() -> None:
    """Entry point for `vmware-harden-mcp` (stdio transport)."""
    server = build_server()
    server.run()


if __name__ == "__main__":
    main()
