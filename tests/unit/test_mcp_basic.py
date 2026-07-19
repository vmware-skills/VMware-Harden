"""MCP server scaffold + first tool tests."""
import pytest

from vmware_harden.mcp_server.server import build_server


@pytest.mark.unit
def test_build_server_returns_fastmcp():
    """build_server() returns an importable FastMCP-like server."""
    s = build_server(db_path=":memory:")
    assert s.name == "vmware-harden"


@pytest.mark.unit
def test_list_baselines_tool_exposed():
    """The `list_baselines` tool is registered on the server."""
    s = build_server(db_path=":memory:")
    tools = list(s._tool_manager._tools.keys())
    assert "list_baselines" in tools


@pytest.mark.unit
def test_list_baselines_returns_built_ins():
    """list_baselines envelopes a list holding our 4 known built-ins."""
    from vmware_harden.mcp.tools import list_baselines

    out = list_baselines()["items"]
    names = {b["id"] for b in out}
    assert "cis-vmware-esxi-8.0-subset" in names
    assert "dengbao-2.0-level3-vmware" in names
    for b in out:
        assert {"id", "name", "version", "applies_to", "rule_count"}.issubset(b.keys())


@pytest.mark.unit
def test_main_function_exists():
    """The `main` entry point function exists (踩坑 #17 defense)."""
    from vmware_harden.mcp_server.server import main

    assert callable(main)
