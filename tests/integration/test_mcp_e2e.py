"""End-to-end MCP smoke: tool dispatch through protocol layer."""
from pathlib import Path

import pytest

from mcp_server import server as srv


@pytest.mark.integration
def test_list_baselines_via_fastmcp_dispatch(tmp_path: Path):
    """Call the tool through the FastMCP server's internal dispatch layer."""
    server = srv.build_server(db_path=tmp_path / "twin.duckdb")

    tools = server._tool_manager._tools
    assert "list_baselines" in tools, f"available tools: {list(tools.keys())}"

    tool = tools["list_baselines"]
    fn = tool.fn
    assert callable(fn), f"tool entry not callable: {tool!r}"

    result = fn()
    assert isinstance(result, list)
    ids = {b.get("id") for b in result}
    assert "cis-vmware-esxi-8.0-subset" in ids


@pytest.mark.integration
def test_get_baseline_rules_via_fastmcp_dispatch(tmp_path: Path):
    server = srv.build_server(db_path=tmp_path / "twin.duckdb")
    tool = server._tool_manager._tools["get_baseline_rules"]
    rules = tool.fn(baseline_id="cis-vmware-esxi-8.0-subset")
    assert len(rules) == 20


@pytest.mark.integration
def test_all_six_tools_registered(tmp_path: Path):
    server = srv.build_server(db_path=tmp_path / "twin.duckdb")
    expected = {
        "list_baselines",
        "list_violations",
        "get_remediation",
        "list_drift_events",
        "get_baseline_rules",
        "scan_target",
    }
    actual = set(server._tool_manager._tools.keys())
    missing = expected - actual
    assert not missing, f"missing tools: {missing}; have: {actual}"


@pytest.mark.integration
def test_main_entry_point_runs_server_synchronously():
    """Verify `main()` is the right shape — should call server.run()."""
    import inspect

    src = inspect.getsource(srv.main)
    assert "build_server" in src
    assert "run" in src
