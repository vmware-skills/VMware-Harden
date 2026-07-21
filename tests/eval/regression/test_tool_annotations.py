"""Harden's tool annotations must match its read-only, mostly-local nature.

Recovered from ``test_read_only_mode.py`` (retired with the read-only feature in
v1.8.7). The read-only gate is gone, but these are NOT gate tests — they pin that
every tool is ``[READ]``, declares the read-only MCP hints its docstring promises,
and sets ``openWorldHint`` correctly: ``True`` only for ``scan_target`` (which
reaches a network) and ``False`` for the local-only rest. Copying the family's
usual ``openWorldHint=True`` everywhere would contradict those tool docstrings.
"""

import asyncio

from vmware_harden.mcp_server import server as server_module


def _tools(tmp_path):
    """Build a server against a throwaway DB so no real twin is touched."""
    server = server_module.build_server(db_path=tmp_path / "twin.duckdb")
    return asyncio.run(server.list_tools())


def test_no_tool_is_marked_write(tmp_path):
    """This skill has no write tools."""
    for tool in _tools(tmp_path):
        assert (tool.description or "").lstrip().startswith("[READ]"), tool.name


def test_every_tool_declares_read_only_annotations(tmp_path):
    """Annotations must agree with the ``[READ]`` docstring marker — they drive
    MCP client UI, and a hint contradicting the marker would mislead clients."""
    for tool in _tools(tmp_path):
        annotations = getattr(tool, "annotations", None)
        assert annotations is not None, f"{tool.name} carries no annotations"
        assert annotations.readOnlyHint is True, tool.name
        assert annotations.destructiveHint is False, tool.name
        assert annotations.idempotentHint is True, tool.name


def test_open_world_hint_matches_what_the_tool_touches(tmp_path):
    """Only ``scan_target`` reaches a network; the rest are local-only."""
    for tool in _tools(tmp_path):
        expected = tool.name == "scan_target"
        assert tool.annotations.openWorldHint is expected, tool.name
