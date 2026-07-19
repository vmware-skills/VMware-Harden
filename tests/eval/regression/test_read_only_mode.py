"""Read-only mode must be a no-op here — and that is worth pinning.

Regression source: VMware-AIops issue #31 (juanpf-ha). An operator driving the
family with a local Llama 3.3 70B had to hand-write the prompt instruction
"work exclusively in read-only mode and never modify alerts, definitions,
reports or configuration", because read-only was only ever a documented
intent. A weak model can ignore a prompt; it cannot call a tool that is not in
list_tools().

vmware-harden is the awkward case for the gate. Its tools are registered by a
``build_server()`` factory that passes **no MCP annotations at all**, so
``readOnlyHint`` is None for every tool and the gate has only the
``[READ]``/``[WRITE]`` docstring marker to classify on. That marker is exactly
why nothing is withheld here — the gate's fallback for an unclassifiable tool
is "treat as write and remove it", so a dropped marker would silently gut this
server. These tests pin that it does not happen.

``scan_target`` surviving is deliberate, not an oversight: it makes read-only
vCenter calls and writes only to the local DuckDB twin, which the gate's
contract treats as a cache of observations rather than managed infrastructure.
"""

import asyncio

import pytest
from vmware_policy import apply_read_only_gate

from mcp_server import server as server_module

EXPECTED_TOOLS = {
    "list_baselines",
    "list_violations",
    "get_remediation",
    "list_drift_events",
    "get_baseline_rules",
    "scan_target",
}


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    monkeypatch.delenv("VMWARE_READ_ONLY", raising=False)
    monkeypatch.delenv("VMWARE_HARDEN_READ_ONLY", raising=False)


def _build(tmp_path):
    """Build a server against a throwaway DB so no real twin is touched."""
    return server_module.build_server(db_path=tmp_path / "twin.duckdb")


def _tools(server):
    return asyncio.run(server.list_tools())


def _tool_names(server):
    return {t.name for t in _tools(server)}


def test_no_tool_is_marked_write(tmp_path):
    """The premise: this skill has no write tools to withhold."""
    for tool in _tools(_build(tmp_path)):
        description = (tool.description or "").lstrip()
        assert description.startswith("[READ]"), tool.name


def test_every_tool_declares_read_only_annotations(tmp_path):
    """Annotations now exist, and they must agree with the docstring marker.

    They were added for MCP client UI, which reads the hints rather than the
    docstring. The gate still classifies from the [READ]/[WRITE] marker (it is
    checked before readOnlyHint), so these hints change no safety decision —
    but a hint that contradicted the marker would mislead every client, so the
    two are pinned together here.
    """
    for tool in _tools(_build(tmp_path)):
        annotations = getattr(tool, "annotations", None)
        assert annotations is not None, f"{tool.name} carries no annotations"
        assert annotations.readOnlyHint is True, tool.name
        assert annotations.destructiveHint is False, tool.name
        assert annotations.idempotentHint is True, tool.name


def test_open_world_hint_matches_what_the_tool_touches(tmp_path):
    """Only scan_target reaches a network; the rest are local-only.

    Copying the family's usual openWorldHint=True everywhere would contradict
    these tools' own docstrings, which promise no network access.
    """
    for tool in _tools(_build(tmp_path)):
        expected = tool.name == "scan_target"
        assert tool.annotations.openWorldHint is expected, tool.name


def test_default_mode_exposes_every_tool(tmp_path):
    server = _build(tmp_path)
    assert _tool_names(server) == EXPECTED_TOOLS
    assert server_module.WITHHELD_WRITE_TOOLS == []


def test_read_only_withholds_nothing(tmp_path, monkeypatch):
    """Read-only mode must not cost this skill any capability."""
    monkeypatch.setenv("VMWARE_READ_ONLY", "true")
    _build(tmp_path)
    assert server_module.WITHHELD_WRITE_TOOLS == []


def test_read_only_keeps_every_tool(tmp_path, monkeypatch):
    """Every tool survives — the whole point of testing a read-only skill."""
    monkeypatch.setenv("VMWARE_READ_ONLY", "true")
    assert _tool_names(_build(tmp_path)) == EXPECTED_TOOLS


def test_skill_env_var_also_withholds_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("VMWARE_HARDEN_READ_ONLY", "true")
    server = _build(tmp_path)
    assert server_module.WITHHELD_WRITE_TOOLS == []
    assert _tool_names(server) == EXPECTED_TOOLS


def test_gate_is_live_not_a_no_op(tmp_path, monkeypatch):
    """An empty withheld list must mean "no write tools", not "gate never ran".

    Every other assertion in this file is satisfied just as well by a gate that
    was never wired in. Register a tool this skill does not have, marked
    [WRITE], and prove the gate removes it under the same env and skill name
    build_server() uses.
    """
    monkeypatch.setenv("VMWARE_READ_ONLY", "true")
    server = _build(tmp_path)
    assert server_module.WITHHELD_WRITE_TOOLS == []

    @server.tool(name="_probe_write")
    def _probe() -> str:
        """[WRITE] Probe tool — must not survive the gate."""
        return "probe"

    assert apply_read_only_gate(server, "vmware-harden") == ["_probe_write"]
    assert _tool_names(server) == EXPECTED_TOOLS


def test_fastmcp_registry_api_still_present(tmp_path):
    """The gate reaches into _tool_manager.list_tools(); pin that it exists.

    If an mcp upgrade moves this, we want a red test here rather than a gate
    that silently stops removing anything.
    """
    server = _build(tmp_path)
    assert callable(getattr(server, "remove_tool", None))
    assert callable(getattr(server._tool_manager, "list_tools", None))
    assert server._tool_manager.list_tools()


def test_build_server_actually_applies_the_gate(monkeypatch):
    """The gate must be CALLED by the factory, not merely importable.

    vmware-debug shipped for a while with `apply_read_only_gate` imported and
    never called, and every "withholds nothing" assertion still passed — that is
    trivially true of a gate that never runs. This repo wires it correctly, and
    this test is what keeps that true.
    """
    import mcp_server.server as server

    calls = []
    real = server.apply_read_only_gate

    def spy(instance, skill, config_flag=None):
        calls.append(skill)
        return real(instance, skill, config_flag=config_flag)

    monkeypatch.setattr(server, "apply_read_only_gate", spy)
    server.build_server()
    assert calls == ["vmware-harden"], "build_server() must apply the read-only gate"
