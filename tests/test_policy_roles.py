"""HLD §18: the role metadata this skill declares matches its real tools."""

from __future__ import annotations

import asyncio

import pytest

from vmware_harden import policy_roles


def _registry() -> set[str]:
    import tempfile

    from vmware_harden.mcp_server.server import build_server

    with tempfile.TemporaryDirectory() as d:
        server = build_server(db_path=f"{d}/twin.duckdb")
        return {t.name for t in asyncio.run(server.list_tools())}


@pytest.mark.unit
def test_every_declared_name_is_a_real_tool():
    named = set(policy_roles.ESCAPES) | set(getattr(policy_roles, "AKO_TOOLS", ()))
    assert named - _registry() == set(), sorted(named - _registry())


@pytest.mark.unit
def test_metadata_is_declared_when_policy_has_roles():
    roles = pytest.importorskip("vmware_policy.roles")
    import vmware_harden.mcp_server.server  # noqa: F401  (registers the metadata on import)

    meta = roles.metadata("harden")
    assert meta is not None and meta.version == 1
    assert meta.escapes == policy_roles.ESCAPES
    assert (meta.resolver is not None) is True
