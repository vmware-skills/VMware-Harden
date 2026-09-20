"""The MCP server must tell a client which targets a scan can reach, and how to pick.

``initialize`` returns the server's ``instructions``, and for a skill whose
``scan_target`` resolves a target name that text is the only place the client
learns what is configured. This server shipped an empty string.

The consequence is measured, not hypothetical: in vmware-monitor on 2026-09-15 a
model with no listing called tools with no target, silently got the default — a
standalone ESXi host — and answered "the vCenter has 9 VMs" from it, then
reported that no vCenter was configured at all.

The indirection that makes this one easy to get wrong is the same one
``test_doctor_checks_what_it_is_cited_for`` documents: harden owns no target
config. Its collectors connect with ``vmware_aiops.connection.ConnectionManager``
and its doctor enumerates with ``vmware_aiops.config.load_config()``, both
reading ``~/.vmware-aiops/config.yaml``. So the listing has to be built from a
file this repo never opens, through an import that may legitimately be absent
(vmware-aiops is the optional ``collectors`` extra).
"""

from __future__ import annotations

import sys
import types

import pytest

from vmware_harden.mcp_server import server as srv

LISTING_MARKER = "Configured targets:"
RULE_MARKER = "Choosing a target:"


def _fake_aiops(monkeypatch, targets, *, load_error: Exception | None = None) -> None:
    """Install a stand-in ``vmware_aiops.config`` — the module the code imports.

    Patched through ``sys.modules`` rather than an attribute on this server,
    because the import is deliberately lazy: vmware-aiops is an optional extra,
    and a server installed without it must still start.
    """
    objs = [
        types.SimpleNamespace(name=n, host=h, type=ty) for n, h, ty in targets
    ]

    def _load():
        if load_error is not None:
            raise load_error
        return types.SimpleNamespace(targets=tuple(objs))

    cfg_mod = types.ModuleType("vmware_aiops.config")
    cfg_mod.load_config = _load
    monkeypatch.setitem(sys.modules, "vmware_aiops", types.ModuleType("vmware_aiops"))
    monkeypatch.setitem(sys.modules, "vmware_aiops.config", cfg_mod)


@pytest.mark.unit
def test_every_configured_target_is_named(monkeypatch):
    _fake_aiops(
        monkeypatch,
        [
            ("home-vcenter", "192.168.60.16", "vcenter"),
            ("home-esxi", "192.168.60.15", "esxi"),
        ],
    )

    text = srv._target_instructions()

    assert "home-vcenter (vcenter, 192.168.60.16, default)" in text
    assert "home-esxi (esxi, 192.168.60.15)" in text
    # Say where they came from: the operator edits vmware-aiops' file, not one of
    # this skill's, and a reader told only the names cannot find it.
    assert "~/.vmware-aiops/config.yaml" in text


@pytest.mark.unit
def test_the_default_marked_is_the_one_a_caller_gets(monkeypatch):
    """``AppConfig.default_target`` is entry one, so entry one is what is marked."""
    _fake_aiops(
        monkeypatch,
        [("first", "10.0.0.1", "vcenter"), ("second", "10.0.0.2", "vcenter")],
    )

    text = srv._target_instructions()

    assert "first (vcenter, 10.0.0.1, default)" in text
    assert "second (vcenter, 10.0.0.2)" in text


@pytest.mark.unit
def test_both_marker_phrases_are_present(monkeypatch):
    _fake_aiops(monkeypatch, [("lab", "10.0.0.1", "vcenter")])

    text = srv._target_instructions()

    for marker in (LISTING_MARKER, RULE_MARKER):
        assert marker in text, f"instructions must contain {marker!r}"
    assert "`target`" in text
    assert "scan_target" in text


def _break_by_import(monkeypatch) -> None:
    """Make the lazy import itself fail, wherever vmware-aiops is installed or not.

    ``None`` in ``sys.modules`` makes ``import`` raise, so this reproduces the
    not-installed state deterministically — deleting the entry instead would
    quietly succeed on a machine that has the ``collectors`` extra, and the test
    would then pass for the wrong reason.
    """
    monkeypatch.setitem(sys.modules, "vmware_aiops.config", None)


def _break_by_loader(monkeypatch) -> None:
    _fake_aiops(
        monkeypatch,
        [],
        load_error=FileNotFoundError("Config file not found. Run 'vmware-aiops init'"),
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    "break_it",
    [_break_by_import, _break_by_loader],
    ids=["extra-not-installed", "config-missing"],
)
def test_an_unreadable_config_does_not_stop_the_server_from_starting(
    monkeypatch, break_it
):
    """Both failures are legitimate states, and neither may raise.

    A failing import in particular is the *supported* configuration: the
    collectors are an optional extra, so a server installed without them has to
    start and serve its local tools.
    """
    break_it(monkeypatch)

    text = srv._target_instructions()

    assert text.strip()
    assert RULE_MARKER in text
    assert LISTING_MARKER in text
    # "could not look" must not be rendered as "there are none".
    assert "not readable here" in text


@pytest.mark.unit
def test_an_empty_config_says_none_rather_than_trailing_off(monkeypatch):
    _fake_aiops(monkeypatch, [])

    text = srv._target_instructions()

    assert LISTING_MARKER in text
    assert "none" in text
    assert "Configured targets: ." not in text


@pytest.mark.unit
def test_the_built_server_carries_the_instructions(monkeypatch, tmp_path):
    """The text has to reach the client, not merely exist as a function."""
    _fake_aiops(monkeypatch, [("lab", "10.0.0.1", "vcenter")])

    server = srv.build_server(db_path=tmp_path / "twin.duckdb")

    assert server.instructions
    assert LISTING_MARKER in server.instructions
    assert RULE_MARKER in server.instructions
    assert "lab (vcenter, 10.0.0.1, default)" in server.instructions
