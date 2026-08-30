"""No MCP tool may write a byte to stdout.

Real-hardware finding, 2026-08-30, in a round that drove the MCP surface rather
than the CLI. ``scan_target`` printed six progress lines — "Snapshot … started
against …", "Collected N host entities", "Found N violations …" — because the
tool and ``vmware-harden scan`` share ``cli.runner.run_scan``, and that function
reported progress with ``typer.echo``.

Under the stdio transport, stdout is not a place to talk. It is the exclusive
JSON-RPC channel: every byte on it is framed as protocol, so a progress line
lands in the middle of the message stream and corrupts the frame the server was
about to send. The tester reproduced exactly that. stderr is unaffected — the
spec reserves it for the server's own logging — so the constraint is one-sided
and absolute: no tool, on any path, writes to stdout.

The check below is behavioural, not structural. A test that grepped the source
for ``typer.echo`` would pass a "fix" that swapped in ``print``, and would go
blind the moment a tool started printing from a module nobody thought to grep.
This one captures file descriptor 1 (``capfd``, not ``capsys``: a C-level write
lands there too) around a real dispatch through ``FastMCP.call_tool`` and
requires it to be empty.

Two controls sit beside it, because "nothing was printed" is exactly the kind
of assertion that also passes when nothing was run and when the probe is blind
(recurring shape #1):

* ``test_the_probe_can_see_a_tool_writing_to_stdout`` makes one tool print, and
  requires the sweep to catch it.
* ``test_cli_scan_still_prints_its_progress`` requires the CLI to keep the
  progress the MCP path must not have. Silencing both would satisfy a careless
  stdout test while deleting a feature.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from vmware_harden.cli.main import app
from vmware_harden.mcp_server import server as srv

#: One host, enough fields for the CIS host rules to reach a verdict. The shape
#: matches what ``collectors.hosts._fetch_hosts`` returns from a real vCenter;
#: only the transport is faked, so the scan runs its real length.
_HOSTS = [
    {
        "id": "host-1",
        "name": "esx-1",
        "esxi_version": "8.0.2",
        "esxi_build": 99999999,
        "ntp_enabled": True,
        "ntp_servers": ["10.0.0.1"],
        "ntp_service_policy": "on",
        "lockdown_mode": "normal",
        "syslog_remote_host": "syslog.lab",
        "persistent_logs": True,
        "audit_retention_days": 90,
        "mgmt_vmk_isolated": True,
        "vswitch_promiscuous_mode": "reject",
        "forged_transmits": "reject",
        "firewall_enabled": True,
        "ssh_running": False,
        "ad_joined": True,
        "lockdown_exceptions_count": 0,
        "root_ssh_key_auth": False,
        "vsan_enabled": False,
        "vsan_encryption_enabled": False,
        "encrypted_vmotion": "required",
        "dcui_timeout_seconds": 600,
        "shell_timeout_seconds": 900,
        "console_keyboard": "US Default",
    }
]

#: Arguments for every registered tool. ``scan_target`` is the one that reaches
#: a vCenter; the collector it dispatches to is patched below, and everything
#: after the fetch — persistence, rule evaluation, coverage, the progress
#: reporting this test is about — runs for real.
_TOOL_ARGS: dict[str, dict[str, Any]] = {
    "list_baselines": {},
    "list_violations": {},
    "get_remediation": {"violation_id": "no-such-violation"},
    "list_drift_events": {},
    "get_baseline_rules": {"baseline_id": "cis-vmware-esxi-8.0-subset"},
    "scan_target": {"target": "lab", "baseline": "cis-vmware-esxi-8.0-subset"},
    "list_stig_controls": {},
    "describe_stig_content_sync": {},
}


def _tool_names(server) -> list[str]:
    return sorted(asyncio.run(server.list_tools()) and server._tool_manager._tools)


def _call(server, name: str) -> Any:
    return asyncio.run(server.call_tool(name, _TOOL_ARGS[name]))


@pytest.fixture
def server(tmp_path: Path):
    """A server whose twin DB is disposable, with the vCenter fetch stubbed."""
    built = srv.build_server(db_path=tmp_path / "twin.duckdb")
    with patch(
        "vmware_harden.collectors.hosts._fetch_hosts", return_value=_HOSTS
    ):
        yield built


@pytest.mark.integration
def test_every_registered_tool_is_covered_by_this_sweep(server) -> None:
    """A tool added later must not slip past the check by not being listed.

    Without this, the parametrised sweep below would keep passing while a new
    tool printed freely — the check would still be green and no longer be
    checking the thing its name claims.
    """
    registered = set(_tool_names(server))
    assert registered, "no tools registered — the sweep would assert nothing"
    assert registered == set(_TOOL_ARGS), (
        "tools registered but not swept: "
        f"{sorted(registered - set(_TOOL_ARGS))}; "
        f"swept but not registered: {sorted(set(_TOOL_ARGS) - registered)}"
    )


@pytest.mark.integration
@pytest.mark.parametrize("tool_name", sorted(_TOOL_ARGS))
def test_tool_writes_nothing_to_stdout(server, capfd, tool_name: str) -> None:
    capfd.readouterr()  # discard anything the fixtures wrote
    _call(server, tool_name)
    captured = capfd.readouterr()
    assert captured.out == "", (
        f"{tool_name} wrote {captured.out!r} to stdout. Under the MCP stdio "
        "transport stdout carries JSON-RPC frames only, so this corrupts the "
        "message stream. Route the text to stderr, or to a caller-supplied "
        "sink the CLI passes and the MCP path does not."
    )


@pytest.mark.integration
def test_the_probe_can_see_a_tool_writing_to_stdout(server, capfd) -> None:
    """Positive control: the capture above is not blind.

    If ``capfd`` could not see writes from inside a dispatched tool, every
    assertion in this file would pass unconditionally.
    """
    capfd.readouterr()
    with patch(
        "vmware_harden.mcp.tools.list_baselines",
        side_effect=lambda: print("frame-corrupting text") or {"items": []},
    ):
        _call(server, "list_baselines")
    assert "frame-corrupting text" in capfd.readouterr().out


@pytest.mark.integration
def test_cli_scan_still_prints_its_progress(tmp_path: Path) -> None:
    """Control: the CLI keeps the progress the MCP path must not have.

    The point of routing progress through a sink rather than deleting it. A
    scan of a large estate is minutes of silence otherwise, and a fix that
    silenced both surfaces would pass every assertion above.
    """
    db = tmp_path / "cli.duckdb"
    with patch(
        "vmware_harden.collectors.hosts._fetch_hosts", return_value=_HOSTS
    ):
        result = CliRunner().invoke(
            app,
            [
                "scan",
                "--target",
                "lab",
                "--baseline",
                "cis-vmware-esxi-8.0-subset",
                "--db",
                str(db),
            ],
        )
    assert result.exit_code == 0, result.output
    assert "started against lab" in result.output
    assert "Collected 1 host entities" in result.output
    assert "Found" in result.output and "violations" in result.output
