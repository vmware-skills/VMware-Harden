"""Drift end-to-end: scan twice with changes, verify drift CLI shows them."""
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from vmware_harden.cli.main import app
from vmware_harden.cli.runner import run_scan


cli = CliRunner()


def _full_compliant_host(host_id: str, ntp: bool) -> dict:
    return {
        "id": host_id, "name": f"esx-{host_id}",
        "ntp_enabled": ntp, "build": 99999999,
        "ntp_servers": [], "ntp_service_policy": "on",
        "lockdown_mode": "normal", "syslog_remote_host": "syslog.lab",
        "persistent_logs": True, "audit_retention_days": 90,
        "mgmt_vmk_isolated": True, "vswitch_promiscuous_mode": "reject",
        "forged_transmits": "reject", "firewall_enabled": True,
        "ssh_running": False, "ad_joined": True,
        "lockdown_exceptions_count": 0, "root_ssh_key_auth": False,
        "vsan_enabled": False, "vsan_encryption_enabled": False,
        "encrypted_vmotion": "required", "dcui_timeout_seconds": 600,
        "shell_timeout_seconds": 900, "console_keyboard": "US Default",
    }


@pytest.mark.integration
def test_drift_e2e_via_two_scans(tmp_path: Path, capsys):
    """Scan twice with NTP toggled; drift command sees the change."""
    db = str(tmp_path / "t.duckdb")

    # Scan 1: NTP on
    with patch(
        "vmware_harden.collectors.hosts._fetch_hosts",
        return_value=[_full_compliant_host("h-1", ntp=True)],
    ):
        run_scan(target="lab", baseline="cis-vmware-esxi-8.0-subset", db=db)
    capsys.readouterr()

    # Scan 2: NTP off
    with patch(
        "vmware_harden.collectors.hosts._fetch_hosts",
        return_value=[_full_compliant_host("h-1", ntp=False)],
    ):
        run_scan(target="lab", baseline="cis-vmware-esxi-8.0-subset", db=db)
    capsys.readouterr()

    # Drift CLI
    result = cli.invoke(app, ["drift", "--db", db, "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    fields_changed = {(p["node_id"], p["field"]) for p in payload}
    # The collector creates lab:h-1 and we toggled ntp_enabled
    assert ("lab:h-1", "ntp_enabled") in fields_changed
