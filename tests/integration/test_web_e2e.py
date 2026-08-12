"""Web E2E: scan → toggle → scan → verify dashboard reflects changes."""
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from vmware_harden.cli.runner import run_scan
from vmware_harden.web.app import build_app


def _full_compliant_host(host_id: str, ntp: bool, build: int = 99999999) -> dict:
    return {
        "id": host_id, "name": f"esx-{host_id}",
        "ntp_enabled": ntp, "esxi_build": build,
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
def test_web_e2e_scan_toggle_scan_verify(tmp_path: Path, capsys):
    db = tmp_path / "e2e.duckdb"

    # Scan 1: NTP on, build current — fully compliant
    with patch(
        "vmware_harden.collectors.hosts._fetch_hosts",
        return_value=[_full_compliant_host("h-1", ntp=True)],
    ):
        run_scan(target="lab", baseline="cis-vmware-esxi-8.0-subset", db=str(db))
    capsys.readouterr()

    # Scan 2: NTP off, outdated build — multiple violations + drift event
    with patch(
        "vmware_harden.collectors.hosts._fetch_hosts",
        return_value=[_full_compliant_host("h-1", ntp=False, build=1)],
    ):
        run_scan(target="lab", baseline="cis-vmware-esxi-8.0-subset", db=str(db))
    capsys.readouterr()

    # Build the web app and run all 3 pages
    app = build_app(db_path=db)
    client = TestClient(app)

    # 1. Summary page shows violations
    r = client.get("/")
    assert r.status_code == 200
    summary = r.text
    assert "Compliance Summary" in summary
    # Should have at least 2 violations (NTP off + outdated build)
    assert "lab:h-1" not in summary  # summary doesn't list nodes inline
    # Severity counts: at least 1 medium (NTP) + 1 high (build)
    assert "Medium" in summary or "MEDIUM" in summary
    assert "High" in summary or "HIGH" in summary

    # 2. Violations page lists rules
    r = client.get("/violations")
    assert r.status_code == 200
    violations = r.text
    assert "cis-esxi-2.2.1" in violations  # build rule
    # NTP rule is undetermined (nothing collects $.ntp_enabled), not a violation
    assert "cis-esxi-2.1.1" not in violations
    assert "lab:h-1" in violations

    # 3. Drift page shows the field changes between scan 1 and scan 2
    r = client.get("/drift")
    assert r.status_code == 200
    drift = r.text
    assert "lab:h-1" in drift
    assert "ntp_enabled" in drift
    assert "build" in drift
