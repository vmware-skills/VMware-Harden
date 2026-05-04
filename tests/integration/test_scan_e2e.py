"""End-to-end scan + report tests with mocked vCenter."""
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from vmware_harden.cli.runner import run_report, run_scan


# A fully-compliant host plus one violator
HOSTS = [
    {
        "id": "host-good",
        "name": "esx-good",
        "esxi_version": "8.0.2",
        "build": 99999999,
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
    },
    {
        "id": "host-bad",
        "name": "esx-bad",
        "esxi_version": "8.0.2",
        "build": 1,                    # outdated → cis-esxi-2.2.1
        "ntp_enabled": False,          # → cis-esxi-2.1.1
        "ntp_servers": [],
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
    },
]


@pytest.mark.integration
def test_scan_then_report_text(tmp_path: Path, capsys):
    db = str(tmp_path / "t.duckdb")
    with patch(
        "vmware_harden.collectors.hosts._fetch_hosts", return_value=HOSTS
    ):
        run_scan(target="lab", baseline="cis-vmware-esxi-8.0-subset", db=db)
    capsys.readouterr()  # flush scan output

    run_report(db=db, format="text")
    out = capsys.readouterr().out
    # Violator host appears
    assert "host-bad" in out
    # Specific rules fire
    assert "cis-esxi-2.1.1" in out  # NTP
    assert "cis-esxi-2.2.1" in out  # build
    # Compliant host doesn't show as violator (text mode lists violators only)
    assert "host-good" not in out


@pytest.mark.integration
def test_scan_then_report_json(tmp_path: Path, capsys):
    db = str(tmp_path / "t.duckdb")
    with patch(
        "vmware_harden.collectors.hosts._fetch_hosts", return_value=HOSTS
    ):
        run_scan(target="lab", baseline="cis-vmware-esxi-8.0-subset", db=db)
    capsys.readouterr()

    run_report(db=db, format="json")
    payload = json.loads(capsys.readouterr().out)

    assert isinstance(payload, list)
    assert len(payload) >= 2  # at least NTP + build for host-bad
    rule_ids = {entry["rule"] for entry in payload}
    assert "cis-esxi-2.1.1" in rule_ids
    assert "cis-esxi-2.2.1" in rule_ids
    # Each entry has the canonical fields
    for entry in payload:
        assert "rule" in entry
        assert "node" in entry
        assert "severity" in entry
        assert "evidence" in entry


@pytest.mark.integration
def test_scan_creates_db_directory(tmp_path: Path):
    """`db` path inside a non-existent directory should auto-create parents."""
    db = str(tmp_path / "deep" / "nested" / "twin.duckdb")
    with patch(
        "vmware_harden.collectors.hosts._fetch_hosts", return_value=HOSTS
    ):
        run_scan(target="lab", baseline="cis-vmware-esxi-8.0-subset", db=db)
    assert Path(db).exists()


@pytest.mark.integration
def test_scan_expands_user_home(tmp_path: Path, monkeypatch):
    """`~/...` should be expanded to the user home (or HOME override)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    db = "~/twin.duckdb"  # under monkeypatched HOME
    with patch(
        "vmware_harden.collectors.hosts._fetch_hosts", return_value=HOSTS
    ):
        run_scan(target="lab", baseline="cis-vmware-esxi-8.0-subset", db=db)
    assert (tmp_path / "twin.duckdb").exists()
