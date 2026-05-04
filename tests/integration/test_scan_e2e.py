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


@pytest.mark.integration
def test_scan_closes_twin_on_collector_error(tmp_path: Path):
    """run_scan must close Twin even when collector raises."""
    from vmware_harden.collectors.base import CollectorError

    db = str(tmp_path / "t.duckdb")
    bad = [{"name": "noid"}]  # missing 'id' triggers CollectorError
    with patch("vmware_harden.collectors.hosts._fetch_hosts", return_value=bad):
        with pytest.raises(CollectorError):
            run_scan(target="lab", baseline="cis-vmware-esxi-8.0-subset", db=db)

    # If Twin wasn't closed, a second connection would either fail
    # or see stale state; verify we can re-open the file cleanly.
    from vmware_harden.store.twin import Twin
    twin2 = Twin(Path(db))
    rows = twin2.conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()
    assert rows[0] == 1  # the failed scan still wrote a snapshot row
    twin2.close()


@pytest.mark.integration
def test_report_empty_twin_helpful_message(tmp_path: Path, capsys):
    """report against an empty Twin should guide the user, not show 'No violations'."""
    db = str(tmp_path / "empty.duckdb")
    run_report(db=db, format="text")
    out = capsys.readouterr().out
    assert "No scans yet" in out
    assert "vmware-harden scan" in out


@pytest.mark.integration
def test_scan_dispatches_multiple_collectors_for_dengbao(tmp_path: Path, capsys):
    """Scanning with the 等保 baseline (host+vm+datastore+dfw_rule) must invoke all 4 collectors."""
    db = str(tmp_path / "t.duckdb")

    one_host = [
        {"id": "h-1", "name": "esx", "ntp_enabled": True, "build": 99999999,
         "ntp_servers": ["10.0.0.1"], "ntp_service_policy": "on",
         "lockdown_mode": "normal", "syslog_remote_host": "syslog.lab",
         "persistent_logs": True, "audit_retention_days": 200,
         "mgmt_vmk_isolated": True, "vswitch_promiscuous_mode": "reject",
         "forged_transmits": "reject", "firewall_enabled": True,
         "ssh_running": False, "ad_joined": True,
         "lockdown_exceptions_count": 0, "root_ssh_key_auth": False,
         "vsan_enabled": False, "vsan_encryption_enabled": False,
         "encrypted_vmotion": "required", "dcui_timeout_seconds": 600,
         "shell_timeout_seconds": 900, "console_keyboard": "US Default",
         "host_secure_boot": True, "host_tpm_attested": True,
         "tls_min_version": "1.2"},
    ]
    one_vm = [
        {"id": "vm-1", "name": "v", "host_id": "h-1", "tools_running": True,
         "secure_boot": True, "encryption_enabled": False, "tags": []},
    ]
    one_ds = [
        {"id": "ds-1", "name": "d", "type": "vmfs", "capacity_gb": 100,
         "free_gb": 50, "encryption_enabled": True, "ssd": True},
    ]
    one_dfw = {
        "sections": [{"id": "s-1", "name": "S"}],
        "rules": [{"id": "r-1", "name": "deny", "section_id": "s-1",
                   "action": "reject", "source": ["ANY"], "destination": ["ANY"],
                   "services": ["ANY"], "applied_to": [], "hit_count": 0,
                   "disabled": False}],
    }

    with patch("vmware_harden.collectors.hosts._fetch_hosts", return_value=one_host), \
         patch("vmware_harden.collectors.vms._fetch_vms", return_value=one_vm), \
         patch("vmware_harden.collectors.datastores._fetch_datastores",
               return_value=one_ds), \
         patch("vmware_harden.collectors.dfw._fetch_dfw", return_value=one_dfw):
        run_scan(target="lab", baseline="dengbao-2.0-level3-vmware", db=db)

    out = capsys.readouterr().out
    # All 4 collector summaries should appear
    assert "host" in out.lower()
    assert "vm" in out.lower()
    assert "datastore" in out.lower()
    assert ("dfw" in out.lower()) or ("dfw_rule" in out.lower())
