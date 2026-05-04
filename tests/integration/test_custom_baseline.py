"""End-to-end: import custom baseline extending CIS, scan, verify."""
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from vmware_harden.baselines import loader
from vmware_harden.cli.main import app
from vmware_harden.cli.runner import run_report, run_scan

cli = CliRunner()


@pytest.mark.integration
def test_custom_baseline_import_then_scan(tmp_path: Path, monkeypatch, capsys):
    # 1. Set up isolated user baselines dir (so we don't pollute real ~/.vmware-harden)
    user_dir = tmp_path / "user"
    monkeypatch.setattr(loader, "USER_DIR", user_dir)

    # 2. Write a child baseline that:
    #    - extends cis-vmware-esxi-8.0-subset (20 rules)
    #    - overrides cis-esxi-2.1.1 (NTP) with a stricter critical severity
    #    - adds a new rule cust-1 that flags hosts with build > 999999998 (always fires
    #      on our test data so we can assert "new rule fired")
    custom_yaml = tmp_path / "my-strict.yaml"
    custom_yaml.write_text(textwrap.dedent("""
        id: my-strict-cis
        name: My Strict CIS (extends CIS subset)
        version: 1.0.0
        extends: cis-vmware-esxi-8.0-subset
        applies_to: [host]
        rules:
          - id: cis-esxi-2.1.1
            title: NTP must be enabled (STRICTER — was medium)
            severity: critical
            category: time-sync
            check:
              type: query
              sql: |
                SELECT id, name FROM nodes
                WHERE type = 'host'
                  AND CAST(json_extract(attrs, '$.ntp_enabled') AS BOOLEAN) = false
            remediation:
              summary: Enable NTP
            review_policy:
              human_review_required: true
              min_confidence: 0.99
          - id: cust-tag-required
            title: Hosts must carry a 'managed_by' tag
            severity: high
            category: governance
            check:
              type: query
              sql: |
                SELECT id, name FROM nodes
                WHERE type = 'host'
                  AND (json_extract_string(attrs, '$.managed_by') IS NULL
                       OR json_extract_string(attrs, '$.managed_by') = '')
            remediation:
              summary: Tag hosts with managed_by
    """).strip())

    # 3. Import via CLI (use --name so destination stem matches baseline id for lookup)
    result = cli.invoke(
        app, ["baseline", "import", str(custom_yaml), "--name", "my-strict-cis"]
    )
    assert result.exit_code == 0, f"import failed: {result.output}"
    assert (user_dir / "my-strict-cis.yaml").exists()

    # 4. Scan a fixture estate where:
    #    - host-bad has ntp_enabled=False (fires cis-esxi-2.1.1 — overridden, severity=critical)
    #                   AND no managed_by (fires cust-tag-required)
    db = str(tmp_path / "scan.duckdb")
    hosts = [
        {
            "id": "host-bad", "name": "esx-bad",
            "ntp_enabled": False,        # triggers stricter NTP rule
            "build": 99999999,
            "ntp_servers": [], "ntp_service_policy": "on",
            "lockdown_mode": "normal",
            "syslog_remote_host": "syslog.lab",
            "persistent_logs": True, "audit_retention_days": 90,
            "mgmt_vmk_isolated": True,
            "vswitch_promiscuous_mode": "reject",
            "forged_transmits": "reject",
            "firewall_enabled": True, "ssh_running": False,
            "ad_joined": True, "lockdown_exceptions_count": 0,
            "root_ssh_key_auth": False,
            "vsan_enabled": False, "vsan_encryption_enabled": False,
            "encrypted_vmotion": "required",
            "dcui_timeout_seconds": 600, "shell_timeout_seconds": 900,
            "console_keyboard": "US Default",
            # NOTE: no managed_by field — triggers cust-tag-required
        },
    ]

    with patch("vmware_harden.collectors.hosts._fetch_hosts", return_value=hosts):
        run_scan(target="lab", baseline="my-strict-cis", db=db)
    capsys.readouterr()  # discard scan output

    # 5. Run report and verify both rules fired with correct severities
    run_report(db=db, format="json")
    import json as _json
    payload = _json.loads(capsys.readouterr().out)

    by_rule = {(v["rule"], v["node"]): v for v in payload}

    # Overridden rule: cis-esxi-2.1.1, severity is now CRITICAL (was medium in parent)
    assert ("cis-esxi-2.1.1", "lab:host-bad") in by_rule
    assert by_rule[("cis-esxi-2.1.1", "lab:host-bad")]["severity"] == "critical"

    # New rule fires
    assert ("cust-tag-required", "lab:host-bad") in by_rule
    assert by_rule[("cust-tag-required", "lab:host-bad")]["severity"] == "high"

    # Inherited rules from parent still apply (e.g., NTP-related are now consolidated
    # under the override; but other parent rules like 2.2.1 don't fire because build is OK).
    # Verify count: 1 host with NTP off + missing managed_by = 2 violations from these 2 rules.
    # Plus any other parent rules that happen to fire on this fixture host. Most parent
    # rules have a "good" config in this fixture, so we assert >= 2 (the two we know fire).
    assert len(payload) >= 2


@pytest.mark.integration
def test_custom_baseline_validate_then_import(tmp_path: Path, monkeypatch):
    """`baseline validate` and `baseline import` work together cleanly."""
    user_dir = tmp_path / "user"
    monkeypatch.setattr(loader, "USER_DIR", user_dir)

    yaml_path = tmp_path / "v.yaml"
    yaml_path.write_text(textwrap.dedent("""
        id: v
        name: V
        version: 1.0.0
        applies_to: [host]
        rules:
          - id: r1
            title: x
            severity: low
            category: x
            check: {type: query, sql: "SELECT 1"}
            remediation: {summary: y}
    """).strip())

    # 1. validate succeeds
    result = cli.invoke(app, ["baseline", "validate", str(yaml_path)])
    assert result.exit_code == 0, result.output
    assert "OK" in result.output

    # 2. import succeeds
    result = cli.invoke(app, ["baseline", "import", str(yaml_path)])
    assert result.exit_code == 0

    # 3. baseline list now includes it
    result = cli.invoke(app, ["baseline", "list"])
    assert "v" in result.output  # 'v' is the file stem
