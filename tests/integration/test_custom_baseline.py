"""End-to-end: import custom baseline extending CIS, scan, verify."""
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from vmware_harden.baselines import loader
from vmware_harden.cli.main import app
from vmware_harden.cli.runner import run_report, run_scan
from vmware_harden.store.twin import Twin

cli = CliRunner()


@pytest.mark.integration
def test_custom_baseline_import_then_scan(tmp_path: Path, monkeypatch, capsys):
    # 1. Set up isolated user baselines dir (so we don't pollute real ~/.vmware-harden)
    user_dir = tmp_path / "user"
    monkeypatch.setattr(loader, "USER_DIR", user_dir)

    # 2. Write a child baseline that:
    #    - extends cis-vmware-esxi-8.0-subset (20 rules)
    #    - overrides cis-esxi-3.1.1 (remote syslog) with a stricter critical severity
    #    - adds cust-tag-required, which reads an attribute no collector produces
    #
    # The override deliberately targets a rule whose attribute IS collected, so it
    # really fires. cust-tag-required deliberately targets one that is not, so the
    # runner records it undetermined — the protection that matters most for user
    # baselines, which CI never sees. Before this existed, such a rule matched zero
    # rows and the report counted it as a pass.
    custom_yaml = tmp_path / "my-strict.yaml"
    custom_yaml.write_text(textwrap.dedent("""
        id: my-strict-cis
        name: My Strict CIS (extends CIS subset)
        version: 1.0.0
        extends: cis-vmware-esxi-8.0-subset
        applies_to: [host]
        rules:
          - id: cis-esxi-3.1.1
            title: Remote syslog must be configured (STRICTER — was high)
            severity: critical
            category: logging
            check:
              type: query
              sql: |
                SELECT id, name FROM nodes
                WHERE type = 'host'
                  AND (json_extract_string(attrs, '$.syslog_remote_host') IS NULL
                       OR json_extract_string(attrs, '$.syslog_remote_host') = '')
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
    #    - host-bad has no remote syslog (fires cis-esxi-3.1.1 — overridden, critical)
    #                   AND no managed_by (cust-tag-required → undetermined, not a pass)
    db = str(tmp_path / "scan.duckdb")
    hosts = [
        {
            "id": "host-bad", "name": "esx-bad",
            "esxi_build": 99999999,
            "ntp_servers": [], "ntp_service_policy": "on",
            "lockdown_mode": "normal",
            "syslog_remote_host": "",    # triggers the stricter syslog rule
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

    by_rule = {(v["rule"], v["node"]): v for v in payload["violations"]}

    # Overridden rule: cis-esxi-3.1.1, severity is now CRITICAL (was high in parent)
    assert ("cis-esxi-3.1.1", "lab:host-bad") in by_rule
    assert by_rule[("cis-esxi-3.1.1", "lab:host-bad")]["severity"] == "critical"

    # The custom rule reads $.managed_by, which no collector writes. It must NOT
    # appear as a violation — and, more importantly, must not be counted as a pass
    # either. It is recorded undetermined, with a reason naming the attribute.
    assert ("cust-tag-required", "lab:host-bad") not in by_rule

    twin = Twin(Path(db))
    outcome, reason = twin.conn.execute(
        "SELECT outcome, reason FROM rule_outcome WHERE rule_id = 'cust-tag-required'"
    ).fetchone()
    twin.close()
    assert outcome == "undetermined"
    assert "managed_by" in reason

    assert len(payload) >= 1


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
