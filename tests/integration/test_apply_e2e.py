"""End-to-end: scan → advise → apply (mocked pilot) → verify task_id persisted."""
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from vmware_harden.cli.main import app
from vmware_harden.cli.runner import run_scan
from vmware_harden.store.twin import Twin


cli = CliRunner()


def _full_compliant_host(host_id: str, compliant: bool) -> dict:
    """A host compliant on every CIS rule except, optionally, remote syslog.

    The single non-compliance used to be ``ntp_enabled=False``, but that rule
    reads an attribute no collector writes, so it is now recorded undetermined
    rather than executed and the scan had nothing to advise on. ``syslog_remote_host``
    is collected for real (it is one of the advanced settings the host collector
    fetches), and like the old NTP rule its remediation needs no human review —
    so this flow still exercises apply's straight-through path rather than the
    approval gate.

    ``build`` was also the wrong key — rule 2.2.1 reads ``$.esxi_build``; the old
    spelling made this fixture's "current build" claim unfalsifiable.
    """
    return {
        "id": host_id, "name": f"esx-{host_id}",
        "esxi_build": 99999999,
        "ntp_servers": [], "ntp_service_policy": "on",
        "lockdown_mode": "normal",
        "syslog_remote_host": "syslog.lab" if compliant else "",
        "persistent_logs": True, "audit_retention_days": 90,
        "mgmt_vmk_isolated": True, "vswitch_promiscuous_mode": "reject",
        "forged_transmits": "reject", "firewall_enabled": True,
        "ssh_running": False, "ad_joined": True,
        "lockdown_exceptions_count": 0, "root_ssh_key_auth": False,
        "vsan_enabled": False, "vsan_encryption_enabled": False,
        "encrypted_vmotion": "required", "dcui_timeout_seconds": 600,
        "shell_timeout_seconds": 900, "console_keyboard": "US Default",
    }


CANNED = json.dumps({
    "summary": "Configure NTP",
    "execution_plan": {"steps": [{"step": 1, "mcp_tool": "vmware_aiops.host_ntp_configure",
                                  "params": {"servers": ["ntp1"]}}]},
    "impact_prediction": {
        "affects_running_workload": False,
        "requires_maintenance_window": False,
    },
    "confidence": 0.9,
    "human_review_required": False,
})


@pytest.mark.integration
def test_scan_advise_apply_e2e(tmp_path: Path, monkeypatch, capsys):
    """Run the full M3 user flow against a mocked vCenter + mocked LLM + mocked pilot."""
    db = str(tmp_path / "e2e.duckdb")

    # Step 1: scan with remote syslog unset → at least one violation
    with patch(
        "vmware_harden.collectors.hosts._fetch_hosts",
        return_value=[_full_compliant_host("h-1", compliant=False)],
    ):
        run_scan(target="lab", baseline="cis-vmware-esxi-8.0-subset", db=db)
    capsys.readouterr()

    # Get the syslog violation id
    twin = Twin(Path(db))
    rows = twin.conn.execute(
        "SELECT id FROM violation WHERE rule_id = 'cis-esxi-3.1.1' "
        "AND node_id = 'lab:h-1'"
    ).fetchall()
    twin.close()
    assert len(rows) == 1
    vid = rows[0][0]

    # Step 2: advise (mock LLM)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    import vmware_harden.cli.advise as advise_mod
    from vmware_harden.advisor.llm import MockProvider
    monkeypatch.setattr(
        advise_mod, "_get_provider",
        lambda: MockProvider(canned_response=CANNED),
    )
    result = cli.invoke(app, ["advise", "--db", db, "--violation-id", vid])
    assert result.exit_code == 0

    # Step 3: apply (mocked pilot — default mode)
    result = cli.invoke(app, ["apply", "--db", db, "--violation-id", vid])
    assert result.exit_code == 0
    assert "mock-pilot-" in result.output

    # Step 4: verify pilot_task_id persisted
    twin = Twin(Path(db))
    row = twin.conn.execute(
        "SELECT pilot_task_id FROM remediation WHERE violation_id = ?", [vid]
    ).fetchone()
    twin.close()
    assert row[0] is not None
    assert row[0].startswith("mock-pilot-")


@pytest.mark.integration
def test_apply_without_existing_suggestion_invokes_advisor(tmp_path: Path, monkeypatch):
    """If no Suggestion exists when apply is called, Advisor generates one inline."""
    db = str(tmp_path / "e2e2.duckdb")

    with patch(
        "vmware_harden.collectors.hosts._fetch_hosts",
        return_value=[_full_compliant_host("h-1", compliant=False)],
    ):
        run_scan(target="lab", baseline="cis-vmware-esxi-8.0-subset", db=db)

    twin = Twin(Path(db))
    rows = twin.conn.execute(
        "SELECT id FROM violation WHERE rule_id = 'cis-esxi-3.1.1' "
        "AND node_id = 'lab:h-1'"
    ).fetchall()
    twin.close()
    vid = rows[0][0]

    # Patch the apply CLI's LLM provider factory
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    import vmware_harden.cli.apply as apply_mod
    from vmware_harden.advisor.llm import MockProvider
    monkeypatch.setattr(
        apply_mod, "_get_llm_provider",
        lambda: MockProvider(canned_response=CANNED),
    )

    # apply without prior advise — should generate Suggestion via Advisor first
    result = cli.invoke(app, ["apply", "--db", db, "--violation-id", vid])
    assert result.exit_code == 0
    assert "mock-pilot-" in result.output

    # Suggestion was persisted
    twin = Twin(Path(db))
    s = twin.get_suggestion(vid)
    twin.close()
    assert s is not None
