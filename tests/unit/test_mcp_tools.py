"""Tests for the additional MCP read tools."""
import json
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from vmware_harden.store.twin import Twin


def _seed_db(tmp_path: Path):
    """Build a Twin with a host, snapshot, violation, and a change event."""
    db = tmp_path / "t.duckdb"
    twin = Twin(db)
    snap = twin.start_snapshot("v.lab")
    twin.conn.execute(
        "INSERT INTO nodes (id, type, target, name, attrs) "
        "VALUES (?, 'host', 'v.lab', 'esx', ?)",
        ["v.lab:h-1", json.dumps({"ntp_enabled": False})],
    )
    vid = str(uuid.uuid4())
    twin.conn.execute(
        """INSERT INTO violation
           (id, snapshot_id, baseline_id, rule_id, node_id, severity, evidence)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        [vid, snap, "b", "r-1", "v.lab:h-1", "high", "{}"],
    )
    twin.conn.execute(
        """INSERT INTO change_event (id, snapshot_id, node_id, field, old_value, new_value)
           VALUES (?, ?, ?, ?, ?, ?)""",
        [str(uuid.uuid4()), snap, "v.lab:h-1", "ntp_enabled", "True", "False"],
    )
    twin.finish_snapshot(snap)
    twin.close()
    return db, vid


@pytest.mark.unit
def test_list_violations(tmp_path: Path):
    db, vid = _seed_db(tmp_path)
    from vmware_harden.mcp import tools as srv
    srv._DB_PATH = db
    out = srv.list_violations()
    assert any(v["id"] == vid and v["severity"] == "high" for v in out)


@pytest.mark.unit
def test_list_violations_severity_filter(tmp_path: Path):
    db, _ = _seed_db(tmp_path)
    from vmware_harden.mcp import tools as srv
    srv._DB_PATH = db
    high_only = srv.list_violations(severity="high")
    assert all(v["severity"] == "high" for v in high_only)
    crit_only = srv.list_violations(severity="critical")
    assert crit_only == []


@pytest.mark.unit
def test_get_remediation_returns_none_when_missing(tmp_path: Path):
    db, vid = _seed_db(tmp_path)
    from vmware_harden.mcp import tools as srv
    srv._DB_PATH = db
    assert srv.get_remediation(vid) is None


@pytest.mark.unit
def test_get_remediation_returns_dict_when_present(tmp_path: Path):
    db, vid = _seed_db(tmp_path)

    twin = Twin(db)
    from vmware_harden.baselines.model import (
        ExecutionPlan, ImpactPrediction, Suggestion,
    )
    sugg = Suggestion(
        summary="x",
        execution_plan=ExecutionPlan(steps=[]),
        impact_prediction=ImpactPrediction(
            affects_running_workload=False,
            requires_maintenance_window=False,
        ),
        confidence=0.5,
        human_review_required=True,
    )
    twin.save_suggestion(vid, sugg)
    twin.close()

    from vmware_harden.mcp import tools as srv
    srv._DB_PATH = db
    out = srv.get_remediation(vid)
    assert out is not None
    assert out["summary"] == "x"
    assert out["confidence"] == 0.5


@pytest.mark.unit
def test_list_drift_events(tmp_path: Path):
    db, _ = _seed_db(tmp_path)
    from vmware_harden.mcp import tools as srv
    srv._DB_PATH = db
    events = srv.list_drift_events()
    assert any(e["field"] == "ntp_enabled" for e in events)


@pytest.mark.unit
def test_get_baseline_rules():
    from vmware_harden.mcp import tools as srv
    rules = srv.get_baseline_rules("cis-vmware-esxi-8.0-subset")
    assert len(rules) == 20
    assert all("id" in r and "title" in r and "severity" in r for r in rules)


@pytest.mark.unit
def test_scan_target_invokes_collectors(tmp_path: Path):
    db = tmp_path / "scan.duckdb"
    fake_hosts = [
        {"id": "h-1", "name": "esx", "ntp_enabled": True, "build": 99999999,
         "ntp_servers": [], "ntp_service_policy": "on", "lockdown_mode": "normal",
         "syslog_remote_host": "syslog", "persistent_logs": True,
         "audit_retention_days": 90, "mgmt_vmk_isolated": True,
         "vswitch_promiscuous_mode": "reject", "forged_transmits": "reject",
         "firewall_enabled": True, "ssh_running": False, "ad_joined": True,
         "lockdown_exceptions_count": 0, "root_ssh_key_auth": False,
         "vsan_enabled": False, "vsan_encryption_enabled": False,
         "encrypted_vmotion": "required", "dcui_timeout_seconds": 600,
         "shell_timeout_seconds": 900, "console_keyboard": "US Default"},
    ]
    from vmware_harden.mcp import tools as srv
    srv._DB_PATH = db
    with patch("vmware_harden.collectors.hosts._fetch_hosts", return_value=fake_hosts):
        out = srv.scan_target(target="lab", baseline="cis-vmware-esxi-8.0-subset")
    assert "snapshot_id" in out
    assert out.get("hosts") == 1
    assert "violations" in out
