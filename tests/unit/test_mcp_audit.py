"""Verify MCP tool calls write audit rows via vmware_policy.@vmware_tool."""
from pathlib import Path

import pytest


@pytest.fixture
def audit_db_in_tmp(tmp_path: Path, monkeypatch):
    """Redirect vmware_policy audit DB to tmp_path and reset the singleton."""
    from vmware_policy import audit as audit_mod

    db = tmp_path / "audit.db"
    monkeypatch.setattr(audit_mod, "_DEFAULT_DB", db)
    monkeypatch.setattr(audit_mod, "_engine", None)
    yield db
    # Reset engine so subsequent tests get a fresh one
    monkeypatch.setattr(audit_mod, "_engine", None)


@pytest.mark.unit
def test_list_baselines_writes_audit_row(audit_db_in_tmp):
    """After calling list_baselines, an audit row exists for it."""
    from vmware_harden.mcp import tools as srv

    srv.list_baselines()

    assert audit_db_in_tmp.exists(), f"audit.db not created at {audit_db_in_tmp}"

    import sqlite3

    conn = sqlite3.connect(audit_db_in_tmp)
    rows = conn.execute(
        "SELECT skill, tool FROM audit_log WHERE tool = 'list_baselines'"
    ).fetchall()
    conn.close()
    assert len(rows) >= 1
    assert rows[0][1] == "list_baselines"
    # Skill should be inferred from module path (vmware_harden.mcp.tools → harden)
    assert rows[0][0] == "harden", f"expected skill=harden, got {rows[0][0]!r}"


@pytest.mark.unit
def test_get_baseline_rules_audited(audit_db_in_tmp):
    from vmware_harden.mcp import tools as srv

    srv.get_baseline_rules("cis-vmware-esxi-8.0-subset")

    assert audit_db_in_tmp.exists()
    import sqlite3

    conn = sqlite3.connect(audit_db_in_tmp)
    rows = conn.execute(
        "SELECT tool, status FROM audit_log WHERE tool = 'get_baseline_rules'"
    ).fetchall()
    conn.close()
    assert len(rows) >= 1
    assert rows[0][1] == "ok"
