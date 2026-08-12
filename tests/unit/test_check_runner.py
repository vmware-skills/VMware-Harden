"""CheckRunner unit tests against in-memory Twin."""
import json
from pathlib import Path

import pytest

from vmware_harden.baselines.loader import load_builtin
from vmware_harden.baselines.model import Baseline, QueryCheck, Remediation, Rule
from vmware_harden.checks.runner import CheckRunner
from vmware_harden.store.twin import Twin


def _insert_host(
    twin: Twin,
    host_id: str,
    name: str,
    attrs: dict,
    snapshot_id: str | None = None,
    target: str = "v.lab",
) -> None:
    twin.conn.execute(
        "INSERT INTO nodes (id, type, target, name, attrs) VALUES (?, 'host', ?, ?, ?)",
        [host_id, target, name, json.dumps(attrs)],
    )
    if snapshot_id is not None:
        # Mirror collectors: nodes observed in a scan also get a node_state
        # row, which CheckRunner uses to scope violations to the snapshot.
        twin.write_node_state(snapshot_id, host_id, attrs)


@pytest.mark.unit
def test_runner_detects_ntp_violation_on_noncompliant_host(tmp_path: Path):
    """Host with ntp_enabled=false should be flagged by CIS rule 2.1.1."""
    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")
    _insert_host(
        twin, "host-01", "esx01",
        {"ntp_enabled": True, "esxi_build": 99999999}, snapshot_id=snap_id,
    )
    _insert_host(
        twin, "host-02", "esx02",
        {"ntp_enabled": False, "esxi_build": 99999999}, snapshot_id=snap_id,
    )

    baseline = load_builtin("cis-vmware-esxi-8.0-subset")
    runner = CheckRunner(twin)
    violations = runner.run_baseline(snap_id, baseline)

    pairs = {(v["rule_id"], v["node_id"]) for v in violations}
    assert ("cis-esxi-2.1.1", "host-02") in pairs
    assert ("cis-esxi-2.1.1", "host-01") not in pairs
    twin.close()


@pytest.mark.unit
def test_violations_persisted_to_db(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")
    _insert_host(
        twin, "host-02", "esx02",
        {"ntp_enabled": False, "esxi_build": 99999999}, snapshot_id=snap_id,
    )

    baseline = load_builtin("cis-vmware-esxi-8.0-subset")
    CheckRunner(twin).run_baseline(snap_id, baseline)

    rows = twin.conn.execute(
        "SELECT rule_id, node_id, severity, baseline_id FROM violation "
        "WHERE snapshot_id = ?",
        [snap_id],
    ).fetchall()
    assert any(
        r[0] == "cis-esxi-2.1.1" and r[1] == "host-02" and r[2] == "medium"
        and r[3] == "cis-vmware-esxi-8.0-subset"
        for r in rows
    )
    twin.close()


_FULLY_COMPLIANT_HOST_ATTRS = {
    # time-sync
    "ntp_enabled": True,
    "ntp_service_policy_on": True,
    # patching
    "esxi_build": 99999999,
    "lockdown_mode_enabled": True,
    # logging
    "syslog_remote_host": "syslog.lab.local:514",
    "persistent_logs": True,
    "audit_retention_days": 90,
    # network
    "mgmt_vmk_isolated": True,
    "vswitch_promiscuous_mode": "reject",
    "forged_transmits": "reject",
    # firewall
    "firewall_enabled": True,
    "ssh_running": False,
    # auth
    "ad_joined": True,
    "lockdown_exceptions_count": 0,
    "root_ssh_key_auth": False,
    # encryption
    "vsan_enabled": False,
    "vsan_encryption_enabled": False,
    "encrypted_vmotion": "required",
    # misc
    "dcui_timeout_seconds": 600,
    "shell_timeout_seconds": 900,
    "console_keyboard": "US Default",
}


@pytest.mark.unit
def test_compliant_estate_yields_zero_violations(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")
    _insert_host(twin, "host-ok", "esx-ok", _FULLY_COMPLIANT_HOST_ATTRS, snapshot_id=snap_id)

    baseline = load_builtin("cis-vmware-esxi-8.0-subset")
    violations = CheckRunner(twin).run_baseline(snap_id, baseline)

    assert violations == []
    twin.close()


@pytest.mark.unit
def test_violation_evidence_includes_query_row(tmp_path: Path):
    """The evidence column should contain the row that matched the query."""
    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")
    _insert_host(
        twin, "host-02", "esx02",
        {"ntp_enabled": False, "esxi_build": 99999999}, snapshot_id=snap_id,
    )

    baseline = load_builtin("cis-vmware-esxi-8.0-subset")
    CheckRunner(twin).run_baseline(snap_id, baseline)

    row = twin.conn.execute(
        "SELECT evidence FROM violation WHERE rule_id = 'cis-esxi-2.1.1' "
        "AND node_id = 'host-02'"
    ).fetchone()
    evidence = json.loads(row[0])
    assert evidence["id"] == "host-02"
    assert evidence["name"] == "esx02"
    twin.close()


@pytest.mark.unit
def test_runner_returns_per_violation_metadata(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")
    _insert_host(twin, "h-1", "n", {"ntp_enabled": False, "esxi_build": 1}, snapshot_id=snap_id)

    baseline = load_builtin("cis-vmware-esxi-8.0-subset")
    violations = CheckRunner(twin).run_baseline(snap_id, baseline)

    # Both rules should fire on this host (NTP off + outdated build)
    rule_ids = {v["rule_id"] for v in violations}
    assert {"cis-esxi-2.1.1", "cis-esxi-2.2.1"}.issubset(rule_ids)

    # Each violation has the canonical fields
    for v in violations:
        assert "id" in v
        assert "snapshot_id" in v
        assert "rule_id" in v
        assert "node_id" in v
        assert "severity" in v
        assert "evidence" in v
    twin.close()


@pytest.mark.unit
def test_runner_skips_script_checks(tmp_path: Path):
    """ScriptCheck never executes (loader rejects, but defensive in runner)."""
    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")

    # Hand-craft a baseline (skip loader so ScriptCheck reaches runner)
    baseline = Baseline(
        id="b", name="b", version="1.0",
        applies_to=["host"],
        rules=[
            Rule(
                id="script-rule",
                title="x",
                severity="low",
                category="x",
                check={"type": "script", "module": "m", "function": "f"},
                remediation=Remediation(summary="x"),
            )
        ],
    )
    violations = CheckRunner(twin).run_baseline(snap_id, baseline)
    assert violations == []  # script check silently skipped
    twin.close()


@pytest.mark.unit
def test_runner_duplicates_violations_on_rerun(tmp_path: Path):
    """Pin current behavior: re-running creates duplicate violation rows.

    Each call generates fresh uuids, so this is observable. v2 may add a
    unique constraint to deduplicate; for MVP the runner is single-shot
    per (snapshot, baseline).
    """
    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")
    _insert_host(
        twin, "host-02", "esx02",
        {"ntp_enabled": False, "esxi_build": 99999999}, snapshot_id=snap_id,
    )

    baseline = load_builtin("cis-vmware-esxi-8.0-subset")
    runner = CheckRunner(twin)
    runner.run_baseline(snap_id, baseline)
    runner.run_baseline(snap_id, baseline)

    count = twin.conn.execute(
        "SELECT COUNT(*) FROM violation WHERE rule_id = 'cis-esxi-2.1.1' "
        "AND node_id = 'host-02'"
    ).fetchone()[0]
    assert count == 2  # current MVP behavior — duplicates allowed
    twin.close()


@pytest.mark.unit
def test_violations_scoped_to_snapshot_nodes_not_other_targets(tmp_path: Path):
    """Regression (#1): scanning target A must not attribute violations from
    target B's (or decommissioned) nodes still present in the cumulative
    `nodes` table."""
    twin = Twin(tmp_path / "t.duckdb")

    # Target B was scanned earlier; its non-compliant node lives in `nodes`.
    snap_b = twin.start_snapshot("vcenter-b.lab")
    _insert_host(
        twin, "host-b1", "esxb1",
        {"ntp_enabled": False, "esxi_build": 1},
        snapshot_id=snap_b, target="vcenter-b.lab",
    )
    twin.finish_snapshot(snap_b)

    # Now scan target A — only A's node is observed in this snapshot.
    snap_a = twin.start_snapshot("vcenter-a.lab")
    _insert_host(
        twin, "host-a1", "esxa1",
        {"ntp_enabled": False, "esxi_build": 1},
        snapshot_id=snap_a, target="vcenter-a.lab",
    )

    baseline = load_builtin("cis-vmware-esxi-8.0-subset")
    violations = CheckRunner(twin).run_baseline(snap_a, baseline)

    node_ids = {v["node_id"] for v in violations}
    assert "host-a1" in node_ids
    assert "host-b1" not in node_ids  # B's node must not leak into A's scan
    # And nothing was persisted for B under A's snapshot either.
    persisted = {
        r[0]
        for r in twin.conn.execute(
            "SELECT node_id FROM violation WHERE snapshot_id = ?", [snap_a]
        ).fetchall()
    }
    assert persisted == {"host-a1"}
    twin.close()


@pytest.mark.unit
def test_absence_check_synthetic_id_violation_is_emitted(tmp_path: Path):
    """Regression (data-loss): "control entirely absent" rules emit a SYNTHETIC
    CONSTANT id (e.g. `SELECT 'pci-default-deny-missing' AS id ... WHERE NOT
    EXISTS(...)`) that is never a scanned node in node_state. The snapshot-
    scoping filter must NOT drop these — otherwise the most severe estate-wide
    gaps (no default-deny firewall) silently report CLEAN.

    Seeds an empty-DFW estate (a host in node_state for snapshot A, no deny
    rule) and asserts the CRITICAL pci-default-deny-missing violation IS
    emitted. This test FAILS under a plain `node_id not in snapshot_node_ids`
    set-membership filter (the synthetic id is filtered out)."""
    twin = Twin(tmp_path / "t.duckdb")
    snap_a = twin.start_snapshot("vcenter-a.lab")
    # A real scanned host lives in node_state; no DFW deny rule anywhere.
    _insert_host(
        twin, "host-a1", "esxa1",
        {"ntp_enabled": True, "esxi_build": 99999999},
        snapshot_id=snap_a, target="vcenter-a.lab",
    )

    baseline = load_builtin("pci-dss-4.0-vmware")
    violations = CheckRunner(twin).run_baseline(snap_a, baseline)

    # The synthetic-id absence violation must survive the snapshot filter.
    pairs = {(v["rule_id"], v["node_id"]) for v in violations}
    assert ("pci-r1-2", "pci-default-deny-missing") in pairs
    crit = next(
        v for v in violations
        if v["node_id"] == "pci-default-deny-missing"
    )
    assert crit["severity"] == "critical"
    # And it was persisted under this snapshot.
    persisted = {
        r[0]
        for r in twin.conn.execute(
            "SELECT node_id FROM violation WHERE snapshot_id = ? AND rule_id = ?",
            [snap_a, "pci-r1-2"],
        ).fetchall()
    }
    assert "pci-default-deny-missing" in persisted
    twin.close()


@pytest.mark.unit
def test_violation_evidence_includes_rule_category_and_title(tmp_path: Path):
    """Regression (#6): evidence must carry rule category/title so the web
    dashboard category chart works without a rule lookup."""
    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")
    _insert_host(
        twin, "host-02", "esx02",
        {"ntp_enabled": False, "esxi_build": 99999999}, snapshot_id=snap_id,
    )

    baseline = load_builtin("cis-vmware-esxi-8.0-subset")
    CheckRunner(twin).run_baseline(snap_id, baseline)

    rule = next(r for r in baseline.rules if r.id == "cis-esxi-2.1.1")
    row = twin.conn.execute(
        "SELECT evidence FROM violation WHERE rule_id = 'cis-esxi-2.1.1' "
        "AND node_id = 'host-02'"
    ).fetchone()
    evidence = json.loads(row[0])
    assert evidence["category"] == rule.category
    assert evidence["title"] == rule.title
    twin.close()
