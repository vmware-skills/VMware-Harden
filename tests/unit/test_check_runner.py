"""CheckRunner unit tests against in-memory Twin."""
import json
from pathlib import Path

import pytest

from vmware_harden.baselines.loader import load_builtin
from vmware_harden.baselines.model import Baseline, QueryCheck, Remediation, Rule
from vmware_harden.checks.runner import CheckRunner
from vmware_harden.store.twin import Twin


def _insert_host(twin: Twin, host_id: str, name: str, attrs: dict) -> None:
    twin.conn.execute(
        "INSERT INTO nodes (id, type, name, attrs) VALUES (?, 'host', ?, ?)",
        [host_id, name, json.dumps(attrs)],
    )


@pytest.mark.unit
def test_runner_detects_ntp_violation_on_noncompliant_host(tmp_path: Path):
    """Host with ntp_enabled=false should be flagged by CIS rule 2.1.1."""
    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")
    _insert_host(twin, "host-01", "esx01", {"ntp_enabled": True, "build": 99999999})
    _insert_host(twin, "host-02", "esx02", {"ntp_enabled": False, "build": 99999999})

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
    _insert_host(twin, "host-02", "esx02", {"ntp_enabled": False, "build": 99999999})

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


@pytest.mark.unit
def test_compliant_estate_yields_zero_violations(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")
    _insert_host(twin, "host-ok", "esx-ok",
                 {"ntp_enabled": True, "build": 99999999})

    baseline = load_builtin("cis-vmware-esxi-8.0-subset")
    violations = CheckRunner(twin).run_baseline(snap_id, baseline)

    assert violations == []
    twin.close()


@pytest.mark.unit
def test_violation_evidence_includes_query_row(tmp_path: Path):
    """The evidence column should contain the row that matched the query."""
    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")
    _insert_host(twin, "host-02", "esx02", {"ntp_enabled": False, "build": 99999999})

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
    _insert_host(twin, "h-1", "n", {"ntp_enabled": False, "build": 1})

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
