"""The advisory catalog as a scannable baseline (`vmsa-advisories`).

Integration of :mod:`vmware_harden.advisories` with the existing engine: one
rule per advisory, verdicts written to the same violation / rule_outcome /
rule_node_gap tables every report already reads, and every "could not say"
recorded as undetermined — never as a pass.
"""

import json
from pathlib import Path

import pytest

from vmware_harden.advisories.baseline import (
    ADVISORY_BASELINE_ID,
    advisory_baseline,
    judge_nodes,
)
from vmware_harden.advisories.catalog import load_catalog
from vmware_harden.baselines.loader import list_builtins, load_all_baselines, load_builtin
from vmware_harden.baselines.model import AdvisoryCheck
from vmware_harden.checks.runner import CheckRunner
from vmware_harden.store.twin import Twin

# Shipped-catalog facts these tests lean on (VMSA-2025-0004, ESXi 8.0 U3d fix).
_ESXI_ADVISORY = "VMSA-2025-0004"
_VC_ADVISORY = "VMSA-2024-0019"
_BELOW_FIX = 24280767  # ESXi 8.0 Update 3b
_AT_FIX = 24585383  # ESXi 8.0 Update 3d


def _node(twin: Twin, snap: str, node_id: str, node_type: str, attrs: dict) -> None:
    twin.conn.execute(
        "INSERT INTO nodes (id, type, target, name, attrs) VALUES (?, ?, 'v.lab', ?, ?)",
        [node_id, node_type, node_id, json.dumps(attrs)],
    )
    twin.write_node_state(snap, node_id, attrs)


def _host(twin, snap, node_id, version, build, **extra):
    _node(
        twin,
        snap,
        node_id,
        "host",
        {"name": node_id, "esxi_version": version, "esxi_build": build, **extra},
    )


def _outcome(twin, snap, rule_id):
    return twin.conn.execute(
        "SELECT outcome, nodes_in_scope, nodes_undetermined, reason FROM rule_outcome "
        "WHERE snapshot_id = ? AND rule_id = ?",
        [snap, rule_id],
    ).fetchone()


def _gaps(twin, snap, rule_id):
    return dict(
        twin.conn.execute(
            "SELECT node_id, missing_attributes FROM rule_node_gap "
            "WHERE snapshot_id = ? AND rule_id = ?",
            [snap, rule_id],
        ).fetchall()
    )


@pytest.fixture
def twin(tmp_path: Path):
    t = Twin(tmp_path / "t.duckdb")
    yield t
    t.close()


# --- the baseline itself ----------------------------------------------------


def test_one_rule_per_catalogued_advisory():
    b = advisory_baseline()
    assert b.id == ADVISORY_BASELINE_ID
    assert {r.id for r in b.rules} == {a.id for a in load_catalog().advisories}
    assert all(isinstance(r.check, AdvisoryCheck) for r in b.rules)
    assert set(b.applies_to) == {"host", "vcenter"}


def test_vendor_severity_maps_onto_the_engine_scale():
    sev = {r.id: r.severity for r in advisory_baseline().rules}
    assert sev[_ESXI_ADVISORY] == "critical"


def test_discoverable_and_loadable_like_any_builtin():
    assert ADVISORY_BASELINE_ID in list_builtins()
    assert load_builtin(ADVISORY_BASELINE_ID).id == ADVISORY_BASELINE_ID
    loaded, failures = load_all_baselines()
    assert ADVISORY_BASELINE_ID in loaded, failures


def test_rules_state_the_catalog_date_and_what_a_clean_result_means():
    for r in advisory_baseline().rules:
        assert load_catalog().as_of.isoformat() in r.rationale
        assert "不等于没有漏洞" in r.rationale or "not" in r.rationale.lower()


# --- verdicts through the runner -----------------------------------------------


def test_affected_host_is_a_violation_with_the_fix_in_evidence(twin):
    snap = twin.start_snapshot("v.lab")
    _host(twin, snap, "v.lab:esx-old", "8.0.3", _BELOW_FIX)
    vs = CheckRunner(twin).run_baseline(snap, advisory_baseline())
    hits = [v for v in vs if v["rule_id"] == _ESXI_ADVISORY]
    assert [v["node_id"] for v in hits] == ["v.lab:esx-old"]
    ev = hits[0]["evidence"]
    assert ev["status"] == "affected"
    assert ev["fixed_in"] == "ESXi 8.0 Update 3d"
    assert ev["build"] == _BELOW_FIX
    assert ev["kev"] is True
    assert ev["catalog_as_of"] == load_catalog().as_of.isoformat()
    assert "CVE-2025-22224" in ev["cves"]


def test_fixed_host_is_judged_and_not_a_violation(twin):
    snap = twin.start_snapshot("v.lab")
    _host(twin, snap, "v.lab:esx-new", "8.0.3", _AT_FIX)
    vs = CheckRunner(twin).run_baseline(snap, advisory_baseline())
    assert not [v for v in vs if v["rule_id"] == _ESXI_ADVISORY]
    outcome, in_scope, undetermined, _ = _outcome(twin, snap, _ESXI_ADVISORY)
    assert (outcome, in_scope, undetermined) == ("evaluated", 1, 0)


@pytest.mark.parametrize(
    "version,build",
    [("8.0.3", "N/A"), ("N/A", _BELOW_FIX), (None, None), ("9.9.0", 99999999)],
)
def test_host_that_cannot_be_judged_is_a_gap_not_a_pass(twin, version, build):
    snap = twin.start_snapshot("v.lab")
    _host(twin, snap, "v.lab:esx-x", version, build)
    vs = CheckRunner(twin).run_baseline(snap, advisory_baseline())
    assert not [v for v in vs if v["rule_id"] == _ESXI_ADVISORY]
    outcome, in_scope, undetermined, _ = _outcome(twin, snap, _ESXI_ADVISORY)
    assert (outcome, in_scope, undetermined) == ("evaluated", 1, 1)
    assert "v.lab:esx-x" in _gaps(twin, snap, _ESXI_ADVISORY)


def test_unmeasured_host_is_a_gap_even_if_build_looks_old(twin):
    # A host vCenter cannot reach: the collector drops its cached config and
    # marks it measured=false. Nothing it carries is an observation.
    snap = twin.start_snapshot("v.lab")
    _node(
        twin,
        snap,
        "v.lab:esx-dead",
        "host",
        {"name": "esx-dead", "connection_state": "notResponding", "measured": False},
    )
    vs = CheckRunner(twin).run_baseline(snap, advisory_baseline())
    assert not [v for v in vs if v["rule_id"] == _ESXI_ADVISORY]
    assert "v.lab:esx-dead" in _gaps(twin, snap, _ESXI_ADVISORY)


def test_vcenter_is_out_of_scope_for_an_esxi_only_advisory(twin):
    snap = twin.start_snapshot("v.lab")
    _node(
        twin,
        snap,
        "v.lab:vc",
        "vcenter",
        {"name": "vc", "vcenter_version": "8.0.3", "vcenter_build": 24322831},
    )
    CheckRunner(twin).run_baseline(snap, advisory_baseline())
    # No ESXi host was collected: the ESXi advisory judged nothing, and says so
    # rather than reporting zero affected.
    outcome, in_scope, undetermined, reason = _outcome(twin, snap, _ESXI_ADVISORY)
    assert (outcome, in_scope) == ("undetermined", None)
    assert "no component" in reason
    # ...and in scope for the vCenter one, judged fixed (8.0 U3d).
    assert _outcome(twin, snap, _VC_ADVISORY)[1:3] == (1, 0)


def test_rule_with_nothing_in_scope_is_undetermined_when_its_collector_failed(twin):
    snap = twin.start_snapshot("v.lab")
    CheckRunner(twin).run_baseline(
        snap, advisory_baseline(), uncollected={"host": "HostCollector failed: boom"}
    )
    outcome, *_, reason = _outcome(twin, snap, _ESXI_ADVISORY)
    assert outcome == "undetermined"
    assert "host" in reason


def test_build_compared_only_within_its_line(twin):
    # 24585295 is past the 7.0 U3s fix (24585291) and below 8.0 U3d (24585383):
    # on its own 8.0 line it is affected; read against 7.0 it would be "fixed".
    snap = twin.start_snapshot("v.lab")
    _host(twin, snap, "v.lab:esx-8", "8.0.3", 24585295)
    vs = CheckRunner(twin).run_baseline(snap, advisory_baseline())
    hit = [v for v in vs if v["rule_id"] == _ESXI_ADVISORY]
    assert hit and hit[0]["evidence"]["fixed_in"] == "ESXi 8.0 Update 3d"


def test_partially_collected_advisory_is_undetermined_not_complete(twin):
    # VMSA-2025-0004 covers ESXi only, so use a two-product case: a vCenter
    # advisory judged on the vCenter while the host collector failed must not
    # read as fully evaluated for an advisory that also covers ESX.
    snap = twin.start_snapshot("v.lab")
    _node(
        twin,
        snap,
        "v.lab:vc",
        "vcenter",
        {"name": "vc", "vcenter_version": "8.0.3", "vcenter_build": 25600417},
    )
    CheckRunner(twin).run_baseline(
        snap, advisory_baseline(), uncollected={"host": "HostCollector failed: boom"}
    )
    outcome, *_, reason = _outcome(twin, snap, "VMSA-2026-0006")
    assert outcome == "undetermined"
    assert "host" in reason


def test_user_yaml_cannot_use_the_advisory_check(tmp_path):
    from vmware_harden.baselines.loader import load_baseline

    f = tmp_path / "mine.yaml"
    f.write_text(
        "id: mine\nname: mine\nversion: '1'\napplies_to: [host]\nrules:\n"
        "  - id: r1\n    title: t\n    severity: high\n    category: c\n"
        "    check: {type: advisory, advisory_id: VMSA-9999-0001}\n"
        "    remediation: {summary: s}\n",
        encoding="utf-8",
    )
    with pytest.raises(NotImplementedError, match="advisory"):
        load_baseline(f)


def test_reserved_id_cannot_be_claimed_by_a_user_baseline(tmp_path):
    from vmware_harden.baselines.loader import load_baseline

    f = tmp_path / "other.yaml"
    f.write_text(
        "id: vmsa-advisories\nname: x\nversion: '1'\napplies_to: [host]\nrules: []\n",
        encoding="utf-8",
    )
    with pytest.raises(NotImplementedError, match="reserved"):
        load_baseline(f)


def test_unknown_advisory_id_raises_a_readable_error():
    with pytest.raises(KeyError, match="VMSA-9999-0001"):
        judge_nodes("VMSA-9999-0001", {})


def test_unmeasured_host_carrying_a_cached_old_build_is_still_a_gap(twin):
    # The collector drops cached config today. If it ever stops, the old build
    # left on an unreachable host must not become a violation (or a pass).
    snap = twin.start_snapshot("v.lab")
    _host(twin, snap, "v.lab:esx-cached", "8.0.3", _BELOW_FIX, measured=False)
    vs = CheckRunner(twin).run_baseline(snap, advisory_baseline())
    assert not [v for v in vs if v["rule_id"] == _ESXI_ADVISORY]
    assert "v.lab:esx-cached" in _gaps(twin, snap, _ESXI_ADVISORY)


def test_import_refuses_the_reserved_filename(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from vmware_harden.baselines import loader
    from vmware_harden.cli.main import app

    monkeypatch.setattr(loader, "USER_DIR", tmp_path / "user")
    src = tmp_path / "ok.yaml"
    src.write_text(
        "id: ok\nname: ok\nversion: '1'\napplies_to: [host]\nrules: []\n", encoding="utf-8"
    )
    result = CliRunner().invoke(app, ["baseline", "import", str(src), "--name", "vmsa-advisories"])
    assert result.exit_code == 1, result.output
    assert "reserved" in result.output
    assert not (tmp_path / "user" / "vmsa-advisories.yaml").exists()
