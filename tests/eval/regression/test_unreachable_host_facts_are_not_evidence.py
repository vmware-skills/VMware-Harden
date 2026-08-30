"""A host vCenter cannot reach supplies no facts — least of all compliant ones.

Real-hardware finding, 2026-08-30 (VCF 9.1, 8 hosts, 4 ``notResponding``).
vCenter answers ``config.option`` / ``config.service`` / ``config.product`` for a
host it has lost contact with, out of its own cache, with no error and no marker.
The collector wrote those last-known values into ``nodes.attrs``, the baseline
SQL read them as measurements, and the STIG/BSI scan reported **8 HIGH
violations that were never observed** — while the same host also appeared in the
missing-data list, because the attributes vCenter had no cache for came back
absent. One host, judged and unjudged at once.

The failure is worse than a plain false positive: a compliance report's whole
claim is that it looked. Here it certified findings about four machines it could
not talk to.

The engine already had the right answer for this — a node whose attributes are
absent is recorded as a gap, not a pass (:mod:`vmware_harden.checks.nodescope`).
It never fired because the attributes were not absent; they were stale. So the
fix is at the collector: discard what cannot have been measured, and let the
existing machinery report the host as unjudged.
"""
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from vmware_harden.checks.coverage import coverage_for
from vmware_harden.cli.runner import run_scan
from vmware_harden.collectors.hosts import _shape_host
from vmware_harden.store.twin import Twin

#: Two hosts, identical configuration, differing only in reachability. Both have
#: NTP off, so both would violate cis-esxi-2.1.1 if their data were believed.
_ATTRS = {
    "esxi_version": "9.1.0",
    "esxi_build": 1,
    "ntp_enabled": False,
    "ntp_servers": [],
    "ntp_service_policy_on": False,
    "ssh_running": True,
    "firewall_enabled": False,
}
LIVE = {"name": "esx-live", "connection_state": "connected", **_ATTRS}
STALE = {"name": "esx-gone", "connection_state": "notResponding", **_ATTRS}


@pytest.mark.unit
@pytest.mark.parametrize("state", ["notResponding", "disconnected", "N/A"])
def test_unreachable_host_keeps_only_its_identity_and_its_state(state):
    """Everything vCenter answered from cache is dropped; the two live facts stay.

    ``N/A`` is included deliberately: it is what ``list_hosts`` writes when it
    could not read ``runtime.connectionState`` at all. Not knowing whether a host
    is reachable is not evidence that it is.
    """
    shaped = _shape_host({**STALE, "connection_state": state}, {"dcui_access": "root"})

    assert shaped["name"] == "esx-gone"
    assert shaped["id"] == "esx-gone"
    assert shaped["connection_state"] == state
    assert shaped["measured"] is False
    leaked = set(shaped) - {"name", "id", "connection_state", "measured"}
    assert not leaked, (
        f"last-known values survived for an unreachable host: {sorted(leaked)}. "
        "Each one is a measurement a baseline rule will treat as observed."
    )


@pytest.mark.unit
def test_a_reachable_host_is_untouched():
    """The control. A fix that drops facts from live hosts too would pass the
    test above and destroy the product."""
    shaped = _shape_host(LIVE, {"dcui_access": "root"})
    for key, value in _ATTRS.items():
        assert shaped[key] == value, f"{key} was dropped from a connected host"
    assert shaped["dcui_access"] == "root"


@pytest.mark.integration
def test_scan_does_not_raise_violations_against_an_unreachable_host(tmp_path: Path):
    """End to end: same configuration, opposite outcomes, because one was seen."""
    db = str(tmp_path / "t.duckdb")
    with patch(
        "vmware_harden.collectors.hosts._fetch_hosts",
        return_value=[_shape_host(LIVE), _shape_host(STALE)],
    ):
        snap = run_scan(target="lab", baseline="cis-vmware-esxi-8.0-subset", db=db)

    twin = Twin(Path(db))
    try:
        # Node ids are namespaced per target (``lab:esx-live``) so two vCenters
        # in one Twin cannot collide; compare on the host part.
        violating = {
            row[0].split(":", 1)[-1]
            for row in twin.conn.execute(
                "SELECT node_id FROM violation WHERE snapshot_id = ?", [snap]
            ).fetchall()
        }
        assert "esx-live" in violating, (
            "the reachable host really does have NTP off and must still be flagged — "
            "otherwise this test would pass on a build that reports nothing at all"
        )
        assert "esx-gone" not in violating, (
            "a violation was recorded against a host vCenter could not reach; its "
            "configuration was read out of cache, not off the machine"
        )

        # And it is not silently absent either: the same host is reported as
        # unjudged, which is the claim the data supports.
        gaps = {
            row[0].split(":", 1)[-1]
            for row in twin.conn.execute(
                "SELECT DISTINCT node_id FROM rule_node_gap WHERE snapshot_id = ?",
                [snap],
            ).fetchall()
        }
        assert "esx-gone" in gaps, (
            "dropping the stale facts must leave the host visibly unjudged, not "
            "quietly compliant — that trade would swap one false claim for another"
        )
        cov = coverage_for(twin, snap)
        assert cov.node_checks_undetermined > 0
        assert not cov.complete
    finally:
        twin.close()


@pytest.mark.integration
def test_the_unreachable_host_is_still_recorded_as_a_node(tmp_path: Path):
    """It must not vanish. A host missing from the inventory reads as an estate
    that is smaller than it is, and rules that count rows would then agree."""
    db = str(tmp_path / "t.duckdb")
    with patch(
        "vmware_harden.collectors.hosts._fetch_hosts",
        return_value=[_shape_host(LIVE), _shape_host(STALE)],
    ):
        snap = run_scan(target="lab", baseline="cis-vmware-esxi-8.0-subset", db=db)

    twin = Twin(Path(db))
    try:
        rows = twin.conn.execute(
            "SELECT n.id, n.attrs FROM nodes n JOIN node_state ns ON ns.node_id = n.id "
            "WHERE ns.snapshot_id = ? AND n.type = 'host' ORDER BY n.id",
            [snap],
        ).fetchall()
        assert [r[0].split(":", 1)[-1] for r in rows] == ["esx-gone", "esx-live"]
        stored = json.loads({r[0].split(":", 1)[-1]: r[1] for r in rows}["esx-gone"])
        assert stored.get("connection_state") == "notResponding", (
            "the reason it could not be judged has to survive into the snapshot, "
            "or the report can only say 'data missing' without saying why"
        )
    finally:
        twin.close()


@pytest.mark.integration
def test_a_rule_that_only_reads_liveness_still_judges_an_unreachable_host(
    tmp_path: Path,
):
    """The exemption, and the reason the filter is not a blanket one.

    "This host is not responding" is a legitimate finding *about* a host nobody
    measured — the one claim its record does support. Suppressing every rule on
    an unmeasured node would take that with it, and would do so silently, which
    is the same shape as the defect being fixed pointing the other way. So the
    filter asks what the rule read, not what type of node it read it from.
    """
    from vmware_harden.baselines.model import Baseline, QueryCheck, Remediation, Rule
    from vmware_harden.checks.runner import CheckRunner
    from vmware_harden.collectors.hosts import HostCollector

    baseline = Baseline(
        id="liveness-only",
        name="Hosts vCenter can talk to",
        version="1",
        applies_to=["host"],
        rules=[
            Rule(
                id="host-responding",
                title="Ensure vCenter can reach every host",
                severity="high",
                category="availability",
                check=QueryCheck(
                    type="query",
                    sql=(
                        "SELECT id, name FROM nodes WHERE type = 'host' "
                        "AND json_extract_string(attrs, '$.connection_state') "
                        "<> 'connected'"
                    ),
                ),
                remediation=Remediation(summary="Reconnect the host in vCenter."),
            )
        ],
    )

    db = str(tmp_path / "t.duckdb")
    twin = Twin(Path(db))
    try:
        snap = twin.start_snapshot("lab")
        with patch(
            "vmware_harden.collectors.hosts._fetch_hosts",
            return_value=[_shape_host(LIVE), _shape_host(STALE)],
        ):
            HostCollector(twin).collect(snap, "lab")
        found = CheckRunner(twin).run_baseline(snap, baseline)
        assert [v["node_id"].split(":", 1)[-1] for v in found] == ["esx-gone"], (
            "a rule reading only the liveness the record does carry was "
            "suppressed along with the ones reading cached configuration"
        )
    finally:
        twin.close()


@pytest.mark.integration
def test_the_report_names_the_one_cause_behind_the_run_of_gaps(tmp_path: Path, capsys):
    """Eight rules "missing data" on one host is one fact, not eight.

    Without this line the reader sees eight gap rows naming eight different
    attributes and goes looking for eight collectors, when the answer is that
    vCenter has not spoken to the machine.
    """
    from vmware_harden.cli.runner import run_report

    db = str(tmp_path / "t.duckdb")
    with patch(
        "vmware_harden.collectors.hosts._fetch_hosts",
        return_value=[_shape_host(LIVE), _shape_host(STALE)],
    ):
        run_scan(target="lab", baseline="cis-vmware-esxi-8.0-subset", db=db)
    capsys.readouterr()

    run_report(db=db, format="text")
    out = capsys.readouterr().out
    assert "Never measured" in out
    header, _, after = out.partition("Never measured")
    assert "connection_state=notResponding" in after
    assert "esx-live" not in after.split("Not judged")[0], (
        "the reachable host was listed as never measured"
    )

    run_report(db=db, format="json")
    payload = json.loads(capsys.readouterr().out)
    unmeasured = payload["coverage"]["unmeasured_nodes"]
    assert [u["node"].split(":", 1)[-1] for u in unmeasured] == ["esx-gone"]
    assert payload["coverage"]["complete"] is False
