"""A rule that judged nothing about a host must not count that host as compliant.

1.9.0 stopped rules from passing an estate on data no collector produces. That
judgement is per *rule*, and it leaves the per *node* case open, which is what
these pin: a rule can clear the vocabulary check — some collector demonstrably
writes every attribute it reads — and still learn nothing about one particular
host, because there the value came back absent or as the ``N/A`` sentinel. The
rule matches no row for that host, and no row is what the engine reported as a
pass.

The shape is identical to the one 1.9.0 removed, one level down, and it is the
reason the release notes for that version said "attributes nobody collects will
not silently pass" rather than "false compliance is impossible".
"""
import json
from pathlib import Path

import duckdb
import pytest

from vmware_harden.baselines.loader import load_builtin
from vmware_harden.baselines.model import Baseline, QueryCheck, Remediation, Rule
from vmware_harden.checks.coverage import coverage_for
from vmware_harden.checks.nodescope import missing_attributes, scope_for_rule
from vmware_harden.checks.runner import CheckRunner
from vmware_harden.store.twin import Twin

#: Reads one host attribute the collector really does produce, so the rule is
#: evaluable and any silence about a host is a data problem, not a build one.
_SYSLOG_SQL = (
    "SELECT id, name FROM nodes WHERE type = 'host' "
    "AND json_extract_string(attrs, '$.syslog_remote_host') = ''"
)


def _rule(rule_id: str, sql: str) -> Rule:
    return Rule(
        id=rule_id, title=rule_id, severity="high", category="test",
        check=QueryCheck(type="query", sql=sql),
        remediation=Remediation(summary="x"),
    )


def _baseline(*rules: Rule) -> Baseline:
    return Baseline(id="b", name="b", version="1.0", applies_to=["host"], rules=list(rules))


def _host(twin: Twin, snap_id: str, host_id: str, attrs: dict) -> None:
    twin.conn.execute(
        "INSERT INTO nodes (id, type, target, name, attrs) VALUES (?, 'host', 'v.lab', ?, ?)",
        [host_id, host_id, json.dumps(attrs)],
    )
    twin.write_node_state(snap_id, host_id, attrs)


# --- what counts as missing -------------------------------------------------

@pytest.mark.unit
def test_absent_key_null_value_and_the_unreadable_sentinel_are_all_missing():
    """``list_hosts`` returns the string 'N/A' for a property it could not read.

    It reaches ``attrs`` as a value, so nothing downstream distinguishes it from
    configuration unless this does.
    """
    assert missing_attributes({}, {"a"}) == ("a",)
    assert missing_attributes({"a": None}, {"a"}) == ("a",)
    assert missing_attributes({"a": "N/A"}, {"a"}) == ("a",)


@pytest.mark.unit
def test_an_empty_string_is_a_value_not_a_gap():
    """``syslog_remote_host = ''`` means no remote syslog — the finding itself.

    Reading falsiness instead of absence here would suppress the violation the
    rule exists to raise, turning a fix for false compliance into a cause of it.
    """
    assert missing_attributes({"a": "", "b": 0, "c": False}, {"a", "b", "c"}) == ()


@pytest.mark.unit
def test_a_node_the_rule_flagged_is_not_also_a_gap():
    """Its verdict is settled: violating. A missing second attribute cannot unsettle it."""
    scope = scope_for_rule(
        [("h-1", {"a": "bad"}), ("h-2", {"a": "bad"})],
        {"a", "b"},
        judged_node_ids={"h-1"},
    )
    assert [node for node, _ in scope.gaps] == ["h-2"]
    assert (scope.in_scope, scope.evaluated) == (2, 1)


@pytest.mark.unit
def test_a_rule_reading_no_attribute_has_no_per_node_gaps():
    """The estate-wide absence checks assert over which rows exist, not their contents."""
    scope = scope_for_rule([("h-1", {}), ("h-2", {})], set(), judged_node_ids=set())
    assert scope.gaps == ()
    assert scope.evaluated == 2


# --- the runner: recording the gap ------------------------------------------

@pytest.mark.unit
def test_host_missing_the_attribute_is_recorded_as_a_gap_not_a_pass(tmp_path: Path):
    """The core guarantee.

    Both hosts are in scope of an evaluable rule. ``h-2`` has no
    ``syslog_remote_host`` at all, so the rule matches nothing for it — the exact
    silence that used to be reported as compliance.
    """
    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")
    _host(twin, snap_id, "h-1", {"syslog_remote_host": "syslog.lab"})
    _host(twin, snap_id, "h-2", {})

    violations = CheckRunner(twin).run_baseline(snap_id, _baseline(_rule("r", _SYSLOG_SQL)))

    assert violations == []
    cov = coverage_for(twin, snap_id)
    assert cov.undetermined == 0, "the rule itself was evaluable"
    assert cov.node_checks_undetermined == 1
    assert cov.node_checks_evaluated == 1
    assert cov.nodes_affected == 1
    assert cov.undetermined_node_checks == (("r", "h-2", "syslog_remote_host"),)
    assert cov.complete is False
    twin.close()


@pytest.mark.unit
def test_the_gap_is_what_makes_coverage_incomplete(tmp_path: Path):
    """Mutation guard: remove the gap and the same scan must go green.

    Without this, a `complete` that returned False for some unrelated reason
    would satisfy the test above while the node dimension did nothing.
    """
    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")
    _host(twin, snap_id, "h-1", {"syslog_remote_host": "syslog.lab"})
    _host(twin, snap_id, "h-2", {"syslog_remote_host": "syslog.lab"})

    CheckRunner(twin).run_baseline(snap_id, _baseline(_rule("r", _SYSLOG_SQL)))

    cov = coverage_for(twin, snap_id)
    assert cov.node_checks_undetermined == 0
    assert cov.complete is True
    assert cov.summary_line() == ""
    twin.close()


@pytest.mark.unit
def test_the_unreadable_sentinel_on_a_real_baseline_is_caught(tmp_path: Path):
    """End to end with a builtin baseline, on the value a live scan actually produces.

    ``esxi_build`` comes back as ``'N/A'`` when the host is unreachable or the
    account lacks the privilege. The CIS build-number rule then matches nothing
    for that host — and ``TRY_CAST``, which stops one such host from aborting the
    whole scan, is exactly what makes the silence look like a pass.
    """
    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")
    _host(twin, snap_id, "h-1", {"esxi_build": 99999999, "syslog_remote_host": "s.lab"})
    _host(twin, snap_id, "h-2", {"esxi_build": "N/A", "syslog_remote_host": "s.lab"})

    CheckRunner(twin).run_baseline(snap_id, load_builtin("cis-vmware-esxi-8.0-subset"))

    cov = coverage_for(twin, snap_id)
    gaps = {(rule, node) for rule, node, _ in cov.undetermined_node_checks}
    assert ("cis-esxi-2.2.1", "h-2") in gaps
    assert ("cis-esxi-2.2.1", "h-1") not in gaps
    twin.close()


@pytest.mark.unit
def test_a_rule_that_found_no_node_of_its_type_is_named(tmp_path: Path):
    """Zero in scope is the most complete form of the same failure.

    A host collector that returned nothing leaves every host rule matching zero
    rows. Each reports no violation, and the scan looks spotless.
    """
    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")  # no nodes at all

    CheckRunner(twin).run_baseline(snap_id, _baseline(_rule("r", _SYSLOG_SQL)))

    cov = coverage_for(twin, snap_id)
    assert cov.rules_without_targets == ("r",)
    assert cov.complete is False
    assert "judged nothing" in cov.summary_line()
    twin.close()


@pytest.mark.unit
def test_an_absence_check_that_fired_on_an_empty_estate_is_not_called_vacuous(
    tmp_path: Path,
):
    """It has no nodes in scope and it still reached a verdict — a violation.

    Naming it alongside the genuinely vacuous rules would train readers to skim
    the list, which is the point at which a real one gets missed.
    """
    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")

    CheckRunner(twin).run_baseline(snap_id, _baseline(_rule(
        "absence",
        "SELECT 'absence' AS id, 'estate' AS name "
        "WHERE NOT EXISTS (SELECT 1 FROM nodes WHERE type = 'host')",
    )))

    cov = coverage_for(twin, snap_id)
    assert cov.rules_without_targets == ()
    twin.close()


@pytest.mark.unit
def test_rerunning_a_baseline_replaces_gaps_rather_than_doubling_them(tmp_path: Path):
    """Same reason as the rule-level tally: these are a denominator, not a log."""
    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")
    _host(twin, snap_id, "h-1", {})
    baseline = _baseline(_rule("r", _SYSLOG_SQL))

    runner = CheckRunner(twin)
    runner.run_baseline(snap_id, baseline)
    first = coverage_for(twin, snap_id)
    runner.run_baseline(snap_id, baseline)
    second = coverage_for(twin, snap_id)

    assert first.node_checks_undetermined == 1
    assert second.node_checks_undetermined == 1
    assert second.nodes_affected == 1
    twin.close()


@pytest.mark.unit
def test_nodes_from_another_snapshot_are_not_in_scope(tmp_path: Path):
    """Scope is what this scan observed, not every node ever seen.

    A decommissioned host still sits in the cumulative `nodes` table; counting it
    would manufacture a gap on hardware that no longer exists.
    """
    twin = Twin(tmp_path / "t.duckdb")
    old = twin.start_snapshot("v.lab")
    _host(twin, old, "gone", {})
    snap_id = twin.start_snapshot("v.lab")
    _host(twin, snap_id, "h-1", {"syslog_remote_host": "syslog.lab"})

    CheckRunner(twin).run_baseline(snap_id, _baseline(_rule("r", _SYSLOG_SQL)))

    cov = coverage_for(twin, snap_id)
    assert cov.node_checks_total == 1
    assert cov.node_checks_undetermined == 0
    twin.close()


# --- upgrading from 1.9.0 ---------------------------------------------------

def _strip_node_tracking(db_path: Path) -> None:
    """Return a database to the shape 1.9.0 wrote.

    The index has to go first — DuckDB refuses to alter a table an index depends
    on. Adding a column to an indexed table, which is the direction the
    migration actually runs in, has no such restriction.
    """
    conn = duckdb.connect(str(db_path))
    conn.execute("DROP INDEX idx_rule_outcome_snapshot")
    conn.execute("ALTER TABLE rule_outcome DROP COLUMN nodes_in_scope")
    conn.execute("ALTER TABLE rule_outcome DROP COLUMN nodes_undetermined")
    conn.execute("CREATE INDEX idx_rule_outcome_snapshot ON rule_outcome(snapshot_id)")
    conn.execute("DROP TABLE rule_node_gap")
    conn.close()


@pytest.mark.unit
def test_a_1_9_0_database_gains_the_columns_when_opened_for_writing(tmp_path: Path):
    """`CREATE TABLE IF NOT EXISTS` leaves an existing table alone.

    Without the migration the new columns would never appear in an upgrading
    user's database, and every scan would fail on the insert.
    """
    db = tmp_path / "t.duckdb"
    twin = Twin(db)
    snap_id = twin.start_snapshot("v.lab")
    _host(twin, snap_id, "h-1", {})
    twin.close()
    _strip_node_tracking(db)

    twin = Twin(db)  # re-open: init_schema migrates
    CheckRunner(twin).run_baseline(snap_id, _baseline(_rule("r", _SYSLOG_SQL)))
    assert coverage_for(twin, snap_id).node_checks_undetermined == 1
    twin.close()


@pytest.mark.unit
def test_a_1_9_0_snapshot_read_only_reports_unmeasured_not_clean(tmp_path: Path):
    """The web dashboard opens read-only and cannot migrate.

    Its old snapshots must come back as "never measured per node" — reporting
    them as fully covered would put the false-compliance claim back through the
    one surface that has no way to correct itself.
    """
    db = tmp_path / "t.duckdb"
    twin = Twin(db)
    snap_id = twin.start_snapshot("v.lab")
    _host(twin, snap_id, "h-1", {"syslog_remote_host": "syslog.lab"})
    CheckRunner(twin).run_baseline(snap_id, _baseline(_rule("r", _SYSLOG_SQL)))
    twin.close()
    _strip_node_tracking(db)

    ro = Twin.open_readonly(db)
    cov = coverage_for(ro, snap_id)
    assert cov.tracked is True, "the rule-level tally must survive"
    assert cov.evaluated == 1
    assert cov.node_tracked is False
    assert cov.complete is False
    assert "not which nodes" in cov.summary_line()
    ro.close()


# --- the surfaces -----------------------------------------------------------

@pytest.mark.integration
def test_report_text_names_the_node_and_the_missing_attribute(tmp_path: Path, capsys):
    """A count tells nobody which host to go and look at."""
    from vmware_harden.cli.runner import run_report

    db = tmp_path / "t.duckdb"
    twin = Twin(db)
    snap_id = twin.start_snapshot("v.lab")
    _host(twin, snap_id, "h-1", {})
    CheckRunner(twin).run_baseline(snap_id, _baseline(_rule("r", _SYSLOG_SQL)))
    twin.finish_snapshot(snap_id)
    twin.close()

    run_report(db=str(db))
    out = capsys.readouterr().out
    assert "No violations." not in out, "a bare pass claim over an unjudged host"
    assert "Not judged on these nodes" in out
    assert "h-1" in out
    assert "syslog_remote_host" in out


@pytest.mark.integration
def test_report_json_carries_the_node_gaps(tmp_path: Path, capsys):
    """A script consuming the report must be able to see them without parsing prose."""
    from vmware_harden.cli.runner import run_report

    db = tmp_path / "t.duckdb"
    twin = Twin(db)
    snap_id = twin.start_snapshot("v.lab")
    _host(twin, snap_id, "h-1", {})
    CheckRunner(twin).run_baseline(snap_id, _baseline(_rule("r", _SYSLOG_SQL)))
    twin.finish_snapshot(snap_id)
    twin.close()

    run_report(db=str(db), format="json")
    payload = json.loads(capsys.readouterr().out)
    cov = payload["coverage"]
    assert cov["complete"] is False
    assert cov["node_checks_undetermined"] == 1
    assert cov["undetermined_node_checks"] == [
        {"rule": "r", "node": "h-1", "missing": "syslog_remote_host"}
    ]


@pytest.mark.integration
def test_mcp_list_violations_carries_the_node_gaps(tmp_path: Path, monkeypatch):
    """The agent surface: `violations: []` must arrive with the reason it may lie."""
    from vmware_harden.mcp import tools

    db = tmp_path / "t.duckdb"
    twin = Twin(db)
    snap_id = twin.start_snapshot("v.lab")
    _host(twin, snap_id, "h-1", {})
    CheckRunner(twin).run_baseline(snap_id, _baseline(_rule("r", _SYSLOG_SQL)))
    twin.finish_snapshot(snap_id)
    twin.close()
    monkeypatch.setattr(tools, "_resolve_db", lambda *a, **k: db)

    result = tools.list_violations()
    assert result["violations"] == []
    assert result["coverage"]["node_checks_undetermined"] == 1
    assert "per-node checks" in result["note"]
