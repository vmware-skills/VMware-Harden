"""A rule that cannot judge must not be reported as a pass.

The check engine used to execute every rule and treat "no rows matched" as
compliance. For a rule reading an attribute no collector writes, no rows can
ever match, so 76 of 99 builtin rules certified estates they had never actually
inspected.

These pin the runtime half of the fix: the runner refuses such a rule instead of
running it, and records why. The static contract test covers the builtin
baselines at CI time; only this behaviour protects a user pointing ``--baseline``
at a file CI has never seen.
"""
import json
from pathlib import Path

import pytest

from vmware_harden.baselines.loader import load_builtin
from vmware_harden.baselines.model import Baseline, QueryCheck, Remediation, Rule
from vmware_harden.checks.evaluability import classify
from vmware_harden.checks.runner import CheckRunner
from vmware_harden.store.twin import Twin


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


# --- classify(): the decision itself ---------------------------------------

@pytest.mark.unit
def test_rule_reading_only_collected_attributes_is_evaluable():
    verdict = classify(_rule(
        "ok",
        "SELECT id, name FROM nodes WHERE type = 'host' "
        "AND json_extract_string(attrs, '$.syslog_remote_host') = ''",
    ))
    assert verdict.evaluable
    assert verdict.reason == ""


@pytest.mark.unit
def test_rule_reading_a_pending_attribute_is_undetermined():
    """Declared, intended, but nothing writes it yet."""
    verdict = classify(_rule(
        "pending",
        "SELECT id, name FROM nodes WHERE type = 'host' "
        "AND json_extract_string(attrs, '$.lockdown_mode') = 'disabled'",
    ))
    assert not verdict.evaluable
    assert "lockdown_mode" in verdict.reason
    assert verdict.blocking_attributes == ("lockdown_mode",)


@pytest.mark.unit
def test_rule_reading_an_undeclared_attribute_is_undetermined():
    """The external-baseline case: a key the vocabulary has never heard of."""
    verdict = classify(_rule(
        "unknown",
        "SELECT id, name FROM nodes WHERE type = 'host' "
        "AND json_extract_string(attrs, '$.managed_by') IS NULL",
    ))
    assert not verdict.evaluable
    assert "managed_by" in verdict.reason
    assert "vocabulary.py" in verdict.reason


@pytest.mark.unit
def test_rule_whose_scope_cannot_be_read_is_undetermined_not_guessed():
    """Fail closed. Defaulting the scope would evaluate against the wrong collector."""
    verdict = classify(_rule("noscope", "SELECT id, name FROM nodes"))
    assert not verdict.evaluable
    assert "scope" in verdict.reason


@pytest.mark.unit
def test_attribute_of_the_wrong_node_type_is_undetermined():
    """``tools_status`` is a VM attribute; a host-scoped rule cannot read it.

    Catches the class of mistake where a name exists in the vocabulary but not
    for the node type the rule is scoped to.
    """
    verdict = classify(_rule(
        "wrongtype",
        "SELECT id, name FROM nodes WHERE type = 'host' "
        "AND json_extract_string(attrs, '$.tools_status') = 'guestToolsNotRunning'",
    ))
    assert not verdict.evaluable
    assert "tools_status" in verdict.reason


# --- the runner: refusal, recording, and not lying -------------------------

@pytest.mark.unit
def test_undetermined_rule_is_not_executed_and_produces_no_violation(tmp_path: Path):
    """The core guarantee.

    The host below would satisfy the rule's violating condition if the rule ran —
    ``managed_by`` is absent, so ``IS NULL`` is true. The point is that a rule
    reading an uncollected key must not be executed at all: on a real estate the
    key is absent everywhere, so running it would report every host compliant.
    """
    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")
    _host(twin, snap_id, "h-1", {"syslog_remote_host": "syslog.lab"})

    violations = CheckRunner(twin).run_baseline(snap_id, _baseline(_rule(
        "cust-1",
        "SELECT id, name FROM nodes WHERE type = 'host' "
        "AND json_extract_string(attrs, '$.managed_by') IS NULL",
    )))

    assert violations == []
    outcome, reason = twin.conn.execute(
        "SELECT outcome, reason FROM rule_outcome WHERE rule_id = 'cust-1'"
    ).fetchone()
    assert outcome == "undetermined"
    assert "managed_by" in reason
    twin.close()


@pytest.mark.unit
def test_evaluated_rules_are_recorded_too(tmp_path: Path):
    """Both outcomes are stored.

    Recording only failures would leave "evaluated cleanly" and "scanned by a
    build that did not track this" indistinguishable, and a report could not then
    state how much of the baseline it actually covered.
    """
    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")
    _host(twin, snap_id, "h-1", {"syslog_remote_host": "syslog.lab"})

    CheckRunner(twin).run_baseline(snap_id, _baseline(
        _rule("good", "SELECT id, name FROM nodes WHERE type = 'host' "
                      "AND json_extract_string(attrs, '$.syslog_remote_host') = ''"),
        _rule("bad", "SELECT id, name FROM nodes WHERE type = 'host' "
                     "AND json_extract_string(attrs, '$.managed_by') IS NULL"),
    ))

    outcomes = dict(twin.conn.execute(
        "SELECT rule_id, outcome FROM rule_outcome WHERE snapshot_id = ?", [snap_id]
    ).fetchall())
    assert outcomes == {"good": "evaluated", "bad": "undetermined"}
    twin.close()


@pytest.mark.unit
def test_evaluable_rule_still_reports_violations(tmp_path: Path):
    """The refusal must not suppress rules that can judge."""
    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")
    _host(twin, snap_id, "h-1", {"syslog_remote_host": ""})

    violations = CheckRunner(twin).run_baseline(snap_id, _baseline(_rule(
        "good",
        "SELECT id, name FROM nodes WHERE type = 'host' "
        "AND json_extract_string(attrs, '$.syslog_remote_host') = ''",
    )))

    assert [v["rule_id"] for v in violations] == ["good"]
    twin.close()


@pytest.mark.unit
def test_builtin_cis_scan_reports_most_rules_undetermined(tmp_path: Path):
    """The headline number, pinned.

    A CIS scan against a fully-populated host used to report near-total
    compliance. Only 4 of its 20 rules read attributes a collector produces; the
    other 16 are now undetermined rather than silently passing.
    """
    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")
    _host(twin, snap_id, "h-1", {"esxi_build": 99999999, "syslog_remote_host": "s.lab"})

    CheckRunner(twin).run_baseline(snap_id, load_builtin("cis-vmware-esxi-8.0-subset"))

    counts = dict(twin.conn.execute(
        "SELECT outcome, COUNT(*) FROM rule_outcome WHERE snapshot_id = ? GROUP BY outcome",
        [snap_id],
    ).fetchall())
    assert counts == {"evaluated": 4, "undetermined": 16}
    twin.close()


@pytest.mark.unit
def test_rerunning_a_baseline_replaces_outcomes_rather_than_doubling_them(tmp_path: Path):
    """Coverage is a denominator; appending would fabricate the ratio.

    Violations deliberately accumulate on a re-run — that list just gets longer.
    Outcomes cannot: a second run of the same baseline against the same snapshot
    reported "32 of 40 rules could not be evaluated", a total no scan ever had.
    """
    from vmware_harden.checks.coverage import coverage_for

    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")
    _host(twin, snap_id, "h-1", {"syslog_remote_host": "syslog.lab"})
    baseline = load_builtin("cis-vmware-esxi-8.0-subset")

    runner = CheckRunner(twin)
    runner.run_baseline(snap_id, baseline)
    first = coverage_for(twin, snap_id)
    runner.run_baseline(snap_id, baseline)
    second = coverage_for(twin, snap_id)

    assert first.total == 20
    assert (second.total, second.evaluated, second.undetermined) == (
        first.total, first.evaluated, first.undetermined
    )
    twin.close()


@pytest.mark.unit
def test_a_second_baseline_on_one_snapshot_adds_its_own_rules(tmp_path: Path):
    """Replacement is scoped per baseline, so it must not wipe a sibling's rows."""
    from vmware_harden.checks.coverage import coverage_for

    twin = Twin(tmp_path / "t.duckdb")
    snap_id = twin.start_snapshot("v.lab")
    _host(twin, snap_id, "h-1", {"syslog_remote_host": "syslog.lab"})

    runner = CheckRunner(twin)
    runner.run_baseline(snap_id, load_builtin("cis-vmware-esxi-8.0-subset"))
    runner.run_baseline(snap_id, load_builtin("eu-nis2-vmware"))

    assert coverage_for(twin, snap_id).total == 32  # 20 CIS + 12 NIS2
    twin.close()


@pytest.mark.unit
@pytest.mark.parametrize("path", ["ssh_enabled", "$.ssh_enabled", '$."ssh_enabled"'])
def test_every_path_spelling_duckdb_accepts_is_checked(path):
    """DuckDB reads a bare key exactly as it reads ``$.key``.

    Matching only the ``$.`` form meant a rule written the other way cited no
    attributes at all, so it was judged evaluable, ran, matched nothing, and
    counted as compliance. Legal SQL, and reachable by an external baseline —
    precisely the case the runtime check exists for.
    """
    verdict = classify(_rule(
        "spelling",
        f"SELECT id, name FROM nodes WHERE type = 'host' "
        f"AND json_extract_string(attrs, '{path}') = 'true'",
    ))
    assert not verdict.evaluable
    assert "ssh_enabled" in verdict.reason


@pytest.mark.unit
def test_table_qualified_attrs_read_is_checked():
    """``n.attrs`` is the same column as ``attrs``."""
    verdict = classify(_rule(
        "qualified",
        "SELECT n.id, n.name FROM nodes n WHERE n.type = 'host' "
        "AND json_extract_string(n.attrs, '$.ssh_enabled') = 'true'",
    ))
    assert not verdict.evaluable


@pytest.mark.unit
def test_unparseable_attrs_path_is_undetermined_not_ignored():
    """A path we cannot reduce to one name means unknown inputs, not no inputs.

    Returning an empty set for a nested path would read as "cites nothing",
    which the caller takes as safe to run — the same fail-open shape.
    """
    verdict = classify(_rule(
        "nested",
        "SELECT id, name FROM nodes WHERE type = 'host' "
        "AND json_extract_string(attrs, '$.a.b') = 'x'",
    ))
    assert not verdict.evaluable
    assert "cannot resolve" in verdict.reason
