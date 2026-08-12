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


# --- spellings the text-based parser must refuse rather than miss ------------

#: Legal DuckDB that reads an uncollected attribute while defeating a
#: pattern-matching parser. Every one of these was verified to (a) really read
#: the attribute and (b) be judged evaluable, by an adversarial review of the
#: previous implementation — a single space after the function name was enough.
#:
#: The parser cannot be trusted to recognise every spelling, so the contract is
#: inverted: anything it cannot account for must raise, not return an empty set.
#: These are the forms that inversion has to keep catching.
_BYPASS_SQL = {
    "space-after-function-name":
        "json_extract_string (attrs, '$.ssh_enabled') = 'true'",
    "inline-comment-between-args":
        "json_extract_string(attrs/*c*/, '$.ssh_enabled') = 'true'",
    "line-comment":
        "json_extract_string(attrs, '$.mob_enabled') IS NOT NULL --x\n"
        "  AND json_extract_string (attrs, '$.ssh_enabled') = 'true'",
    "quoted-identifier":
        "json_extract_string(\"attrs\", '$.ssh_enabled') = 'true'",
    "cast-between-column-and-comma":
        "json_extract_string(attrs::JSON, '$.ssh_enabled') = 'true'",
    "concatenated-path":
        "json_extract_string(attrs, '$.' || 'ssh_enabled') = 'true'",
    "arrow-operator":
        "attrs->>'$.ssh_enabled' = 'true'",
    "bare-column-predicate":
        "json_extract_string(attrs, '$.mob_enabled') IS NOT NULL "
        "AND attrs LIKE '%ssh%'",
    "decoy-active-attribute-plus-smuggled-read":
        "json_extract_string(attrs, '$.mob_enabled') IS NOT NULL "
        "AND json_extract_string (attrs, '$.ssh_enabled') = 'true'",
}


@pytest.mark.unit
@pytest.mark.parametrize("form", sorted(_BYPASS_SQL))
def test_unparseable_attrs_spelling_is_refused_not_ignored(form):
    """A read the parser cannot see must not become "reads nothing".

    "Reads nothing" is what the caller treats as safe to run, so a missed read
    is a rule that executes, matches zero rows on an estate where the attribute
    was never collected, and counts as compliant.
    """
    verdict = classify(_rule(
        form,
        f"SELECT id, name FROM nodes WHERE type = 'host' AND {_BYPASS_SQL[form]}",
    ))
    assert not verdict.evaluable, f"{form} was waved through"


@pytest.mark.unit
@pytest.mark.parametrize("predicate", ["type IN ('host')", "type LIKE 'host'"])
def test_scope_predicate_the_parser_cannot_read_is_refused(predicate):
    """Scope decides which collector's vocabulary applies.

    Misreading it is enough on its own: an attribute uncollected for hosts may
    be ACTIVE for another node type, and the vocabulary check then passes while
    checking the wrong thing.

    Reads ``mob_enabled``, which IS collected for hosts, so the vocabulary has
    no objection and the unreadable scope is the only thing left to refuse it.
    A first draft used a pending attribute and passed for that reason instead —
    the assertion held whether or not the scope gate existed.
    """
    verdict = classify(_rule(
        "scope",
        f"SELECT id, name FROM nodes WHERE {predicate} "
        f"AND json_extract_string(attrs, '$.mob_enabled') = 'false'",
    ))
    assert not verdict.evaluable
    assert "type" in verdict.reason


@pytest.mark.unit
@pytest.mark.parametrize("comment", ["-- note\n", "/* note */ "])
def test_a_comment_neither_hides_a_read_nor_blocks_a_valid_rule(comment):
    """Comments had to be banned outright while the check matched SQL text.

    ``json_extract_string(attrs/*c*/, '$.k')`` parsed for DuckDB and not for the
    pattern, so a comment could hide a read — and the ban also rejected honest
    commented rules. The parser strips comments before we see the tree, so they
    are neither a blind spot nor a reason to refuse. Both halves are pinned: a
    comment must not make a valid rule unreadable, and must not conceal a read
    of an uncollected attribute.
    """
    ok = classify(_rule(
        "commented-ok",
        f"SELECT id, name FROM nodes WHERE type = 'host' {comment}"
        f"AND json_extract_string(attrs, '$.mob_enabled') = 'false'",
    ))
    assert ok.evaluable

    hidden = classify(_rule(
        "commented-smuggle",
        f"SELECT id, name FROM nodes WHERE type = 'host' {comment}"
        f"AND json_extract_string(attrs, '$.ssh_enabled') = 'true'",
    ))
    assert not hidden.evaluable
    assert "ssh_enabled" in hidden.reason


@pytest.mark.unit
def test_a_subquery_cannot_smuggle_a_second_scope():
    """The one scope attack the other gates do not reach.

    The outer predicate declares ``dfw_rule`` — where ``action`` is collected,
    so the vocabulary is satisfied — while the rows actually come from a host
    subquery, where nothing collects it. Both spellings are legal, the attrs
    read is canonical, and there is no comment: only counting every ``type``
    reference against the ones parsed catches it.
    """
    verdict = classify(_rule(
        "smuggled-scope",
        "SELECT id, name FROM nodes WHERE type = 'dfw_rule' "
        "AND id IN (SELECT id FROM nodes WHERE type IN ('host')) "
        "AND json_extract_string(attrs, '$.action') = 'DROP'",
    ))
    assert not verdict.evaluable
    assert "type" in verdict.reason


@pytest.mark.unit
def test_a_computed_path_is_refused_not_silently_dropped():
    """The extraction is recognised; the attribute it names is not.

    ``json_extract_string(attrs, '$.' || 'ssh_enabled')`` is a read the parser
    sees — so the column reference is accounted for and the stray check is
    satisfied — while the path is assembled at runtime. Dropping it would leave
    the rule citing nothing, which the caller reads as safe to run.
    """
    verdict = classify(_rule(
        "computed-path",
        "SELECT id, name FROM nodes WHERE type = 'host' "
        "AND json_extract_string(attrs, '$.' || 'ssh_enabled') = 'true'",
    ))
    assert not verdict.evaluable
    assert "computed path" in verdict.reason


@pytest.mark.unit
def test_sql_that_will_not_parse_is_refused_not_waved_through():
    """A parse failure means unknown inputs, and must not become "no inputs".

    It also must not abort the scan: the runner turns this into an undetermined
    outcome so the remaining rules still run.
    """
    verdict = classify(_rule(
        "malformed", "SELECT id, name FROM nodes WHERE type = 'host' AND ((("
    ))
    assert not verdict.evaluable
    assert "could not be parsed" in verdict.reason
