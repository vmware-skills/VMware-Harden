"""Every rule that runs must be able to reach both verdicts.

The three contract layers ask whether a rule's *names and values* are right.
None asks whether it can decide anything. A rule can pass all three and still be
inert — ``TRY_CAST(...) > 30000`` on a lockout threshold reads correctly, cites a
collected attribute, compares against a plausible number, and can never fire.
Twenty-one of the twenty-nine runnable rules had no behavioural coverage at all,
including all twelve STIG rules; flipping one from ``= true`` to ``= false`` or
widening a threshold past every real value left the suite green.

So this drives each rule against a generated spread of records and asserts it
**discriminates**: some estate makes it fire, some estate does not. The values
come from the rule itself — its declared value domain, the literals it compares
against, and the numeric thresholds in its SQL, each probed at ``n-1/n/n+1`` —
so the estate is shaped by what the rule actually tests rather than by a fixture
someone wrote to match it.

**What this does not catch: an inverted verdict.** ``mob_enabled = true`` and
``mob_enabled = false`` both discriminate; only one of them is the control. Which
side is compliant is per-rule semantics, and needs the hand-written expectations
in ``test_real_shape_rule_parity.py``. Saying so here rather than letting the
file's name imply otherwise — a check that reads as broader than it is, is how
the defect this whole release addresses went unnoticed.
"""
import itertools
import json
from pathlib import Path

import pytest

from vmware_harden.baselines.introspect import cited_attributes, cited_literals, node_type_of
from vmware_harden.baselines.loader import list_builtins, load_builtin
from vmware_harden.baselines.vocabulary import lookup
from vmware_harden.checks.evaluability import classify
from vmware_harden.checks.query import execute_query_check
from vmware_harden.store.twin import Twin

#: The value space an attribute plausibly holds on a real estate — **fixed, and
#: deliberately not derived from the rule under test**.
#:
#: A first version built candidates from the rule's own SQL, probing each numeric
#: threshold at n-1/n/n+1. It passed every mutation: widening a lockout threshold
#: from 3 to 30000 simply moved the probe with it. Inputs taken from the thing
#: under test cannot detect a change to it — the check confirms whatever it is
#: handed (形态 #2).
#:
#: The numbers span what these settings really are: counts and retries in single
#: digits, retention in days, timeouts in seconds up to an hour, build numbers.
#: A rule whose threshold sits outside this range cannot fire on any real host,
#: which is precisely the finding.
_BASE_VALUES = (
    "true", "false", "", "x",
    '["ANY"]', '["net-1"]',
    "0", "1", "3", "5", "10", "30", "60", "90", "180", "365",
    "300", "600", "900", "3600",
    "19", "23305545", "23305546", "99999999",
)

#: Names probed alongside the attributes: a few rules constrain the ``name``
#: column rather than anything in ``attrs``. Both a matching and a non-matching
#: name are required — trimming this to ("", "rule-7") made every probe row
#: violate pci-r1-3, which then looked like a rule that always fires.
_NAMES = ("", "rule-7", "friendly-name")

#: Ceiling on the cartesian product per rule. Reached only by the three-attribute
#: DFW rules; everything else enumerates fully. Kept low enough that the whole
#: file stays well under a minute — a probe nobody runs catches nothing.
_MAX_COMBINATIONS = 800

#: Per-attribute candidate ceiling, applied after the rule-derived values so a
#: boundary value is never the one that gets cut.
_MAX_CANDIDATES = 16


def _evaluable_rules() -> dict:
    """Every builtin rule the runner would actually execute, by id."""
    rules = {}
    for baseline_id in list_builtins():
        for rule in load_builtin(baseline_id).rules:
            if classify(rule).evaluable:
                rules[rule.id] = rule
    return rules


def _candidate_values(node_type: str, attr: str, literals: list[str], sql: str) -> list[str]:
    """Values worth trying for one attribute, most rule-specific first.

    The declared value domain comes first — that is a fact about the attribute,
    not about any rule — followed by the fixed spread. Nothing here reads the
    rule, so a rule that stops being able to fire shows up as one that stops
    being able to fire.
    """
    del sql, literals  # deliberately unused — see _BASE_VALUES
    entry = lookup(node_type, attr)
    if entry and entry.probe_values:
        # The attribute declares what it really ranges over. Use only that: a
        # generic spread wide enough to suit a build number also makes an
        # absurd lockout threshold look reachable, and the probe then confirms
        # whatever it is given.
        return list(entry.probe_values)
    values = list(entry.value_domain) if (entry and entry.value_domain) else []
    values += list(_BASE_VALUES)
    return list(dict.fromkeys(values))


def _populate(twin: Twin, rule) -> tuple[int, int]:
    """Insert the generated estate for ``rule``; return (matched, inserted)."""
    sql = rule.check.sql
    node_type = node_type_of(rule)
    attrs = sorted(cited_attributes(rule))

    literals: dict[str, list[str]] = {a: [] for a in attrs}
    for attr, values in cited_literals(rule):
        literals.setdefault(attr, []).extend(values)

    per_attr = {a: _candidate_values(node_type, a, literals.get(a, []), sql) for a in attrs}
    combinations = (
        list(itertools.islice(
            itertools.product(*[per_attr[a] for a in attrs]), _MAX_COMBINATIONS
        ))
        if attrs else [()]
    )

    snapshot = twin.start_snapshot("probe")
    node_rows, state_rows = [], []
    inserted = 0
    for combo in combinations:
        for name in _NAMES:
            inserted += 1
            node_id = f"n{inserted}"
            record = dict(zip(attrs, combo, strict=True))
            record["name"] = name or node_id
            node_rows.append([node_id, node_type, name, json.dumps(record)])
            state_rows.append((node_id, record))
    # Batch: a few thousand single-row inserts dominated the runtime. States go
    # through the Twin's own writer rather than hand-written SQL — node_state
    # stores a hash and canonicalised JSON, not the raw attrs column.
    twin.conn.executemany(
        "INSERT INTO nodes (id, type, target, name, attrs) VALUES (?, ?, 'v.lab', ?, ?)",
        node_rows,
    )
    twin.write_node_states(snapshot, state_rows)
    matched = len(execute_query_check(twin, rule.check))
    return matched, inserted


def _reset(twin: Twin) -> None:
    twin.conn.execute("DELETE FROM nodes")
    twin.conn.execute("DELETE FROM node_state")


@pytest.fixture(scope="module")
def probe_results(tmp_path_factory) -> dict:
    """Run every evaluable rule against its generated estate, once."""
    twin = Twin(tmp_path_factory.mktemp("discriminate") / "t.duckdb")
    results = {}
    try:
        for rule_id, rule in sorted(_evaluable_rules().items()):
            matched, inserted = _populate(twin, rule)
            _reset(twin)
            # An absence check ("no default-deny rule exists") can only fire on
            # an estate that lacks the thing, so the empty case is part of the
            # spread rather than a special case.
            twin.start_snapshot("empty")
            on_empty = len(execute_query_check(twin, rule.check))
            results[rule_id] = (matched, inserted, on_empty)
    finally:
        twin.close()
    return results


@pytest.mark.unit
def test_the_probe_covers_every_runnable_rule(probe_results):
    """Guard the guard: a probe that silently covers nothing still reports green."""
    assert probe_results, "no evaluable rules were probed"
    # 29 -> 38 when the service/time/firewall collector landed: six host
    # attributes became collectable and nine rules across the builtin baselines
    # went from unevaluatable to judged.
    assert len(probe_results) == 38, (
        f"expected 38 evaluable builtin rules, probed {len(probe_results)} — "
        "update this count deliberately when a collector batch lands"
    )


@pytest.mark.unit
def test_every_runnable_rule_can_fire(probe_results):
    """A rule that no estate can trigger is decoration.

    Catches an impossible threshold, a value domain nothing holds, and a
    condition contradicting itself — each of which passes all three contract
    layers.
    """
    inert = [
        rule_id
        for rule_id, (matched, _, on_empty) in probe_results.items()
        if matched == 0 and on_empty == 0
    ]
    assert not inert, (
        "these rules did not fire on any generated record, so they cannot "
        "report a violation on a real estate either:\n  " + "\n  ".join(inert)
    )


@pytest.mark.unit
def test_every_runnable_rule_can_pass(probe_results):
    """The mirror: a rule that fires on everything reports noise, not findings."""
    # `on_empty` plays no part: an always-true rule matches every row of the
    # probe estate and, having no rows on an empty one, matched nothing there.
    # Requiring on_empty > 0 as well let `AND 1=1` through.
    always = [
        rule_id
        for rule_id, (matched, inserted, _) in probe_results.items()
        if inserted > 0 and matched == inserted
    ]
    assert not always, (
        "these rules fired on every generated record, so they flag regardless "
        "of configuration:\n  " + "\n  ".join(always)
    )


@pytest.mark.unit
def test_candidates_do_not_depend_on_the_rule_under_test():
    """The property that makes the whole file able to fail.

    Two rules with wildly different thresholds must be probed with the same
    values; otherwise widening a threshold moves the probe with it and the
    mutation goes unseen — which is exactly what the first version did.
    """
    lenient = _candidate_values("host", "shell_timeout_seconds", [], "... > 900")
    absurd = _candidate_values("host", "shell_timeout_seconds", [], "... > 900000")
    assert lenient == absurd

    # and each numeric attribute must be probed over its own range, not a
    # shared one: a build number and a retry count in the same list is what let
    # a threshold of 30000 on a lockout counter look reachable
    assert max(int(v) for v in lenient if v.isdigit()) <= 3600
    builds = _candidate_values("host", "esxi_build", [], "")
    assert max(int(v) for v in builds if v.isdigit()) > 10 ** 7


@pytest.mark.unit
def test_builtin_directory_is_where_this_looks():
    """``list_builtins`` must be reading the shipped baselines, not an empty dir."""
    from vmware_harden.baselines import builtin

    shipped = list(Path(builtin.__file__).parent.glob("*.yaml"))
    assert len(shipped) == len(list_builtins()) == 9
