"""Every baseline rule must read attributes a collector actually produces.

This is the family-wide contract that ``test_stig_baseline.py`` only ever
enforced for one baseline. The comment on ``PRODUCIBLE_HOST_ATTRS`` has claimed
since it was written that "the parity regression asserts no builtin baseline SQL
reads a host key outside this set" — that sentence was false: the test behind it
loaded the STIG baseline alone, so the other seven drifted unchecked until 76 of
99 rules could no longer match anything (BACKLOG P0 [H-1]). These tests make the
sentence true.

Three layers, because no single one is sufficient:

1. **Declaration** — every ``(node_type, $.attr)`` a rule reads must exist in
   ``vocabulary.py``. Catches typos and silent new attributes.
2. **Value domain** — literals compared against an enum attribute must be inside
   its declared domain. Catches the class of defect where the name is right but
   the value can never match (three rules shipped comparing ``'drop'`` against
   NSX's ``DROP``). A declaration check alone cannot see this.
3. **Pending inventory** — rules blocked on an unwritten collector must match the
   frozen list exactly, in both directions.

Layer 2 exists because layer 1 passed those three rules. Layer 3 exists because
layers 1 and 2 pass a rule whose attribute is *declared* but *not collected* —
that rule still silently reports compliant.

Deliberately **not** a behavioural check: whether a rule fires correctly against
real record shapes is ``test_real_shape_rule_parity.py``. Even together these
are static-plus-fixture guards; the runtime refusal to execute a pending rule
(design step 2) is what protects a user running an external baseline.
"""
from pathlib import Path

import pytest

from vmware_harden.baselines.introspect import (
    cited_attributes,
    cited_literals,
    node_type_of,
)
from vmware_harden.baselines.loader import load_builtin
from vmware_harden.baselines.model import QueryCheck, Remediation, Rule
from vmware_harden.baselines.vocabulary import PRODUCIBLE_BY_NODE_TYPE, Status, lookup, suggest

from .known_pending_rules import KNOWN_PENDING_RULES

BUILTIN_BASELINE_IDS = (
    "bsi-itgs-basisabsicherung-vmware",
    "cis-vmware-esxi-8.0-subset",
    "cis-vmware-esxi-9.0-subset",
    "dengbao-2.0-level3-vmware",
    "eu-nis2-vmware",
    "pci-dss-4.0-vmware",
    "vsphere-scg-v8-subset",
    "vsphere-scg-v9-subset",
    "vsphere-stig-v9-subset",
)

#: Shell baselines (``rules: []``) inherit their parent's rules verbatim, so
#: they contribute nothing of their own and are skipped when attributing rules —
#: otherwise every parent rule would be counted twice under the wrong owner.
_SHELL_BASELINES = {"cis-vmware-esxi-9.0-subset", "vsphere-scg-v9-subset"}


def _rule_with(predicate: str) -> Rule:
    """A minimal, parseable rule whose WHERE clause is ``predicate``."""
    return Rule(
        id="probe", title="probe", severity="high", category="test",
        check=QueryCheck(
            type="query",
            sql=f"SELECT id, name FROM nodes n WHERE type = 'host' AND {predicate}",
        ),
        remediation=Remediation(summary="x"),
    )


def _real_rules():
    """Every ``(baseline_id, rule)`` pair, counting each rule once at its owner."""
    seen: set[str] = set()
    pairs = []
    for baseline_id in BUILTIN_BASELINE_IDS:
        if baseline_id in _SHELL_BASELINES:
            continue
        for rule in load_builtin(baseline_id).rules:
            if rule.id in seen:
                continue
            seen.add(rule.id)
            pairs.append((baseline_id, rule))
    return pairs


@pytest.mark.unit
def test_the_baseline_list_matches_what_ships():
    """The entry list must not drift from the directory.

    Every check in this file iterates ``BUILTIN_BASELINE_IDS``. A tenth baseline
    added to ``builtin/`` and not listed here would be invisible to all three
    layers, and ``test_scan_is_not_empty``'s count would not move either — the
    new file is simply never visited. That is how the STIG-only parity test let
    seven baselines drift for a year, rebuilt one layer up.
    """
    from vmware_harden.baselines import builtin

    shipped = {p.stem for p in Path(builtin.__file__).parent.glob("*.yaml")}
    assert shipped, "no builtin baseline YAML found — wrong directory?"
    assert set(BUILTIN_BASELINE_IDS) == shipped


@pytest.mark.unit
def test_value_domains_are_declared_where_they_are_relied_on():
    """Layer 2 can be disarmed by deleting a domain, silently.

    ``test_compared_literals_are_inside_the_declared_value_domain`` skips any
    attribute with an empty ``value_domain``, so removing one turns the check
    into a no-op with every test still green — on the very attribute whose
    case-sensitivity bug is why layer 2 exists. Pin which attributes must carry
    one, the way KNOWN_PENDING_RULES pins the backlog.
    """
    from vmware_harden.baselines.vocabulary import VOCABULARY

    must_have_domain = {("dfw_rule", "action"), ("vm", "tools_status")}
    missing = {
        key for key in must_have_domain
        if not (VOCABULARY.get(key) and VOCABULARY[key].value_domain)
    }
    assert not missing, (
        f"these attributes must declare a value_domain or layer 2 stops "
        f"checking them: {sorted(missing)}"
    )


@pytest.mark.unit
def test_scan_is_not_empty():
    """A contract test that silently checks nothing is worse than none at all.

    Referencing a path that no longer exists makes ``glob``/``load`` return
    empty and the assertions below vacuously true — the family has shipped
    exactly that kind of forever-green check before (形态 #1).
    """
    pairs = _real_rules()
    assert len(pairs) == 99, (
        f"expected 99 own rules across the builtin baselines, found {len(pairs)}"
    )


@pytest.mark.unit
def test_every_cited_attribute_is_declared():
    """Layer 1: no rule may read an attribute the vocabulary does not know."""
    offenders = []
    for baseline_id, rule in _real_rules():
        node_type = node_type_of(rule)
        for attr in sorted(cited_attributes(rule)):
            if lookup(node_type, attr) is None:
                offenders.append(
                    f"  {baseline_id}::{rule.id} reads {node_type}.{attr}"
                    f" — {suggest(node_type, attr)}"
                )
    assert not offenders, (
        "Rules read attributes not declared in vmware_harden/baselines/vocabulary.py.\n"
        "An undeclared attribute is never collected, so the rule matches zero rows and\n"
        "reports compliant regardless of the real configuration. Declare it (with the\n"
        "collector source) or fix the name:\n" + "\n".join(offenders)
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    ("predicate", "expected"),
    [
        ("json_extract_string(attrs, '$.a') = 'X'", [("a", ["X"])]),
        ("json_extract_string(attrs, '$.a') != 'X'", [("a", ["X"])]),
        ("json_extract_string(attrs, '$.a') <> 'X'", [("a", ["X"])]),
        ("json_extract_string(attrs, '$.a') IN ('X', 'Y')", [("a", ["X", "Y"])]),
        ("json_extract_string(attrs, '$.a') NOT IN ('X', 'Y')", [("a", ["X", "Y"])]),
        # the other extraction functions and the operator forms
        ("json_extract(attrs, '$.a') = 'X'", [("a", ["X"])]),
        ("json_extract(attrs, '$.a') NOT IN ('X')", [("a", ["X"])]),
        # parenthesised: ->> binds looser than AND, so without them the
        # conjunction becomes the operator's left operand
        ("(attrs ->> '$.a') = 'X'", [("a", ["X"])]),
        # spellings the parser used to lose: a stray space, a comment, quoting,
        # a bare key, a table qualifier. The AST normalises every one of them,
        # which is the whole reason for parsing instead of pattern matching.
        ("json_extract_string (attrs, '$.a') = 'X'", [("a", ["X"])]),
        ("json_extract_string(attrs/*c*/, '$.a') = 'X'", [("a", ["X"])]),
        ('json_extract_string("attrs", \'$.a\') = \'X\'', [("a", ["X"])]),
        ("json_extract_string(attrs, 'a') = 'X'", [("a", ["X"])]),
        ("json_extract_string(n.attrs, '$.a') = 'X'", [("a", ["X"])]),
        # the empty literal is a value like any other
        ("json_extract_string(attrs, '$.a') = ''", [("a", [""])]),
        ("json_extract_string(attrs, '$.a') IN ('')", [("a", [""])]),
        # thresholds and patterns are not domain members — must NOT be captured
        ("json_extract_string(attrs, '$.a') < '1.2'", []),
        ("json_extract_string(attrs, '$.a') LIKE '%zone%'", []),
    ],
)
def test_comparison_extraction_sees_every_form(predicate, expected):
    """Pin what the value-domain check can see, form by form.

    Its mutation test once tried only a lower-case ``IN`` list, so ``NOT IN``
    went unexamined — an exercise that confirms the answer already known rather
    than probing the boundary (形态 #2). The spellings that defeated the old
    text matching are included deliberately: under the AST they must all resolve
    to the same read.
    """
    rule = _rule_with(predicate)
    assert cited_literals(rule) == expected


def test_compared_literals_are_inside_the_declared_value_domain():
    """Layer 2: a right name compared against an impossible value is still dead.

    ``$.action IN ('reject','drop','deny')`` passed layer 1 — ``action`` is
    produced — yet could never match, because NSX returns ``DROP``.
    """
    offenders = []
    for baseline_id, rule in _real_rules():
        node_type = node_type_of(rule)
        for attr, literals in cited_literals(rule):
            entry = lookup(node_type, attr)
            if entry is None or not entry.value_domain:
                continue
            outside = [lit for lit in literals if lit not in entry.value_domain]
            if outside:
                offenders.append(
                    f"  {baseline_id}::{rule.id} compares {node_type}.{attr} against {outside}; "
                    f"allowed: {list(entry.value_domain)}"
                )
    assert not offenders, (
        "Rules compare an attribute against values it can never hold:\n" + "\n".join(offenders)
    )


@pytest.mark.unit
def test_rules_blocked_on_a_pending_collector_match_the_frozen_list():
    """Layer 3: the collector backlog is explicit, and cannot silently grow or rot.

    Asserting equality (not containment) in both directions is what makes this a
    todo list rather than a permanent exemption: repairing a rule fails the test
    until it is struck off.
    """
    actual = set()
    for baseline_id, rule in _real_rules():
        node_type = node_type_of(rule)
        if any(
            (entry := lookup(node_type, attr)) and entry.status is Status.PENDING
            for attr in cited_attributes(rule)
        ):
            actual.add((baseline_id, rule.id))

    newly_broken = sorted(actual - KNOWN_PENDING_RULES)
    repaired = sorted(KNOWN_PENDING_RULES - actual)
    assert not newly_broken and not repaired, (
        "The set of rules blocked on an unwritten collector changed.\n"
        + ("NEWLY BLOCKED (a rule started reading an uncollected attribute):\n"
           + "".join(f"  {b}::{r}\n" for b, r in newly_broken) if newly_broken else "")
        + ("REPAIRED (remove these from known_pending_rules.py):\n"
           + "".join(f"  {b}::{r}\n" for b, r in repaired) if repaired else "")
    )


@pytest.mark.unit
def test_active_attributes_are_really_produced_by_their_collector():
    """The vocabulary may not claim an attribute is collected when it is not.

    ``vocabulary.py`` asserts this at import for each ACTIVE entry; this pins it
    as a test so the failure is a named regression rather than a collection error.
    """
    from vmware_harden.baselines.vocabulary import VOCABULARY

    active = [e for e in VOCABULARY.values() if e.status is Status.ACTIVE]
    assert active, "no ACTIVE attributes — this test would pass vacuously"
    for (node_type, name), entry in VOCABULARY.items():
        if entry.status is Status.ACTIVE:
            producible = PRODUCIBLE_BY_NODE_TYPE[node_type]
            assert name in producible, (
                f"vocabulary marks {node_type}.{name} ACTIVE but the {node_type} collector "
                f"does not produce it"
            )


@pytest.mark.unit
def test_shell_baselines_inherit_and_add_nothing():
    """The ``rules: []`` v9 baselines are pure aliases of their parent.

    Worth pinning because it is easy to read them as "9.x is covered": they
    inherit the two *worst* baselines verbatim, so whatever is broken in the
    parent is what a user selecting the v9 baseline actually runs.
    """
    for shell_id, parent_id in (
        ("cis-vmware-esxi-9.0-subset", "cis-vmware-esxi-8.0-subset"),
        ("vsphere-scg-v9-subset", "vsphere-scg-v8-subset"),
    ):
        shell = load_builtin(shell_id)
        parent = load_builtin(parent_id)
        assert {r.id for r in shell.rules} == {r.id for r in parent.rules}, (
            f"{shell_id} no longer mirrors {parent_id} — update this test and "
            "known_pending_rules.py together"
        )
