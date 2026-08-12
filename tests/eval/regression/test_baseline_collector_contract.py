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
import re

import pytest

from vmware_harden.baselines.loader import load_builtin
from vmware_harden.baselines.model import QueryCheck
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

_NODE_TYPE_RE = re.compile(r"type\s*=\s*'([a-z_]+)'")
_ATTR_RE = re.compile(r"\$\.([a-zA-Z0-9_]+)")
#: ``json_extract[_string](attrs, '$.x') <op> 'literal'`` plus the ``IN`` and
#: ``NOT IN`` list forms.
#:
#: Both extraction functions must be matched, and ``NOT`` must be optional: the
#: first version of this pattern accepted only ``json_extract_string`` and only
#: bare ``IN``, so it silently skipped two of the 49 literal comparisons in the
#: builtin baselines. A check whose name promises to validate value domains but
#: quietly ignores a whole comparison form is the exact defect shape this file
#: was written to catch (形态 #4) — measure coverage, do not assume it.
#:
#: Ordered comparisons (``<``, ``>``) are deliberately excluded: their literal is
#: a threshold, not a member of the domain, so ``tls_min_version < '1.2'`` is
#: correct even though ``'1.2'`` need not be an enumerated value. ``LIKE`` is
#: excluded for the same reason — its operand is a pattern.
_CMP_RE = re.compile(
    r"json_extract(?:_string)?\(\s*attrs\s*,\s*'\$\.([a-zA-Z0-9_]+)'\s*\)\s*"
    r"(?:(?:=|!=|<>)\s*'([^']*)'|(?:NOT\s+)?IN\s*\(([^)]*)\))",
    re.IGNORECASE,
)


#: Shell baselines (``rules: []``) inherit their parent's rules verbatim, so
#: they contribute nothing of their own and are skipped when attributing rules —
#: otherwise every parent rule would be counted twice under the wrong owner.
_SHELL_BASELINES = {"cis-vmware-esxi-9.0-subset", "vsphere-scg-v9-subset"}


def _node_type_of(rule) -> str:
    """The single node type a rule's SQL is scoped to.

    Refuses to guess. An earlier analysis defaulted to ``host`` when no scope was
    found — a fail-open that happened never to trigger, but would have hidden a
    whole rule from the contract the day it did.
    """
    assert isinstance(rule.check, QueryCheck), f"{rule.id}: only query checks are supported"
    found = set(_NODE_TYPE_RE.findall(rule.check.sql))
    assert len(found) == 1, (
        f"{rule.id}: expected exactly one `type = '...'` scope in the SQL, "
        f"found {found or 'none'}. "
        "The contract cannot be checked without knowing which collector owns the attributes."
    )
    return found.pop()


def _cited_attrs(rule) -> set[str]:
    return set(_ATTR_RE.findall(rule.check.sql))


def _cited_literals(rule) -> list[tuple[str, list[str]]]:
    """``(attr, [literals])`` for each equality/IN comparison in the SQL."""
    out = []
    for attr, single, in_list in _CMP_RE.findall(rule.check.sql):
        if single:
            out.append((attr, [single]))
        elif in_list:
            out.append((attr, re.findall(r"'([^']*)'", in_list)))
    return out


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
        node_type = _node_type_of(rule)
        for attr in sorted(_cited_attrs(rule)):
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
    ("sql", "expected"),
    [
        ("json_extract_string(attrs, '$.a') = 'X'", [("a", ["X"])]),
        ("json_extract_string(attrs, '$.a') != 'X'", [("a", ["X"])]),
        ("json_extract_string(attrs, '$.a') <> 'X'", [("a", ["X"])]),
        ("json_extract_string(attrs, '$.a') IN ('X', 'Y')", [("a", ["X", "Y"])]),
        ("json_extract_string(attrs, '$.a') NOT IN ('X', 'Y')", [("a", ["X", "Y"])]),
        # the other extraction function must be covered too
        ("json_extract(attrs, '$.a') = 'X'", [("a", ["X"])]),
        ("json_extract(attrs, '$.a') NOT IN ('X')", [("a", ["X"])]),
        # thresholds and patterns are not domain members — must NOT be captured
        ("json_extract_string(attrs, '$.a') < '1.2'", []),
        ("json_extract_string(attrs, '$.a') LIKE '%zone%'", []),
    ],
)
def test_comparison_pattern_recognises_every_form_used(sql, expected):
    """Pin what layer 2 can see, form by form.

    The mutation test for layer 2 only ever tried a lower-case ``IN`` list, so it
    passed while ``NOT IN`` went unexamined — an exercise that confirms the
    answer already known rather than probing the boundary (形态 #2). These cases
    fail if the pattern loses a form, and are the reason the ``NOT IN`` gap was
    found at all.
    """
    rule = type("R", (), {"check": QueryCheck(type="query", sql=sql)})()
    assert _cited_literals(rule) == expected


@pytest.mark.unit
def test_compared_literals_are_inside_the_declared_value_domain():
    """Layer 2: a right name compared against an impossible value is still dead.

    ``$.action IN ('reject','drop','deny')`` passed layer 1 — ``action`` is
    produced — yet could never match, because NSX returns ``DROP``.
    """
    offenders = []
    for baseline_id, rule in _real_rules():
        node_type = _node_type_of(rule)
        for attr, literals in _cited_literals(rule):
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
        node_type = _node_type_of(rule)
        if any(
            (entry := lookup(node_type, attr)) and entry.status is Status.PENDING
            for attr in _cited_attrs(rule)
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
