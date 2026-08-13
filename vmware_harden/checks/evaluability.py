"""Decide whether a rule can judge anything before running it.

A rule that reads an ``attrs`` key no collector writes matches zero rows. Zero
rows is indistinguishable from "every node complies", so executing such a rule
and reporting no violations states something the scan never established. 76 of
99 builtin rules were in exactly that state, silently reporting compliance.

So the runner asks here first, and refuses to execute a rule it cannot trust —
the same fail-closed stance a guard is supposed to take when it cannot get its
data (a guard that returns "nothing to see" when the lookup failed is how a
management-interface deletion got waved through once already).

This is the runtime half of the contract. The regression test in
``tests/eval/regression/test_baseline_collector_contract.py`` covers the builtin
baselines at CI time; this covers whatever the user actually loads, including an
external ``--baseline custom.yaml`` that CI has never seen.
"""

from dataclasses import dataclass

from vmware_harden.baselines.introspect import UnreadableRuleError, cited_attributes, node_type_of
from vmware_harden.baselines.model import Rule
from vmware_harden.baselines.vocabulary import Status, lookup


@dataclass(frozen=True)
class Evaluability:
    """Whether a rule can be executed, and why not when it cannot."""

    evaluable: bool
    #: Empty when evaluable. Otherwise a teaching sentence naming the blocking
    #: attributes and what to do — this reaches the user in scan output.
    reason: str = ""
    #: The attributes that blocked evaluation, for machine consumers.
    blocking_attributes: tuple[str, ...] = ()
    #: The node type the rule is scoped to, and every attribute its SQL reads.
    #: Empty when the SQL could not be introspected at all. Carried here so the
    #: caller can do per-node coverage without parsing the same SQL a second
    #: time — and, more to the point, without a second parse that could reach a
    #: different answer than the one this verdict was based on.
    node_type: str = ""
    attributes: tuple[str, ...] = ()


def classify(rule: Rule) -> Evaluability:
    """Report whether ``rule`` can judge real configuration.

    A rule is evaluable only when every ``attrs`` key it reads is declared
    ACTIVE for its node type — that is, some collector demonstrably writes it.
    Anything else is undetermined:

    * an attribute declared ``PENDING`` (intended, collector unwritten)
    * an attribute absent from the vocabulary (typo, or an external baseline
      written against keys this build does not collect)
    * SQL whose node-type scope cannot be read at all
    """
    try:
        node_type = node_type_of(rule)
        attrs = sorted(cited_attributes(rule))
    except UnreadableRuleError as exc:
        return Evaluability(False, str(exc))

    pending: list[str] = []
    unknown: list[str] = []
    for attr in attrs:
        entry = lookup(node_type, attr)
        if entry is None:
            unknown.append(attr)
        elif entry.status is not Status.ACTIVE:
            pending.append(attr)

    if not pending and not unknown:
        return Evaluability(True, node_type=node_type, attributes=tuple(attrs))

    # Name the attributes and nothing else. Why an unevaluated rule is not a
    # pass belongs in the report's one-line summary, not repeated verbatim on
    # every row — a reason that scrolls is a reason nobody reads.
    parts: list[str] = []
    if pending:
        parts.append(
            f"no collector writes {', '.join(f'{node_type}.{a}' for a in pending)}"
        )
    if unknown:
        parts.append(
            f"{', '.join(f'{node_type}.{a}' for a in unknown)} "
            f"not declared in vocabulary.py"
        )
    return Evaluability(
        False,
        "; ".join(parts),
        tuple(pending + unknown),
        node_type=node_type,
        attributes=tuple(attrs),
    )
