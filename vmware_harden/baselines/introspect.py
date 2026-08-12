"""Read what a rule's SQL asks of the Twin, without executing it.

Both the contract test and the check runner need to know which node type a rule
is scoped to and which ``attrs`` keys it reads. Keeping one implementation here
is the point: a second copy in the test would drift from the one production
uses, and the test would then be validating parsing that never runs.

The parsing is deliberately shallow — regex over the rule's SQL text, not a SQL
parser. It is sound for the shapes the builtin baselines use, and every function
refuses rather than guesses when it meets something it cannot read (see
:func:`node_type_of`), so an unparseable rule becomes visibly undetermined
instead of silently evaluated against the wrong scope.
"""

import re

from vmware_harden.baselines.model import QueryCheck, Rule

_NODE_TYPE_RE = re.compile(r"type\s*=\s*'([a-z_]+)'")
_ATTR_RE = re.compile(r"\$\.([a-zA-Z0-9_]+)")

#: ``json_extract[_string](attrs, '$.x') <op> 'literal'`` plus ``IN`` / ``NOT IN``.
#:
#: Both extraction functions must be matched, and ``NOT`` must be optional: an
#: earlier version accepted only ``json_extract_string`` and only a bare ``IN``,
#: so it silently skipped two of the 49 literal comparisons in the builtin
#: baselines — a check whose name promised to validate all of them.
#:
#: Ordered comparisons (``<``, ``>``) and ``LIKE`` are excluded on purpose: their
#: operand is a threshold or a pattern, not a member of the value domain, so
#: ``tls_min_version < '1.2'`` is correct even though ``'1.2'`` is not an
#: enumerated value.
_CMP_RE = re.compile(
    r"json_extract(?:_string)?\(\s*attrs\s*,\s*'\$\.([a-zA-Z0-9_]+)'\s*\)\s*"
    r"(?:(?:=|!=|<>)\s*'([^']*)'|(?:NOT\s+)?IN\s*\(([^)]*)\))",
    re.IGNORECASE,
)


class UnreadableRuleError(ValueError):
    """A rule's SQL cannot be introspected, so its scope is unknown."""


def node_type_of(rule: Rule) -> str:
    """The single node type a rule's SQL is scoped to.

    Refuses to guess. An early draft of this analysis defaulted to ``host`` when
    no scope was found — a fail-open that happened never to trigger, but would
    have hidden a whole rule from the contract the day it did. A rule that joins
    two node types, or names none, raises instead: the caller must decide, and
    the check runner turns that into an undetermined outcome rather than
    evaluating against a guessed scope.
    """
    if not isinstance(rule.check, QueryCheck):
        raise UnreadableRuleError(f"{rule.id}: not a query check")
    found = set(_NODE_TYPE_RE.findall(rule.check.sql))
    if len(found) != 1:
        raise UnreadableRuleError(
            f"{rule.id}: expected exactly one `type = '...'` scope in the SQL, "
            f"found {sorted(found) or 'none'} — cannot tell which collector owns "
            f"its attributes"
        )
    return found.pop()


def cited_attributes(rule: Rule) -> set[str]:
    """Every ``$.key`` the rule's SQL reads from ``attrs``."""
    if not isinstance(rule.check, QueryCheck):
        return set()
    return set(_ATTR_RE.findall(rule.check.sql))


def cited_literals(rule: Rule) -> list[tuple[str, list[str]]]:
    """``(attr, [literals])`` for each equality/``IN`` comparison in the SQL."""
    if not isinstance(rule.check, QueryCheck):
        return []
    out: list[tuple[str, list[str]]] = []
    for attr, single, in_list in _CMP_RE.findall(rule.check.sql):
        if single:
            out.append((attr, [single]))
        elif in_list:
            out.append((attr, re.findall(r"'([^']*)'", in_list)))
    return out
