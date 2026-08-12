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

#: Every read of the ``attrs`` JSON column, whatever path syntax it uses.
#:
#: Anchored on the extraction call rather than on ``$.``, because DuckDB accepts
#: a bare key too: ``json_extract_string(attrs, 'ssh_enabled')`` returns exactly
#: what ``'$.ssh_enabled'`` does. Matching only the ``$.`` form meant such a rule
#: cited *no* attributes at all, so it was judged evaluable, ran, matched
#: nothing, and its silence counted as compliance — the very defect this module
#: exists to prevent, reachable by an external baseline written in legal SQL.
_ATTRS_READ_RE = re.compile(
    r"json_extract(?:_string)?\(\s*(?:[a-zA-Z_][a-zA-Z0-9_]*\s*\.\s*)?attrs\s*,\s*'([^']*)'\s*\)",
    re.IGNORECASE,
)
#: A path this module knows how to reduce to a single attribute name:
#: ``$.name``, ``$."name"`` or a bare ``name``. Anything else (nested paths,
#: wildcards, array indexes) is deliberately *not* parsed — see
#: :func:`cited_attributes`.
_SIMPLE_PATH_RE = re.compile(r"^\s*(?:\$\.)?\"?([a-zA-Z0-9_]+)\"?\s*$")

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
    r"json_extract(?:_string)?\(\s*(?:[a-zA-Z_][a-zA-Z0-9_]*\s*\.\s*)?attrs\s*,\s*"
    r"'(?:\$\.)?\"?([a-zA-Z0-9_]+)\"?'\s*\)\s*"
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
    """Every ``attrs`` key the rule's SQL reads.

    Accepts the three spellings DuckDB treats as equivalent — ``'$.name'``,
    ``'$."name"'`` and a bare ``'name'``.

    Raises :class:`UnreadableRuleError` for a path this cannot reduce to one
    attribute name (a nested path, a wildcard, an array index). Returning an
    empty set there would read as "cites nothing", which the caller takes as
    "safe to run" — the same fail-open that let bare-key rules through. An
    unparseable read means the rule's inputs are unknown, and unknown inputs
    must land on undetermined.
    """
    if not isinstance(rule.check, QueryCheck):
        return set()
    names: set[str] = set()
    for path in _ATTRS_READ_RE.findall(rule.check.sql):
        m = _SIMPLE_PATH_RE.match(path)
        if m is None:
            raise UnreadableRuleError(
                f"{rule.id}: cannot resolve the attrs path {path!r} to a single "
                f"attribute name, so the rule's inputs cannot be checked against "
                f"the collector vocabulary"
            )
        names.add(m.group(1))
    return names


def cited_literals(rule: Rule) -> list[tuple[str, list[str]]]:
    """``(attr, [literals])`` for each equality/``IN`` comparison in the SQL."""
    if not isinstance(rule.check, QueryCheck):
        return []
    out: list[tuple[str, list[str]]] = []
    for m in _CMP_RE.finditer(rule.check.sql):
        attr, single, in_list = m.group(1), m.group(2), m.group(3)
        # Branch on which group matched, not on truthiness: `= ''` yields an
        # empty string, which is falsy, so a comparison against the empty
        # literal was dropped entirely — validated in `IN ('')` form and
        # skipped in `= ''` form, for the same attribute.
        if single is not None:
            out.append((attr, [single]))
        elif in_list is not None:
            out.append((attr, re.findall(r"'([^']*)'", in_list)))
    return out
