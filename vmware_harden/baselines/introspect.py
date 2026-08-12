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

_NODE_TYPE_RE = re.compile(r"\btype\s*=\s*'([a-z_]+)'")
#: Any mention of the `type` column, however it is used. Paired with
#: `_NODE_TYPE_RE` to prove no scope predicate went unread — see `node_type_of`.
_TYPE_IDENT_RE = re.compile(r"\btype\b")
#: Any mention of the `attrs` column, quoted or not. Paired with
#: `_ATTRS_READ_RE` the same way — see `cited_attributes`.
_ATTRS_IDENT_RE = re.compile(r'"?\battrs\b"?')

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
    sql = rule.check.sql
    _reject_sql_comments(rule.id, sql)
    found = set(_NODE_TYPE_RE.findall(sql))
    if len(found) != 1:
        raise UnreadableRuleError(
            f"{rule.id}: expected exactly one `type = '...'` scope in the SQL, "
            f"found {sorted(found) or 'none'} — cannot tell which collector owns "
            f"its attributes"
        )
    # Same counting argument as for `attrs`: a predicate written `type IN
    # ('host')` or `type LIKE 'host'` is invisible to the equality pattern, so a
    # rule can be scoped to one node type and judged against another's
    # vocabulary — and an attribute that is uncollected for hosts may well be
    # ACTIVE for dfw_rule, which turns the vocabulary check into a formality.
    mentions = len(_TYPE_IDENT_RE.findall(sql))
    if mentions != len(_NODE_TYPE_RE.findall(sql)):
        raise UnreadableRuleError(
            f"{rule.id}: the SQL constrains `type` in a form this cannot read "
            f"(only `type = '<node_type>'` is understood, not IN / LIKE / a "
            f"join). The node type decides which collector's vocabulary the "
            f"rule is checked against, so it must be unambiguous."
        )
    return found.pop()


def cited_attributes(rule: Rule) -> set[str]:
    """Every ``attrs`` key the rule's SQL reads.

    Accepts the three spellings DuckDB treats as equivalent — ``'$.name'``,
    ``'$."name"'`` and a bare ``'name'``.

    Refuses anything else. The refusal is the point: this is regex over SQL
    text, and a regex that misses a read reports "cites nothing", which the
    caller reads as safe to run. An adversarial pass produced 19 legal DuckDB
    spellings that all slipped past an earlier version — a single space after
    the function name was enough, as were an inline comment, a quoted
    ``"attrs"``, ``attrs->>'k'``, ``attrs['k']``, a concatenated path, and a
    CTE that aliases the column. Each read the attribute for real and was
    waved through as evaluable.

    So the check is inverted: rather than trust the pattern to find every read,
    :func:`_assert_every_attrs_reference_was_understood` demands that the number
    of reads it *did* parse accounts for every mention of ``attrs`` in the SQL.
    A spelling this cannot parse is then a hard error rather than an invisible
    one, and the runner turns it into an undetermined outcome.

    None of the nine builtin baselines uses any of these forms; the exposure is
    external ``--baseline`` files and rules written later — which is exactly the
    case this module exists for.
    """
    if not isinstance(rule.check, QueryCheck):
        return set()
    sql = rule.check.sql
    _reject_sql_comments(rule.id, sql)
    names: set[str] = set()
    matches = list(_ATTRS_READ_RE.finditer(sql))
    for m in matches:
        path = m.group(1)
        simple = _SIMPLE_PATH_RE.match(path)
        if simple is None:
            raise UnreadableRuleError(
                f"{rule.id}: cannot resolve the attrs path {path!r} to a single "
                f"attribute name, so the rule's inputs cannot be checked against "
                f"the collector vocabulary"
            )
        names.add(simple.group(1))
    _assert_every_attrs_reference_was_understood(rule.id, sql, len(matches))
    return names


def _reject_sql_comments(rule_id: str, sql: str) -> None:
    """SQL comments hide reads from every text-based check here.

    ``json_extract_string(attrs/*x*/, '$.k')`` parses for DuckDB and not for us,
    and a comment can equally carry a decoy ``type = '...'`` that misdirects the
    scope. No builtin rule uses a comment, so refusing them costs nothing and
    removes a whole class of blind spot.
    """
    if "--" in sql or "/*" in sql:
        raise UnreadableRuleError(
            f"{rule_id}: SQL comments are not allowed in a rule — they can hide "
            f"an attribute read or a node-type scope from the collector-contract "
            f"check. Remove the comment; put the explanation in the rule's "
            f"rationale."
        )


def _assert_every_attrs_reference_was_understood(
    rule_id: str, sql: str, parsed: int
) -> None:
    """Every mention of ``attrs`` must belong to a read we parsed.

    The regex can only vouch for reads it recognises. Counting the bare
    identifier and demanding the totals agree converts "a spelling we never saw"
    into "a spelling we could not read" — which the fail-closed path already
    handles. Without it, an unrecognised spelling is silently worth zero cited
    attributes and the rule runs.
    """
    mentions = len(_ATTRS_IDENT_RE.findall(sql))
    if mentions != parsed:
        raise UnreadableRuleError(
            f"{rule_id}: the SQL mentions `attrs` {mentions} time(s) but only "
            f"{parsed} of them are reads this can parse. Use "
            f"json_extract_string(attrs, '$.key') — other spellings "
            f"(->>, attrs['key'], a quoted \"attrs\", an alias, a concatenated "
            f"path) read the column without declaring which attribute the rule "
            f"depends on, so it cannot be checked against the collector "
            f"vocabulary."
        )


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
