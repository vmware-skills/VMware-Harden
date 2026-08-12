"""Read what a rule's SQL asks of the Twin, without executing it.

Both the contract test and the check runner need to know which node type a rule
is scoped to and which ``attrs`` keys it reads. Keeping one implementation here
is the point: a second copy in the test would drift from the one production
uses, and the test would then be validating parsing that never runs.

**Why an AST and not a regex.** This started as pattern matching over the SQL
text. An adversarial pass produced 19 legal DuckDB spellings that each read an
uncollected attribute for real and were still judged evaluable — the cheapest
being a single space after the function name. The anchor was the weakness: the
pattern needed the literal function name, the literal identifier ``attrs`` and
an adjacent comma, and one stray character unhooked it. A missed read reports
"cites nothing", and "cites nothing" is what the caller treats as safe to run.

DuckDB will parse its own dialect for us. ``json_serialize_sql()`` returns the
real syntax tree, where every one of those spellings collapses to the same
node — the space, the comment, the quoted ``"attrs"``, the bare key. What the
tree cannot normalise (``attrs::JSON``, a concatenated path, ``attrs->>'k'``,
``attrs['k']``, a CTE that aliases the column) it still *shows*, as a reference
to the ``attrs`` column that no recognised extraction accounts for.

That is the invariant this module enforces: **every reference to a column must
belong to a read we understood.** Counting on the tree is sound in a way
counting on text never was — a ``COLUMN_REF`` naming ``attrs`` is there however
the query was written. Anything left over raises, and the runner turns that into
an undetermined outcome rather than a pass.
"""

import json
import re
import threading

import duckdb

from vmware_harden.baselines.model import QueryCheck, Rule

#: JSON extraction functions whose first argument is the JSON column and whose
#: second is the path. DuckDB normalises the ``->>`` and ``->`` operators into
#: function nodes under these names, so the operator forms are covered here too.
_EXTRACTORS = frozenset(
    {"json_extract", "json_extract_string", "json_value", "->", "->>"}
)

#: ``$.name``, ``$."name"`` or a bare ``name`` — the paths that name exactly one
#: attribute. Nested paths, wildcards and array indexes are deliberately not
#: reduced; see :func:`cited_attributes`.
_SIMPLE_PATH_RE = re.compile(r'^\s*(?:\$\.)?"?([a-zA-Z0-9_]+)"?\s*$')

#: One in-process DuckDB handle for parsing. Parsing touches no table and takes
#: ~0.1 ms, but a connection per call would dominate that. Guarded by a lock
#: because a connection is not documented as thread-safe and the MCP server may
#: serve concurrent tool calls.
_PARSER: duckdb.DuckDBPyConnection | None = None
_PARSER_LOCK = threading.Lock()


class UnreadableRuleError(ValueError):
    """A rule's SQL cannot be introspected, so what it depends on is unknown."""


def _parse(rule_id: str, sql: str) -> dict:
    """Return DuckDB's syntax tree for ``sql``, or raise.

    A rule whose SQL will not parse could not have run anyway; raising here
    means the runner reports it as undetermined instead of failing the scan.
    """
    global _PARSER
    with _PARSER_LOCK:
        if _PARSER is None:
            _PARSER = duckdb.connect()
        try:
            raw = _PARSER.execute("SELECT json_serialize_sql(?)", [sql]).fetchone()[0]
        except Exception as exc:  # duckdb raises its own hierarchy
            raise UnreadableRuleError(f"{rule_id}: SQL could not be parsed — {exc}") from exc
    tree = json.loads(raw)
    if tree.get("error"):
        raise UnreadableRuleError(
            f"{rule_id}: SQL could not be parsed — "
            f"{tree.get('error_message', 'unknown parse error')}"
        )
    statements = tree.get("statements") or []
    if len(statements) != 1:
        raise UnreadableRuleError(
            f"{rule_id}: expected exactly one statement, found {len(statements)}"
        )
    return statements[0]


def _walk(node) -> list:
    """Every dict in the tree, in no particular order."""
    out: list = []
    stack = [node]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            out.append(cur)
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)
    return out


def _column_refs(nodes: list, column: str) -> list[dict]:
    """Every reference to ``column``, however the query spelled it.

    This is the ground truth the parsed reads are checked against: quoting,
    whitespace and comments are gone by the time DuckDB hands us a
    ``COLUMN_REF``, and a table qualifier appears as a leading element of
    ``column_names`` rather than changing the name.
    """
    return [
        n for n in nodes
        if n.get("class") == "COLUMN_REF" and column in (n.get("column_names") or [])
    ]


def _constant_value(node) -> str | None:
    """The string value of a constant node, or None if it is not a plain constant."""
    if not isinstance(node, dict) or node.get("class") != "CONSTANT":
        return None
    value = node.get("value") or {}
    if value.get("is_null"):
        return None
    raw = value.get("value")
    return raw if isinstance(raw, str) else None


def _extraction_reads(nodes: list, column: str) -> list[tuple[dict, str | None]]:
    """``(function_node, path)`` for each recognised extraction from ``column``.

    ``path`` is None when the second argument is not a plain constant — a
    concatenated path, say. The read is still reported, so the caller can refuse
    it rather than lose track of it.
    """
    reads: list[tuple[dict, str | None]] = []
    for n in nodes:
        if n.get("class") != "FUNCTION" or n.get("function_name") not in _EXTRACTORS:
            continue
        children = n.get("children") or []
        if len(children) != 2:
            continue
        target, path = children
        if not (
            isinstance(target, dict)
            and target.get("class") == "COLUMN_REF"
            and column in (target.get("column_names") or [])
        ):
            # A cast or an alias sits between the column and the call. The
            # column reference is still counted below, so the mismatch surfaces.
            continue
        reads.append((n, _constant_value(path)))
    return reads


def _require_query_check(rule: Rule) -> str:
    if not isinstance(rule.check, QueryCheck):
        raise UnreadableRuleError(f"{rule.id}: not a query check")
    return rule.check.sql


def node_type_of(rule: Rule) -> str:
    """The single node type a rule's SQL is scoped to.

    Refuses to guess, twice over. There must be exactly one ``type = '<name>'``
    comparison, *and* every other reference to the ``type`` column must belong
    to it — otherwise a rule can declare one scope and select rows of another,
    which is enough on its own: an attribute uncollected for hosts may be
    collected for ``dfw_rule``, and the vocabulary check then passes while
    checking the wrong thing. An outer ``type = 'dfw_rule'`` over rows drawn
    from a ``type IN ('host')`` subquery is the concrete case.
    """
    sql = _require_query_check(rule)
    nodes = _walk(_parse(rule.id, sql))

    scoped: set[str] = set()
    accounted: list[int] = []
    for n in nodes:
        if n.get("class") != "COMPARISON" or n.get("type") != "COMPARE_EQUAL":
            continue
        left, right = n.get("left"), n.get("right")
        for column_side, value_side in ((left, right), (right, left)):
            if not (
                isinstance(column_side, dict)
                and column_side.get("class") == "COLUMN_REF"
                and "type" in (column_side.get("column_names") or [])
            ):
                continue
            value = _constant_value(value_side)
            if value is None:
                continue
            scoped.add(value)
            accounted.append(id(column_side))

    if len(scoped) != 1:
        raise UnreadableRuleError(
            f"{rule.id}: expected exactly one `type = '<node_type>'` scope, found "
            f"{sorted(scoped) or 'none'} — cannot tell which collector owns its "
            f"attributes"
        )
    stray = [n for n in _column_refs(nodes, "type") if id(n) not in accounted]
    if stray:
        raise UnreadableRuleError(
            f"{rule.id}: the SQL references `type` {len(stray)} more time(s) than "
            f"the single scope predicate accounts for (an IN / LIKE / subquery "
            f"form). The node type decides which collector's vocabulary applies, "
            f"so it must be unambiguous."
        )
    return scoped.pop()


def cited_attributes(rule: Rule) -> set[str]:
    """Every ``attrs`` key the rule's SQL reads.

    Accepts the spellings DuckDB treats as naming one attribute — ``'$.name'``,
    ``'$."name"'`` and a bare ``'name'`` — through any of its JSON extraction
    functions or the ``->``/``->>`` operators.

    Raises rather than returning an incomplete set. Two ways that happens: an
    extraction whose path is not a single constant name (nested, wildcard,
    concatenated), and any reference to the ``attrs`` column that no recognised
    extraction accounts for (``attrs::JSON``, ``attrs['k']``, a CTE aliasing the
    column). Both mean the rule's inputs are unknown, and unknown inputs must
    land on undetermined — silently returning fewer names is the failure this
    module was rewritten to remove.
    """
    if not isinstance(rule.check, QueryCheck):
        return set()
    nodes = _walk(_parse(rule.id, rule.check.sql))

    names: set[str] = set()
    accounted: list[int] = []
    for function_node, path in _extraction_reads(nodes, "attrs"):
        if path is None:
            raise UnreadableRuleError(
                f"{rule.id}: an attrs read has a computed path, so which attribute "
                f"it depends on cannot be determined"
            )
        simple = _SIMPLE_PATH_RE.match(path)
        if simple is None:
            raise UnreadableRuleError(
                f"{rule.id}: cannot resolve the attrs path {path!r} to a single "
                f"attribute name, so the rule's inputs cannot be checked against "
                f"the collector vocabulary"
            )
        names.add(simple.group(1))
        accounted.append(id((function_node.get("children") or [None])[0]))

    stray = [n for n in _column_refs(nodes, "attrs") if id(n) not in accounted]
    if stray:
        raise UnreadableRuleError(
            f"{rule.id}: the SQL references `attrs` {len(stray)} time(s) outside a "
            f"recognised extraction. Use json_extract_string(attrs, '$.key') — a "
            f"cast, a subscript, or aliasing the column reads it without declaring "
            f"which attribute the rule depends on, so it cannot be checked against "
            f"the collector vocabulary."
        )
    return names


#: Comparisons whose literal must lie inside the attribute's value domain.
#: Ordered comparisons are excluded on purpose: their operand is a threshold,
#: not a member of the domain, so ``tls_min_version < '1.2'`` is correct even
#: though ``'1.2'`` is not an enumerated value. ``LIKE`` is excluded likewise —
#: its operand is a pattern.
_DOMAIN_COMPARISONS = frozenset({"COMPARE_EQUAL", "COMPARE_NOTEQUAL"})


def cited_literals(rule: Rule) -> list[tuple[str, list[str]]]:
    """``(attr, [literals])`` for each equality or ``IN`` comparison in the SQL.

    Feeds the value-domain check: a rule can name a collected attribute and
    still be dead, if it compares against a value the attribute never holds.
    Three shipped comparing lower-case ``'drop'`` against NSX's ``DROP``.
    """
    if not isinstance(rule.check, QueryCheck):
        return []
    try:
        nodes = _walk(_parse(rule.id, rule.check.sql))
    except UnreadableRuleError:
        # Callers that want the refusal ask via cited_attributes/node_type_of;
        # this one reports what it can see and lets them decide.
        return []

    #: function node id -> attribute name, for extractions with a simple path
    reads: dict[int, str] = {}
    for function_node, path in _extraction_reads(nodes, "attrs"):
        if path is None:
            continue
        simple = _SIMPLE_PATH_RE.match(path)
        if simple is not None:
            reads[id(function_node)] = simple.group(1)

    out: list[tuple[str, list[str]]] = []
    for n in nodes:
        cls, node_type = n.get("class"), n.get("type")
        if cls == "COMPARISON" and node_type in _DOMAIN_COMPARISONS:
            left, right = n.get("left"), n.get("right")
            for column_side, value_side in ((left, right), (right, left)):
                attr = reads.get(id(column_side))
                value = _constant_value(value_side)
                # `is not None`, not truthiness: `= ''` is a value like any
                # other, and dropping it on falsiness meant the empty literal
                # was validated in IN form and skipped in equality form.
                if attr is not None and value is not None:
                    out.append((attr, [value]))
        elif cls == "OPERATOR" and node_type in ("COMPARE_IN", "COMPARE_NOT_IN"):
            children = n.get("children") or []
            if not children:
                continue
            attr = reads.get(id(children[0]))
            if attr is None:
                continue
            values = [v for v in (_constant_value(c) for c in children[1:]) if v is not None]
            if values:
                out.append((attr, values))
    return out
