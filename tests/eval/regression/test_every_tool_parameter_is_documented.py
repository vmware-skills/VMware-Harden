"""Regression: every MCP tool parameter carries a Google-style ``Args:`` entry.

Why this exists
---------------
The JSON schema is the only part of a tool an agent can actually read. Prose in
the docstring body explains the tool; it says nothing about a *parameter*. A
measurement across the family's 327 tools found ``description`` coverage on
parameter schemas at 0% — every word of guidance was in prose the schema never
carried — and every one of this skill's 10 parameters was undescribed — including
``list_violations.severity``, whose five legal strings are validated exactly
and were nowhere in the schema, so a wrong guess returned zero violations.

The failure that produces is silent twice over. Guess a parameter name wrong
and the extra key is discarded, so a filtered query quietly returns the
unfiltered set. Guess a *value* wrong — ``aggregation="count()"`` where the
appliance wants ``COUNT`` — and you get an error or an empty series where there
was data. Neither looks like a mistake from the outside.

The family is landing a shared helper that copies each parameter's ``Args:``
entry into the schema at registration time. That helper can only copy text that
exists, so this test guards the input side: it fails the moment a tool grows a
parameter nobody described.

Not a style check
-----------------
It also refuses a description that only restates the name (``target: The
target.``). That is worse than an absent one: it fills the slot, so the gap
stops being visible while the agent still learns nothing.

形态 #1 — the check must not pass vacuously. If the registry hands back no
tools, or no tool has parameters, that is this test being broken rather than
this skill being clean, and it fails saying so.
"""

from __future__ import annotations

import inspect
import re

from vmware_harden.mcp_server.server import build_server

#: Words that carry no information about a parameter beyond its own name.
#: A description built only from these has filled the slot without saying
#: anything — the shape this test exists to reject.
_FILLER = {"a", "an", "the", "of", "for", "to", "this", "s", "id", "name", "optional"}


def parse_args_block(doc: str | None) -> dict[str, str]:
    """Return {parameter: description} from a Google-style ``Args:`` block.

    Deliberately the same parsing the family's schema-injection helper does:
    a check that reads docstrings differently from the code that consumes them
    would go green on text the helper cannot use.
    """
    if not doc:
        return {}
    block = re.search(
        r"\n\s*Args:\s*\n(.*?)(?:\n\s*(?:Returns|Raises|Yields|Examples?|Notes?):|\Z)",
        doc,
        re.DOTALL,
    )
    if not block:
        return {}
    out: dict[str, str] = {}
    current: str | None = None
    for line in block.group(1).splitlines():
        if not line.strip():
            continue
        entry = re.match(r"\s{4,}(\*{0,2}\w+)\s*(?:\([^)]*\))?\s*:\s*(.*)", line)
        if entry:
            current = entry.group(1).lstrip("*")
            out[current] = entry.group(2).strip()
        elif current:
            out[current] += " " + line.strip()
    return out


def _says_something(param: str, text: str) -> bool:
    """True when the description adds anything beyond the parameter's own name.

    Deliberately the weakest rule that still catches ``target: The target.`` —
    one word that is neither part of the name nor a connective. A stricter
    length or word-count rule would start failing short descriptions that are
    complete ("Server IP address."), and a check that fires on correct text is
    a check people learn to route around.
    """
    words = {w for w in re.findall(r"[a-z0-9]+", text.lower()) if w}
    words -= _FILLER
    words -= set(re.findall(r"[a-z0-9]+", param.lower()))
    return bool(words)


def test_every_tool_parameter_has_an_args_entry():
    """No registered tool parameter may be missing from its ``Args:`` block."""
    tools = build_server()._tool_manager._tools
    assert tools, "no MCP tools registered — this check would pass vacuously"

    checked = 0
    missing: list[str] = []
    for name, tool in tools.items():
        documented = parse_args_block(inspect.getdoc(tool.fn))
        for param in (tool.parameters or {}).get("properties", {}):
            checked += 1
            if param not in documented:
                missing.append(f"{name}.{param}")

    assert checked, "no tool parameters found — this check would pass vacuously"
    assert not missing, (
        f"{len(missing)} of {checked} tool parameters have no Args: entry, so the "
        f"schema an agent reads describes them not at all: {sorted(missing)}"
    )


def test_no_parameter_description_merely_restates_its_name():
    """A description that only echoes the name hides the gap instead of closing it."""
    tools = build_server()._tool_manager._tools
    assert tools, "no MCP tools registered — this check would pass vacuously"

    checked = 0
    empty: list[str] = []
    for name, tool in tools.items():
        documented = parse_args_block(inspect.getdoc(tool.fn))
        for param in (tool.parameters or {}).get("properties", {}):
            text = documented.get(param)
            if text is None:
                continue  # the test above owns this failure
            checked += 1
            if not _says_something(param, text):
                empty.append(f"{name}.{param}: {text!r}")

    assert checked, "no documented parameters found — this check would pass vacuously"
    assert not empty, "parameter descriptions that say nothing beyond the name: " + str(empty)
