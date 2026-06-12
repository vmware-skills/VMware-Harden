"""Posture drift: detect baseline version evolution.

Compares two Baseline instances and reports rules added / removed / modified.
Modifications detect changes in: severity, category, check (type or sql/module),
and review_policy.
"""
from dataclasses import dataclass, field

from vmware_harden.baselines.model import (
    Baseline,
    QueryCheck,
    Rule,
    ScriptCheck,
)


@dataclass(frozen=True)
class RuleModification:
    """A single rule modified between versions."""

    rule_id: str
    # changed_fields[field_path] = (old_value, new_value)
    changed_fields: dict[str, tuple[str, str]]


@dataclass
class PostureDelta:
    """Aggregate of rule additions / removals / modifications."""

    added: list[Rule] = field(default_factory=list)
    removed: list[Rule] = field(default_factory=list)
    modified: list[RuleModification] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"{len(self.added)} added, "
            f"{len(self.removed)} removed, "
            f"{len(self.modified)} modified"
        )


def _rule_check_signature(rule: Rule) -> str:
    """Stable string repr of the check body for diff comparison."""
    if isinstance(rule.check, QueryCheck):
        return f"query::{rule.check.sql}"
    if isinstance(rule.check, ScriptCheck):
        return f"script::{rule.check.module}::{rule.check.function}"
    return "unknown"


def _diff_rule(old: Rule, new: Rule) -> dict[str, tuple[str, str]]:
    """Field-level diff between two rules with the same id."""
    changes: dict[str, tuple[str, str]] = {}
    if old.severity != new.severity:
        changes["severity"] = (old.severity, new.severity)
    if old.category != new.category:
        changes["category"] = (old.category, new.category)
    if old.title != new.title:
        changes["title"] = (old.title, new.title)
    old_sig = _rule_check_signature(old)
    new_sig = _rule_check_signature(new)
    if old_sig != new_sig:
        # Be more precise — split type vs body
        if isinstance(old.check, QueryCheck) and isinstance(new.check, QueryCheck):
            if old.check.sql != new.check.sql:
                changes["check.sql"] = (old.check.sql, new.check.sql)
        else:
            changes["check.type"] = (
                getattr(old.check, "type", "?"),
                getattr(new.check, "type", "?"),
            )
    if old.review_policy != new.review_policy:
        changes["review_policy"] = (
            str(old.review_policy.model_dump()),
            str(new.review_policy.model_dump()),
        )
    return changes


def posture_drift(old: Baseline, new: Baseline) -> PostureDelta:
    """Compare two Baseline versions; return added/removed/modified rules.

    RESERVED: this is intentionally not wired to any CLI or MCP entry point
    yet. It is the building block for a future "your baseline evolved since
    last scan" surface; it is covered by unit tests and kept ready, not a
    dead/forgotten function.
    """
    old_by_id = {r.id: r for r in old.rules}
    new_by_id = {r.id: r for r in new.rules}

    delta = PostureDelta()

    for rid, rule in new_by_id.items():
        if rid not in old_by_id:
            delta.added.append(rule)

    for rid, rule in old_by_id.items():
        if rid not in new_by_id:
            delta.removed.append(rule)

    for rid in old_by_id.keys() & new_by_id.keys():
        diff = _diff_rule(old_by_id[rid], new_by_id[rid])
        if diff:
            delta.modified.append(
                RuleModification(rule_id=rid, changed_fields=diff)
            )

    return delta
