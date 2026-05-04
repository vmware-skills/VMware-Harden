"""Posture drift detection tests."""
import pytest

from vmware_harden.baselines.model import (
    Baseline,
    QueryCheck,
    Remediation,
    Rule,
    ReviewPolicy,
)
from vmware_harden.drift.posture import PostureDelta, posture_drift


def _rule(rid: str, severity: str = "medium", sql: str = "SELECT 1") -> Rule:
    return Rule(
        id=rid,
        title=rid,
        severity=severity,
        category="x",
        check=QueryCheck(type="query", sql=sql),
        remediation=Remediation(summary="x"),
    )


def _baseline(version: str, rules: list[Rule]) -> Baseline:
    return Baseline(
        id="b",
        name="b",
        version=version,
        applies_to=["host"],
        rules=rules,
    )


@pytest.mark.unit
def test_no_changes_yields_empty_delta():
    old = _baseline("1.0", [_rule("r-1"), _rule("r-2")])
    new = _baseline("1.0", [_rule("r-1"), _rule("r-2")])
    delta = posture_drift(old, new)
    assert delta.added == []
    assert delta.removed == []
    assert delta.modified == []


@pytest.mark.unit
def test_rule_added_in_new_version():
    old = _baseline("1.0", [_rule("r-1")])
    new = _baseline("1.1", [_rule("r-1"), _rule("r-2")])
    delta = posture_drift(old, new)
    assert [r.id for r in delta.added] == ["r-2"]
    assert delta.removed == []
    assert delta.modified == []


@pytest.mark.unit
def test_rule_removed_in_new_version():
    old = _baseline("1.0", [_rule("r-1"), _rule("r-2")])
    new = _baseline("1.1", [_rule("r-1")])
    delta = posture_drift(old, new)
    assert [r.id for r in delta.removed] == ["r-2"]
    assert delta.added == []


@pytest.mark.unit
def test_rule_severity_changed_modified_event():
    old = _baseline("1.0", [_rule("r-1", severity="medium")])
    new = _baseline("1.1", [_rule("r-1", severity="critical")])
    delta = posture_drift(old, new)
    assert len(delta.modified) == 1
    mod = delta.modified[0]
    assert mod.rule_id == "r-1"
    assert "severity" in mod.changed_fields
    assert mod.changed_fields["severity"] == ("medium", "critical")


@pytest.mark.unit
def test_rule_sql_changed_modified_event():
    old = _baseline("1.0", [_rule("r-1", sql="SELECT 1")])
    new = _baseline("1.1", [_rule("r-1", sql="SELECT 2")])
    delta = posture_drift(old, new)
    assert len(delta.modified) == 1
    assert "check.sql" in delta.modified[0].changed_fields


@pytest.mark.unit
def test_combined_add_remove_modify():
    old = _baseline("1.0", [
        _rule("r-1", severity="low"),
        _rule("r-2"),  # will be removed
    ])
    new = _baseline("1.1", [
        _rule("r-1", severity="critical"),  # modified
        _rule("r-3"),  # added
    ])
    delta = posture_drift(old, new)
    assert [r.id for r in delta.added] == ["r-3"]
    assert [r.id for r in delta.removed] == ["r-2"]
    assert len(delta.modified) == 1
    assert delta.modified[0].rule_id == "r-1"


@pytest.mark.unit
def test_summary_property_string():
    old = _baseline("1.0", [_rule("r-1")])
    new = _baseline("1.1", [_rule("r-1"), _rule("r-2")])
    delta = posture_drift(old, new)
    s = delta.summary()
    assert "1 added" in s
    assert "0 removed" in s
    assert "0 modified" in s
