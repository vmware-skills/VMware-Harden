"""Pydantic schema validation for baseline YAML format."""
import pytest
from pydantic import ValidationError

from vmware_harden.baselines.model import (
    Baseline,
    QueryCheck,
    Remediation,
    ReviewPolicy,
    Rule,
    ScriptCheck,
)


@pytest.mark.unit
def test_parse_minimal_baseline():
    raw = {
        "id": "test-1",
        "name": "Test Baseline",
        "version": "1.0.0",
        "applies_to": ["host"],
        "rules": [
            {
                "id": "r-1",
                "title": "NTP enabled",
                "severity": "medium",
                "category": "time-sync",
                "check": {
                    "type": "query",
                    "sql": "SELECT id FROM nodes WHERE type = 'host'",
                },
                "remediation": {"summary": "Enable NTP"},
            }
        ],
    }
    b = Baseline(**raw)
    assert b.id == "test-1"
    assert b.applies_to == ["host"]
    assert len(b.rules) == 1
    rule = b.rules[0]
    assert rule.id == "r-1"
    assert isinstance(rule.check, QueryCheck)
    assert rule.check.type == "query"


@pytest.mark.unit
def test_parse_script_check_baseline():
    raw = {
        "id": "test-script",
        "name": "Script test",
        "version": "1.0.0",
        "applies_to": ["host"],
        "rules": [
            {
                "id": "r-script",
                "title": "Custom check",
                "severity": "high",
                "category": "custom",
                "check": {
                    "type": "script",
                    "module": "vmware_harden.checks.custom",
                    "function": "check_x",
                },
                "remediation": {"summary": "Fix x"},
            }
        ],
    }
    b = Baseline(**raw)
    assert isinstance(b.rules[0].check, ScriptCheck)
    assert b.rules[0].check.module == "vmware_harden.checks.custom"
    assert b.rules[0].check.function == "check_x"


@pytest.mark.unit
def test_invalid_severity_rejected():
    with pytest.raises(ValidationError):
        Rule(
            id="r",
            title="x",
            severity="bogus",
            category="x",
            check={"type": "query", "sql": "SELECT 1"},
            remediation={"summary": "x"},
        )


@pytest.mark.unit
def test_invalid_node_type_rejected():
    with pytest.raises(ValidationError):
        Baseline(
            id="t", name="t", version="1.0.0", applies_to=["bogus_type"], rules=[]
        )


@pytest.mark.unit
def test_unknown_check_type_rejected():
    with pytest.raises(ValidationError):
        Rule(
            id="r",
            title="x",
            severity="low",
            category="x",
            check={"type": "magic", "spell": "abracadabra"},
            remediation={"summary": "x"},
        )


@pytest.mark.unit
def test_review_policy_defaults():
    """ReviewPolicy not provided defaults applied."""
    raw_rule = {
        "id": "r-1",
        "title": "x",
        "severity": "medium",
        "category": "x",
        "check": {"type": "query", "sql": "SELECT 1"},
        "remediation": {"summary": "x"},
    }
    rule = Rule(**raw_rule)
    assert rule.review_policy.human_review_required is True
    assert rule.review_policy.min_confidence == 0.8


@pytest.mark.unit
def test_review_policy_overridable():
    raw_rule = {
        "id": "r-1",
        "title": "x",
        "severity": "medium",
        "category": "x",
        "check": {"type": "query", "sql": "SELECT 1"},
        "remediation": {"summary": "x"},
        "review_policy": {"human_review_required": False, "min_confidence": 0.95},
    }
    rule = Rule(**raw_rule)
    assert rule.review_policy.human_review_required is False
    assert rule.review_policy.min_confidence == 0.95


@pytest.mark.unit
def test_remediation_optional_fields():
    """Remediation requires only `summary`; others optional."""
    r = Remediation(summary="just docs")
    assert r.mcp_tool is None
    assert r.params_template is None
    assert r.manual_steps is None
    assert r.risk is None


@pytest.mark.unit
def test_baseline_extends_field():
    """`extends` is optional on Baseline (used in Task 6)."""
    raw = {
        "id": "child", "name": "child", "version": "1.0.0",
        "extends": "parent-baseline",
        "applies_to": ["host"], "rules": [],
    }
    b = Baseline(**raw)
    assert b.extends == "parent-baseline"
