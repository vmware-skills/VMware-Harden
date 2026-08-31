"""Baseline extends merge tests."""
import textwrap
from pathlib import Path

import pytest

from vmware_harden.baselines.loader import load_baseline


@pytest.mark.unit
def test_extends_merges_parent_rules(tmp_path: Path):
    """Child baseline gets all parent rules + its own."""
    child_yaml = textwrap.dedent("""
        id: my-child
        name: My Child
        version: 1.0.0
        extends: cis-vmware-esxi-8.0-subset
        applies_to: [host]
        rules:
          - id: my-extra
            title: Extra rule from child
            severity: low
            category: custom
            check:
              type: query
              sql: "SELECT id FROM nodes WHERE 1=2"
            remediation:
              summary: never fires
    """).strip()
    p = tmp_path / "child.yaml"
    p.write_text(child_yaml, encoding="utf-8")

    merged = load_baseline(p)
    rule_ids = {r.id for r in merged.rules}
    # Parent has 20 rules (cis-vmware-esxi-8.0-subset)
    assert "cis-esxi-2.1.1" in rule_ids  # parent rule preserved
    assert "my-extra" in rule_ids       # child rule added
    assert len(merged.rules) == 21      # 20 parent + 1 new


@pytest.mark.unit
def test_extends_child_overrides_parent_rule(tmp_path: Path):
    """Child rule with same id as parent rule replaces the parent's."""
    child_yaml = textwrap.dedent("""
        id: my-override
        name: Override
        version: 1.0.0
        extends: cis-vmware-esxi-8.0-subset
        applies_to: [host]
        rules:
          - id: cis-esxi-2.1.1
            title: REPLACED rule
            severity: critical
            category: time-sync
            check:
              type: query
              sql: "SELECT id FROM nodes WHERE 1=1"
            remediation:
              summary: replaced
    """).strip()
    p = tmp_path / "override.yaml"
    p.write_text(child_yaml, encoding="utf-8")

    merged = load_baseline(p)
    matching = [r for r in merged.rules if r.id == "cis-esxi-2.1.1"]
    assert len(matching) == 1  # not 2; parent rule was replaced
    assert matching[0].title == "REPLACED rule"
    assert matching[0].severity == "critical"  # was "medium" in parent
    # Parent still contributed its other 19 rules
    assert len(merged.rules) == 20


@pytest.mark.unit
def test_extends_unknown_parent_raises(tmp_path: Path):
    child_yaml = textwrap.dedent("""
        id: orphan
        name: orphan
        version: 1.0.0
        extends: does-not-exist-baseline
        applies_to: [host]
        rules: []
    """).strip()
    p = tmp_path / "orphan.yaml"
    p.write_text(child_yaml, encoding="utf-8")

    with pytest.raises(FileNotFoundError):
        load_baseline(p)


@pytest.mark.unit
def test_extends_preserves_child_metadata(tmp_path: Path):
    """Merged baseline has CHILD's id/name/version, not parent's."""
    child_yaml = textwrap.dedent("""
        id: my-id
        name: My Name
        version: 9.9.9
        extends: cis-vmware-esxi-8.0-subset
        applies_to: [host]
        rules: []
    """).strip()
    p = tmp_path / "c.yaml"
    p.write_text(child_yaml, encoding="utf-8")

    merged = load_baseline(p)
    assert merged.id == "my-id"
    assert merged.name == "My Name"
    assert merged.version == "9.9.9"
    # Inherited 20 parent rules
    assert len(merged.rules) == 20


@pytest.mark.unit
def test_no_extends_field_unchanged_behavior():
    """Loading a baseline without `extends` returns it as-is (regression guard)."""
    from vmware_harden.baselines.loader import load_builtin

    b = load_builtin("cis-vmware-esxi-8.0-subset")
    assert b.extends is None
    assert len(b.rules) == 20  # not doubled
