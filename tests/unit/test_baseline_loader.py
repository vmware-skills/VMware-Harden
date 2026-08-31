"""Baseline YAML loader tests."""
import pytest

from vmware_harden.baselines.loader import (
    list_builtins,
    load_baseline,
    load_builtin,
)
from vmware_harden.baselines.model import Baseline


@pytest.mark.unit
def test_list_builtins_includes_cis_esxi_subset():
    builtins = list_builtins()
    assert "cis-vmware-esxi-8.0-subset" in builtins


@pytest.mark.unit
def test_load_builtin_returns_baseline_instance():
    b = load_builtin("cis-vmware-esxi-8.0-subset")
    assert isinstance(b, Baseline)
    assert b.id == "cis-vmware-esxi-8.0-subset"
    assert b.applies_to == ["host"]


@pytest.mark.unit
def test_load_builtin_has_at_least_two_rules():
    b = load_builtin("cis-vmware-esxi-8.0-subset")
    assert len(b.rules) >= 2
    rule_ids = {r.id for r in b.rules}
    assert "cis-esxi-2.1.1" in rule_ids


@pytest.mark.unit
def test_load_baseline_from_arbitrary_path(tmp_path):
    """load_baseline accepts any path, parses YAML, returns Baseline."""
    p = tmp_path / "custom.yaml"
    p.write_text(
        """
id: test-custom
name: Custom Test
version: 1.0.0
applies_to: [host]
rules:
  - id: r-1
    title: x
    severity: low
    category: x
    check:
      type: query
      sql: SELECT 1
    remediation:
      summary: y
""".lstrip()
    , encoding="utf-8")
    b = load_baseline(p)
    assert b.id == "test-custom"
    assert len(b.rules) == 1


@pytest.mark.unit
def test_load_builtin_unknown_raises_filenotfound():
    with pytest.raises(FileNotFoundError):
        load_builtin("does-not-exist")


@pytest.mark.unit
def test_script_check_rejected_at_load_time(tmp_path):
    """Per Task 5 review I3: ScriptCheck reserved for v2 — loader must reject.

    Even though the schema accepts it, loader gates execution to v2.
    """
    p = tmp_path / "script.yaml"
    p.write_text(
        """
id: script-test
name: Script
version: 1.0.0
applies_to: [host]
rules:
  - id: r-script
    title: x
    severity: low
    category: x
    check:
      type: script
      module: m
      function: f
    remediation:
      summary: y
""".lstrip()
    , encoding="utf-8")
    with pytest.raises(NotImplementedError, match="script checks reserved for v2"):
        load_baseline(p)
