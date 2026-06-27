"""Regression tests for the vSphere 9 built-in baselines.

The v9 baselines are honest relabels: they `extends` their v8 counterparts and
inherit every stable host/VM hardening rule verbatim (no fabricated v9-specific
rule IDs or build thresholds). These tests lock that contract.
"""

from __future__ import annotations

import pytest

from vmware_harden.baselines.loader import list_builtins, load_builtin

_V9_PARENTS = {
    "cis-vmware-esxi-9.0-subset": "cis-vmware-esxi-8.0-subset",
    "vsphere-scg-v9-subset": "vsphere-scg-v8-subset",
}


@pytest.mark.parametrize("name", sorted(_V9_PARENTS))
def test_v9_baseline_is_discoverable(name: str) -> None:
    assert name in list_builtins()


@pytest.mark.parametrize("name,parent", sorted(_V9_PARENTS.items()))
def test_v9_inherits_all_parent_rules(name: str, parent: str) -> None:
    child = load_builtin(name)
    parent_baseline = load_builtin(parent)
    # extends with empty child rules → exact inheritance, no rules dropped/added.
    assert {r.id for r in child.rules} == {r.id for r in parent_baseline.rules}
    assert child.version.endswith("-subset")
    assert child.extends == parent


@pytest.mark.parametrize("name", sorted(_V9_PARENTS))
def test_v9_rules_all_have_checks(name: str) -> None:
    # Guard against an inherited rule losing its check (would silently pass).
    assert all(r.check is not None for r in load_builtin(name).rules)
