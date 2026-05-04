"""Pin the count of rules in the CIS ESXi subset."""
import pytest

from vmware_harden.baselines.loader import load_builtin


@pytest.mark.unit
def test_cis_esxi_subset_has_20_rules():
    b = load_builtin("cis-vmware-esxi-8.0-subset")
    assert len(b.rules) == 20


@pytest.mark.unit
def test_cis_esxi_subset_covers_required_categories():
    """All eight policy categories must be represented."""
    b = load_builtin("cis-vmware-esxi-8.0-subset")
    categories = {r.category for r in b.rules}
    required = {
        "time-sync",
        "patching",
        "logging",
        "network",
        "firewall",
        "auth",
        "encryption",
        "misc",
    }
    missing = required - categories
    assert not missing, f"Missing categories: {missing}"


@pytest.mark.unit
def test_cis_esxi_subset_rule_ids_unique():
    b = load_builtin("cis-vmware-esxi-8.0-subset")
    ids = [r.id for r in b.rules]
    assert len(ids) == len(set(ids)), "Duplicate rule ids found"


@pytest.mark.unit
def test_cis_esxi_subset_all_query_checks():
    """MVP only supports query checks; ScriptCheck would be rejected by loader."""
    from vmware_harden.baselines.model import QueryCheck

    b = load_builtin("cis-vmware-esxi-8.0-subset")
    for rule in b.rules:
        assert isinstance(rule.check, QueryCheck), (
            f"Rule {rule.id} has non-query check"
        )
