"""PCI-DSS 4.0 baseline shape tests."""
import pytest

from vmware_harden.baselines.loader import load_builtin
from vmware_harden.baselines.model import QueryCheck


@pytest.mark.unit
def test_pci_loadable():
    b = load_builtin("pci-dss-4.0-vmware")
    assert b.id == "pci-dss-4.0-vmware"


@pytest.mark.unit
def test_pci_has_10_rules():
    assert len(load_builtin("pci-dss-4.0-vmware").rules) == 10


@pytest.mark.unit
def test_pci_rule_ids_prefixed():
    b = load_builtin("pci-dss-4.0-vmware")
    for r in b.rules:
        assert r.id.startswith("pci-r"), f"Rule {r.id} should start with pci-r<N>-"


@pytest.mark.unit
def test_pci_rationale_cites_requirement():
    b = load_builtin("pci-dss-4.0-vmware")
    for r in b.rules:
        assert r.rationale, f"Rule {r.id} missing rationale"
        # Each rule must cite a PCI-DSS Requirement number
        assert "Requirement" in r.rationale or "Req " in r.rationale, \
            f"Rule {r.id} should cite a PCI-DSS Requirement"


@pytest.mark.unit
def test_pci_covers_required_pci_areas():
    """At least 4 of Reqs 1, 2, 7, 8, 10 covered."""
    b = load_builtin("pci-dss-4.0-vmware")
    reqs = set()
    for r in b.rules:
        for tag in ("Req 1", "Req 2", "Req 7", "Req 8", "Req 10",
                    "Requirement 1", "Requirement 2", "Requirement 7",
                    "Requirement 8", "Requirement 10"):
            if tag in (r.rationale or ""):
                reqs.add(tag.replace("Requirement ", "Req "))
    # Normalize to req numbers
    nums = {r.split()[-1] for r in reqs}
    assert len(nums) >= 4, f"Only {len(nums)} requirements covered: {nums}"


@pytest.mark.unit
def test_pci_applies_includes_dfw():
    """PCI Req 1 lives on dfw_rule type."""
    b = load_builtin("pci-dss-4.0-vmware")
    assert "dfw_rule" in b.applies_to


@pytest.mark.unit
def test_pci_all_query_checks():
    b = load_builtin("pci-dss-4.0-vmware")
    for r in b.rules:
        assert isinstance(r.check, QueryCheck)
