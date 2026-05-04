"""vSphere SCG v8 baseline shape tests."""
import pytest

from vmware_harden.baselines.loader import load_builtin
from vmware_harden.baselines.model import QueryCheck


@pytest.mark.unit
def test_scg_baseline_loadable():
    b = load_builtin("vsphere-scg-v8-subset")
    assert b.id == "vsphere-scg-v8-subset"


@pytest.mark.unit
def test_scg_has_15_rules():
    b = load_builtin("vsphere-scg-v8-subset")
    assert len(b.rules) == 15


@pytest.mark.unit
def test_scg_applies_to_host_and_vm():
    b = load_builtin("vsphere-scg-v8-subset")
    assert "host" in b.applies_to
    assert "vm" in b.applies_to


@pytest.mark.unit
def test_scg_rule_ids_unique_and_prefixed():
    b = load_builtin("vsphere-scg-v8-subset")
    ids = [r.id for r in b.rules]
    assert len(ids) == len(set(ids))
    assert all(rid.startswith("scg-") for rid in ids)


@pytest.mark.unit
def test_scg_all_query_checks():
    b = load_builtin("vsphere-scg-v8-subset")
    for r in b.rules:
        assert isinstance(r.check, QueryCheck), f"Rule {r.id} not query"


@pytest.mark.unit
def test_scg_categories_distributed():
    """Rules span at least 4 categories (host-hardening, vm-hardening, network, encryption)."""
    b = load_builtin("vsphere-scg-v8-subset")
    cats = {r.category for r in b.rules}
    assert len(cats) >= 4


@pytest.mark.unit
def test_scg_source_references_vmware():
    b = load_builtin("vsphere-scg-v8-subset")
    assert b.source is not None
    assert "vmware.com" in b.source.lower() or "vmware/" in b.source.lower()
