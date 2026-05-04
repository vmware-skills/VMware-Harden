"""EU NIS2 Directive baseline shape tests."""
import pytest

from vmware_harden.baselines.loader import load_builtin
from vmware_harden.baselines.model import QueryCheck


@pytest.mark.unit
def test_nis2_loadable():
    b = load_builtin("eu-nis2-vmware")
    assert b.id == "eu-nis2-vmware"


@pytest.mark.unit
def test_nis2_has_12_rules():
    assert len(load_builtin("eu-nis2-vmware").rules) == 12


@pytest.mark.unit
def test_nis2_rule_ids_prefixed():
    b = load_builtin("eu-nis2-vmware")
    for r in b.rules:
        assert r.id.startswith("nis2-"), f"Rule {r.id} should start with nis2-"


@pytest.mark.unit
def test_nis2_rule_ids_unique():
    b = load_builtin("eu-nis2-vmware")
    ids = [r.id for r in b.rules]
    assert len(ids) == len(set(ids))


@pytest.mark.unit
def test_nis2_rationale_cites_directive():
    b = load_builtin("eu-nis2-vmware")
    for r in b.rules:
        assert r.rationale, f"Rule {r.id} missing rationale"
        assert "NIS2" in r.rationale, f"Rule {r.id} should cite NIS2"


@pytest.mark.unit
def test_nis2_all_query_checks():
    b = load_builtin("eu-nis2-vmware")
    for r in b.rules:
        assert isinstance(r.check, QueryCheck)


@pytest.mark.unit
def test_nis2_applies_to_host_and_dfw():
    b = load_builtin("eu-nis2-vmware")
    assert "host" in b.applies_to
    assert "dfw_rule" in b.applies_to
