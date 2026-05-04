"""BSI IT-Grundschutz Basis-Absicherung baseline shape tests."""
import pytest

from vmware_harden.baselines.loader import load_builtin
from vmware_harden.baselines.model import QueryCheck


@pytest.mark.unit
def test_bsi_loadable():
    b = load_builtin("bsi-itgs-basisabsicherung-vmware")
    assert b.id == "bsi-itgs-basisabsicherung-vmware"


@pytest.mark.unit
def test_bsi_has_10_rules():
    assert len(load_builtin("bsi-itgs-basisabsicherung-vmware").rules) == 10


@pytest.mark.unit
def test_bsi_rule_ids_prefixed():
    b = load_builtin("bsi-itgs-basisabsicherung-vmware")
    for r in b.rules:
        assert r.id.startswith("bsi-itgs-"), f"Rule {r.id} should start with bsi-itgs-"


@pytest.mark.unit
def test_bsi_rule_ids_unique():
    b = load_builtin("bsi-itgs-basisabsicherung-vmware")
    ids = [r.id for r in b.rules]
    assert len(ids) == len(set(ids))


@pytest.mark.unit
def test_bsi_rationale_cites_grundschutz():
    b = load_builtin("bsi-itgs-basisabsicherung-vmware")
    for r in b.rules:
        assert r.rationale, f"Rule {r.id} missing rationale"
        assert "BSI IT-Grundschutz" in r.rationale, \
            f"Rule {r.id} should cite BSI IT-Grundschutz"


@pytest.mark.unit
def test_bsi_rationale_cites_module_id():
    """Each rule must cite a specific module ID like OPS.1.1.4 or SYS.1.1."""
    b = load_builtin("bsi-itgs-basisabsicherung-vmware")
    for r in b.rules:
        assert ("OPS.1.1.4" in r.rationale) or ("SYS.1.1" in r.rationale), \
            f"Rule {r.id} should cite OPS.1.1.4 or SYS.1.1"


@pytest.mark.unit
def test_bsi_all_query_checks():
    b = load_builtin("bsi-itgs-basisabsicherung-vmware")
    for r in b.rules:
        assert isinstance(r.check, QueryCheck)


@pytest.mark.unit
def test_bsi_severity_mix():
    """Should have mix of high and medium severity."""
    b = load_builtin("bsi-itgs-basisabsicherung-vmware")
    severities = {r.severity for r in b.rules}
    assert "high" in severities
    assert "medium" in severities


@pytest.mark.unit
def test_bsi_applies_to_host():
    b = load_builtin("bsi-itgs-basisabsicherung-vmware")
    assert b.applies_to == ["host"]
