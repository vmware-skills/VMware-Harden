"""等保 2.0 三级 baseline shape and content tests."""
import pytest

from vmware_harden.baselines.loader import load_builtin
from vmware_harden.baselines.model import QueryCheck


@pytest.mark.unit
def test_dengbao_loadable():
    b = load_builtin("dengbao-2.0-level3-vmware")
    assert b.id == "dengbao-2.0-level3-vmware"


@pytest.mark.unit
def test_dengbao_has_20_rules():
    b = load_builtin("dengbao-2.0-level3-vmware")
    assert len(b.rules) == 20


@pytest.mark.unit
def test_dengbao_rule_ids_prefixed_db_l3():
    b = load_builtin("dengbao-2.0-level3-vmware")
    for r in b.rules:
        assert r.id.startswith("db-l3-"), f"Rule {r.id} missing db-l3- prefix"


@pytest.mark.unit
def test_dengbao_all_query_checks():
    b = load_builtin("dengbao-2.0-level3-vmware")
    for r in b.rules:
        assert isinstance(r.check, QueryCheck), f"Rule {r.id} not query"


@pytest.mark.unit
def test_dengbao_rationale_cites_gb_standard():
    """Every rule must cite GB/T 22239 章节号 in rationale (国内合规审计要素)."""
    b = load_builtin("dengbao-2.0-level3-vmware")
    for r in b.rules:
        assert r.rationale is not None, f"Rule {r.id} missing rationale"
        assert "GB/T 22239" in r.rationale, (
            f"Rule {r.id} rationale must cite GB/T 22239: got {r.rationale!r}"
        )


@pytest.mark.unit
def test_dengbao_covers_required_chapters():
    """Rules must reference at least 5 of the 8 主要章节 (8.1.1 通过 8.1.8)."""
    b = load_builtin("dengbao-2.0-level3-vmware")
    chapters = set()
    for r in b.rules:
        for ch in ("8.1.1", "8.1.2", "8.1.3", "8.1.4", "8.1.5", "8.1.6", "8.1.7", "8.1.8"):
            if ch in (r.rationale or ""):
                chapters.add(ch)
    assert len(chapters) >= 5, f"Only {len(chapters)} chapters covered: {chapters}"


@pytest.mark.unit
def test_dengbao_applies_to_multi_resource():
    """等保 spans host, vm, dfw_rule, datastore."""
    b = load_builtin("dengbao-2.0-level3-vmware")
    assert "host" in b.applies_to
    assert "vm" in b.applies_to


@pytest.mark.unit
def test_dengbao_source_field_present():
    b = load_builtin("dengbao-2.0-level3-vmware")
    assert b.source is not None
    assert "GB/T 22239" in b.source or "等保" in b.source
