"""Mixed-product advisories must retain each CVE's own applicability and fix."""

from datetime import date

import pytest
from pydantic import ValidationError

from vmware_harden.advisories.baseline import NodeVerdict, evidence
from vmware_harden.advisories.catalog import load_shipped_catalog
from vmware_harden.advisories.match import Component, evaluate
from vmware_harden.advisories.model import Advisory, Catalog


def _catalog(**overrides):
    data = {
        "id": "VMSA-test",
        "published": "2026-01-01",
        "title": "Mixed products",
        "severity": "critical",
        "sources": ["https://example.invalid/advisory"],
        "cves": [
            {"id": "CVE-2026-1001", "products": ["vcenter"], "cvss": 9.8, "kev": True},
            {"id": "CVE-2026-1002", "products": ["esxi"], "cvss": 9.3},
            {"id": "CVE-2026-1003", "products": ["esxi"], "cvss": 7.6, "kev": True},
        ],
        "affected": [
            {
                "product": "vcenter",
                "line": "8.0",
                "fixed": [{"update": 3, "build": 300, "label": "VC fix"}],
            },
            {
                "product": "esxi",
                "line": "8.0",
                "cves": ["CVE-2026-1002"],
                "fixed": [{"update": 3, "build": 200, "label": "ESX critical fix"}],
            },
            {
                "product": "esxi",
                "line": "8.0",
                "cves": ["CVE-2026-1003"],
                "fixed": [{"update": 3, "build": 100, "label": "ESX important fix"}],
            },
        ],
    }
    data.update(overrides)
    return Catalog(as_of=date(2026, 1, 2), advisories=[Advisory.model_validate(data)])


def _judge(product, build, *, catalog=None, version="8.0.3"):
    cat = catalog or _catalog()
    return evaluate(Component(product, version, build), cat.advisories[0], cat)


def test_cves_are_scoped_to_the_component_product():
    result = _judge("vcenter", 50)
    assert {c.id for c in result.cves} == {"CVE-2026-1001"}
    assert result.status == "affected"
    result = _judge("esxi", 50)
    assert {c.id for c in result.cves} == {"CVE-2026-1002", "CVE-2026-1003"}


def test_partial_fix_does_not_attribute_fixed_or_foreign_cves_or_kev():
    cat = _catalog()
    result = _judge("esxi", 150, catalog=cat)
    assert result.status == "affected" and result.fixed_in == "ESX critical fix"
    assert {c.id: c.status for c in result.cves} == {
        "CVE-2026-1002": "affected",
        "CVE-2026-1003": "fixed",
    }
    detail = evidence("VMSA-test", NodeVerdict("host-1", result, "8.0.3", 150), cat)
    assert detail["cves"] == ["CVE-2026-1002"]
    assert detail["kev"] is False
    assert detail["max_affected_cvss"] == 9.3
    assert len(detail["cve_results"]) == 2


def test_all_applicable_cves_must_be_fixed_for_a_clean_result():
    assert _judge("esxi", 200).status == "fixed"
    assert _judge("esxi", None).status == "unknown"
    cat = _catalog()
    data = cat.model_dump()
    data["advisories"][0]["affected"][2]["line"] = "9.0"
    cat = Catalog.model_validate(data)
    result = _judge("esxi", 200, catalog=cat)
    assert result.status == "unknown"
    assert {c.id: c.status for c in result.cves}["CVE-2026-1003"] == "unknown"


@pytest.mark.parametrize("mutation", ["unknown-cve", "wrong-product", "overlap"])
def test_catalog_rejects_ambiguous_or_invalid_cve_mappings(mutation):
    data = _catalog().advisories[0].model_dump()
    if mutation == "unknown-cve":
        data["affected"][1]["cves"] = ["CVE-2026-9999"]
    elif mutation == "wrong-product":
        data["affected"][1]["cves"] = ["CVE-2026-1001"]
    else:
        data["affected"].append(dict(data["affected"][1]))
    with pytest.raises(ValidationError):
        Advisory.model_validate(data)


@pytest.mark.parametrize(
    "version,build,affected",
    [
        ("8.0.3", 25205845, {"CVE-2026-47876", "CVE-2026-41709"}),
        ("8.0.3", 25429389, {"CVE-2026-47876"}),
        ("8.0.3", 25595708, set()),
        ("9.1.0", 25370933, {"CVE-2026-47876"}),
        ("9.1.0", 25557999, set()),
        ("9.0.2", 25595025, set()),
    ],
)
def test_official_esxi_fix_thresholds_remain_distinct(version, build, affected):
    cat = load_shipped_catalog()
    adv = next(a for a in cat.advisories if a.id == "VMSA-2026-0006")
    result = evaluate(Component("esxi", version, build), adv, cat)
    assert {c.id for c in result.cves if c.status == "affected"} == affected
    assert result.status == ("affected" if affected else "fixed")
    assert all(c.id not in {"CVE-2026-59309", "CVE-2026-59310"} for c in result.cves)


def test_vcenter_91_first_fix_is_not_confused_with_the_second_cve_fix():
    cat = load_shipped_catalog()
    adv = next(a for a in cat.advisories if a.id == "VMSA-2026-0006")
    result = evaluate(Component("vcenter", "9.1.0.0200", 25573614), adv, cat)
    assert {c.id: c.status for c in result.cves} == {
        "CVE-2026-59309": "fixed",
        "CVE-2026-59310": "affected",
    }


def test_unlisted_eol_cve_rows_remain_unknown_even_with_another_affected_cve():
    cat = load_shipped_catalog()
    adv = next(a for a in cat.advisories if a.id == "VMSA-2026-0006")
    result = evaluate(Component("esxi", "7.0.3", 24585291), adv, cat)
    assert result.status == "affected"
    assert {c.id: c.status for c in result.cves} == {
        "CVE-2026-47876": "affected",
        "CVE-2026-41703": "unknown",
        "CVE-2026-41709": "unknown",
    }


def test_a_product_outside_the_advisory_is_not_applicable():
    assert _judge("other-product", 100).status == "not_applicable"
