"""Regression: the vSphere 9 STIG-aligned baseline is loadable, correctly
counted, and — critically — cites only *verified* STIG controls and no phantom
compliance API (踩坑 #36 / 形态 #1 guards).

This is content/definition work, not endpoint work: harden wraps no compliance
API because VCF Operations 9.1 ACC/SPM exposes none. These tests pin that the
shipped baseline maps every control to a verified ESXi advanced setting, that
its content source is a verified one, and that nothing in the package reaches
for a hallucinated compliance endpoint.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.eval.spec import vcf91_compliance as spec
from vmware_harden.baselines.loader import list_builtins, load_builtin
from vmware_harden.baselines.model import QueryCheck
from vmware_harden.baselines.stig import (
    CONTROL_SETTINGS,
    STIG_BASELINE_ID,
    describe_content_sync,
    stig_catalog,
)
from vmware_harden.collectors.hosts import PRODUCIBLE_HOST_ATTRS

#: Matches a ``json_extract(attrs, '$.some_key')`` attribute reference in rule SQL.
_ATTR_KEY_RE = re.compile(r"\$\.([a-z_][a-z0-9_]*)")


def _cited_attr_keys(baseline) -> set[str]:
    keys: set[str] = set()
    for rule in baseline.rules:
        keys.update(_ATTR_KEY_RE.findall(rule.check.sql))
    return keys

#: Locks the representative control set — a dropped rule (which would silently
#: stop scanning that control) fails here rather than shipping.
EXPECTED_RULE_COUNT = 12

pytestmark = pytest.mark.unit


def test_stig_baseline_discoverable_and_loadable():
    assert STIG_BASELINE_ID in list_builtins()
    b = load_builtin(STIG_BASELINE_ID)
    assert b.id == STIG_BASELINE_ID
    assert b.applies_to == ["host"]
    assert b.rules  # non-empty (also enforced by test_baseline_loadable)


def test_stig_baseline_rule_count_pinned():
    b = load_builtin(STIG_BASELINE_ID)
    assert len(b.rules) == EXPECTED_RULE_COUNT
    assert len({r.id for r in b.rules}) == EXPECTED_RULE_COUNT  # ids unique


def test_stig_rules_are_query_checks_against_nodes():
    """Declarative SQL only (no ScriptCheck) and each reads the twin's nodes."""
    b = load_builtin(STIG_BASELINE_ID)
    for rule in b.rules:
        assert isinstance(rule.check, QueryCheck), rule.id
        assert "nodes" in rule.check.sql, rule.id
        assert "type = 'host'" in rule.check.sql, rule.id


def test_every_control_maps_to_a_verified_advanced_setting():
    """Anti-phantom: no rule may cite a STIG control nobody verified.

    The rule->setting map must cover exactly the baseline's rules, and every
    mapped setting must be in the verified-settings set seeded from the spec.
    """
    b = load_builtin(STIG_BASELINE_ID)
    rule_ids = {r.id for r in b.rules}
    assert set(CONTROL_SETTINGS) == rule_ids, (
        "CONTROL_SETTINGS keys must match the baseline's rule ids exactly; "
        f"symmetric diff: {set(CONTROL_SETTINGS) ^ rule_ids}"
    )
    unverified = set(CONTROL_SETTINGS.values()) - spec.VERIFIED_STIG_ADVANCED_SETTINGS
    assert not unverified, f"phantom STIG advanced settings cited: {unverified}"


def test_stig_source_is_a_verified_content_source():
    b = load_builtin(STIG_BASELINE_ID)
    assert b.source in spec.VERIFIED_STIG_CONTENT_SOURCES


def test_stig_catalog_rows_are_high_signal():
    catalog = stig_catalog()
    assert len(catalog) == EXPECTED_RULE_COUNT
    for row in catalog:
        assert set(row) == {"id", "title", "severity", "category", "advanced_setting"}
        # advanced_setting resolved for every shipped rule (no gap)
        assert row["advanced_setting"], row["id"]
        assert row["advanced_setting"] in spec.VERIFIED_STIG_ADVANCED_SETTINGS


def test_content_sync_is_honest_about_no_api():
    info = describe_content_sync()
    assert info["compliance_api_available"] is False
    assert spec.COMPLIANCE_API_AVAILABLE is False
    # Routes continuous enforcement to SPM/ACC, keeps harden as the scanner.
    assert "SPM" in info["routing_note"] or "ACC" in info["routing_note"]
    assert info["content_sources"]


def test_every_stig_sql_key_is_collector_producible():
    """doc-vs-code parity (形态 #6): every ``$.key`` the STIG baseline SQL reads
    must be a key the host collector can actually populate.

    This is the guard for the false-compliance defect: rules that read
    ``nodes.attrs`` keys no collector writes match zero rows, so every host
    reports compliant regardless of its real configuration. If the collector's
    producible-key set and the baseline's cited keys drift apart, this fails
    here rather than silently shipping a baseline that always passes.
    """
    b = load_builtin(STIG_BASELINE_ID)
    cited = _cited_attr_keys(b)
    assert cited, "STIG baseline SQL cites no attrs keys — parser or baseline broke"
    unproducible = cited - PRODUCIBLE_HOST_ATTRS
    assert not unproducible, (
        "STIG rules read nodes.attrs keys the host collector cannot populate "
        f"(they would match 0 rows → false compliance): {sorted(unproducible)}. "
        "Add them to vmware_harden.collectors.hosts.STIG_ADVANCED_SETTING_ATTRS "
        "or remove the rules."
    )


def test_stig_baseline_marked_experimental_until_collector_verified():
    """Honesty marker: the baseline must self-declare its non-authoritative
    status in its metadata, and describe_stig_content_sync must relay it.

    The advanced-settings collector path is real-hardware-gated and unverified,
    so a scan must not read as authoritative. This pins that the ``status`` field
    is present (in the YAML → model) and surfaced through the content-sync
    description with an explicit caveat.
    """
    b = load_builtin(STIG_BASELINE_ID)
    assert getattr(b, "status", None) == "experimental-collector-pending"

    info = describe_content_sync()
    assert info["baseline_status"] == "experimental-collector-pending"
    assert info["authoritative"] is False
    assert info["status_caveat"]  # non-empty caveat string
    assert "experimental" in info["status_caveat"].lower()


def test_list_stig_controls_truncated_is_offset_aware():
    """MEDIUM: paginate the local STIG catalog and confirm ``truncated`` reflects
    absolute position, not just page size.

    paginated() computes ``truncated = returned < total``, which is
    offset-unaware: past the first page every slice is partial, so it would
    report truncated=true even on the final page. The tool must correct for
    offset so an agent paging to the end isn't told "there may be more" forever.
    """
    from vmware_harden.mcp.stig import list_stig_controls

    total = len(stig_catalog())
    assert total == EXPECTED_RULE_COUNT

    # Final partial page (offset past page 1): nothing follows it.
    last = list_stig_controls(limit=5, offset=total - 2)
    assert last["returned"] == 2
    assert last["truncated"] is False, "final page must not report more remaining"
    assert last["hint"] is None

    # A middle page (more rows follow) still reports truncated.
    mid = list_stig_controls(limit=5, offset=5)
    assert mid["returned"] == 5
    assert mid["truncated"] is True

    # total is still exact and offset-independent.
    assert last["total"] == total and mid["total"] == total


def test_no_phantom_compliance_api_in_package():
    """No source file may reference a hallucinated ACC/SPM compliance endpoint.

    Guards the 踩坑 #36 shape at the package level: a future contributor tempted
    to "just wrap ACC" would introduce one of these path fragments. Scans .py
    sources under the shipped package.
    """
    pkg_root = Path(__file__).resolve().parents[3] / "vmware_harden"
    sources = list(pkg_root.rglob("*.py"))
    assert sources, f"no python sources found under {pkg_root}"  # never scan nothing
    offenders: dict[str, list[str]] = {}
    for path in sources:
        text = path.read_text(encoding="utf-8")
        hits = [m for m in spec.FORBIDDEN_COMPLIANCE_API_MARKERS if m in text]
        if hits:
            offenders[str(path.relative_to(pkg_root))] = hits
    assert not offenders, f"phantom compliance API path fragments found: {offenders}"
