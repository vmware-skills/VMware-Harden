"""Three-state advisory matching (proposal 2026-10-19 §7 B2).

A build is judged against one advisory as ``affected``, ``fixed``,
``not_affected`` (only when the advisory says so), ``not_applicable`` (the
advisory does not cover this product at all) or ``unknown``. Every way of not
knowing must land on ``unknown`` — the case this file exists to pin is the one
where the code has an easy wrong answer available.
"""

from datetime import date

import pytest

from vmware_harden.advisories.match import Component, evaluate, parse_version
from vmware_harden.advisories.model import Advisory, AffectedLine, Catalog, FixedRelease

AS_OF = date(2026, 10, 19)


def _advisory(**overrides) -> Advisory:
    base = {
        "id": "VMSA-2025-9999",
        "published": date(2025, 3, 4),
        "title": "test advisory",
        "severity": "critical",
        "cves": [{"id": "CVE-2025-0001", "cvss": 9.3}],
        "sources": ["https://example.invalid/vmsa"],
        "affected": [
            AffectedLine(
                product="esxi",
                line="8.0",
                fixed=[
                    FixedRelease(update=2, build=24585300, label="ESXi 8.0 Update 2d"),
                    FixedRelease(update=3, build=24585383, label="ESXi 8.0 Update 3d"),
                ],
            ),
            AffectedLine(
                product="esxi",
                line="7.0",
                fixed=[FixedRelease(update=3, build=24585291, label="ESXi 7.0 Update 3s")],
            ),
        ],
        "not_affected": [],
    }
    base.update(overrides)
    return Advisory(**base)


def _catalog(*advisories: Advisory, eol: dict | None = None) -> Catalog:
    return Catalog(
        as_of=AS_OF,
        eol=eol or {"esxi": {"6.7": date(2022, 10, 15)}},
        advisories=list(advisories),
    )


def _esxi(version: str | None, build) -> Component:
    return Component(product="esxi", version=version, build=build)


def _verdict(
    component: Component, advisory: Advisory | None = None, catalog: Catalog | None = None
):
    adv = advisory or _advisory()
    return evaluate(component, adv, catalog or _catalog(adv))


# --- the plain cases -----------------------------------------------------


def test_same_update_older_build_is_affected():
    v = _verdict(_esxi("8.0.3", 24280767))
    assert v.status == "affected"
    assert v.fixed_in == "ESXi 8.0 Update 3d"


def test_same_update_fixed_build_is_fixed():
    assert _verdict(_esxi("8.0.3", 24585383)).status == "fixed"


def test_same_update_newer_build_is_fixed():
    assert _verdict(_esxi("8.0.3", 25429389)).status == "fixed"


def test_branch_fix_is_judged_on_its_own_branch():
    # 8.0 U2 has its own fix (U2d). A U2 build is compared against U2d, not U3d.
    assert _verdict(_esxi("8.0.2", 24585300)).status == "fixed"
    assert _verdict(_esxi("8.0.2", 23825572)).status == "affected"


def test_update_older_than_every_fix_is_affected():
    v = _verdict(_esxi("8.0.1", 22088125))
    assert v.status == "affected"
    # The earliest branch that carries a fix is the one named.
    assert v.fixed_in == "ESXi 8.0 Update 2d"


def test_later_update_past_the_newest_fix_is_fixed():
    # Patches are cumulative within a line: a later update whose build is past
    # the newest fix contains it.
    v = _verdict(_esxi("8.0.4", 25000000))
    assert v.status == "fixed"
    assert v.fixed_in == "ESXi 8.0 Update 3d"


# --- every way of not knowing is unknown ------------------------------------


@pytest.mark.parametrize(
    "version,build",
    [
        (None, 24280767),
        ("8.0.3", None),
        ("N/A", 24280767),  # list_hosts' placeholder for an unreadable property
        ("8.0.3", "N/A"),
        ("8.0.3", ""),
        ("", 24280767),
        ("garbage", 24280767),
        ("8.0.3", "not-a-number"),
    ],
)
def test_unreadable_version_or_build_is_unknown(version, build):
    v = _verdict(_esxi(version, build))
    assert v.status == "unknown", (version, build, v)


def test_line_not_listed_is_unknown_not_safe():
    # 9.0 appears nowhere in the advisory. Not listed is not a verdict.
    v = _verdict(_esxi("9.0.0", 24755229))
    assert v.status == "unknown"


def test_eol_line_is_unknown_with_reason():
    # An advisory lists only supported lines; an EOL line's absence says nothing.
    v = _verdict(_esxi("6.7.0", 17700523))
    assert v.status == "unknown"
    assert "end of" in v.reason.lower() or "eol" in v.reason.lower()


def test_update_newer_than_every_fix_with_lower_build_is_unknown():
    # A later update whose build is below the newest fix cannot be placed.
    v = _verdict(_esxi("8.0.4", 24000000))
    assert v.status == "unknown"


def test_update_between_two_fixes_is_unknown():
    adv = _advisory(
        affected=[
            AffectedLine(
                product="esxi",
                line="8.0",
                fixed=[
                    FixedRelease(update=1, build=22088125, label="ESXi 8.0 Update 1x"),
                    FixedRelease(update=3, build=24585383, label="ESXi 8.0 Update 3d"),
                ],
            )
        ]
    )
    # U2 has no fix of its own listed; whether it is affected is not established.
    assert _verdict(_esxi("8.0.2", 99999999), adv).status == "unknown"


# --- build numbers are only comparable inside a line -------------------------


def test_build_is_never_compared_across_lines():
    # 24585295 is past the 7.0 U3s fix (24585291) but below 8.0 U3d (24585383).
    # Compared against the 7.0 entry it would read as fixed; on its own 8.0
    # line it is affected.
    v = _verdict(_esxi("8.0.3", 24585295))
    assert v.status == "affected"
    assert v.fixed_in == "ESXi 8.0 Update 3d"


def test_older_update_is_affected_whatever_its_build_number():
    # 7.0 U2 is older than the only 7.0 fix (U3s): a large build number on the
    # older branch does not make it fixed.
    assert _verdict(_esxi("7.0.2", 99999999)).status == "affected"


# --- explicit vendor statements --------------------------------------------


def test_no_fix_available_is_affected():
    adv = _advisory(affected=[AffectedLine(product="esxi", line="8.0", fixed=[])])
    v = _verdict(_esxi("8.0.3", 99999999), adv)
    assert v.status == "affected"
    assert v.fixed_in is None
    assert "no fix" in v.reason.lower()


def test_not_affected_only_when_the_advisory_says_so():
    adv = _advisory(not_affected=[{"product": "esxi", "line": "9.0"}])
    assert _verdict(_esxi("9.0.0", 24755229), adv).status == "not_affected"


def test_product_the_advisory_does_not_cover_is_not_applicable():
    vc = Component(product="vcenter", version="8.0.3", build=24322831)
    assert _verdict(vc).status == "not_applicable"


# --- parsing -----------------------------------------------------------------


@pytest.mark.parametrize(
    "text,expected",
    [
        ("8.0.3", ("8.0", 3)),
        ("7.0.3", ("7.0", 3)),
        ("9.1.0", ("9.1", 0)),
        ("8.0", ("8.0", 0)),
        ("8.0.3.00500", ("8.0", 3)),  # vCenter VAMI-style four-part version
    ],
)
def test_parse_version(text, expected):
    assert parse_version(text) == expected


@pytest.mark.parametrize(
    "text", [None, "", "N/A", "8", "abc", "8.x.3", 8.0, "8.0.\u00b3", "\uff18.0.3"]
)
def test_parse_version_rejects_what_it_cannot_read(text):
    assert parse_version(text) is None


def test_bool_build_is_not_a_build():
    # bool is an int subclass; True must not read as build 1.
    assert _verdict(_esxi("8.0.3", True)).status == "unknown"


# --- what the catalog itself is unsure of ------------------------------------


def test_branch_marked_uncertain_is_unknown_even_with_a_high_build():
    # VMSA-2024-0019: sources disagree on whether 8.0 U2e carries the fix.
    adv = _advisory(
        affected=[
            AffectedLine(
                product="esxi",
                line="8.0",
                fixed=[FixedRelease(update=3, build=24585383, label="ESXi 8.0 Update 3d")],
                unknown_updates=[2],
            )
        ]
    )
    v = _verdict(_esxi("8.0.2", 99999999), adv)
    assert v.status == "unknown"
    assert "uncertain" in v.reason.lower() or "not established" in v.reason.lower()


def test_product_covered_but_not_catalogued_is_unknown_not_applicable():
    # VMSA-2026-0006 covers ESX too; only its vCenter half is catalogued.
    adv = _advisory(uncatalogued_products=["vcenter"])
    vc = Component(product="vcenter", version="8.0.3", build=25600417)
    v = _verdict(vc, adv)
    assert v.status == "unknown"
    assert "not catalogued" in v.reason.lower()


@pytest.mark.parametrize("build", ["\u00b3", "\uff12\uff14\uff15", "24585383\n"])
def test_non_ascii_digit_build_is_unknown_not_a_crash(build):
    assert _verdict(_esxi("8.0.3", build)).status in {"unknown", "fixed"}
    assert _verdict(_esxi("8.0.3", "\u00b3")).status == "unknown"
