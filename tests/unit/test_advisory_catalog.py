"""Mechanical checks on the shipped advisory catalog (形态 #6).

The catalog is hand-maintained data that decides whether a host is reported
vulnerable. These tests tie every fix to the build KB snapshot, so a typo in a
build number fails here instead of turning into a wrong verdict.
"""

from datetime import date

import pytest

from vmware_harden.advisories.catalog import load_builds, load_catalog
from vmware_harden.advisories.match import parse_version


@pytest.fixture(scope="module")
def catalog():
    return load_catalog()


@pytest.fixture(scope="module")
def builds():
    return load_builds()


def test_catalog_loads_and_is_not_empty(catalog):
    assert catalog.advisories, "the shipped catalog has no advisories"


def test_advisory_ids_are_unique(catalog):
    ids = [a.id for a in catalog.advisories]
    assert len(ids) == len(set(ids))


def test_no_advisory_postdates_the_catalog(catalog):
    for a in catalog.advisories:
        assert a.published <= catalog.as_of, a.id


def test_every_fix_matches_the_build_snapshot(catalog, builds):
    by_label = {r["label"]: r for r in builds["releases"]}
    checked = 0
    for adv in catalog.advisories:
        for line in adv.affected:
            for fix in line.fixed:
                row = by_label.get(fix.label)
                assert row is not None, f"{adv.id}: {fix.label!r} not in builds.yaml"
                assert row["product"] == line.product, (adv.id, fix.label)
                assert row["build"] == fix.build, (adv.id, fix.label, row["build"], fix.build)
                parsed = parse_version(row["version"])
                assert parsed == (line.line, fix.update), (adv.id, fix.label, parsed)
                checked += 1
    assert checked, "no fixes were checked — the comparison above ran on nothing"


def test_fix_was_released_on_or_after_publication_and_before_as_of(catalog, builds):
    by_label = {r["label"]: r for r in builds["releases"]}
    for adv in catalog.advisories:
        for line in adv.affected:
            for fix in line.fixed:
                released = by_label[fix.label]["released"]
                assert released <= catalog.as_of, (adv.id, fix.label)
                # A fix cannot predate the advisory that announced it.
                assert released >= adv.published, (adv.id, fix.label, released)


def test_builds_snapshot_has_no_duplicate_labels(builds):
    labels = [r["label"] for r in builds["releases"]]
    assert len(labels) == len(set(labels))


def test_every_advisory_cites_its_vmsa_page_and_nvd(catalog):
    for a in catalog.advisories:
        assert any("SecurityAdvisories" in s for s in a.sources), a.id
        assert any("nvd.nist.gov" in s for s in a.sources), a.id


def test_eol_dates_are_dates(catalog):
    for product, lines in catalog.eol.items():
        for line, when in lines.items():
            assert isinstance(when, date), (product, line)
            assert parse_version(line) is not None, (product, line)
