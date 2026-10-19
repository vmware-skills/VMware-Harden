"""Optional online refresh of the advisory catalog (proposal §8 P2).

`vmware-harden advisories update` reads the CISA KEV feed and NVD, writes a
local cache, and the catalog loader overlays it. Every way a fetch can go wrong
must be a failure the user sees — never an empty refresh read as "nothing new".
"""

import json
from datetime import date

import pytest
from typer.testing import CliRunner

from vmware_harden.advisories import catalog as catalog_mod
from vmware_harden.advisories.catalog import load_catalog
from vmware_harden.advisories.model import Catalog
from vmware_harden.advisories.refresh import (
    RefreshError,
    apply_overlay,
    parse_kev,
    parse_nvd_cvss,
    refresh,
)

KEV = {
    "catalogVersion": "2026.10.20",
    "dateReleased": "2026-10-20T12:00:00Z",
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-59309",
            "vendorProject": "VMware",
            "product": "vCenter",
            "dateAdded": "2026-10-19",
        },
        {
            "cveID": "CVE-2026-59310",
            "vendorProject": "VMware",
            "product": "vCenter",
            "dateAdded": "2026-08-18",
        },
        {
            "cveID": "CVE-2026-99999",
            "vendorProject": "Broadcom",
            "product": "VMware ESXi",
            "dateAdded": "2026-10-20",
        },
        {
            "cveID": "CVE-2025-0001",
            "vendorProject": "Other",
            "product": "Thing",
            "dateAdded": "2025-01-01",
        },
        {
            "cveID": "CVE-2022-22965",
            "vendorProject": "VMware",
            "product": "Spring Framework",
            "dateAdded": "2022-04-04",
        },
        {
            "cveID": "CVE-2020-3950",
            "vendorProject": "VMware",
            "product": "Multiple Products",
            "dateAdded": "2021-11-03",
        },
    ],
}


def _nvd(cve: str, score: float | None, source: str = "security@vmware.com") -> dict:
    metrics = (
        {"cvssMetricV31": [{"source": source, "cvssData": {"baseScore": score}}]}
        if score is not None
        else {}
    )
    return {"vulnerabilities": [{"cve": {"id": cve, "metrics": metrics}}]}


class FakeHttp:
    """Records requests; answers from a table keyed by URL substring."""

    def __init__(self, table: dict, fail: set | None = None):
        self.table, self.fail, self.calls = table, fail or set(), []

    def __call__(self, url: str) -> bytes:
        self.calls.append(url)
        for key in self.fail:
            if key in url:
                raise RefreshError(f"HTTP 503 from {url}")
        for key, body in self.table.items():
            if key in url:
                return body if isinstance(body, bytes) else json.dumps(body).encode()
        raise AssertionError(f"unexpected URL {url}")


def _http(**overrides) -> FakeHttp:
    table = {"known_exploited": KEV}
    for c in load_catalog().advisories:
        for cve in c.cves:
            table[cve.id] = _nvd(cve.id, cve.cvss)
    table.update(overrides)
    return FakeHttp(table)


# --- parsing: every malformed answer is a failure ----------------------------


def test_parse_kev_reads_the_cve_set_and_vmware_rows():
    snap = parse_kev(json.dumps(KEV).encode())
    assert snap.catalog_version == "2026.10.20"
    assert "CVE-2026-59309" in snap.cves
    assert {r["cveID"] for r in snap.vmware} == {
        "CVE-2026-59309",
        "CVE-2026-59310",
        "CVE-2026-99999",
        "CVE-2022-22965",
        "CVE-2020-3950",
    }


@pytest.mark.parametrize(
    "body",
    [
        b"<!DOCTYPE html><title>Just a moment...</title>",  # bot challenge page
        b"",
        b"{}",
        json.dumps({"catalogVersion": "x", "vulnerabilities": []}).encode(),
        json.dumps({"vulnerabilities": [{"nope": 1}]}).encode(),
        json.dumps([1, 2]).encode(),
    ],
)
def test_parse_kev_refuses_anything_that_is_not_a_populated_feed(body):
    with pytest.raises(RefreshError):
        parse_kev(body)


def test_parse_nvd_prefers_vmware_scored_cvss():
    body = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-1",
                    "metrics": {
                        "cvssMetricV31": [
                            {"source": "nvd@nist.gov", "cvssData": {"baseScore": 7.0}},
                            {"source": "security@vmware.com", "cvssData": {"baseScore": 9.3}},
                        ]
                    },
                }
            }
        ]
    }
    assert parse_nvd_cvss(json.dumps(body).encode(), "CVE-1") == 9.3


def test_parse_nvd_without_a_score_is_none_not_zero():
    assert parse_nvd_cvss(json.dumps(_nvd("CVE-1", None)).encode(), "CVE-1") is None


@pytest.mark.parametrize("body", [b"<html>", b"{}", json.dumps({"vulnerabilities": []}).encode()])
def test_parse_nvd_refuses_a_missing_record(body):
    with pytest.raises(RefreshError):
        parse_nvd_cvss(body, "CVE-1")


# --- refresh --------------------------------------------------------------------


def test_refresh_marks_catalogued_cves_and_lists_the_uncatalogued(tmp_path):
    cache = tmp_path / "cache.json"
    result = refresh(load_catalog(), cache, http_get=_http(), sleep=lambda s: None)
    data = json.loads(cache.read_text(encoding="utf-8"))
    assert data["kev"]["catalog_version"] == "2026.10.20"
    assert "CVE-2026-59309" in data["kev"]["cves"]
    # Only products this catalog could judge are listed; an ambiguous
    # "Multiple Products" row is kept rather than dropped.
    assert [r["cveID"] for r in result.kev_not_catalogued] == ["CVE-2026-99999", "CVE-2020-3950"]
    # Spring and the like are counted, not listed.
    assert result.kev_other_vmware == 1
    assert "CVE-2026-59309" in result.kev_newly_flagged


def test_refresh_reports_cvss_disagreements_without_applying_them(tmp_path):
    http = _http(**{"CVE-2026-59310": _nvd("CVE-2026-59310", 8.1)})
    result = refresh(
        load_catalog(), tmp_path / "c.json", http_get=http, include_nvd=True, sleep=lambda s: None
    )
    assert ("CVE-2026-59310", 9.8, 8.1) in result.cvss_disagreements


def test_no_nvd_makes_no_nvd_request(tmp_path):
    http = _http()
    refresh(
        load_catalog(), tmp_path / "c.json", http_get=http, include_nvd=False, sleep=lambda s: None
    )
    assert all("known_exploited" in u for u in http.calls)


@pytest.mark.parametrize("nvd", [False, True])
def test_a_failed_kev_fetch_raises_and_leaves_the_old_cache_alone(tmp_path, nvd):
    cache = tmp_path / "c.json"
    cache.write_text('{"old": true}', encoding="utf-8")
    http = _http()
    http.fail = {"known_exploited"}
    with pytest.raises(RefreshError):
        refresh(load_catalog(), cache, http_get=http, include_nvd=nvd, sleep=lambda s: None)
    assert json.loads(cache.read_text(encoding="utf-8")) == {"old": True}
    assert [p.name for p in tmp_path.iterdir()] == ["c.json"]  # no temp file left


def test_a_failed_nvd_record_is_reported_and_does_not_block_kev(tmp_path):
    # NVD is enrichment; KEV is what the verdict evidence uses.
    cache = tmp_path / "c.json"
    http = _http()
    http.fail = {"CVE-2026-59310"}
    result = refresh(load_catalog(), cache, http_get=http, include_nvd=True, sleep=lambda s: None)
    assert [cve for cve, _ in result.nvd_failures] == ["CVE-2026-59310"]
    data = json.loads(cache.read_text(encoding="utf-8"))
    assert "CVE-2026-59310" in data["kev"]["cves"]
    assert "CVE-2026-59310" not in data["nvd"]


def test_nvd_is_off_unless_asked(tmp_path):
    http = _http()
    refresh(load_catalog(), tmp_path / "c.json", http_get=http, sleep=lambda s: None)
    assert all("known_exploited" in u for u in http.calls)


def test_cache_keeps_the_whole_kev_set_so_a_newer_catalog_is_still_flagged(tmp_path):
    # A CVE KEV lists that the catalog does not carry yet must still flag the
    # catalog that later adds it, without another refresh.
    cache = tmp_path / "c.json"
    refresh(load_catalog(), cache, http_get=_http(), sleep=lambda s: None)
    data = json.loads(cache.read_text(encoding="utf-8"))
    assert "CVE-2026-99999" in data["kev"]["cves"]
    assert "CVE-2025-0001" in data["kev"]["cves"]


def test_nvd_requests_are_spaced_for_the_public_rate_limit(tmp_path):
    slept = []
    refresh(
        load_catalog(), tmp_path / "c.json", http_get=_http(), include_nvd=True, sleep=slept.append
    )
    n_cves = sum(len(a.cves) for a in load_catalog().advisories)
    assert len(slept) == n_cves - 1
    assert all(s >= 6 for s in slept)


# --- overlay ----------------------------------------------------------------------


def test_overlay_only_adds_kev_flags_and_returns_a_new_catalog():
    shipped = load_catalog()
    cache = {
        "fetched_at": "2026-10-19T00:00:00+00:00",
        "kev": {"catalog_version": "v", "cves": ["CVE-2026-59309"]},
    }
    out = apply_overlay(shipped, cache)
    assert isinstance(out, Catalog) and out is not shipped
    flags = {c.id: c.kev for a in out.advisories for c in a.cves}
    assert flags["CVE-2026-59309"] is True
    # Shipped True stays True even though the cache does not list it.
    assert flags["CVE-2026-59310"] is True
    # The shipped object is untouched.
    assert {c.id: c.kev for a in shipped.advisories for c in a.cves}["CVE-2026-59309"] is False
    assert out.kev_catalog_version == "v"
    assert out.kev_refreshed_at is not None


def test_overlay_fills_a_missing_cvss_but_never_replaces_one():
    shipped = load_catalog()
    adv = shipped.advisories[0].model_copy(
        update={"cves": [c.model_copy(update={"cvss": None}) for c in shipped.advisories[0].cves]}
    )
    cat = shipped.model_copy(update={"advisories": [adv, *shipped.advisories[1:]]})
    first = adv.cves[0].id
    cache = {
        "fetched_at": "2026-10-19T00:00:00+00:00",
        "kev": {"catalog_version": "v", "cves": []},
        "nvd": {first: 5.5, "CVE-2026-59310": 1.0},
    }
    out = apply_overlay(cat, cache)
    by_id = {c.id: c.cvss for a in out.advisories for c in a.cves}
    assert by_id[first] == 5.5
    assert by_id["CVE-2026-59310"] == 9.8


# --- loader -----------------------------------------------------------------------


def test_loader_applies_a_valid_cache(tmp_path, monkeypatch):
    path = tmp_path / "c.json"
    path.write_text(
        json.dumps(
            {
                "fetched_at": "2026-10-19T00:00:00+00:00",
                "kev": {"catalog_version": "v9", "cves": ["CVE-2026-59309"]},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(catalog_mod, "cache_path", lambda: path)
    catalog_mod.reset_cache()
    try:
        cat = load_catalog()
        assert cat.kev_catalog_version == "v9"
    finally:
        catalog_mod.reset_cache()


def test_loader_ignores_a_corrupt_cache_and_says_so(tmp_path, monkeypatch, caplog):
    path = tmp_path / "c.json"
    path.write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(catalog_mod, "cache_path", lambda: path)
    catalog_mod.reset_cache()
    try:
        cat = load_catalog()
        assert cat.kev_refreshed_at is None
        assert "advisories update" in caplog.text
    finally:
        catalog_mod.reset_cache()


def test_without_a_cache_nothing_is_overlaid(tmp_path, monkeypatch):
    monkeypatch.setattr(catalog_mod, "cache_path", lambda: tmp_path / "absent.json")
    catalog_mod.reset_cache()
    try:
        assert load_catalog().kev_refreshed_at is None
    finally:
        catalog_mod.reset_cache()


# --- CLI --------------------------------------------------------------------------


def test_cli_update_writes_the_cache_and_is_audited(tmp_path, monkeypatch):
    from vmware_harden.cli import advisories as adv_cli
    from vmware_harden.cli.main import app

    path = tmp_path / "c.json"
    monkeypatch.setattr(catalog_mod, "cache_path", lambda: path)
    monkeypatch.setattr(adv_cli, "_http_get", _http())
    monkeypatch.setattr(adv_cli, "_sleep", lambda s: None)
    result = CliRunner().invoke(app, ["advisories", "update"])
    assert result.exit_code == 0, result.output
    assert path.exists()
    assert "CVE-2026-99999" in result.output  # KEV-listed, not catalogued
    assert getattr(adv_cli.update_cmd, "_is_audited", False)
    catalog_mod.reset_cache()


def test_cli_update_failure_exits_1_and_says_why(tmp_path, monkeypatch):
    from vmware_harden.cli import advisories as adv_cli
    from vmware_harden.cli.main import app

    monkeypatch.setattr(catalog_mod, "cache_path", lambda: tmp_path / "c.json")
    http = _http(known_exploited=b"<!DOCTYPE html>")
    monkeypatch.setattr(adv_cli, "_http_get", http)
    monkeypatch.setattr(adv_cli, "_sleep", lambda s: None)
    result = CliRunner().invoke(app, ["advisories", "update"])
    assert result.exit_code == 1
    assert "not refreshed" in result.output.lower()
    assert not (tmp_path / "c.json").exists()


def test_cli_show_names_the_catalog_date_and_refresh_state(tmp_path, monkeypatch):
    from vmware_harden.cli.main import app

    monkeypatch.setattr(catalog_mod, "cache_path", lambda: tmp_path / "absent.json")
    catalog_mod.reset_cache()
    result = CliRunner().invoke(app, ["advisories", "show"])
    assert result.exit_code == 0, result.output
    assert load_catalog().as_of.isoformat() in result.output
    assert "never refreshed" in result.output.lower()
    catalog_mod.reset_cache()


def test_evidence_records_when_kev_was_last_refreshed():
    from vmware_harden.advisories.baseline import NodeVerdict, evidence
    from vmware_harden.advisories.match import Verdict

    nv = NodeVerdict("n", Verdict("affected", "r", "fix"), "8.0.3", 1)
    ev = evidence("VMSA-2025-0004", nv)
    assert "kev_refreshed_at" in ev


def test_catalog_date_unchanged_by_overlay():
    shipped = load_catalog()
    out = apply_overlay(
        shipped,
        {"fetched_at": "2026-10-19T00:00:00+00:00", "kev": {"catalog_version": "v", "cves": []}},
    )
    assert out.as_of == shipped.as_of == date(2026, 10, 19)


def test_a_challenge_page_is_named_as_such_not_as_bad_json():
    # The user needs to know the source blocked or moved, not that a parser failed.
    with pytest.raises(RefreshError, match="HTML page"):
        parse_kev(b"<!DOCTYPE html><title>Just a moment...</title>")


# --- review round (2026-10-20) ------------------------------------------------------


def test_overlay_leaves_verdict_inputs_untouched():
    shipped = load_catalog()
    cache = {
        "fetched_at": "2026-10-19T00:00:00+00:00",
        "kev": {"catalog_version": "v", "cves": ["CVE-2026-59309"]},
        "nvd": {"CVE-2026-59309": 1.0},
    }
    out = apply_overlay(shipped, cache)
    for a, b in zip(shipped.advisories, out.advisories):
        assert a.affected == b.affected and a.not_affected == b.not_affected
        assert a.uncatalogued_products == b.uncatalogued_products
    assert out.as_of == shipped.as_of and out.eol == shipped.eol


@pytest.mark.parametrize(
    "cache",
    [
        {
            "fetched_at": "2026-10-19T00:00:00+00:00",
            "kev": {"catalog_version": "v", "cves": []},
            "nvd": [],
        },
        {
            "fetched_at": "2026-10-19T00:00:00+00:00",
            "kev": {"catalog_version": "v", "cves": "CVE-1"},
        },
        {"fetched_at": "2026-10-20T00:00:00", "kev": {"catalog_version": "v", "cves": []}},  # naive
        {"fetched_at": "2099-01-01T00:00:00+00:00", "kev": {"catalog_version": "v", "cves": []}},
        {
            "fetched_at": "2026-10-19T00:00:00+00:00",
            "kev": {"catalog_version": "v", "cves": []},
            "nvd": {"CVE-2025-22224": 99.0},
        },
        {
            "fetched_at": "2026-10-19T00:00:00+00:00",
            "kev": {"catalog_version": "v", "cves": []},
            "nvd": {"CVE-2025-22224": "NaN-text"},
        },
    ],
)
def test_a_malformed_cache_is_refused_by_the_loader_not_half_applied(
    tmp_path, monkeypatch, caplog, cache
):
    shipped = load_catalog()
    # Make one CVSS missing so an "nvd" overlay would be attempted.
    first = shipped.advisories[0].model_copy(
        update={"cves": [c.model_copy(update={"cvss": None}) for c in shipped.advisories[0].cves]}
    )
    monkeypatch.setattr(
        catalog_mod,
        "load_shipped_catalog",
        lambda: shipped.model_copy(update={"advisories": [first, *shipped.advisories[1:]]}),
    )
    path = tmp_path / "c.json"
    path.write_text(json.dumps(cache), encoding="utf-8")
    monkeypatch.setattr(catalog_mod, "cache_path", lambda: path)
    catalog_mod.reset_cache()
    try:
        cat = load_catalog()
        assert cat.kev_refreshed_at is None
        assert "advisories update" in caplog.text
    finally:
        catalog_mod.reset_cache()


def test_loader_picks_up_a_cache_written_by_another_process(tmp_path, monkeypatch):
    # A long-running MCP server must see a refresh without a restart.
    path = tmp_path / "c.json"
    monkeypatch.setattr(catalog_mod, "cache_path", lambda: path)
    catalog_mod.reset_cache()
    try:
        assert load_catalog().kev_refreshed_at is None
        path.write_text(
            json.dumps(
                {
                    "fetched_at": "2026-10-19T00:00:00+00:00",
                    "kev": {"catalog_version": "v2", "cves": []},
                }
            ),
            encoding="utf-8",
        )
        assert load_catalog().kev_catalog_version == "v2"
    finally:
        catalog_mod.reset_cache()


def test_cli_update_is_visible_to_the_next_load_in_the_same_process(tmp_path, monkeypatch):
    from vmware_harden.cli import advisories as adv_cli
    from vmware_harden.cli.main import app

    path = tmp_path / "c.json"
    monkeypatch.setattr(catalog_mod, "cache_path", lambda: path)
    monkeypatch.setattr(adv_cli, "_http_get", _http())
    monkeypatch.setattr(adv_cli, "_sleep", lambda s: None)
    catalog_mod.reset_cache()
    try:
        assert load_catalog().kev_catalog_version is None
        assert CliRunner().invoke(app, ["advisories", "update"]).exit_code == 0
        assert load_catalog().kev_catalog_version == "2026.10.20"
    finally:
        catalog_mod.reset_cache()


def test_cli_nvd_failure_still_refreshes_kev_and_names_the_failures(tmp_path, monkeypatch):
    from vmware_harden.cli import advisories as adv_cli
    from vmware_harden.cli.main import app

    path = tmp_path / "c.json"
    monkeypatch.setattr(catalog_mod, "cache_path", lambda: path)
    http = _http()
    http.fail = {"CVE-2026-59310"}
    monkeypatch.setattr(adv_cli, "_http_get", http)
    monkeypatch.setattr(adv_cli, "_sleep", lambda s: None)
    result = CliRunner().invoke(app, ["advisories", "update", "--nvd"])
    assert result.exit_code == 0, result.output
    assert "CVE-2026-59310" in result.output and "NVD" in result.output
    catalog_mod.reset_cache()


def test_cli_write_failure_is_reported_not_a_traceback(tmp_path, monkeypatch):
    from vmware_harden.cli import advisories as adv_cli
    from vmware_harden.cli.main import app

    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    monkeypatch.setattr(catalog_mod, "cache_path", lambda: blocker / "c.json")  # parent is a file
    monkeypatch.setattr(adv_cli, "_http_get", _http())
    monkeypatch.setattr(adv_cli, "_sleep", lambda s: None)
    result = CliRunner().invoke(app, ["advisories", "update"])
    assert result.exit_code == 1
    assert "not refreshed" in result.output.lower()
    assert result.exception is None or isinstance(result.exception, SystemExit)


class _Resp:
    def __init__(self, body: bytes):
        self.body = body

    def read(self, n: int = -1) -> bytes:
        return self.body if n < 0 else self.body[:n]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_http_get_caps_the_body_it_reads(monkeypatch):
    from vmware_harden.advisories.refresh import MAX_BODY_BYTES
    from vmware_harden.cli import advisories as adv_cli

    big = b"x" * (MAX_BODY_BYTES + 10)
    monkeypatch.setattr(adv_cli, "_open", lambda req, timeout: _Resp(big))
    body = adv_cli._http_get("https://example.invalid/feed")
    assert len(body) == MAX_BODY_BYTES + 1
    with pytest.raises(RefreshError, match="larger than"):
        parse_kev(body)


@pytest.mark.parametrize(
    "exc", [OSError("down"), __import__("http.client").client.IncompleteRead(b"")]
)
def test_http_get_turns_transport_errors_into_refresh_errors(monkeypatch, exc):
    from vmware_harden.cli import advisories as adv_cli

    def boom(req, timeout):
        raise exc

    monkeypatch.setattr(adv_cli, "_open", boom)
    with pytest.raises(RefreshError):
        adv_cli._http_get("https://example.invalid/feed")


def test_redirect_to_plain_http_is_refused():
    import urllib.request

    from vmware_harden.cli import advisories as adv_cli

    handler = adv_cli._HttpsOnlyRedirect()
    req = urllib.request.Request("https://www.cisa.gov/x")
    with pytest.raises(urllib.error.HTTPError):
        handler.redirect_request(req, None, 302, "Found", {}, "http://evil.invalid/x")


def test_nvd_id_comparison_ignores_case():
    body = json.dumps(_nvd("cve-2025-22224", 9.3)).encode()
    assert parse_nvd_cvss(body, "CVE-2025-22224") == 9.3


def test_kev_row_without_vendor_project_is_fine():
    feed = {"catalogVersion": "v", "vulnerabilities": [{"cveID": "CVE-2025-1", "product": "ESXi"}]}
    snap = parse_kev(json.dumps(feed).encode())
    assert [r["cveID"] for r in snap.vmware] == ["CVE-2025-1"]


def test_evidence_carries_the_actual_refresh_time(tmp_path, monkeypatch):
    from vmware_harden.advisories.baseline import NodeVerdict, evidence
    from vmware_harden.advisories.match import Verdict

    path = tmp_path / "c.json"
    path.write_text(
        json.dumps(
            {"fetched_at": "2026-10-19T01:02:03+00:00", "kev": {"catalog_version": "v", "cves": []}}
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(catalog_mod, "cache_path", lambda: path)
    catalog_mod.reset_cache()
    try:
        nv = NodeVerdict("n", Verdict("affected", "r", "fix"), "8.0.3", 1)
        assert evidence("VMSA-2025-0004", nv)["kev_refreshed_at"] == "2026-10-19T01:02:03+00:00"
    finally:
        catalog_mod.reset_cache()


def test_a_failed_cache_write_leaves_no_temp_file_and_the_old_cache(tmp_path, monkeypatch):
    from vmware_harden.advisories import refresh as refresh_mod

    cache = tmp_path / "c.json"
    cache.write_text('{"old": true}', encoding="utf-8")

    def boom(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(refresh_mod.os, "replace", boom)
    with pytest.raises(OSError):
        refresh(load_catalog(), cache, http_get=_http(), sleep=lambda s: None)
    assert [p.name for p in tmp_path.iterdir()] == ["c.json"]
    assert json.loads(cache.read_text(encoding="utf-8")) == {"old": True}


def test_another_vendors_multiple_products_row_is_not_vmware():
    # Live feed 2026-10-20: the vendor-less fallback briefly counted every
    # vendor's "Multiple Products" row as VMware (15 → 99 rows).
    feed = {
        "catalogVersion": "v",
        "vulnerabilities": [
            {"cveID": "CVE-2025-61624", "vendorProject": "Apache", "product": "Multiple Products"},
            {"cveID": "CVE-2025-2", "vendorProject": "", "product": "Multiple Products"},
            {"cveID": "CVE-2025-3", "vendorProject": "Microsoft", "product": "vCenter-like Thing"},
            {"cveID": "CVE-2025-4", "vendorProject": "VMware", "product": "Multiple Products"},
        ],
    }
    snap = parse_kev(json.dumps(feed).encode())
    assert [r["cveID"] for r in snap.vmware] == ["CVE-2025-4"]


# --- narrow review (2026-10-20) ------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        {"vulnerabilities": [{"cve": "str"}]},
        {"vulnerabilities": [{"cve": {"id": "CVE-2026-59310", "metrics": []}}]},
        {"vulnerabilities": [{"cve": {"id": "CVE-2026-59310", "metrics": {"cvssMetricV31": "x"}}}]},
        {"vulnerabilities": "nope"},
    ],
)
def test_a_structurally_odd_nvd_record_is_a_reported_failure_not_a_crash(tmp_path, body):
    cache = tmp_path / "c.json"
    http = _http(**{"CVE-2026-59310": body})
    result = refresh(load_catalog(), cache, http_get=http, include_nvd=True, sleep=lambda s: None)
    assert "CVE-2026-59310" in [cve for cve, _ in result.nvd_failures]
    assert "CVE-2026-59310" in json.loads(cache.read_text(encoding="utf-8"))["kev"]["cves"]


def test_a_rewritten_cache_is_seen_without_a_restart(tmp_path, monkeypatch):
    import os

    path = tmp_path / "c.json"

    def write(version: str) -> None:
        tmp = tmp_path / "t.json"
        tmp.write_text(
            json.dumps(
                {
                    "fetched_at": "2026-10-19T00:00:00+00:00",
                    "kev": {"catalog_version": version, "cves": []},
                }
            ),
            encoding="utf-8",
        )
        os.replace(tmp, path)  # what the refresh does: a new file each time

    monkeypatch.setattr(catalog_mod, "cache_path", lambda: path)
    catalog_mod.reset_cache()
    try:
        write("one")
        os.utime(path, ns=(1, 1))
        assert load_catalog().kev_catalog_version == "one"
        write("two")  # same size as "one"
        os.utime(path, ns=(1, 1))  # identical mtime: only the new inode tells them apart
        assert load_catalog().kev_catalog_version == "two"
    finally:
        catalog_mod.reset_cache()


def test_the_https_only_redirect_handler_is_installed_on_the_opener_in_use():
    from vmware_harden.cli import advisories as adv_cli

    handlers = adv_cli._open_url.__self__.handlers
    assert any(isinstance(h, adv_cli._HttpsOnlyRedirect) for h in handlers)


@pytest.mark.parametrize("version", [None, "", 7])
def test_a_cache_without_a_kev_catalog_version_is_refused(version):
    cache = {
        "fetched_at": "2026-10-19T00:00:00+00:00",
        "kev": {"catalog_version": version, "cves": []},
    }
    with pytest.raises(ValueError):
        apply_overlay(load_catalog(), cache)


def test_any_error_from_one_nvd_record_is_that_records_failure(tmp_path, monkeypatch):
    # The refresh loop's own net, independent of how robust the parser is.
    from vmware_harden.advisories import refresh as refresh_mod

    def odd(body, cve):
        raise AttributeError("unexpected shape")

    monkeypatch.setattr(refresh_mod, "parse_nvd_cvss", odd)
    cache = tmp_path / "c.json"
    result = refresh(
        load_catalog(), cache, http_get=_http(), include_nvd=True, sleep=lambda s: None
    )
    assert len(result.nvd_failures) == sum(len(a.cves) for a in load_catalog().advisories)
    assert cache.exists()
