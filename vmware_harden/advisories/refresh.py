"""Optional online refresh of the advisory catalog: CISA KEV and NVD.

Run only by ``vmware-harden advisories update``. It writes a local cache that
:func:`vmware_harden.advisories.catalog.load_catalog` overlays on the shipped
catalog. Two sources, both machine-readable and public:

* CISA KEV — which CVEs are exploited in the wild. Flags are only ever *added*:
  a stale or partial cache must not erase a flag the shipped catalog carries.
* NVD — CVSS scores, used only to fill a score the catalog lacks. A different
  score is reported, never applied; NVD's vulnerable-version lists are not used
  at all (they can be incomplete — CVE-2024-38812 omits 8.0 U3–U3c).

Broadcom's advisory pages are behind a bot challenge and are not fetched.

Every way a fetch can go wrong — an HTTP error, a challenge page, a body that is
not the expected JSON, an empty feed — raises :class:`RefreshError`, and the
existing cache is left untouched. An empty refresh is never "nothing new".
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from vmware_harden.advisories.model import Catalog

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"

#: NVD's public limit is 5 requests per rolling 30 seconds without an API key.
NVD_SPACING_SECONDS = 6.5

#: Larger than any real KEV feed (~2 MB in 2026) by a wide margin; a body past it
#: is not the feed.
MAX_BODY_BYTES = 32 * 1024 * 1024

#: The scorer whose CVSS a VMSA prints. Preferred when NVD carries several.
_VMWARE_CNA = "security@vmware.com"


#: Product words naming something this catalog judges (ESXi hosts, vCenter).
#: "multiple products" is ambiguous and kept: listing one too many is cheaper
#: than hiding an ESXi or vCenter CVE behind a vague product name.
_IN_SCOPE_WORDS = ("esxi", "vcenter", "vsphere", "cloud foundation", "multiple products")


#: Product words that name a VMware product by themselves.
_VMWARE_PRODUCT_WORDS = ("esxi", "vcenter", "vsphere", "cloud foundation")


def _in_scope(row: dict) -> bool:
    return any(w in row.get("product", "").lower() for w in _IN_SCOPE_WORDS)


class RefreshError(Exception):
    """A refresh source could not be read. The cache was not changed."""


@dataclass(frozen=True)
class KevSnapshot:
    catalog_version: str
    cves: frozenset[str]
    #: Every KEV row whose vendor or product names VMware or Broadcom.
    vmware: tuple[dict, ...]


@dataclass(frozen=True)
class RefreshResult:
    cache_path: Path
    kev_catalog_version: str
    #: Catalogued CVEs the shipped catalog does not flag but KEV now lists.
    kev_newly_flagged: tuple[str, ...]
    #: KEV rows for ESXi/vCenter-scope products whose CVE is in no catalogued
    #: advisory: the catalog cannot judge them at all.
    kev_not_catalogued: tuple[dict, ...]
    #: VMware/Broadcom KEV rows for products this catalog does not judge
    #: (Spring, Aria, Workspace ONE, …), counted only.
    kev_other_vmware: int = 0
    #: (cve, catalogued score, NVD score) where they differ. Reported only.
    cvss_disagreements: tuple[tuple[str, float, float], ...] = field(default_factory=tuple)
    #: (cve, reason) for NVD records that could not be read. NVD is enrichment:
    #: its failures are reported and do not block the KEV refresh.
    nvd_failures: tuple[tuple[str, str], ...] = field(default_factory=tuple)


def _json(body: bytes, what: str) -> object:
    if not body:
        raise RefreshError(f"{what}: empty response")
    if len(body) > MAX_BODY_BYTES:
        raise RefreshError(f"{what}: response larger than {MAX_BODY_BYTES} bytes")
    head = body.lstrip()[:15].lower()
    if head.startswith((b"<!doctype", b"<html")):
        # A bot challenge or error page answered instead of the data.
        raise RefreshError(f"{what}: got an HTML page instead of JSON (blocked or moved?)")
    try:
        return json.loads(body)
    except (ValueError, UnicodeDecodeError) as e:
        raise RefreshError(f"{what}: not valid JSON ({type(e).__name__})") from e


def parse_kev(body: bytes) -> KevSnapshot:
    data = _json(body, "CISA KEV")
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise RefreshError("CISA KEV: no 'vulnerabilities' list in the response")
    rows = data["vulnerabilities"]
    if not rows:
        raise RefreshError("CISA KEV: the feed lists no vulnerabilities")
    cves: set[str] = set()
    vmware: list[dict] = []
    for row in rows:
        cve = row.get("cveID") if isinstance(row, dict) else None
        if not isinstance(cve, str) or not cve.startswith("CVE-"):
            raise RefreshError("CISA KEV: a row has no valid 'cveID'")
        cves.add(cve)
        names = f"{row.get('vendorProject', '')} {row.get('product', '')}".lower()
        # A row with no vendor at all is attributed by an unambiguous product
        # word only; "multiple products" names nobody (live feed 2026-10-20).
        vendorless = not str(row.get("vendorProject") or "").strip()
        product = str(row.get("product", "")).lower()
        if (
            "vmware" in names
            or "broadcom" in names
            or (vendorless and any(w in product for w in _VMWARE_PRODUCT_WORDS))
        ):
            vmware.append(
                {k: str(row.get(k, "")) for k in ("cveID", "vendorProject", "product", "dateAdded")}
            )
    version = data.get("catalogVersion")
    if not isinstance(version, str) or not version:
        raise RefreshError("CISA KEV: no 'catalogVersion' in the response")
    return KevSnapshot(version, frozenset(cves), tuple(vmware))


def parse_nvd_cvss(body: bytes, cve: str) -> float | None:
    """The CVSS v3 base score NVD holds for ``cve``; None when it holds none."""
    data = _json(body, f"NVD {cve}")
    # Every level is type-checked: a valid JSON body of an unexpected shape must
    # be a RefreshError for this CVE, not an AttributeError that aborts the KEV
    # refresh (narrow review, 2026-10-20).
    vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
    records = [
        v["cve"]
        for v in (vulns if isinstance(vulns, list) else [])
        if isinstance(v, dict) and isinstance(v.get("cve"), dict)
    ]
    record = next((r for r in records if str(r.get("id", "")).upper() == cve.upper()), None)
    if record is None:
        raise RefreshError(f"NVD {cve}: the response does not contain this CVE")
    # Absent metrics means NVD holds no score (None). Present but malformed is
    # not "no score" — it is a record this code cannot read.
    metrics = record.get("metrics", {})
    if not isinstance(metrics, dict):
        raise RefreshError(f"NVD {cve}: 'metrics' is not an object")
    scored = []
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if not isinstance(entries, list):
            raise RefreshError(f"NVD {cve}: '{key}' is not a list")
        for m in entries:
            data_ = m.get("cvssData") if isinstance(m, dict) else None
            score = data_.get("baseScore") if isinstance(data_, dict) else None
            if isinstance(score, (int, float)) and not isinstance(score, bool):
                scored.append(m)
    if not scored:
        return None
    vmware = [m for m in scored if m.get("source") == _VMWARE_CNA]
    return float((vmware or scored)[0]["cvssData"]["baseScore"])


def refresh(
    catalog: Catalog,
    cache_file: Path,
    *,
    http_get: Callable[[str], bytes],
    include_nvd: bool = False,
    sleep: Callable[[float], None],
) -> RefreshResult:
    """Fetch, then write the cache atomically.

    A KEV failure raises before anything is written. NVD (opt-in) is per-CVE
    enrichment: a record that cannot be read is listed in ``nvd_failures`` and
    the refresh goes on, because the KEV flags are what verdict evidence uses.
    """
    kev = parse_kev(http_get(KEV_URL))
    catalogued = {c.id: c for a in catalog.advisories for c in a.cves}

    nvd: dict[str, float] = {}
    disagreements: list[tuple[str, float, float]] = []
    nvd_failures: list[tuple[str, str]] = []
    if include_nvd:
        for i, cve_id in enumerate(sorted(catalogued)):
            if i:
                sleep(NVD_SPACING_SECONDS)
            try:
                score = parse_nvd_cvss(http_get(NVD_URL.format(cve=cve_id)), cve_id)
            except (RefreshError, AttributeError, TypeError, KeyError, ValueError) as e:
                # Belt to the parser's braces: whatever one NVD record does, it
                # is that record's failure, never the KEV refresh's.
                nvd_failures.append((cve_id, f"{type(e).__name__}: {e}"[:200]))
                continue
            if score is None:
                continue
            nvd[cve_id] = score
            shipped = catalogued[cve_id].cvss
            if shipped is not None and abs(shipped - score) > 1e-9:
                disagreements.append((cve_id, shipped, score))

    flagged = sorted(c for c in catalogued if c in kev.cves)
    # The whole KEV set, not only today's catalogued CVEs: a catalog upgraded
    # later must be flagged from this cache too, or its new CVEs would read as
    # "checked against KEV at <fetched_at>" when they never were.
    payload = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "catalog_as_of": catalog.as_of.isoformat(),
        "kev": {
            "catalog_version": kev.catalog_version,
            "cves": sorted(kev.cves),
            "vmware": list(kev.vmware),
        },
        "nvd": nvd,
    }
    _write_atomic(cache_file, payload)
    return RefreshResult(
        cache_path=cache_file,
        kev_catalog_version=kev.catalog_version,
        kev_newly_flagged=tuple(c for c in flagged if not catalogued[c].kev),
        kev_not_catalogued=tuple(
            r for r in kev.vmware if r["cveID"] not in catalogued and _in_scope(r)
        ),
        kev_other_vmware=sum(1 for r in kev.vmware if not _in_scope(r)),
        cvss_disagreements=tuple(disagreements),
        nvd_failures=tuple(nvd_failures),
    )


def _write_atomic(path: Path, payload: dict) -> None:
    """Unique temp file in the same directory, fsync, then rename over the cache.

    Two concurrent updates each rename a complete file; a failed write leaves no
    temp file behind and the previous cache in place.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def apply_overlay(catalog: Catalog, cache: dict) -> Catalog:
    """A new catalog with the cache's KEV flags added and missing CVSS filled.

    Raises ``KeyError``/``ValueError``/``TypeError`` on a cache that is not the
    shape :func:`refresh` writes; the loader turns that into a warning.
    """
    kev = cache["kev"]
    cves = kev["cves"]
    if not isinstance(cves, list) or not all(isinstance(c, str) for c in cves):
        raise ValueError("kev.cves is not a list of CVE ids")
    flagged = frozenset(cves)
    version = kev["catalog_version"]
    if not isinstance(version, str) or not version:
        raise ValueError("kev.catalog_version is missing")
    nvd = cache.get("nvd", {})
    if not isinstance(nvd, dict):
        raise ValueError("nvd is not a mapping")
    for cve_id, score in nvd.items():
        if isinstance(score, bool) or not isinstance(score, (int, float)) or not 0 <= score <= 10:
            raise ValueError(f"nvd score for {cve_id} is not a CVSS value")
    fetched = datetime.fromisoformat(cache["fetched_at"])
    if fetched.tzinfo is None:
        raise ValueError("fetched_at has no timezone")
    if fetched > datetime.now(timezone.utc) + timedelta(minutes=5):
        raise ValueError("fetched_at is in the future")
    advisories = [
        adv.model_copy(
            update={
                "cves": [
                    c.model_copy(
                        update={
                            "kev": c.kev or c.id in flagged,
                            "cvss": c.cvss if c.cvss is not None else nvd.get(c.id),
                        }
                    )
                    for c in adv.cves
                ]
            }
        )
        for adv in catalog.advisories
    ]
    out = catalog.model_copy(
        update={
            "advisories": advisories,
            "kev_refreshed_at": fetched,
            "kev_catalog_version": str(kev["catalog_version"]),
        }
    )
    # model_copy does not validate; a cache is outside data and must meet the
    # same model constraints as the shipped catalog (CVSS 0–10, types).
    return Catalog.model_validate(out.model_dump())
