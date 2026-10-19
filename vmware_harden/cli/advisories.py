"""`vmware-harden advisories` — inspect and (optionally) refresh the VMSA catalog."""

import http.client
import time
import urllib.error
import urllib.request

import typer
from vmware_policy import audited, cli_local

from vmware_harden.advisories import catalog as catalog_mod
from vmware_harden.advisories.refresh import MAX_BODY_BYTES, RefreshError, refresh

app = typer.Typer(no_args_is_help=True)

_TIMEOUT_SECONDS = 30
_sleep = time.sleep


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    """Follow redirects only to https: never downgrade the two fixed URLs."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith("https://"):
            raise urllib.error.HTTPError(
                newurl, code, f"refused redirect to non-https URL {newurl}", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# A URL opener, not text file I/O — bound under its own name so the package's
# "every open() declares utf-8" gate keeps meaning what it says.
_open_url = urllib.request.build_opener(_HttpsOnlyRedirect()).open


def _open(req: urllib.request.Request, timeout: float):
    return _open_url(req, timeout=timeout)  # nosec B310 - fixed https URLs only


def _http_get(url: str) -> bytes:
    """GET ``url`` (one of the two fixed refresh URLs), reading at most one byte
    past the size cap so an oversized body is detected, not held in memory."""
    req = urllib.request.Request(url, headers={"User-Agent": "vmware-harden advisories update"})
    try:
        with _open(req, timeout=_TIMEOUT_SECONDS) as resp:
            return resp.read(MAX_BODY_BYTES + 1)
    except (OSError, http.client.HTTPException) as e:
        # URLError, HTTPError and timeouts are OSError; IncompleteRead and
        # BadStatusLine are HTTPException.
        raise RefreshError(f"{url.split('?')[0]}: {type(e).__name__}: {e}") from e


@app.command("update")
@audited("update_advisory_catalog")
def update_cmd(
    nvd: bool = typer.Option(
        False,
        "--nvd/--no-nvd",
        help="Also read CVSS scores from NVD (one request per CVE, rate-limited). Off by default.",
    ),
) -> None:
    """Refresh KEV flags (CISA) and missing CVSS (NVD) into a local cache.

    Outbound HTTPS to cisa.gov and nvd.nist.gov only. The shipped catalog is
    not changed; which advisories exist and which builds fix them still come
    from it.
    """
    path = catalog_mod.cache_path()
    try:
        result = refresh(
            catalog_mod.load_shipped_catalog(),
            path,
            http_get=_http_get,
            include_nvd=nvd,
            sleep=_sleep,
        )
    except (RefreshError, OSError) as e:
        # OSError here is the cache write (disk full, permissions): the temp
        # file is removed and the previous cache stands.
        typer.echo(
            f"Catalog not refreshed: {e}. The previous cache, if any, is unchanged.", err=True
        )
        raise typer.Exit(code=1) from e
    catalog_mod.reset_cache()

    typer.echo(f"Refreshed: CISA KEV {result.kev_catalog_version} → {result.cache_path}")
    if result.kev_newly_flagged:
        typer.echo(f"  Now flagged as exploited in the wild: {', '.join(result.kev_newly_flagged)}")
    for cve, reason in result.nvd_failures:
        typer.echo(f"  NVD record for {cve} not read ({reason}); its CVSS was not refreshed")
    for cve, ours, theirs in result.cvss_disagreements:
        typer.echo(f"  CVSS differs for {cve}: catalog {ours}, NVD {theirs} (catalog value kept)")
    if result.kev_not_catalogued:
        typer.echo(
            f"  {len(result.kev_not_catalogued)} VMware/Broadcom CVE(s) in KEV are in no "
            "catalogued advisory — this catalog cannot judge them:"
        )
        for row in result.kev_not_catalogued:
            typer.echo(f"    {row['cveID']}  {row['product']}  (added {row['dateAdded']})")
    if result.kev_other_vmware:
        typer.echo(
            f"  ({result.kev_other_vmware} other VMware/Broadcom KEV entries are for products "
            "this catalog does not judge, e.g. Spring or Aria.)"
        )


@app.command("show")
@cli_local("reads the shipped advisory catalog and the local refresh cache")
def show_cmd() -> None:
    """Show the catalog date, its advisories, and the refresh state."""
    cat = catalog_mod.load_catalog()
    typer.echo(f"Catalog as of {cat.as_of.isoformat()} — {len(cat.advisories)} advisories")
    for a in cat.advisories:
        kev = " KEV" if a.kev else ""
        typer.echo(f"  {a.id}  {a.severity}{kev}  {', '.join(c.id for c in a.cves)}")
    if cat.kev_refreshed_at is None:
        typer.echo(
            "KEV flags: never refreshed (shipped values). Run `vmware-harden advisories update`."
        )
    else:
        typer.echo(
            f"KEV flags: refreshed {cat.kev_refreshed_at.isoformat()} "
            f"(CISA KEV {cat.kev_catalog_version})"
        )
