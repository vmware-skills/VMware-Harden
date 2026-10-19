"""Load the advisory catalog shipped inside the package.

Read as UTF-8 explicitly, for the same reason the baseline loader does: the
locale codec on a cp936 Windows host cannot decode it.

When ``vmware-harden advisories update`` has written a refresh cache, its KEV
flags (and any missing CVSS) are overlaid; see
:mod:`vmware_harden.advisories.refresh`. Without a cache — the default — the
shipped catalog is used as is.
"""

import json
import logging
from functools import lru_cache
from pathlib import Path

import yaml

from vmware_harden.advisories.model import Catalog

_log = logging.getLogger(__name__)

_DIR = Path(__file__).parent
CATALOG_PATH = _DIR / "catalog.yaml"
BUILDS_PATH = _DIR / "builds.yaml"


def _read_yaml(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def cache_path() -> Path:
    """Where the online refresh cache lives."""
    return Path("~/.vmware-harden/advisories-cache.json").expanduser()


def load_shipped_catalog() -> Catalog:
    """The catalog exactly as shipped, with no refresh overlay."""
    return Catalog(**_read_yaml(CATALOG_PATH))


def _cache_stamp() -> tuple[str, int, int, int] | None:
    """Identity of the cache file's current version: path, inode, size, mtime.

    The refresh replaces the file (new inode every time), so a rewrite within
    one tick of a coarse-mtime filesystem is still a new stamp.
    """
    path = cache_path()
    try:
        st = path.stat()
    except OSError:
        return None
    return str(path), st.st_ino, st.st_size, st.st_mtime_ns


def load_catalog() -> Catalog:
    """The shipped catalog, with the refresh cache overlaid when one exists.

    Memoised per cache file version (path + mtime): a long-running MCP server
    picks up a refresh written by another process on its next call, without a
    restart.
    """
    return _load(_cache_stamp())


def reset_cache() -> None:
    """Forget memoised catalogs (tests, and after this process rewrites the cache)."""
    _load.cache_clear()


@lru_cache(maxsize=4)
def _load(stamp: tuple[str, int, int, int] | None) -> Catalog:
    """A cache that cannot be read or does not meet the model is not used and is
    reported: the shipped data still answers, and the warning names the command
    that rewrites the cache."""
    from vmware_harden.advisories.refresh import apply_overlay

    shipped = load_shipped_catalog()
    if stamp is None:
        return shipped
    path = Path(stamp[0])
    try:
        cache = json.loads(path.read_text(encoding="utf-8"))
        return apply_overlay(shipped, cache)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        _log.warning(
            "Advisory refresh cache %s is unreadable (%s); using the shipped catalog. "
            "Re-run `vmware-harden advisories update` to rewrite it.",
            path,
            type(e).__name__,
        )
        return shipped


def load_builds() -> dict:
    """The release → build snapshot the catalog's fixes are checked against."""
    return _read_yaml(BUILDS_PATH)
