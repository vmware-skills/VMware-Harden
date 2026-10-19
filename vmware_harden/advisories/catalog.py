"""Load the advisory catalog shipped inside the package.

Read as UTF-8 explicitly, for the same reason the baseline loader does: the
locale codec on a cp936 Windows host cannot decode it.
"""

from functools import lru_cache
from pathlib import Path

import yaml

from vmware_harden.advisories.model import Catalog

_DIR = Path(__file__).parent
CATALOG_PATH = _DIR / "catalog.yaml"
BUILDS_PATH = _DIR / "builds.yaml"


def _read_yaml(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


@lru_cache(maxsize=1)
def load_catalog() -> Catalog:
    """The shipped catalog. Raises if the file is missing or invalid."""
    return Catalog(**_read_yaml(CATALOG_PATH))


def load_builds() -> dict:
    """The release → build snapshot the catalog's fixes are checked against."""
    return _read_yaml(BUILDS_PATH)
