"""Smoke tests verifying package basics."""
from pathlib import Path

import pytest


@pytest.mark.unit
def test_package_imports():
    """vmware_harden package can be imported and version is set."""
    import re

    import vmware_harden
    # Don't pin the literal version (stale since v1.5.19) — assert semver shape
    # and agreement with pyproject.toml instead.
    assert re.fullmatch(r"\d+\.\d+\.\d+", vmware_harden.__version__)
    import tomllib
    pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    assert vmware_harden.__version__ == tomllib.loads(pyproject.read_text())["project"]["version"]


@pytest.mark.unit
def test_mcp_server_module_imports():
    """mcp_server stub package importable (defends 踩坑 #17)."""
    from mcp_server.server import main
    assert callable(main)
