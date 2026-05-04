"""Smoke tests verifying package basics."""
import pytest


@pytest.mark.unit
def test_package_imports():
    """vmware_harden package can be imported and version is set."""
    import vmware_harden
    assert vmware_harden.__version__ == "1.0.0"


@pytest.mark.unit
def test_mcp_server_module_imports():
    """mcp_server stub package importable (defends 踩坑 #17)."""
    from mcp_server.server import main
    assert callable(main)
