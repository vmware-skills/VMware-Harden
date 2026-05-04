"""FastAPI web app smoke tests via TestClient."""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vmware_harden.store.twin import Twin
from vmware_harden.web.app import build_app


@pytest.fixture
def app_with_db(tmp_path: Path):
    db = tmp_path / "t.duckdb"
    Twin(db).close()  # initialize schema
    app = build_app(db_path=db)
    return app


@pytest.mark.integration
def test_root_returns_200(app_with_db):
    client = TestClient(app_with_db)
    r = client.get("/")
    assert r.status_code == 200
    assert "vmware-harden" in r.text.lower()


@pytest.mark.integration
def test_root_includes_navigation(app_with_db):
    client = TestClient(app_with_db)
    r = client.get("/")
    assert r.status_code == 200
    assert "summary" in r.text.lower() or "dashboard" in r.text.lower()


@pytest.mark.integration
def test_unknown_route_returns_404(app_with_db):
    client = TestClient(app_with_db)
    r = client.get("/this-does-not-exist")
    assert r.status_code == 404


@pytest.mark.integration
def test_static_resources_loadable_via_cdn(app_with_db):
    """Base template references Tailwind/HTMX/ECharts CDN URLs (sanity check)."""
    client = TestClient(app_with_db)
    r = client.get("/")
    text = r.text.lower()
    assert "tailwind" in text or "cdn.tailwindcss.com" in text
    assert "htmx" in text
    assert "echarts" in text
