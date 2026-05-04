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


@pytest.fixture
def app_with_violations(tmp_path: Path):
    """A Twin pre-seeded with one snapshot + violations across multiple severities."""
    db = tmp_path / "t.duckdb"
    twin = Twin(db)
    snap = twin.start_snapshot("v.lab")
    twin.conn.execute(
        "INSERT INTO nodes (id, type, target, name, attrs) "
        "VALUES (?, 'host', ?, ?, '{}')",
        ["v.lab:h-1", "v.lab", "esx-1"],
    )
    import uuid, json as _json
    for rule_id, sev, category in [
        ("rule-c1", "critical", "encryption"),
        ("rule-c2", "critical", "encryption"),
        ("rule-h1", "high", "auth"),
        ("rule-m1", "medium", "logging"),
        ("rule-l1", "low", "misc"),
    ]:
        twin.conn.execute(
            """INSERT INTO violation
               (id, snapshot_id, baseline_id, rule_id, node_id,
                severity, evidence)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            [
                str(uuid.uuid4()), snap, "test-baseline",
                rule_id, "v.lab:h-1", sev,
                _json.dumps({"id": "v.lab:h-1", "category": category}),
            ],
        )
    twin.finish_snapshot(snap)
    twin.close()
    from vmware_harden.web.app import build_app
    return build_app(db_path=db)


@pytest.mark.integration
def test_summary_page_shows_severity_counts(app_with_violations):
    client = TestClient(app_with_violations)
    r = client.get("/")
    assert r.status_code == 200
    text = r.text
    # Counts: 2 critical, 1 high, 1 medium, 1 low
    assert "2" in text  # critical count
    assert "Critical" in text or "CRITICAL" in text
    assert "High" in text or "HIGH" in text


@pytest.mark.integration
def test_summary_page_includes_echarts_radar(app_with_violations):
    client = TestClient(app_with_violations)
    r = client.get("/")
    text = r.text
    # Must include some ECharts initialization for the radar
    assert "echarts.init" in text
    assert "radar" in text.lower()


@pytest.mark.integration
def test_summary_page_shows_total_violations(app_with_violations):
    client = TestClient(app_with_violations)
    r = client.get("/")
    assert "5" in r.text  # 5 total violations seeded


@pytest.mark.integration
def test_summary_empty_twin_shows_no_scans_message(app_with_db):
    """app_with_db fixture has empty Twin (Task 16 fixture, no violations)."""
    client = TestClient(app_with_db)
    r = client.get("/")
    assert r.status_code == 200
    assert "no scans" in r.text.lower() or "no violations" in r.text.lower()
