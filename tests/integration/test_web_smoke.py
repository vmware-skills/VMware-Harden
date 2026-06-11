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


@pytest.mark.integration
def test_violations_page_renders(app_with_violations):
    client = TestClient(app_with_violations)
    r = client.get("/violations")
    assert r.status_code == 200
    text = r.text
    assert "Violations" in text or "violations" in text
    # Each seeded rule appears
    for rid in ["rule-c1", "rule-c2", "rule-h1", "rule-m1", "rule-l1"]:
        assert rid in text


@pytest.mark.integration
def test_violations_page_has_severity_badges(app_with_violations):
    client = TestClient(app_with_violations)
    r = client.get("/violations")
    text = r.text.lower()
    # All 4 severities present in seeded data
    for sev in ("critical", "high", "medium", "low"):
        assert sev in text


@pytest.mark.integration
def test_violation_evidence_endpoint_returns_fragment(app_with_violations):
    """GET /violations/{id}/evidence returns just the evidence as an HTML fragment."""
    client = TestClient(app_with_violations)
    # Find a violation id from the page
    r = client.get("/violations")
    text = r.text
    # Page must include hx-get URLs for evidence — find one
    import re
    m = re.search(r"hx-get=[\"']/violations/([0-9a-f-]+)/evidence[\"']", text)
    assert m, f"No hx-get for evidence found in:\n{text[:500]}"
    vid = m.group(1)

    r2 = client.get(f"/violations/{vid}/evidence")
    assert r2.status_code == 200
    # Fragment should contain evidence JSON content
    assert "v.lab:h-1" in r2.text or "category" in r2.text


@pytest.mark.integration
def test_violations_empty_twin_message(app_with_db):
    client = TestClient(app_with_db)
    r = client.get("/violations")
    assert r.status_code == 200
    assert "no violations" in r.text.lower() or "no scans" in r.text.lower()


@pytest.fixture
def app_with_drift(tmp_path: Path):
    """A Twin pre-seeded with 3 snapshots and change events on the latest two."""
    db = tmp_path / "t.duckdb"
    twin = Twin(db)
    snap1 = twin.start_snapshot("v.lab")
    twin.finish_snapshot(snap1)
    snap2 = twin.start_snapshot("v.lab")
    import uuid
    twin.conn.execute(
        "INSERT INTO change_event "
        "(id, snapshot_id, node_id, field, old_value, new_value) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        [str(uuid.uuid4()), snap2, "h-1", "ntp_enabled", "True", "False"],
    )
    twin.finish_snapshot(snap2)
    snap3 = twin.start_snapshot("v.lab")
    twin.conn.execute(
        "INSERT INTO change_event "
        "(id, snapshot_id, node_id, field, old_value, new_value) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        [str(uuid.uuid4()), snap3, "h-1", "build", "100", "200"],
    )
    twin.conn.execute(
        "INSERT INTO change_event "
        "(id, snapshot_id, node_id, field, old_value, new_value) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        [str(uuid.uuid4()), snap3, "h-2", "_added", None, '{"new": true}'],
    )
    twin.finish_snapshot(snap3)
    twin.close()
    from vmware_harden.web.app import build_app
    return build_app(db_path=db)


@pytest.mark.integration
def test_drift_page_renders(app_with_drift):
    client = TestClient(app_with_drift)
    r = client.get("/drift")
    assert r.status_code == 200
    text = r.text
    assert "Drift" in text or "drift" in text.lower()


@pytest.mark.integration
def test_drift_page_shows_recent_events(app_with_drift):
    client = TestClient(app_with_drift)
    r = client.get("/drift")
    text = r.text
    # Latest snapshot's events visible
    assert "h-1" in text
    assert "build" in text
    assert "h-2" in text
    assert "_added" in text


@pytest.mark.integration
def test_drift_page_includes_echarts(app_with_drift):
    client = TestClient(app_with_drift)
    r = client.get("/drift")
    text = r.text
    assert "echarts.init" in text


@pytest.mark.integration
def test_drift_empty_twin_message(app_with_db):
    client = TestClient(app_with_db)
    r = client.get("/drift")
    assert r.status_code == 200
    assert "no drift" in r.text.lower() or "no scans" in r.text.lower()


@pytest.fixture
def app_with_violation_and_suggestion(tmp_path: Path):
    """Twin with one violation that has a persisted Suggestion."""
    import uuid as _uuid
    db = tmp_path / "t.duckdb"
    twin = Twin(db)
    snap = twin.start_snapshot("v.lab")
    twin.conn.execute(
        "INSERT INTO nodes (id, type, target, name, attrs) "
        "VALUES (?, 'host', 'v.lab', 'esx', '{}')",
        ["v.lab:h-1"],
    )
    vid = str(_uuid.uuid4())
    twin.conn.execute(
        """INSERT INTO violation
           (id, snapshot_id, baseline_id, rule_id, node_id, severity, evidence)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        [vid, snap, "b", "r-1", "v.lab:h-1", "high", "{}"],
    )

    from vmware_harden.baselines.model import (
        ExecutionPlan, ExecutionStep, ImpactPrediction, Suggestion,
    )
    sugg = Suggestion(
        summary="Configure NTP via vmware-aiops",
        execution_plan=ExecutionPlan(steps=[
            ExecutionStep(step=1, mcp_tool="vmware_aiops.host_ntp_configure",
                          params={"servers": ["ntp1.corp"]})
        ]),
        impact_prediction=ImpactPrediction(
            affects_running_workload=False,
            requires_maintenance_window=False,
            estimated_duration="2 minutes",
            rollback_plan="empty servers list",
        ),
        confidence=0.92,
        human_review_required=False,
    )
    twin.save_suggestion(vid, sugg)
    twin.finish_snapshot(snap)
    twin.close()
    from vmware_harden.web.app import build_app
    app = build_app(db_path=db)
    app.state.test_violation_id = vid
    return app


@pytest.mark.integration
def test_remediation_endpoint_returns_suggestion(app_with_violation_and_suggestion):
    client = TestClient(app_with_violation_and_suggestion)
    vid = app_with_violation_and_suggestion.state.test_violation_id
    r = client.get(f"/violations/{vid}/remediation")
    assert r.status_code == 200
    assert "Configure NTP" in r.text
    assert "0.92" in r.text or "92" in r.text
    assert "vmware_aiops.host_ntp_configure" in r.text


@pytest.mark.integration
def test_remediation_endpoint_returns_empty_state_when_missing(app_with_violations):
    """Violation with no Suggestion: friendly message, not error."""
    client = TestClient(app_with_violations)
    # Pick any seeded violation id (doesn't have Suggestion)
    r = client.get("/violations")
    import re
    m = re.search(r"hx-get=[\"']/violations/([0-9a-f-]+)/evidence[\"']", r.text)
    vid = m.group(1)

    r2 = client.get(f"/violations/{vid}/remediation")
    assert r2.status_code == 200
    assert "no remediation" in r2.text.lower() or "not yet" in r2.text.lower() or "advise" in r2.text.lower()


@pytest.mark.integration
def test_violations_page_includes_remediation_button(app_with_violations):
    client = TestClient(app_with_violations)
    r = client.get("/violations")
    text = r.text
    # Each row should have an hx-get to /remediation
    assert "/remediation" in text


@pytest.mark.integration
def test_remediation_panel_shows_pilot_task_id(tmp_path: Path):
    """When pilot_task_id is set on a remediation row, web shows it."""
    import uuid as _uuid

    db = tmp_path / "t.duckdb"
    twin = Twin(db)
    snap = twin.start_snapshot("v.lab")
    twin.conn.execute(
        "INSERT INTO nodes (id, type, target, name, attrs) "
        "VALUES (?, 'host', 'v.lab', 'esx', '{}')",
        ["v.lab:h-1"],
    )
    vid = str(_uuid.uuid4())
    twin.conn.execute(
        """INSERT INTO violation
           (id, snapshot_id, baseline_id, rule_id, node_id, severity, evidence)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        [vid, snap, "b", "r", "v.lab:h-1", "high", "{}"],
    )

    from vmware_harden.baselines.model import (
        ExecutionPlan, ImpactPrediction, Suggestion,
    )
    sugg = Suggestion(
        summary="x",
        execution_plan=ExecutionPlan(steps=[]),
        impact_prediction=ImpactPrediction(
            affects_running_workload=False, requires_maintenance_window=False,
        ),
        confidence=0.5, human_review_required=False,
    )
    twin.save_suggestion(vid, sugg)
    twin.update_pilot_task_id(vid, "mock-pilot-abc12345")
    twin.finish_snapshot(snap)
    twin.close()

    from vmware_harden.web.app import build_app
    app = build_app(db_path=db)
    client = TestClient(app)
    r = client.get(f"/violations/{vid}/remediation")
    assert r.status_code == 200
    assert "mock-pilot-abc12345" in r.text
    assert "Pilot task" in r.text


@pytest.mark.integration
def test_web_uses_readonly_connection(app_with_db, monkeypatch):
    """#10 — web fetches must open the Twin read-only (single-writer DuckDB)."""
    calls = []
    orig = Twin.open_readonly.__func__

    def spy(cls, db_path):
        calls.append(db_path)
        return orig(cls, db_path)

    monkeypatch.setattr(Twin, "open_readonly", classmethod(spy))
    client = TestClient(app_with_db)
    r = client.get("/")
    assert r.status_code == 200
    assert calls, "dashboard route did not use Twin.open_readonly"


@pytest.mark.integration
def test_web_lock_conflict_returns_friendly_busy_page(app_with_db, monkeypatch):
    """#10 — a DuckDB lock conflict renders a friendly 503, not a raw 500."""
    import duckdb

    def boom(cls, db_path):
        raise duckdb.IOException(
            'IO Error: Could not set lock on file: Conflicting lock is held'
        )

    monkeypatch.setattr(Twin, "open_readonly", classmethod(boom))
    client = TestClient(app_with_db)
    r = client.get("/")
    assert r.status_code == 503
    assert "busy" in r.text.lower()


@pytest.mark.integration
def test_web_ignores_running_snapshot(tmp_path: Path):
    """#3 — a newer in-flight (running) snapshot must not become the dashboard's latest."""
    import json
    import uuid

    db = tmp_path / "t.duckdb"
    twin = Twin(db)
    snap = twin.start_snapshot("v.lab")
    twin.conn.execute(
        "INSERT INTO nodes (id, type, target, name, attrs) "
        "VALUES ('h-1', 'host', 'v.lab', 'esx1', '{}')"
    )
    twin.conn.execute(
        """INSERT INTO violation
           (id, snapshot_id, baseline_id, rule_id, node_id, severity, evidence)
           VALUES (?, ?, 'b', 'r-1', 'h-1', 'critical', ?)""",
        [str(uuid.uuid4()), snap, json.dumps({"category": "auth"})],
    )
    twin.finish_snapshot(snap)
    twin.start_snapshot("v.lab")  # crashed/in-flight scan, status='running'
    twin.close()

    client = TestClient(build_app(db_path=db))
    r = client.get("/")
    assert r.status_code == 200
    # The completed snapshot's violation is counted; under the old bug the
    # running snapshot was 'latest' and the dashboard showed 0 violations.
    assert "total <strong>1</strong>" in r.text
