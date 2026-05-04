"""FastAPI dashboard."""
from collections import Counter
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from vmware_harden.store.twin import Twin


TEMPLATES_DIR = Path(__file__).parent / "templates"


def _fetch_summary(db_path: Path) -> dict:
    """Fetch the latest scan's violation distribution by severity + category."""
    twin = Twin(db_path)
    try:
        latest = twin.conn.execute(
            "SELECT id, target, scan_finished_at FROM snapshots "
            "ORDER BY scan_started_at DESC LIMIT 1"
        ).fetchone()
        if not latest:
            return {"has_data": False}
        snap_id, target, finished_at = latest

        rows = twin.conn.execute(
            "SELECT severity, evidence FROM violation WHERE snapshot_id = ?",
            [snap_id],
        ).fetchall()

        sev_counts: Counter[str] = Counter()
        cat_counts: Counter[str] = Counter()
        import json as _json
        for sev, evidence_json in rows:
            sev_counts[sev] += 1
            try:
                ev = _json.loads(evidence_json) if evidence_json else {}
                cat = ev.get("category") or "uncategorized"
            except Exception:
                cat = "uncategorized"
            cat_counts[cat] += 1

        # Order severities canonically
        ordered = ["critical", "high", "medium", "low", "info"]
        severity = [
            {"name": s, "count": sev_counts.get(s, 0)} for s in ordered
        ]
        categories = [
            {"name": c, "count": n} for c, n in sorted(cat_counts.items())
        ]
        return {
            "has_data": True,
            "snapshot_id": snap_id,
            "target": target,
            "finished_at": str(finished_at) if finished_at else None,
            "total": sum(sev_counts.values()),
            "severity": severity,
            "categories": categories,
        }
    finally:
        twin.close()


def _fetch_violations(db_path: Path) -> dict:
    twin = Twin(db_path)
    try:
        latest = twin.conn.execute(
            "SELECT id FROM snapshots ORDER BY scan_started_at DESC LIMIT 1"
        ).fetchone()
        if not latest:
            return {"has_data": False, "violations": []}
        snap_id = latest[0]
        rows = twin.conn.execute(
            """SELECT v.id, v.rule_id, v.node_id, COALESCE(n.name, ''),
                      v.severity, v.baseline_id
               FROM violation v LEFT JOIN nodes n ON n.id = v.node_id
               WHERE v.snapshot_id = ?
               ORDER BY
                 CASE v.severity
                   WHEN 'critical' THEN 0
                   WHEN 'high' THEN 1
                   WHEN 'medium' THEN 2
                   WHEN 'low' THEN 3
                   WHEN 'info' THEN 4
                   ELSE 5
                 END,
                 v.rule_id""",
            [snap_id],
        ).fetchall()
        violations = [
            {
                "id": r[0],
                "rule_id": r[1],
                "node_id": r[2],
                "node_name": r[3],
                "severity": r[4],
                "baseline_id": r[5],
            }
            for r in rows
        ]
        return {"has_data": True, "violations": violations}
    finally:
        twin.close()


def _fetch_evidence(db_path: Path, violation_id: str) -> str | None:
    twin = Twin(db_path)
    try:
        row = twin.conn.execute(
            "SELECT evidence FROM violation WHERE id = ?", [violation_id]
        ).fetchone()
        return row[0] if row else None
    finally:
        twin.close()


def _fetch_drift(db_path: Path) -> dict:
    """Last 5 snapshots' event counts + latest snapshot's events."""
    twin = Twin(db_path)
    try:
        snaps = twin.conn.execute(
            "SELECT id, target, scan_started_at FROM snapshots "
            "ORDER BY scan_started_at DESC LIMIT 5"
        ).fetchall()
        if not snaps:
            return {"has_data": False}

        # Reverse so oldest first on chart x-axis
        snaps_rev = list(reversed(snaps))
        timeline = []
        for snap_id, target, started in snaps_rev:
            count = twin.conn.execute(
                "SELECT COUNT(*) FROM change_event WHERE snapshot_id = ?",
                [snap_id],
            ).fetchone()[0]
            timeline.append({
                "snapshot_id": snap_id,
                "label": str(started)[:19] if started else snap_id[:8],
                "count": count,
            })

        latest_id = snaps[0][0]
        events = twin.conn.execute(
            "SELECT node_id, field, old_value, new_value, detected_at "
            "FROM change_event WHERE snapshot_id = ? "
            "ORDER BY node_id, field",
            [latest_id],
        ).fetchall()
        return {
            "has_data": True,
            "timeline": timeline,
            "events": [
                {
                    "node_id": e[0],
                    "field": e[1],
                    "old_value": e[2],
                    "new_value": e[3],
                    "detected_at": str(e[4]) if e[4] else None,
                }
                for e in events
            ],
        }
    finally:
        twin.close()


def build_app(db_path: Path) -> FastAPI:
    app = FastAPI(title="vmware-harden")
    app.state.db_path = db_path
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    app.state.templates = templates

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        summary = _fetch_summary(db_path)
        return templates.TemplateResponse(
            request, "index.html", {"page": "summary", "summary": summary}
        )

    @app.get("/violations", response_class=HTMLResponse)
    async def violations(request: Request) -> HTMLResponse:
        data = _fetch_violations(db_path)
        return templates.TemplateResponse(
            request, "violations.html", {"page": "violations", **data}
        )

    @app.get("/violations/{violation_id}/evidence", response_class=HTMLResponse)
    async def evidence(request: Request, violation_id: str) -> HTMLResponse:
        evidence_json = _fetch_evidence(db_path, violation_id)
        return templates.TemplateResponse(
            request,
            "_evidence.html",
            {"evidence_json": evidence_json, "violation_id": violation_id},
        )

    @app.get("/drift", response_class=HTMLResponse)
    async def drift_page(request: Request) -> HTMLResponse:
        data = _fetch_drift(db_path)
        return templates.TemplateResponse(
            request, "drift.html", {"page": "drift", **data}
        )

    return app
