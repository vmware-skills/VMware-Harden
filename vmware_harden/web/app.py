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

    return app
