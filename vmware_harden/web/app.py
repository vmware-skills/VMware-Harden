"""FastAPI dashboard."""
import contextlib
from collections import Counter
from pathlib import Path

import duckdb
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from vmware_harden.store.schema import SEVERITY_RANK_SQL
from vmware_harden.store.twin import Twin


TEMPLATES_DIR = Path(__file__).parent / "templates"


class DatabaseBusyError(Exception):
    """Raised when the Twin DB is locked by a concurrent writer (scan)."""


@contextlib.contextmanager
def _open_ro(db_path: Path):
    """Open the Twin read-only for web fetches.

    DuckDB is single-writer; the dashboard must never take the write lock
    (it would block a running scan and vice versa). A lock/IO conflict is
    surfaced as DatabaseBusyError so routes can render a friendly page
    instead of a raw 500.
    """
    try:
        twin = Twin.open_readonly(db_path)
    except duckdb.Error as e:
        raise DatabaseBusyError(str(e)) from e
    try:
        yield twin
    finally:
        twin.close()


def _fetch_summary(db_path: Path) -> dict:
    """Fetch the latest completed scan's violation distribution by severity + category."""
    if not db_path.exists():
        return {"has_data": False}
    with _open_ro(db_path) as twin:
        latest_snap = twin.latest_snapshot()
        if latest_snap is None:
            return {"has_data": False}
        snap_id = latest_snap["id"]
        target = latest_snap["target"]
        finished_at = latest_snap["scan_finished_at"]

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


def _fetch_violations(db_path: Path) -> dict:
    if not db_path.exists():
        return {"has_data": False, "violations": []}
    with _open_ro(db_path) as twin:
        latest = twin.latest_snapshot()
        if latest is None:
            return {"has_data": False, "violations": []}
        snap_id = latest["id"]
        rows = twin.conn.execute(
            f"""
               SELECT v.id, v.rule_id, v.node_id, COALESCE(n.name, ''),
                      v.severity, v.baseline_id
               FROM violation v LEFT JOIN nodes n ON n.id = v.node_id
               WHERE v.snapshot_id = ?
               ORDER BY {SEVERITY_RANK_SQL.format(col="v.severity")},
                 v.rule_id""",  # nosec B608 - SEVERITY_RANK_SQL is a hardcoded constant, no user input
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


def _fetch_evidence(db_path: Path, violation_id: str) -> str | None:
    if not db_path.exists():
        return None
    with _open_ro(db_path) as twin:
        row = twin.conn.execute(
            "SELECT evidence FROM violation WHERE id = ?", [violation_id]
        ).fetchone()
        return row[0] if row else None


def _fetch_remediation(db_path: Path, violation_id: str):
    """Return (suggestion, pilot_task_id) tuple. Either may be None."""
    if not db_path.exists():
        return None, None
    with _open_ro(db_path) as twin:
        suggestion = twin.get_suggestion(violation_id)
        row = twin.conn.execute(
            "SELECT pilot_task_id FROM remediation WHERE violation_id = ?",
            [violation_id],
        ).fetchone()
        pilot_task_id = row[0] if row else None
        return suggestion, pilot_task_id


def _fetch_drift(db_path: Path) -> dict:
    """Last 5 snapshots' event counts + latest snapshot's events."""
    if not db_path.exists():
        return {"has_data": False}
    with _open_ro(db_path) as twin:
        snaps = twin.conn.execute(
            "SELECT id, target, scan_started_at FROM snapshots "
            "ORDER BY scan_started_at DESC LIMIT 5"
        ).fetchall()
        if not snaps:
            return {"has_data": False}

        # Reverse so oldest first on chart x-axis
        snaps_rev = list(reversed(snaps))
        # One GROUP BY over the 5 snapshots instead of one COUNT per snapshot.
        snap_ids = [s[0] for s in snaps_rev]
        placeholders = ", ".join("?" for _ in snap_ids)
        count_rows = twin.conn.execute(
            "SELECT snapshot_id, COUNT(*) FROM change_event "
            f"WHERE snapshot_id IN ({placeholders}) GROUP BY snapshot_id",  # nosec B608 - {placeholders} is only bound '?' params, no user input
            snap_ids,
        ).fetchall()
        counts = {r[0]: r[1] for r in count_rows}
        timeline = [
            {
                "snapshot_id": snap_id,
                "label": str(started)[:19] if started else snap_id[:8],
                "count": counts.get(snap_id, 0),
            }
            for snap_id, target, started in snaps_rev
        ]

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


_BUSY_HTML = """<!doctype html>
<html><head><title>vmware-harden — database busy</title></head>
<body style="font-family: sans-serif; max-width: 40em; margin: 4em auto;">
<h1>Database busy</h1>
<p>The compliance database is currently locked, most likely by a running
scan (<code>vmware-harden scan</code>). DuckDB allows a single writer at a
time.</p>
<p>Wait for the scan to finish, then <a href="javascript:location.reload()">
reload this page</a>.</p>
</body></html>"""


def build_app(db_path: Path) -> FastAPI:
    app = FastAPI(title="vmware-harden")
    app.state.db_path = db_path
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    app.state.templates = templates

    @app.exception_handler(DatabaseBusyError)
    async def _busy_handler(request: Request, exc: DatabaseBusyError) -> HTMLResponse:
        return HTMLResponse(_BUSY_HTML, status_code=503)

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

    @app.get("/violations/{violation_id}/remediation", response_class=HTMLResponse)
    async def remediation(request: Request, violation_id: str) -> HTMLResponse:
        suggestion, pilot_task_id = _fetch_remediation(db_path, violation_id)
        return templates.TemplateResponse(
            request,
            "_remediation.html",
            {
                "violation_id": violation_id,
                "suggestion": suggestion,
                "pilot_task_id": pilot_task_id,
            },
        )

    @app.get("/drift", response_class=HTMLResponse)
    async def drift_page(request: Request) -> HTMLResponse:
        data = _fetch_drift(db_path)
        return templates.TemplateResponse(
            request, "drift.html", {"page": "drift", **data}
        )

    return app
