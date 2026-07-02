"""FastAPI dashboard."""
import contextlib
from pathlib import Path

import duckdb
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from vmware_harden.store.schema import SEVERITY_RANK_SQL
from vmware_harden.store.twin import Twin


TEMPLATES_DIR = Path(__file__).parent / "templates"

# One rendered HTML page must never materialize an unbounded estate. Table
# routes page at this size so tens of thousands of rows can't land in one DOM.
PAGE_SIZE = 100


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

        # Aggregate in SQL (GROUP BY) rather than materializing every violation
        # row in Python — the summary is bounded output regardless of estate size.
        sev_counts = {
            sev: n
            for sev, n in twin.conn.execute(
                "SELECT severity, COUNT(*) FROM violation "
                "WHERE snapshot_id = ? GROUP BY severity",
                [snap_id],
            ).fetchall()
        }
        # Category lives inside the evidence JSON; extract + group in SQL, guarding
        # against non-JSON/empty evidence so a bad row can't abort the whole query.
        cat_rows = twin.conn.execute(
            "SELECT COALESCE(CASE WHEN json_valid(evidence) "
            "THEN NULLIF(json_extract_string(evidence, '$.category'), '') END, "
            "'uncategorized') AS category, COUNT(*) "
            "FROM violation WHERE snapshot_id = ? GROUP BY category",
            [snap_id],
        ).fetchall()

        # Order severities canonically
        ordered = ["critical", "high", "medium", "low", "info"]
        severity = [
            {"name": s, "count": sev_counts.get(s, 0)} for s in ordered
        ]
        categories = [
            {"name": c, "count": n} for c, n in sorted(cat_rows)
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


def _page_bounds(page: int, page_size: int) -> tuple[int, int, int]:
    """Normalize a 1-based page into (page, limit, offset)."""
    page = max(1, page)
    return page, page_size, (page - 1) * page_size


def _fetch_violations(
    db_path: Path, page: int = 1, page_size: int = PAGE_SIZE
) -> dict:
    empty = {
        "has_data": False,
        "violations": [],
        "page": 1,
        "page_size": page_size,
        "total": 0,
        "has_prev": False,
        "has_next": False,
    }
    if not db_path.exists():
        return empty
    with _open_ro(db_path) as twin:
        latest = twin.latest_snapshot()
        if latest is None:
            return empty
        snap_id = latest["id"]
        page, limit, offset = _page_bounds(page, page_size)
        total = twin.conn.execute(
            "SELECT COUNT(*) FROM violation WHERE snapshot_id = ?",
            [snap_id],
        ).fetchone()[0]
        rows = twin.conn.execute(
            f"""
               SELECT v.id, v.rule_id, v.node_id, COALESCE(n.name, ''),
                      v.severity, v.baseline_id
               FROM violation v LEFT JOIN nodes n ON n.id = v.node_id
               WHERE v.snapshot_id = ?
               ORDER BY {SEVERITY_RANK_SQL.format(col="v.severity")},
                 v.rule_id
               LIMIT ? OFFSET ?""",  # nosec B608 - SEVERITY_RANK_SQL is a hardcoded constant, no user input
            [snap_id, limit, offset],
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
        return {
            "has_data": True,
            "violations": violations,
            "page": page,
            "page_size": page_size,
            "total": total,
            "has_prev": page > 1,
            "has_next": offset + len(violations) < total,
        }


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


def _fetch_drift(
    db_path: Path, page: int = 1, page_size: int = PAGE_SIZE
) -> dict:
    """Last 5 snapshots' event counts + a page of the latest snapshot's events."""
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
        page, limit, offset = _page_bounds(page, page_size)
        total = twin.conn.execute(
            "SELECT COUNT(*) FROM change_event WHERE snapshot_id = ?",
            [latest_id],
        ).fetchone()[0]
        events = twin.conn.execute(
            "SELECT node_id, field, old_value, new_value, detected_at "
            "FROM change_event WHERE snapshot_id = ? "
            "ORDER BY node_id, field LIMIT ? OFFSET ?",
            [latest_id, limit, offset],
        ).fetchall()
        event_dicts = [
            {
                "node_id": e[0],
                "field": e[1],
                "old_value": e[2],
                "new_value": e[3],
                "detected_at": str(e[4]) if e[4] else None,
            }
            for e in events
        ]
        return {
            "has_data": True,
            "timeline": timeline,
            "events": event_dicts,
            "page": page,
            "page_size": page_size,
            "total": total,
            "has_prev": page > 1,
            "has_next": offset + len(event_dicts) < total,
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
            request, "index.html", {"nav": "summary", "summary": summary}
        )

    @app.get("/violations", response_class=HTMLResponse)
    async def violations(request: Request, page: int = 1) -> HTMLResponse:
        data = _fetch_violations(db_path, page=page)
        return templates.TemplateResponse(
            request, "violations.html", {"nav": "violations", **data}
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
    async def drift_page(request: Request, page: int = 1) -> HTMLResponse:
        data = _fetch_drift(db_path, page=page)
        return templates.TemplateResponse(
            request, "drift.html", {"nav": "drift", **data}
        )

    return app
