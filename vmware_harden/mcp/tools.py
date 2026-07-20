"""MCP tool implementations for vmware-harden.

Located inside the `vmware_harden` package so the @vmware_tool decorator's
`_infer_skill` walk of `func.__module__` finds `vmware_harden` and tags
audit log rows with skill="harden" instead of "unknown".
"""
import json
import os
from pathlib import Path

from vmware_policy import paginated, vmware_tool

# Module-level state — set by build_server() so tools can read it
_DB_PATH: Path | None = None


def _resolve_db(must_exist: bool = True) -> Path:
    """Return the configured DB path, defaulting to user dir.

    Read tools pass must_exist=True (default) so a missing DB raises a
    teaching error instead of silently creating an empty database that
    would make every later query return "no data".
    """
    path = _DB_PATH or Path(os.path.expanduser("~/.vmware-harden/twin.duckdb"))
    if must_exist and not path.exists():
        raise FileNotFoundError(
            f"Twin DB not found: {path}. No scans have been run yet — "
            "run scan_target (or `vmware-harden scan --target <vc>`) first."
        )
    return path


@vmware_tool(risk_level="low")
def list_baselines() -> dict:
    """List built-in and user-imported baselines.

    Returns: the family list envelope; `items` is a list of
    {id, name, version, applies_to, rule_count}. Every discovered baseline is
    loaded, so `total` is the real count and `truncated` is always False.
    """
    from vmware_harden.baselines.loader import list_builtins, load_builtin

    out: list[dict] = []
    for name in list_builtins():
        try:
            b = load_builtin(name)
            out.append(
                {
                    "id": b.id,
                    "name": b.name,
                    "version": b.version,
                    "applies_to": list(b.applies_to),
                    "rule_count": len(b.rules),
                }
            )
        except Exception as e:
            out.append({"id": name, "error": f"failed to load: {e}"})
    return paginated(out, total=len(out))


@vmware_tool(risk_level="low")
def list_violations(
    severity: str | None = None, limit: int = 50, offset: int = 0
) -> dict:
    """[READ] Latest completed snapshot's violations, optionally filtered by severity.

    Bounded output: at most `limit` rows are serialized (default 50) starting at
    `offset`, so a large estate can't flood the LLM/MCP context. Returns an
    envelope: {violations: [...], total, limit, offset, has_more} where `total`
    is the full matching count so nothing is silently hidden — page with `offset`.
    """
    from typing import get_args

    from vmware_harden.baselines.model import Severity
    from vmware_harden.store.schema import SEVERITY_RANK_SQL
    from vmware_harden.store.twin import Twin

    valid_severities = set(get_args(Severity))
    if severity is not None and severity not in valid_severities:
        raise ValueError(
            f"Invalid severity {severity!r}. Valid values: "
            f"{', '.join(sorted(valid_severities))}. "
            "Re-run list_violations with one of those exact strings, or omit "
            "the parameter to list violations of all severities."
        )
    if limit < 1:
        raise ValueError(
            f"limit must be >= 1 (got {limit}). Re-run list_violations with "
            "limit=50 (the default) or a larger page size."
        )
    if offset < 0:
        raise ValueError(
            f"offset must be >= 0 (got {offset}). Re-run list_violations with "
            "offset=0 for the first page, then raise offset by limit while the "
            "envelope's has_more is true."
        )

    empty: dict = {
        "violations": [],
        "total": 0,
        "limit": limit,
        "offset": offset,
        "has_more": False,
    }
    twin = Twin(_resolve_db())
    try:
        latest = twin.latest_snapshot()
        if latest is None:
            return empty
        where = "WHERE snapshot_id = ?"
        where_params: list = [latest["id"]]
        if severity:
            where += " AND severity = ?"
            where_params.append(severity)

        total = twin.conn.execute(
            f"SELECT COUNT(*) FROM violation {where}",  # nosec B608 - where is fixed clauses with bound '?' params
            where_params,
        ).fetchone()[0]

        sql = (
            "SELECT id, rule_id, node_id, severity, baseline_id, evidence "
            f"FROM violation {where} "  # nosec B608 - where is fixed clauses with bound '?' params
            f"ORDER BY {SEVERITY_RANK_SQL.format(col='severity')}, rule_id "  # nosec B608 - SEVERITY_RANK_SQL is a hardcoded constant, no user input
            "LIMIT ? OFFSET ?"
        )
        rows = twin.conn.execute(sql, [*where_params, limit, offset]).fetchall()
        out: list[dict] = []
        for r in rows:
            try:
                ev = json.loads(r[5]) if r[5] else None
            except Exception:
                ev = None
            out.append(
                {
                    "id": r[0],
                    "rule_id": r[1],
                    "node_id": r[2],
                    "severity": r[3],
                    "baseline_id": r[4],
                    "evidence": ev,
                }
            )
        return {
            "violations": out,
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": offset + len(out) < total,
        }
    finally:
        twin.close()


@vmware_tool(risk_level="low")
def get_remediation(violation_id: str) -> dict | None:
    """[READ] Get the persisted Suggestion for a violation, or None."""
    from vmware_harden.store.twin import Twin

    twin = Twin(_resolve_db())
    try:
        sugg = twin.get_suggestion(violation_id)
        if sugg is None:
            return None
        return sugg.model_dump(mode="json")
    finally:
        twin.close()


@vmware_tool(risk_level="low")
def list_drift_events(limit: int = 50) -> dict:
    """[READ] Latest completed snapshot's change events.

    Returns the family list envelope. `total` is the real count of the
    snapshot's change events, from a COUNT(*) over the same predicate — it hits
    idx_change_event_snapshot, so it costs one index probe and lets a page that
    happens to fill `limit` be reported as complete instead of possibly-more.
    """
    from vmware_harden.store.twin import Twin

    twin = Twin(_resolve_db())
    try:
        latest = twin.latest_snapshot()
        if latest is None:
            return paginated([], limit=limit, total=0)
        total = twin.conn.execute(
            "SELECT COUNT(*) FROM change_event WHERE snapshot_id = ?",
            [latest["id"]],
        ).fetchone()[0]
        rows = twin.conn.execute(
            "SELECT node_id, field, old_value, new_value, detected_at "
            "FROM change_event WHERE snapshot_id = ? "
            "ORDER BY node_id, field LIMIT ?",
            [latest["id"], limit],
        ).fetchall()
        events = [
            {
                "node_id": r[0],
                "field": r[1],
                "old_value": r[2],
                "new_value": r[3],
                "detected_at": str(r[4]) if r[4] else None,
            }
            for r in rows
        ]
        return paginated(events, limit=limit, total=total)
    finally:
        twin.close()


@vmware_tool(risk_level="low")
def get_baseline_rules(baseline_id: str) -> dict:
    """[READ] Return all rules of a given baseline.

    Returns the family list envelope. The whole baseline is loaded either way,
    so `total` is the real rule count and `truncated` is always False.
    """
    from vmware_harden.baselines.loader import load_builtin

    b = load_builtin(baseline_id)
    rules = [
        {
            "id": r.id,
            "title": r.title,
            "severity": r.severity,
            "category": r.category,
        }
        for r in b.rules
    ]
    return paginated(rules, total=len(rules))


@vmware_tool(risk_level="medium")
def scan_target(
    target: str, baseline: str = "cis-vmware-esxi-8.0-subset"
) -> dict:
    """[READ] Run a scan for `target` against `baseline`. Returns counts."""
    from vmware_harden.cli.runner import run_scan
    from vmware_harden.store.twin import Twin

    db_path = _resolve_db(must_exist=False)  # scan legitimately creates the DB
    snap_id = run_scan(target=target, baseline=baseline, db=str(db_path))
    twin = Twin(db_path)
    try:
        host_count = twin.conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE type='host' AND target=?",
            [target],
        ).fetchone()[0]
        viol_count = twin.conn.execute(
            "SELECT COUNT(*) FROM violation WHERE snapshot_id=?", [snap_id]
        ).fetchone()[0]
        return {
            "snapshot_id": snap_id,
            "target": target,
            "baseline": baseline,
            "hosts": host_count,
            "violations": viol_count,
        }
    finally:
        twin.close()
