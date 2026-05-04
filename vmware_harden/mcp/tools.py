"""MCP tool implementations for vmware-harden.

Located inside the `vmware_harden` package so the @vmware_tool decorator's
`_infer_skill` walk of `func.__module__` finds `vmware_harden` and tags
audit log rows with skill="harden" instead of "unknown".
"""
import json
import os
from pathlib import Path

from vmware_policy import vmware_tool

# Module-level state — set by build_server() so tools can read it
_DB_PATH: Path | None = None


def _resolve_db() -> Path:
    """Return the configured DB path, defaulting to user dir."""
    return _DB_PATH or Path(os.path.expanduser("~/.vmware-harden/twin.duckdb"))


@vmware_tool(risk_level="low")
def list_baselines() -> list[dict]:
    """List built-in and user-imported baselines.

    Returns: list of {id, name, version, applies_to, rule_count}.
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
    return out


@vmware_tool(risk_level="low")
def list_violations(severity: str | None = None) -> list[dict]:
    """[READ] Latest snapshot's violations, optionally filtered by severity."""
    from vmware_harden.store.twin import Twin

    twin = Twin(_resolve_db())
    try:
        latest = twin.conn.execute(
            "SELECT id FROM snapshots ORDER BY scan_started_at DESC LIMIT 1"
        ).fetchone()
        if not latest:
            return []
        params: list = [latest[0]]
        sql = (
            "SELECT id, rule_id, node_id, severity, baseline_id, evidence "
            "FROM violation WHERE snapshot_id = ?"
        )
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY severity DESC, rule_id"
        rows = twin.conn.execute(sql, params).fetchall()
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
        return out
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
def list_drift_events(limit: int = 50) -> list[dict]:
    """[READ] Latest snapshot's change events."""
    from vmware_harden.store.twin import Twin

    twin = Twin(_resolve_db())
    try:
        latest = twin.conn.execute(
            "SELECT id FROM snapshots ORDER BY scan_started_at DESC LIMIT 1"
        ).fetchone()
        if not latest:
            return []
        rows = twin.conn.execute(
            "SELECT node_id, field, old_value, new_value, detected_at "
            "FROM change_event WHERE snapshot_id = ? "
            "ORDER BY node_id, field LIMIT ?",
            [latest[0], limit],
        ).fetchall()
        return [
            {
                "node_id": r[0],
                "field": r[1],
                "old_value": r[2],
                "new_value": r[3],
                "detected_at": str(r[4]) if r[4] else None,
            }
            for r in rows
        ]
    finally:
        twin.close()


@vmware_tool(risk_level="low")
def get_baseline_rules(baseline_id: str) -> list[dict]:
    """[READ] Return all rules of a given baseline."""
    from vmware_harden.baselines.loader import load_builtin

    b = load_builtin(baseline_id)
    return [
        {
            "id": r.id,
            "title": r.title,
            "severity": r.severity,
            "category": r.category,
        }
        for r in b.rules
    ]


@vmware_tool(risk_level="medium")
def scan_target(
    target: str, baseline: str = "cis-vmware-esxi-8.0-subset"
) -> dict:
    """[READ] Run a scan for `target` against `baseline`. Returns counts."""
    from vmware_harden.cli.runner import run_scan
    from vmware_harden.store.twin import Twin

    db_path = _resolve_db()
    run_scan(target=target, baseline=baseline, db=str(db_path))
    twin = Twin(db_path)
    try:
        latest = twin.conn.execute(
            "SELECT id FROM snapshots ORDER BY scan_started_at DESC LIMIT 1"
        ).fetchone()
        snap_id = latest[0]
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
