"""End-to-end scan + report orchestration.

Wires Twin + HostCollector + CheckRunner + output. Called by Typer
callbacks in cli/scan.py and cli/report.py.
"""
import json
import os
from pathlib import Path

import typer

from vmware_harden.baselines.loader import load_builtin
from vmware_harden.checks.runner import CheckRunner
from vmware_harden.collectors.hosts import HostCollector
from vmware_harden.store.twin import Twin


def _resolve_db_path(db: str) -> Path:
    """Expand ~/ and create parent dirs if missing."""
    p = Path(os.path.expanduser(db))
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _open_twin(db: str) -> Twin:
    return Twin(_resolve_db_path(db))


def run_scan(target: str, baseline: str, db: str) -> None:
    """Scan target vCenter against the named baseline, persist to Twin."""
    twin = _open_twin(db)
    try:
        snap_id = twin.start_snapshot(target)
        typer.echo(f"Snapshot {snap_id} started against {target}")

        n_hosts = HostCollector(twin).collect(snap_id, target)
        typer.echo(f"Collected {n_hosts} hosts")

        b = load_builtin(baseline)
        violations = CheckRunner(twin).run_baseline(snap_id, b)
        twin.finish_snapshot(snap_id)
        typer.echo(f"Found {len(violations)} violations against {b.id}")
    finally:
        twin.close()


def run_report(db: str, format: str = "text") -> None:
    """Print a report of the most recent snapshot's violations.

    `format` is one of: "text" (default, human-readable) or "json"
    (machine-readable list of violations).
    """
    twin = _open_twin(db)
    try:
        rows = twin.conn.execute(
            """
            SELECT v.rule_id, v.node_id, n.name, v.severity, v.evidence
            FROM violation v
            JOIN nodes n ON n.id = v.node_id
            WHERE v.snapshot_id = (
                SELECT id FROM snapshots ORDER BY scan_started_at DESC LIMIT 1
            )
            ORDER BY v.severity DESC, v.rule_id
            """
        ).fetchall()

        if format == "json":
            out = [
                {
                    "rule": r[0],
                    "node": r[1],
                    "name": r[2],
                    "severity": r[3],
                    "evidence": json.loads(r[4]) if r[4] else None,
                }
                for r in rows
            ]
            typer.echo(json.dumps(out, indent=2, ensure_ascii=False))
        else:
            if not rows:
                typer.echo("No violations.")
            else:
                for r in rows:
                    typer.echo(f"  [{r[3].upper():8s}] {r[0]:30s} {r[1]} ({r[2]})")
                typer.echo(f"\nTotal: {len(rows)} violations")
    finally:
        twin.close()
