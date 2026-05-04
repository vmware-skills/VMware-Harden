"""End-to-end scan + report orchestration."""
import json
import os
from pathlib import Path

import typer

from vmware_harden.baselines.loader import load_builtin
from vmware_harden.baselines.model import Baseline
from vmware_harden.checks.runner import CheckRunner
from vmware_harden.collectors.base import Collector
from vmware_harden.collectors.datastores import DatastoreCollector
from vmware_harden.collectors.dfw import DFWCollector
from vmware_harden.collectors.hosts import HostCollector
from vmware_harden.collectors.vms import VMCollector
from vmware_harden.store.twin import Twin


# Map node_type → collector class. Each collector's `collect` writes the
# corresponding type='X' rows. Some baselines reference both dfw_section
# and dfw_rule; one DFWCollector covers both.
_COLLECTOR_MAP: dict[str, type[Collector]] = {
    "host": HostCollector,
    "vm": VMCollector,
    "datastore": DatastoreCollector,
    "dfw_rule": DFWCollector,
    "dfw_section": DFWCollector,  # same collector handles both
}


def _resolve_db_path(db: str) -> Path:
    p = Path(os.path.expanduser(db))
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _open_twin(db: str) -> Twin:
    return Twin(_resolve_db_path(db))


def _required_collectors(baseline: Baseline) -> list[type[Collector]]:
    """Deduplicate collectors needed for baseline.applies_to."""
    seen: set[type[Collector]] = set()
    result: list[type[Collector]] = []
    for node_type in baseline.applies_to:
        cls = _COLLECTOR_MAP.get(node_type)
        if cls is None or cls in seen:
            continue
        seen.add(cls)
        result.append(cls)
    return result


def run_scan(target: str, baseline: str, db: str) -> None:
    """Scan target vCenter against the named baseline, persist to Twin."""
    twin = _open_twin(db)
    try:
        snap_id = twin.start_snapshot(target)
        typer.echo(f"Snapshot {snap_id} started against {target}")

        b = load_builtin(baseline)
        for collector_cls in _required_collectors(b):
            n = collector_cls(twin).collect(snap_id, target)
            label = collector_cls.__name__.replace("Collector", "").lower()
            typer.echo(f"  Collected {n} {label} entities")

        violations = CheckRunner(twin).run_baseline(snap_id, b)
        twin.finish_snapshot(snap_id)
        typer.echo(f"Found {len(violations)} violations against {b.id}")
    finally:
        twin.close()


def run_report(db: str, format: str = "text") -> None:
    """Print a report of the most recent snapshot's violations."""
    twin = _open_twin(db)
    try:
        snapshot_count = twin.conn.execute(
            "SELECT COUNT(*) FROM snapshots"
        ).fetchone()[0]
        if snapshot_count == 0:
            typer.echo("No scans yet. Run `vmware-harden scan --target <vc>` first.")
            return

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
                    typer.echo(
                        f"  [{r[3].upper():8s}] {r[0]:30s} {r[1]} ({r[2]})"
                    )
                typer.echo(f"\nTotal: {len(rows)} violations")
    finally:
        twin.close()
