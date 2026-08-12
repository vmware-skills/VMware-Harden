"""End-to-end scan + report orchestration."""
import json
import os
from pathlib import Path

import typer

from vmware_harden.baselines.loader import load_builtin
from vmware_harden.baselines.model import Baseline
from vmware_harden.checks.coverage import coverage_for
from vmware_harden.checks.runner import CheckRunner
from vmware_harden.collectors.base import Collector, CollectorDependencyError
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


def run_scan(target: str, baseline: str, db: str) -> str:
    """Scan target vCenter against the named baseline, persist to Twin.

    Returns the snapshot id. On any failure the snapshot is marked
    status='failed' (so it never becomes the "latest" snapshot for reports)
    and the error is re-raised.
    """
    twin = _open_twin(db)
    try:
        snap_id = twin.start_snapshot(target)
        typer.echo(f"Snapshot {snap_id} started against {target}")

        try:
            b = load_builtin(baseline)
            for collector_cls in _required_collectors(b):
                n = collector_cls(twin).collect(snap_id, target)
                label = collector_cls.__name__.replace("Collector", "").lower()
                typer.echo(f"  Collected {n} {label} entities")

            violations = CheckRunner(twin).run_baseline(snap_id, b)

            # Compute and persist drift from prior completed snapshot, if any.
            prior_row = twin.conn.execute(
                "SELECT id FROM snapshots "
                "WHERE target = ? AND id != ? AND status = 'completed' "
                "ORDER BY scan_started_at DESC LIMIT 1",
                [target, snap_id],
            ).fetchone()
            if prior_row:
                from vmware_harden.drift.diff import diff_snapshots
                events = diff_snapshots(twin, prior_row[0], snap_id, persist=True)
                if events:
                    typer.echo(f"  Detected {len(events)} drift events from prior scan")

            twin.finish_snapshot(snap_id)
        except ModuleNotFoundError as e:
            twin.finish_snapshot(snap_id, status="failed")
            pkg = (e.name or "dependency").replace("_", "-")
            # Not RuntimeError: this message is authored, but RuntimeError is
            # Python's generic catch-all and is deliberately off the MCP
            # allowlist, so raising one here reduced the whole instruction to
            # "RuntimeError: operation failed." on the scan_target surface.
            raise CollectorDependencyError(
                f"{pkg} not installed — install it with `uv tool install {pkg}` "
                f"(collector dependency for baseline {baseline!r}). "
                f"Snapshot {snap_id} was marked 'failed' and is excluded from "
                f"reports. After installing, re-run `vmware-harden scan "
                f"--target {target}`; run `vmware-harden doctor` to see which "
                "collector dependencies are present."
            ) from e
        except Exception as e:
            twin.finish_snapshot(snap_id, status="failed")
            typer.echo(
                f"Scan of {target!r} failed; snapshot {snap_id} marked 'failed' "
                f"and excluded from reports. Cause: {e}",
                err=True,
            )
            raise

        typer.echo(f"Found {len(violations)} violations against {b.id}")
        # A violation count on its own reads as a verdict. Say in the same
        # breath how much of the baseline actually ran, or "0 violations"
        # against a mostly-unevaluated baseline reads as "compliant".
        cov = coverage_for(twin, snap_id)
        if not cov.complete:
            typer.echo(f"  {cov.summary_line()}")
            typer.echo("  Run `vmware-harden report` to see which rules and why.")
        return snap_id
    finally:
        twin.close()


def run_report(db: str, format: str = "text", limit: int = 500) -> None:
    """Print a report of the most recent completed snapshot's violations.

    At most `limit` rows are printed (default 500); a truncation note tells the
    user the true total so a huge estate can't silently flood stdout/JSON.
    """
    from vmware_harden.store.schema import SEVERITY_RANK_SQL

    # Do not silently create the DB file just to report on it (item: a
    # report run must never leave an empty database behind).
    db_path = Path(os.path.expanduser(db))
    if not db_path.exists():
        typer.echo("No scans yet. Run `vmware-harden scan --target <vc>` first.")
        return

    twin = Twin(db_path)
    try:
        latest = twin.latest_snapshot()
        if latest is None:
            typer.echo("No completed scans yet. Run `vmware-harden scan --target <vc>` first.")
            return

        total = twin.conn.execute(
            "SELECT COUNT(*) FROM violation WHERE snapshot_id = ?",
            [latest["id"]],
        ).fetchone()[0]
        rows = twin.conn.execute(
            f"""
            SELECT v.rule_id, v.node_id, COALESCE(n.name, '[orphan]') AS name, v.severity, v.evidence
            FROM violation v
            LEFT JOIN nodes n ON n.id = v.node_id
            WHERE v.snapshot_id = ?
            ORDER BY {SEVERITY_RANK_SQL.format(col="v.severity")}, v.rule_id
            LIMIT ?
            """,  # nosec B608 - SEVERITY_RANK_SQL is a hardcoded constant, no user input
            [latest["id"], limit],
        ).fetchall()
        truncated = total > len(rows)
        cov = coverage_for(twin, latest["id"])

        if format == "json":
            violations = [
                {
                    "rule": r[0],
                    "node": r[1],
                    "name": r[2],
                    "severity": r[3],
                    "evidence": json.loads(r[4]) if r[4] else None,
                }
                for r in rows
            ]
            # Object, not the bare list this used to emit. A list gives a script
            # no way to tell "nothing was wrong" from "almost nothing was
            # checked" — both are `[]`. Callers that iterated the top level need
            # to read ["violations"]; the release notes call this out.
            typer.echo(json.dumps(
                {"violations": violations, "coverage": cov.as_dict()},
                indent=2, ensure_ascii=False,
            ))
            if truncated:
                typer.echo(
                    f"# Showing {len(rows)} of {total} violations "
                    f"(limited by --limit {limit}).",
                    err=True,
                )
        else:
            if not rows:
                # Never a bare "No violations." when rules were skipped: that
                # sentence is the false-compliance claim in three words.
                typer.echo(
                    "No violations among the rules that could be evaluated."
                    if not cov.complete else "No violations."
                )
            else:
                for r in rows:
                    typer.echo(
                        f"  [{r[3].upper():8s}] {r[0]:30s} {r[1]} ({r[2]})"
                    )
                if truncated:
                    typer.echo(
                        f"\nShowing {len(rows)} of {total} violations "
                        f"(limited by --limit {limit}). Raise --limit to see more."
                    )
                else:
                    typer.echo(f"\nTotal: {len(rows)} violations")

            if not cov.complete:
                typer.echo(f"\n{cov.summary_line()}")
                # Only when there is a list to print: an untracked snapshot has
                # no rules to name, and a bare "Not evaluated:" header with
                # nothing under it reads as a rendering fault.
                if cov.undetermined_rules:
                    typer.echo("Not evaluated:")
                    for rule_id, reason in cov.undetermined_rules:
                        typer.echo(f"  {rule_id:30s} {reason}")
                    if cov.undetermined_rules_truncated:
                        # Say the list is a page. The count above is complete,
                        # but a short list beside a large count reads as "the
                        # rest were fine".
                        typer.echo(
                            f"  ... and more; showing "
                            f"{len(cov.undetermined_rules)} of {cov.undetermined}."
                        )
    finally:
        twin.close()
