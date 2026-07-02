"""`vmware-harden drift` — show drift between most recent snapshot and prior."""
import json as _json
import os
from pathlib import Path

import typer

from vmware_harden.store.twin import Twin

app = typer.Typer()


@app.callback(invoke_without_command=True)
def show(
    db: str = typer.Option(
        "~/.vmware-harden/twin.duckdb",
        help="Path to Twin database file.",
    ),
    format: str = typer.Option("text", help="Report format: text or json."),
    limit: int = typer.Option(
        500, help="Max drift events to print; a note reports the true total."
    ),
) -> None:
    """Show drift events from the most recent snapshot."""
    if limit < 1:
        typer.echo("--limit must be >= 1.", err=True)
        raise typer.Exit(code=2)

    p = Path(os.path.expanduser(db))
    if not p.exists():
        typer.echo("No scans yet. Run `vmware-harden scan --target <vc>` first.")
        return

    twin = Twin(p)
    try:
        latest = twin.latest_snapshot()
        if latest is None:
            typer.echo("No completed scans yet. Run `vmware-harden scan --target <vc>` first.")
            return
        snap_id = latest["id"]
        total = twin.conn.execute(
            "SELECT COUNT(*) FROM change_event WHERE snapshot_id = ?",
            [snap_id],
        ).fetchone()[0]
        rows = twin.conn.execute(
            "SELECT node_id, field, old_value, new_value, detected_at "
            "FROM change_event WHERE snapshot_id = ? "
            "ORDER BY node_id, field LIMIT ?",
            [snap_id, limit],
        ).fetchall()
        truncated = total > len(rows)

        if format == "json":
            out = [
                {
                    "node_id": r[0],
                    "field": r[1],
                    "old_value": r[2],
                    "new_value": r[3],
                    "detected_at": str(r[4]) if r[4] else None,
                }
                for r in rows
            ]
            typer.echo(_json.dumps(out, indent=2, ensure_ascii=False))
            if truncated:
                typer.echo(
                    f"# Showing {len(rows)} of {total} drift events "
                    f"(limited by --limit {limit}).",
                    err=True,
                )
        else:
            if not rows:
                typer.echo("No drift detected since previous snapshot.")
            else:
                typer.echo(f"Drift events on snapshot {snap_id}:\n")
                for r in rows:
                    typer.echo(
                        f"  {r[0]:30s} {r[1]:25s} {r[2] or 'None':>15} → {r[3] or 'None'}"
                    )
                if truncated:
                    typer.echo(
                        f"\nShowing {len(rows)} of {total} drift events "
                        f"(limited by --limit {limit}). Raise --limit to see more."
                    )
                else:
                    typer.echo(f"\nTotal: {len(rows)} drift events")
    finally:
        twin.close()
