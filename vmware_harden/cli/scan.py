"""`vmware-harden scan` — run compliance scans.

Stub for Task 9; full implementation lands in Task 10 via cli.runner.
"""
import typer

app = typer.Typer()


@app.callback(invoke_without_command=True)
def run(
    target: str = typer.Option(..., help="vCenter target name from upstream config."),
    baseline: str = typer.Option(
        "cis-vmware-esxi-8.0-subset",
        help="Built-in baseline name to evaluate.",
    ),
    db: str = typer.Option(
        "~/.vmware-harden/twin.duckdb",
        help="Path to Twin database file.",
    ),
) -> None:
    """Scan estate against baseline."""
    from vmware_harden.cli.runner import run_scan

    run_scan(target=target, baseline=baseline, db=db)
