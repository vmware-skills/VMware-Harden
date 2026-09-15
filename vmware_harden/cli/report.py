"""`vmware-harden report` — show last scan's violations.

Stub for Task 9; full implementation lands in Task 10 via cli.runner.
"""
import typer
from vmware_policy import cli_local

app = typer.Typer()


@app.callback(invoke_without_command=True)
@cli_local("reads violations from the local compliance database")
def show(
    db: str = typer.Option(
        "~/.vmware-harden/twin.duckdb", envvar="VMWARE_HARDEN_DB",
        help="Path to Twin database file.",
    ),
    format: str = typer.Option("text", help="Report format: text or json."),
    limit: int = typer.Option(
        500, help="Max violations to print; a note reports the true total."
    ),
) -> None:
    """Show the last scan's violations."""
    from vmware_harden.cli.runner import run_report

    if limit < 1:
        typer.echo("--limit must be >= 1.", err=True)
        raise typer.Exit(code=2)
    run_report(db=db, format=format, limit=limit)
