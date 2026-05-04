"""`vmware-harden report` — show last scan's violations.

Stub for Task 9; full implementation lands in Task 10 via cli.runner.
"""
import typer

app = typer.Typer()


@app.callback(invoke_without_command=True)
def show(
    db: str = typer.Option(
        "~/.vmware-harden/twin.duckdb",
        help="Path to Twin database file.",
    ),
    format: str = typer.Option("text", help="Report format: text or json."),
) -> None:
    """Show the last scan's violations."""
    from vmware_harden.cli.runner import run_report

    run_report(db=db, format=format)
