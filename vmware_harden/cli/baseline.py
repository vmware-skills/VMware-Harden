"""`vmware-harden baseline` — manage compliance baselines."""
import typer

from vmware_harden.baselines.loader import list_builtins

app = typer.Typer()


@app.command("list")
def list_cmd() -> None:
    """List built-in baseline names."""
    for name in list_builtins():
        typer.echo(name)
