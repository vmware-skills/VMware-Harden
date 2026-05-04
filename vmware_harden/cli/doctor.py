"""`vmware-harden doctor` — environment diagnostics."""
import typer

from vmware_harden.doctor import run_diagnostics

app = typer.Typer()


_BADGE = {"ok": "✓", "warn": "⚠", "error": "✗", "info": "i"}
_COLOR = {
    "ok": typer.colors.GREEN,
    "warn": typer.colors.YELLOW,
    "error": typer.colors.RED,
    "info": typer.colors.BLUE,
}


@app.callback(invoke_without_command=True)
def doctor() -> None:
    """Run environment diagnostics."""
    results = run_diagnostics()
    errors = sum(1 for r in results if r.status == "error")
    warns = sum(1 for r in results if r.status == "warn")

    for r in results:
        badge = _BADGE.get(r.status, "?")
        typer.secho(
            f"  {badge} {r.name:30s} {r.detail}",
            fg=_COLOR.get(r.status),
        )

    typer.echo()
    if errors:
        typer.secho(
            f"  {errors} error(s), {warns} warning(s)",
            fg=typer.colors.RED,
            bold=True,
        )
        raise typer.Exit(code=1)
    typer.secho(
        f"  All checks passed ({warns} warning(s))",
        fg=typer.colors.GREEN,
        bold=True,
    )
