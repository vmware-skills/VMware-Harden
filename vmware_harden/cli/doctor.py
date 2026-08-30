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
def doctor(
    target: str = typer.Option(
        None,
        "--target",
        help=(
            "Check only this scan target. Without it every configured target is "
            "connected to and authenticated, which is what you want before a "
            "first scan; name one when you already know which vCenter failed "
            "and do not want to wait on timeouts from the others."
        ),
    ),
) -> None:
    """Run environment diagnostics, including reachability of every scan target."""
    results = run_diagnostics(target=target)
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
    if warns:
        # "All checks passed (2 warning(s))" contradicts itself in seven words,
        # and the summary is the line a hurried reader takes away. A user whose
        # collectors were missing was told it passed, then watched every scan
        # fail on the thing the ⚠ lines named (2026-08-30).
        #
        # Exit code stays 0: a warning is a state this command reports, not a
        # failure of the command, and scripts that gate on the exit code are
        # asking about errors.
        typer.secho(
            f"  No errors. {warns} warning(s) above — each names something "
            "harden cannot do until it is resolved.",
            fg=typer.colors.YELLOW,
            bold=True,
        )
        return
    typer.secho("  All checks passed", fg=typer.colors.GREEN, bold=True)
