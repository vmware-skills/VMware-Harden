"""`vmware-harden web` — start the dashboard server."""
import os
from pathlib import Path

import typer

app = typer.Typer()


@app.callback(invoke_without_command=True)
def start(
    db: str = typer.Option(
        "~/.vmware-harden/twin.duckdb",
        help="Path to Twin database file.",
    ),
    host: str = typer.Option("127.0.0.1", help="Bind host."),
    port: int = typer.Option(8080, help="Bind port."),
) -> None:
    """Start the FastAPI dashboard via uvicorn."""
    import uvicorn

    from vmware_harden.web.app import build_app

    db_path = Path(os.path.expanduser(db))
    if not db_path.exists():
        typer.echo(
            f"Twin DB not found at {db_path}. "
            "Run `vmware-harden scan --target <vc>` first.",
            err=True,
        )
        raise typer.Exit(code=1)

    web_app = build_app(db_path=db_path)
    typer.echo(f"Serving vmware-harden on http://{host}:{port}/  (db: {db_path})")
    uvicorn.run(web_app, host=host, port=port, log_level="info")
