"""`vmware-harden baseline` — manage compliance baselines."""
import shutil
from pathlib import Path

import typer
from pydantic import ValidationError

from vmware_harden.baselines import loader
from vmware_harden.baselines.loader import list_builtins, load_baseline

app = typer.Typer()


@app.command("list")
def list_cmd() -> None:
    """List built-in (and imported) baseline names."""
    for name in list_builtins():
        typer.echo(name)


@app.command("validate")
def validate_cmd(
    path: Path = typer.Argument(..., help="YAML file path"),
) -> None:
    """Validate a baseline YAML file against the schema."""
    try:
        b = load_baseline(path)
    except (ValidationError, NotImplementedError) as e:
        typer.echo(f"Validation failed: {e}")
        raise typer.Exit(code=1)
    except FileNotFoundError as e:
        typer.echo(f"File not found: {e}")
        raise typer.Exit(code=2)
    typer.echo(f"OK — {b.id} ({len(b.rules)} rules, applies to {b.applies_to})")


@app.command("import")
def import_cmd(
    path: Path = typer.Argument(..., help="YAML file to import"),
    name: str = typer.Option(
        None,
        "--name",
        help="Override the destination filename stem (default: source filename).",
    ),
) -> None:
    """Validate and copy a baseline to ~/.vmware-harden/baselines/."""
    # Validate before copying — never persist invalid YAML
    try:
        load_baseline(path)
    except (ValidationError, NotImplementedError) as e:
        typer.echo(f"Validation failed: {e}")
        raise typer.Exit(code=1)
    except FileNotFoundError as e:
        typer.echo(f"File not found: {e}")
        raise typer.Exit(code=2)

    loader.USER_DIR.mkdir(parents=True, exist_ok=True)
    dest_name = name if name else path.stem
    dest = loader.USER_DIR / f"{dest_name}.yaml"
    shutil.copyfile(path, dest)
    typer.echo(f"Imported to {dest}")
