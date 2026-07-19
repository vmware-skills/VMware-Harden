"""vmware-harden CLI entry point."""
import typer

from vmware_harden.cli import advise as advise_cmd
from vmware_harden.cli import apply as apply_cmd
from vmware_harden.cli import baseline as baseline_cmd
from vmware_harden.cli import doctor as doctor_cmd
from vmware_harden.cli import drift as drift_cmd
from vmware_harden.cli import report as report_cmd
from vmware_harden.cli import scan as scan_cmd
from vmware_harden.cli import web as web_cmd

app = typer.Typer(
    name="vmware-harden",
    help="AI-native VMware compliance and baseline enforcement.",
    no_args_is_help=True,
)
app.add_typer(scan_cmd.app, name="scan", help="Run compliance scans.")
app.add_typer(report_cmd.app, name="report", help="Generate compliance reports.")
app.add_typer(baseline_cmd.app, name="baseline", help="Manage compliance baselines.")
app.add_typer(drift_cmd.app, name="drift", help="Show drift between snapshots.")
app.add_typer(web_cmd.app, name="web", help="Start the web dashboard.")
app.add_typer(advise_cmd.app, name="advise", help="Generate LLM remediation suggestions.")
app.add_typer(apply_cmd.app, name="apply", help="Submit a Suggestion for execution via vmware-pilot.")
app.add_typer(doctor_cmd.app, name="doctor", help="Run environment diagnostics.")


@app.command("mcp")
def mcp_cmd() -> None:
    """Start the MCP server (stdio transport).

    Single-command entry point for MCP clients (Claude Desktop, Cursor, etc.):
        vmware-harden mcp

    Equivalent to the legacy `vmware-harden-mcp` console script.
    """
    import sys

    if sys.version_info < (3, 10):
        msg = (
            f"ERROR: vmware-harden MCP server requires Python >= 3.10 "
            f"(got {sys.version_info.major}.{sys.version_info.minor}).\n"
            f"Interpreter: {sys.executable}\n"
            "Fix: uv python install 3.12 && "
            "uv tool install --python 3.12 --force vmware-harden"
        )
        typer.echo(msg, err=True)
        raise typer.Exit(2)

    from vmware_harden.mcp_server.server import main as _mcp_main

    _mcp_main()


if __name__ == "__main__":
    app()
