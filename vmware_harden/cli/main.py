"""vmware-harden CLI entry point."""
import typer

from vmware_harden.cli import baseline as baseline_cmd
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


if __name__ == "__main__":
    app()
