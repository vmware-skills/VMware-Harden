"""`vmware-harden apply` — submit a Suggestion to vmware-pilot for execution."""
import os
from pathlib import Path

import typer

from vmware_harden.advisor.advisor import Advisor, AdvisorError
from vmware_harden.advisor.llm import AnthropicProvider, MockProvider
from vmware_harden.pilot.client import (
    MockPilotClient,
    PilotClient,
    PilotSubmissionError,
    RealPilotClient,
)
from vmware_harden.store.twin import Twin

app = typer.Typer()


def _get_pilot_client(mode: str) -> PilotClient:
    if mode == "real":
        return RealPilotClient()
    return MockPilotClient()


def _get_llm_provider():
    if os.getenv("ANTHROPIC_API_KEY"):
        return AnthropicProvider()
    return MockProvider(canned_response="""{
  "summary": "Mock suggestion (set ANTHROPIC_API_KEY for real)",
  "execution_plan": {"steps": []},
  "impact_prediction": {"affects_running_workload": false, "requires_maintenance_window": false},
  "confidence": 0.5,
  "human_review_required": true
}""")


@app.callback(invoke_without_command=True)
def apply(
    violation_id: str = typer.Option(..., "--violation-id", help="Violation id to remediate."),
    db: str = typer.Option(
        "~/.vmware-harden/twin.duckdb", help="Twin DB path."
    ),
    auto_approve: bool = typer.Option(
        False, "--auto-approve", help="Skip y/N prompt for high-risk suggestions."
    ),
    pilot: str = typer.Option(
        "mock", help="Pilot client mode: 'mock' (default) or 'real'."
    ),
) -> None:
    """Submit a Suggestion to vmware-pilot for execution."""
    p = Path(os.path.expanduser(db))
    if not p.exists():
        typer.echo(f"Twin DB not found: {p}", err=True)
        raise typer.Exit(code=1)

    twin = Twin(p)
    try:
        # Verify violation exists
        row = twin.conn.execute(
            "SELECT id FROM violation WHERE id = ?", [violation_id]
        ).fetchone()
        if row is None:
            typer.echo(f"Violation not found: {violation_id}", err=True)
            raise typer.Exit(code=2)

        # Load existing Suggestion or generate one
        suggestion = twin.get_suggestion(violation_id)
        if suggestion is None:
            typer.echo("  No suggestion yet — generating via Advisor...")
            advisor = Advisor(provider=_get_llm_provider())
            try:
                suggestion = advisor.advise(violation_id, twin)
            except AdvisorError as e:
                typer.echo(f"  Advisor failed: {e}", err=True)
                raise typer.Exit(code=3)
            twin.save_suggestion(violation_id, suggestion)

        # Print summary
        typer.echo(f"\nSuggestion: {suggestion.summary}")
        typer.echo(f"Confidence: {suggestion.confidence}")
        typer.echo(f"Affects running workload: {suggestion.impact_prediction.affects_running_workload}")
        typer.echo(
            f"Requires maintenance window: {suggestion.impact_prediction.requires_maintenance_window}"
        )

        # Approval gate
        if suggestion.human_review_required and not auto_approve:
            typer.echo("\nThis remediation requires human review.")
            confirm = typer.prompt("Approve? [y/N]", default="N")
            if confirm.lower() not in ("y", "yes"):
                typer.echo("Aborted; not submitted.")
                return

        # Submit to pilot
        client = _get_pilot_client(pilot)
        try:
            task_id = client.submit_remediation(suggestion)
        except PilotSubmissionError as e:
            typer.echo(f"Pilot submission failed: {e}", err=True)
            raise typer.Exit(code=4)

        twin.update_pilot_task_id(violation_id, task_id)
        typer.echo(f"\nSubmitted to pilot. Task id: {task_id}")
    finally:
        twin.close()
