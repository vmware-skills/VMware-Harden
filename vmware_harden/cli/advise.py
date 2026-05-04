"""`vmware-harden advise` — generate LLM remediation suggestions."""
import os
from pathlib import Path

import typer

from vmware_harden.advisor.advisor import Advisor, AdvisorError
from vmware_harden.advisor.llm import AnthropicProvider, LLMProvider, MockProvider
from vmware_harden.store.twin import Twin

app = typer.Typer()


_MOCK_CANNED = (
    '{"summary":"(MOCK) Configure manually per baseline guidance",'
    '"execution_plan":{"steps":[]},'
    '"impact_prediction":{"affects_running_workload":false,'
    '"requires_maintenance_window":false},'
    '"confidence":0.5,"human_review_required":true}'
)


def _get_provider() -> LLMProvider:
    """Return AnthropicProvider if ANTHROPIC_API_KEY set, else MockProvider with warning."""
    if os.getenv("ANTHROPIC_API_KEY"):
        return AnthropicProvider()
    typer.echo(
        "WARN: ANTHROPIC_API_KEY not set — using MockProvider (stub suggestions). "
        "Set the key for real LLM advice.",
        err=True,
    )
    return MockProvider(canned_response=_MOCK_CANNED)


@app.callback(invoke_without_command=True)
def advise(
    violation_id: str | None = typer.Option(
        None, "--violation-id", help="Single violation id to advise on."
    ),
    all_critical: bool = typer.Option(
        False, "--all-critical",
        help="Generate suggestions for all critical violations in latest snapshot.",
    ),
    db: str = typer.Option(
        "~/.vmware-harden/twin.duckdb", help="Twin DB path."
    ),
) -> None:
    """Generate and persist LLM remediation suggestions."""
    if not violation_id and not all_critical:
        typer.echo("Specify --violation-id ID or --all-critical.", err=True)
        raise typer.Exit(code=2)

    p = Path(os.path.expanduser(db))
    if not p.exists():
        typer.echo(f"Twin DB not found: {p}", err=True)
        raise typer.Exit(code=1)

    twin = Twin(p)
    try:
        provider = _get_provider()
        advisor = Advisor(provider=provider)

        target_ids: list[str] = []
        if violation_id:
            target_ids = [violation_id]
        elif all_critical:
            rows = twin.conn.execute(
                """SELECT id FROM violation
                   WHERE severity = 'critical'
                     AND snapshot_id = (
                        SELECT id FROM snapshots
                        ORDER BY scan_started_at DESC LIMIT 1
                     )"""
            ).fetchall()
            target_ids = [r[0] for r in rows]
            if not target_ids:
                typer.echo("No critical violations in the latest snapshot.")
                return

        for vid in target_ids:
            try:
                suggestion = advisor.advise(vid, twin)
            except AdvisorError as e:
                typer.echo(f"  [{vid}] FAILED: {e}", err=True)
                continue
            twin.save_suggestion(vid, suggestion)
            typer.echo(
                f"  [{vid}] {suggestion.summary} "
                f"(confidence={suggestion.confidence}, "
                f"review_required={suggestion.human_review_required})"
            )
    finally:
        twin.close()
