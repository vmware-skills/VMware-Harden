"""RemediationAdvisor — LLM-driven Suggestion generation.

Builds context from violation + node attrs + nearby change events,
calls the LLM provider, parses JSON output into `Suggestion`.
"""
import json

from pydantic import ValidationError

from vmware_harden.advisor.llm import LLMProvider
from vmware_harden.baselines.model import Suggestion
from vmware_harden.store.twin import Twin


SYSTEM_PROMPT = """You are vmware-harden's Remediation Advisor.

You receive a single VMware compliance violation: a rule, the node's current
attrs, and recent change events. Produce a JSON object matching this schema:

{
  "summary": str,                        # one-line description of the fix
  "execution_plan": {
    "steps": [
      {"step": int, "mcp_tool": str, "params": dict}
    ]
  },
  "impact_prediction": {
    "affects_running_workload": bool,
    "requires_maintenance_window": bool,
    "estimated_duration": str|null,
    "rollback_plan": str|null
  },
  "confidence": float (0.0-1.0),
  "human_review_required": bool
}

Rules:
- Use mcp_tool names from the vmware-* family (vmware_aiops.*, vmware_nsx_security.*, etc.)
- If maintenance_window is needed, set human_review_required=true
- Prefer minimal, reversible changes
- Include a rollback_plan whenever possible
- Output ONLY the JSON object, no prose, no markdown fences
"""


class AdvisorError(Exception):
    """Raised when the Advisor cannot produce a valid Suggestion."""


class Advisor:
    """Turn a violation into a Suggestion via an LLM provider."""

    def __init__(self, provider: LLMProvider):
        self.provider = provider

    def advise(self, violation_id: str, twin: Twin) -> Suggestion:
        ctx = self._build_context(violation_id, twin)
        if ctx is None:
            raise AdvisorError(f"violation not found: {violation_id}")

        response = self.provider.complete(
            system=SYSTEM_PROMPT,
            user=ctx,
        )
        try:
            payload = json.loads(response)
        except json.JSONDecodeError as e:
            raise AdvisorError(f"failed to parse LLM JSON: {e}") from e
        try:
            return Suggestion(**payload)
        except ValidationError as e:
            raise AdvisorError(f"LLM output failed schema: {e}") from e

    def _build_context(self, violation_id: str, twin: Twin) -> str | None:
        row = twin.conn.execute(
            """SELECT v.rule_id, v.node_id, v.severity, v.evidence,
                      v.baseline_id, v.snapshot_id, n.attrs
               FROM violation v LEFT JOIN nodes n ON n.id = v.node_id
               WHERE v.id = ?""",
            [violation_id],
        ).fetchone()
        if row is None:
            return None
        rule_id, node_id, severity, evidence, baseline_id, snap_id, attrs = row

        # Recent change events for this node (last 5)
        change_rows = twin.conn.execute(
            """SELECT field, old_value, new_value
               FROM change_event
               WHERE node_id = ?
               ORDER BY detected_at DESC
               LIMIT 5""",
            [node_id],
        ).fetchall()

        ctx = {
            "violation": {
                "id": violation_id,
                "rule_id": rule_id,
                "node_id": node_id,
                "severity": severity,
                "baseline_id": baseline_id,
                "evidence": json.loads(evidence) if evidence else {},
            },
            "node_attrs": json.loads(attrs) if attrs else {},
            "recent_changes": [
                {"field": r[0], "old": r[1], "new": r[2]}
                for r in change_rows
            ],
        }
        return json.dumps(ctx, indent=2, ensure_ascii=False)
