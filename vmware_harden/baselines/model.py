"""Pydantic models for vmware-harden baseline YAML format.

Schema reference: docs/plans/2026-05-03-vmware-harden-design.md §4.
"""
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


Severity = Literal["critical", "high", "medium", "low", "info"]
NodeType = Literal[
    "vcenter",
    "datacenter",
    "cluster",
    "host",
    "vm",
    "datastore",
    "dfw_section",
    "dfw_rule",
    "nsx_segment",
    "tag",
]


class QueryCheck(BaseModel):
    """SQL query against the Twin. Returns rows = violations."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["query"]
    sql: str


class ScriptCheck(BaseModel):
    """Python function check. Reserved for v2 implementation deferred."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["script"]
    module: str
    function: str


Check = QueryCheck | ScriptCheck


class Remediation(BaseModel):
    """Remediation guidance for a violation."""

    model_config = ConfigDict(extra="forbid")

    summary: str
    mcp_tool: str | None = None
    params_template: dict[str, Any] | None = None
    manual_steps: str | None = None
    risk: str | None = None


class ReviewPolicy(BaseModel):
    """Whether a rule's auto-remediation requires human approval."""

    model_config = ConfigDict(extra="forbid")

    human_review_required: bool = True
    min_confidence: float = 0.8


class Rule(BaseModel):
    """A single compliance rule within a baseline."""

    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    severity: Severity
    category: str
    rationale: str | None = None
    check: Check = Field(discriminator="type")
    remediation: Remediation
    review_policy: ReviewPolicy = Field(default_factory=ReviewPolicy)


class Baseline(BaseModel):
    """A complete baseline of compliance rules."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    version: str
    source: str | None = None
    extends: str | None = None
    applies_to: list[NodeType]
    rules: list[Rule]


class ExecutionStep(BaseModel):
    """A single step in a remediation execution plan."""

    model_config = ConfigDict(extra="forbid")

    step: int
    mcp_tool: str
    params: dict[str, Any] = Field(default_factory=dict)


class ExecutionPlan(BaseModel):
    """Ordered MCP tool calls implementing a remediation."""

    model_config = ConfigDict(extra="forbid")

    steps: list[ExecutionStep] = Field(default_factory=list)


class ImpactPrediction(BaseModel):
    """LLM-estimated impact of executing a remediation."""

    model_config = ConfigDict(extra="forbid")

    affects_running_workload: bool
    requires_maintenance_window: bool
    estimated_duration: str | None = None
    rollback_plan: str | None = None


class Suggestion(BaseModel):
    """Runtime remediation suggestion from the Advisor (LLM-generated).

    Distinct from `Remediation` (static YAML guidance) — Suggestion is
    a per-violation, context-aware execution plan with confidence scoring.
    """

    model_config = ConfigDict(extra="forbid")

    summary: str
    execution_plan: ExecutionPlan
    impact_prediction: ImpactPrediction
    confidence: float = Field(ge=0.0, le=1.0)
    human_review_required: bool
