"""Pydantic models for vmware-harden baseline YAML format.

Schema reference: docs/plans/2026-05-03-vmware-harden-design.md §4.
"""
from typing import Literal, Union

from pydantic import BaseModel, Field


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

    type: Literal["query"]
    sql: str


class ScriptCheck(BaseModel):
    """Python function check. Reserved for v2 implementation deferred."""

    type: Literal["script"]
    module: str
    function: str


Check = Union[QueryCheck, ScriptCheck]


class Remediation(BaseModel):
    """Remediation guidance for a violation."""

    summary: str
    mcp_tool: str | None = None
    params_template: dict | None = None
    manual_steps: str | None = None
    risk: str | None = None


class ReviewPolicy(BaseModel):
    """Whether a rule's auto-remediation requires human approval."""

    human_review_required: bool = True
    min_confidence: float = 0.8


class Rule(BaseModel):
    """A single compliance rule within a baseline."""

    id: str
    title: str
    severity: Severity
    category: str
    rationale: str | None = None
    check: Check = Field(discriminator="type")
    remediation: Remediation
    review_policy: ReviewPolicy = ReviewPolicy()


class Baseline(BaseModel):
    """A complete baseline of compliance rules."""

    id: str
    name: str
    version: str
    source: str | None = None
    extends: str | None = None
    applies_to: list[NodeType]
    rules: list[Rule]
