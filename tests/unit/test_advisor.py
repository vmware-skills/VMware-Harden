"""Advisor module tests using MockProvider."""
import json
import uuid
from pathlib import Path

import pytest

from vmware_harden.advisor.advisor import Advisor, AdvisorError
from vmware_harden.advisor.llm import MockProvider
from vmware_harden.baselines.model import Suggestion
from vmware_harden.store.twin import Twin


def _seed_violation(twin: Twin, snap_id: str) -> str:
    """Insert a host node + a single violation; return violation id."""
    twin.conn.execute(
        "INSERT INTO nodes (id, type, target, name, attrs) "
        "VALUES (?, 'host', 'lab', 'esx-1', ?)",
        ["lab:h-1", json.dumps({"ntp_enabled": False, "build": 99999999})],
    )
    vid = str(uuid.uuid4())
    twin.conn.execute(
        """INSERT INTO violation
           (id, snapshot_id, baseline_id, rule_id, node_id, severity, evidence)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        [vid, snap_id, "cis-vmware-esxi-8.0-subset", "cis-esxi-2.1.1",
         "lab:h-1", "medium", json.dumps({"id": "lab:h-1", "name": "esx-1"})],
    )
    return vid


CANNED_LLM_RESPONSE = json.dumps({
    "summary": "Configure NTP servers ntp1.corp and ntp2.corp on esx-1",
    "execution_plan": {
        "steps": [
            {"step": 1, "mcp_tool": "vmware_aiops.host_ntp_configure",
             "params": {"host_id": "lab:h-1", "servers": ["ntp1.corp", "ntp2.corp"]}},
        ],
    },
    "impact_prediction": {
        "affects_running_workload": False,
        "requires_maintenance_window": False,
        "estimated_duration": "2 minutes",
        "rollback_plan": "host_ntp_configure with empty servers",
    },
    "confidence": 0.95,
    "human_review_required": False,
})


@pytest.mark.unit
def test_advisor_returns_suggestion(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    snap = twin.start_snapshot("lab")
    vid = _seed_violation(twin, snap)

    provider = MockProvider(canned_response=CANNED_LLM_RESPONSE)
    advisor = Advisor(provider=provider)
    suggestion = advisor.advise(vid, twin)

    assert isinstance(suggestion, Suggestion)
    assert suggestion.confidence == 0.95
    assert suggestion.execution_plan.steps[0].mcp_tool == "vmware_aiops.host_ntp_configure"
    twin.close()


@pytest.mark.unit
def test_advisor_passes_context_to_llm(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    snap = twin.start_snapshot("lab")
    vid = _seed_violation(twin, snap)

    provider = MockProvider(canned_response=CANNED_LLM_RESPONSE)
    Advisor(provider=provider).advise(vid, twin)

    assert len(provider.calls) == 1
    system, user = provider.calls[0]
    # User message must include the rule, node attrs, and violation evidence
    assert "cis-esxi-2.1.1" in user
    assert "lab:h-1" in user
    assert "ntp_enabled" in user
    twin.close()


@pytest.mark.unit
def test_advisor_raises_on_unknown_violation(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    advisor = Advisor(provider=MockProvider(canned_response="{}"))
    with pytest.raises(AdvisorError, match="violation not found"):
        advisor.advise("does-not-exist", twin)
    twin.close()


@pytest.mark.unit
def test_advisor_raises_on_invalid_llm_json(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    snap = twin.start_snapshot("lab")
    vid = _seed_violation(twin, snap)

    advisor = Advisor(provider=MockProvider(canned_response="not json"))
    with pytest.raises(AdvisorError, match="parse"):
        advisor.advise(vid, twin)
    twin.close()


@pytest.mark.unit
def test_advisor_raises_on_schema_mismatch(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    snap = twin.start_snapshot("lab")
    vid = _seed_violation(twin, snap)

    advisor = Advisor(
        provider=MockProvider(canned_response='{"summary": "x"}')  # missing fields
    )
    with pytest.raises(AdvisorError, match="schema"):
        advisor.advise(vid, twin)
    twin.close()
