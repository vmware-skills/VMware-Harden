"""LLM provider abstraction tests (mock-only; real provider is `lab` marker)."""
import json
import os
import pytest

from vmware_harden.advisor.llm import (
    LLMProvider,
    MockProvider,
    AnthropicProvider,
)


@pytest.mark.unit
def test_mock_provider_returns_canned_response():
    canned = json.dumps({"summary": "test", "confidence": 0.9})
    provider = MockProvider(canned_response=canned)
    out = provider.complete(system="sys", user="user")
    assert out == canned


@pytest.mark.unit
def test_mock_provider_records_calls():
    provider = MockProvider(canned_response="{}")
    provider.complete(system="s1", user="u1")
    provider.complete(system="s2", user="u2")
    assert len(provider.calls) == 2
    assert provider.calls[0] == ("s1", "u1")


@pytest.mark.unit
def test_provider_protocol_satisfied_by_mock():
    """MockProvider must satisfy LLMProvider duck typing."""
    provider: LLMProvider = MockProvider(canned_response="x")
    assert provider.complete(system="", user="") == "x"


@pytest.mark.unit
def test_anthropic_provider_constructable_without_key(monkeypatch):
    """AnthropicProvider lazy-imports anthropic; constructable even without API key."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    provider = AnthropicProvider(model="claude-haiku-4-5-20251001")
    assert provider.model == "claude-haiku-4-5-20251001"


@pytest.mark.lab
@pytest.mark.skipif(
    not os.getenv("ANTHROPIC_API_KEY"),
    reason="set ANTHROPIC_API_KEY to enable real Anthropic call",
)
def test_anthropic_provider_real_call():
    provider = AnthropicProvider(model="claude-haiku-4-5-20251001")
    out = provider.complete(
        system="Reply with exactly: OK",
        user="Test ping.",
    )
    assert "OK" in out
