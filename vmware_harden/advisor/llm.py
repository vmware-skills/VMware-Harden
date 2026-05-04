"""LLM provider abstraction with prompt caching."""
from typing import Protocol


class LLMProvider(Protocol):
    """Minimal interface — `complete(system, user) -> str`."""

    def complete(self, *, system: str, user: str) -> str: ...


class MockProvider:
    """Deterministic provider for tests. Returns a canned response."""

    def __init__(self, canned_response: str = "{}"):
        self.canned_response = canned_response
        self.calls: list[tuple[str, str]] = []

    def complete(self, *, system: str, user: str) -> str:
        self.calls.append((system, user))
        return self.canned_response


class AnthropicProvider:
    """Production provider using Anthropic API.

    Caches the `system` block (5-min TTL via prompt caching) so repeated
    advisor calls within a session pay token cost only on the changing user
    block. Configure `ANTHROPIC_API_KEY` via env var.
    """

    def __init__(self, model: str = "claude-haiku-4-5-20251001"):
        self.model = model
        self._client = None  # lazy

    def _get_client(self):
        if self._client is None:
            import anthropic
            self._client = anthropic.Anthropic()
        return self._client

    def complete(self, *, system: str, user: str) -> str:
        client = self._get_client()
        response = client.messages.create(
            model=self.model,
            max_tokens=2048,
            system=[
                {
                    "type": "text",
                    "text": system,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[{"role": "user", "content": user}],
        )
        # response.content is a list of content blocks
        text_parts = [
            block.text for block in response.content
            if hasattr(block, "text")
        ]
        return "".join(text_parts)
