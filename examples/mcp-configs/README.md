# MCP Configuration Templates

Copy the relevant config snippet into your AI agent's MCP configuration file.

## Prerequisites

```bash
# Install vmware-harden (recommended — entry point is on PATH, no network at launch)
uv tool install vmware-harden
# or: pip install vmware-harden

# Optional: enable the LLM Remediation Advisor
export ANTHROPIC_API_KEY="sk-ant-..."
# Without ANTHROPIC_API_KEY, the advisor falls back to a deterministic mock provider.

# Twin DB defaults to ~/.vmware-harden/twin.duckdb; override with VMWARE_HARDEN_DB.
```

## Agent Configuration Files

| Agent | Config File | Template |
|-------|-------------|----------|
| Claude Code / Desktop | `~/.claude/settings.json` (or Claude Desktop config) | [claude-code.json](claude-code.json) |
| Cursor | Cursor MCP settings | [cursor.json](cursor.json) |
| Cline (VS Code) | `cline_mcp_settings.json` | [cline.json](cline.json) |
| VS Code Copilot | `.vscode/mcp.json` | [vscode-copilot.json](vscode-copilot.json) |
| Goose | `goose configure` or UI | [goose.json](goose.json) |
| uvx fallback (no install) | any of the above | [uvx-fallback.json](uvx-fallback.json) |

## Corporate TLS / Proxy Notes

If `uvx` fails with `invalid peer certificate: UnknownIssuer` behind a corporate
TLS-intercepting proxy, prefer `uv tool install vmware-harden` and use the entry
point directly (`vmware-harden-mcp`). The installed binary does not hit the
network at launch. If you must use `uvx`, set `UV_NATIVE_TLS=true` so uv reads
the system CA store — see [uvx-fallback.json](uvx-fallback.json) and
references/setup-guide.md.

## Safety Note

All MCP tools in vmware-harden are **read-only by design** in M3. Remediation
suggestions are returned as advisory data only — applying changes goes through
the separate `vmware-pilot` workflow with explicit human approval gates.
