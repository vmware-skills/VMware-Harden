# Release Notes

## v1.0.0 — 2026-05-04

First public release. Production-ready compliance platform for VMware infrastructure with AI-native remediation guidance.

### M3 highlights (this release)

- **Remediation Advisor** — LLM-driven Suggestion generation per violation. Provider abstraction (Anthropic + Mock); falls back to mock with stderr warning when `ANTHROPIC_API_KEY` unset. Persisted to Twin alongside violations.
- **MCP server** — Real FastMCP-based server (replaced the v0.x stub). 6 read-only tools: `list_baselines`, `list_violations`, `get_remediation`, `list_drift_events`, `get_baseline_rules`, `scan_target`. All wrapped with `@vmware_tool` for audit logging to `~/.vmware/audit.db`.
- **CLI: `vmware-harden advise`** — generates Suggestions with `--violation-id` or `--all-critical`.
- **Web Remediation panel** — HTMX-driven inline expansion on the violations page.
- **Documentation** — comprehensive `SKILL.md`, `SECURITY.md`, and `references/` directory (cli-reference, capabilities, setup-guide).
- **Publish artifacts** — `server.json` for MCP Registry; example configs for Claude Code/Cursor/Cline/VS Code Copilot/Goose; uvx fallback for corporate TLS environments.

### M2 (recap — already in main)

- 4 baselines (CIS ESXi, vSphere SCG v8, **等保 2.0 三级**, PCI-DSS 4.0) — 65 rules
- 4 collectors: host, VM, datastore, NSX DFW
- Multi-target Twin (target:moref namespacing)
- Custom YAML import + extends inheritance
- Drift detection (config + inventory + posture)
- Web dashboard (FastAPI + HTMX + Tailwind + ECharts) — 3 pages

### M1 (recap)

- DuckDB Estate Twin
- Pydantic-validated baseline schema
- SQL-based query check executor
- Initial CIS ESXi 8.0 baseline (20 rules)

### Acceptance criteria for v1.0

- 189+ tests passing
- Bandit: 0 issues
- 6 MCP tools, all audited
- SKILL.md ≤ 3000 words, frontmatter compliant
- SECURITY.md with 6 elements + Broadcom disclaimer
- 4 built-in baselines

### Known limitations (deferred to v1.1)

- **MCP audit `skill` field** logs as `unknown` due to `vmware_policy._infer_skill` looking for `vmware_<skill>` package layout (we use `mcp_server`). Same as sibling skills; not a regression.
- **vmware-pilot integration** is in this release (v1.0) but real Pilot endpoint integration may need adjustment based on Pilot v1.x API. Mock client is fully functional.
- **`ScriptCheck` baseline rules** still rejected at load time (script-type checks reserved for v2).

### Upgrade notes

This is the first public release; nothing to migrate from. New deployments:

```bash
uv tool install vmware-harden
vmware-harden baseline list
vmware-harden scan --target <vc> --baseline cis-vmware-esxi-8.0-subset
```
