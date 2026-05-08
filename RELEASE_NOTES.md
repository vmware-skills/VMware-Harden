## v1.5.21 (2026-05-08)

**Family alignment** — no source changes in this skill.

- **deps:** Bumped `python-multipart` 0.0.26 → 0.0.27 (transitive, fixes GHSA HIGH DoS via unbounded multipart headers).
- **align:** Tracks v1.5.21 family bump driven by vmware-monitor folder_path feature (community PR #11).

## v1.5.20 (2026-05-08)

**Family alignment** — no source changes in this skill.

- **align:** Tracks v1.5.20 family bump driven by vmware-nsx-security and vmware-aria PyPI README `mcp-name:` ownership marker fix required by MCP Registry validation. Other 7 skills already had the marker; this release re-publishes them to keep the family version aligned per CLAUDE.md policy.
- **registry:** All 9 skills now registered on registry.modelcontextprotocol.io as `isLatest=true`.

# Release Notes

## v1.5.19 (2026-05-06)

**Performance + correctness fixes** — Twin DB query speed and report completeness.

- **perf(store):** Added `CREATE INDEX IF NOT EXISTS` for `violation.snapshot_id`, `node_state.snapshot_id`, `change_event.snapshot_id` in `store/schema.py`. Without these, every `list_violations` / `report` / drift diff query performed a full table scan, with cost scaling linearly in scan history (yjs review 2026-05-06; CLAUDE.md 踩坑 #28).
- **fix(cli):** `vmware-harden report` now uses `LEFT JOIN nodes` with `COALESCE(name, '[orphan]')`. Previously the INNER JOIN silently dropped violations whose node had been deleted between scans — drift scenarios appeared falsely clean (CLAUDE.md 踩坑 #29).
- **smoke:** Family `scripts/family_smoke.sh` now recursively walks every Typer subcommand to trigger lazy imports.
- **align:** Family version bump to v1.5.19.

## v1.5.18 — 2026-05-04

GA promotion + new EU baselines + doctor command.

- **Promoted to GA family** — vmware-harden is now part of `FAMILY` array in family_smoke.sh; version bumped to 1.5.18 for family-wide alignment (all family skills share this version).
- **EU NIS2 Directive baseline** (12 rules) — for "essential entities" under Articles 21/23/24.
- **BSI IT-Grundschutz Basis-Absicherung baseline** (10 rules) — German federal baseline for VMware ESXi hosts.
- **`vmware-harden doctor` command** — environment diagnostics (Python, deps, Twin, audit DB, ANTHROPIC_API_KEY).
- 6 baselines now ship: CIS ESXi, vSphere SCG, GB/T 22239 三级, PCI-DSS 4.0, EU NIS2, BSI IT-Grundschutz (87 rules total).

No breaking changes from 1.0.1.

## v1.0.1 — 2026-05-04

Patch release for MCP Registry submission.

- Add `mcp-name: io.github.zw008/vmware-harden` marker to README for MCP Registry ownership validation.
- No code or behavior changes; identical to 1.0.0 functionally.

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
- **ScriptCheck rules rejected at load time** — declarative SQL (`QueryCheck`)
  covers all v1.0 baselines (CIS, SCG, 等保, PCI). Implementing executable
  script checks is a v2 feature gated on a security threat model
  (sandboxing arbitrary Python from baseline YAML). Tracked at
  `vmware_harden/baselines/loader.py` (search for "DEFERRED to v2.0").

### Upgrade notes

This is the first public release; nothing to migrate from. New deployments:

```bash
uv tool install vmware-harden
vmware-harden baseline list
vmware-harden scan --target <vc> --baseline cis-vmware-esxi-8.0-subset
```
