## v1.6.1 (2026-06-24) — version alignment

No functional changes — version bumped to stay aligned with the VMware skill family release.

## v1.6.0 (2026-06-22) — family alignment + harness trust architecture

No skill code changes. Aligns to the v1.6.0 family release and automatically picks up the
vmware-policy 1.6.0 governance upgrades (token/runaway budget guard, audit accountability fields,
graduated-autonomy risk tiers) on next install. Read-only compliance engine — no undo tokens applicable.

## v1.5.39 (2026-06-22) — family version alignment

No code changes. Version bump to stay aligned with the v1.5.39 family release
(AIops snapshot-delete async + honest-timeout token-burn fix; Storage datastore-browse timeout fix).

## v1.5.38 (2026-06-12) — backlog finish: collector de-duplication

### Changed
- Lifted the duplicated collect + batch-persist logic into the `Collector` base class; the host/vm/
  datastore/dfw collectors shed ~113 lines (~39%) with identical behavior. (#2)

## v1.5.37 (2026-06-12) — backlog: batched writes, dead-schema cleanup, offline evals

### Fixed
- **Collectors batch their writes** into one transaction + `executemany` (was one transaction per node —
  thousands of commits on large inventories); the drift dashboard's 5 COUNT queries collapsed to one
  GROUP BY. (#1)

### Changed
- Removed dead schema (`edges` table, `nodes.parent_id`); `violation.status` / `posture_drift` are
  documented as reserved-but-unwired. (#4)

### Added
- Offline regression evals (no live-lab env var needed) pinning the v1.5.36 compliance-correctness fixes
  and the approval-gate truth table. (#5)

## v1.5.36 (2026-06-12) — compliance-correctness fixes: scoping, severity, approval gate

### Fixed
- **Absence-check violations are no longer dropped** — the snapshot-scoping filter wrongly removed
  "control entirely absent" findings (e.g. PCI default-deny, no-encryption, no-segmentation) because
  they emit a synthetic node id; the most severe estate-wide gaps could report as CLEAN.
- **Cross-target / decommissioned-node bleed fixed** — rule SQL ran against the cumulative node store,
  so one target's scan reported another target's violations.
- **Failed scans no longer masquerade as the latest clean snapshot** — a collector failure now marks
  the snapshot `failed`, and every "latest snapshot" consumer filters to completed scans.
- **Severity ordering** was alphabetical (critical sorted *last*); now critical-first everywhere.
- **Approval gate no longer trusts the LLM alone** — a rule's `review_policy` (human-review-required /
  min-confidence) is enforced; unresolvable rules default to requiring review for high/critical.
- `list_violations(severity=…)` validates the value; teaching errors for missing dependency / DB.

### Added
- Indexes on `change_event(node_id)` and `remediation(violation_id)`; read-only DuckDB access for the
  web dashboard (no lock conflict with a running scan).

## v1.5.35 (2026-06-10) — security fix: baseline loader path traversal

### Fixed
- **Baseline name path traversal**: `_resolve_baseline_path()` now rejects names containing
  path separators, leading dots, or null bytes and confirms the resolved path stays inside the
  baseline directory. Closes a read-arbitrary-file vector reachable via the CLI, MCP, or a
  malicious `extends:` field.

This release aligns the whole family back to a single version (1.5.35); vmware-policy and vmware-pilot return to the shared number after sitting at 1.5.22.

## v1.5.32 (2026-06-08) — Family version alignment + test hygiene

No functional changes. Version-alignment release with the v1.5.32 family
(spec-audit fixes in sibling skills).

### Tests
- Smoke test no longer pins a stale version literal — asserts semver shape +
  agreement with pyproject.toml.

## v1.5.30 (2026-06-07) — Tool description quality (Glama TDQS)

### Improved
- Rewrote MCP tool descriptions flagged by Glama's Tool Description Quality Score review:
  per-parameter semantics (format, defaults, valid values), return-field documentation,
  sibling-tool routing guidance, and behavioral transparency (side effects, audit logging,
  async semantics). Corrected descriptions that overstated or misstated actual behavior.
- No functional changes; descriptions only.

## v1.5.29 (2026-05-29) — Doctor / Smithery / Python 3.10 Troubleshooting Docs

### Documentation
- README.md: refreshed v1.5.18 framing to make it clear the project is at v1.5.28-aligned (now v1.5.29), not v1.5.18 (commit `27035a1`).
- `references/cli-reference.md`: added full `doctor` command section — synopsis, no-options note, table of 10 environment checks from `vmware_harden/doctor.py::run_diagnostics`, example output, exit codes.
- `references/setup-guide.md`: new "Alternative Deployment: Container / Smithery" section mirroring AVI style (Docker build/run with Twin DB volume mount note, Smithery config schema, deployment-choice table); new "Troubleshooting" section above Security with the Python 3.10 / `subclass() arg 1 must be a class` fix (upgrade to v1.5.28+ or `mcp[cli]>=1.14`).
- `references/capabilities.md`: "Performance & Correctness Notes" section covering v1.5.19 snapshot_id indexes (`IF NOT EXISTS`, idempotent, no migration) and LEFT JOIN + COALESCE orphan-preservation in `list_violations` / `report` (踩坑 #28 / #29 cross-refs).

### No code changes
Documentation-only release.

## v1.5.28 (2026-05-20)

**Fix `subclass() arg 1 must be a class` in goose/old mcp environments** —
v1.5.25–1.5.27 replaced `X | None` with `Optional[X]` but kept
`from __future__ import annotations` at the top of `mcp_server/server.py`.
Under mcp 1.10–1.13 (which Goose and some sandboxes pin), `Tool.from_function`
calls `issubclass(param.annotation, Context)` without resolving forward refs,
so string annotations crash the entire server load. Removed
`from __future__ import annotations` from `mcp_server/server.py` so annotations
are real classes; verified all tools load under mcp 1.10 and 1.14.

Traceback location: `mcp/server/fastmcp/tools/base.py:67`. CLAUDE.md 踩坑 #33
updated. family_smoke.sh Check 4b now installs `mcp==1.10.0` to catch this
regression class.

## v1.5.27 (2026-05-20)

**Loosen Python requirement: now supports Python >= 3.10** — v1.5.25/26 fixed
the PEP 604 root cause in MCP tool signatures (Optional[X] instead of X | None),
but kept `requires-python = ">=3.11"` and a 3.11 hard guard in `mcp_cmd`. Both
relaxed to 3.10 so users on Python 3.10 (e.g. Goose default sandbox, Ubuntu
22.04 system python) can install and run directly without a Python upgrade.

- `pyproject.toml`: `requires-python = ">=3.10"` (was `>=3.11`; VMware-VKS
  was `>=3.12`, now also `>=3.10` for family alignment).
- `<pkg>/cli.py` `mcp_cmd()`: version guard now triggers on `< (3, 10)`.
- Behavior on Python 3.10 matches 3.11/3.12 — the Optional[X] fix from v1.5.25
  is what actually enables this; this release just stops blocking installs.

---

## v1.5.26

**Family-wide MCP server fix — Python 3.10 compatibility (踩坑 #33)** — `vmware-harden mcp`
crashed at decorator time on Python 3.10 with `subclass() arg 1 must be a class`.
Root cause: `mcp_server/server.py` used PEP 604 `X | None` in tool signatures
plus `from __future__ import annotations`; on Python 3.10 + older mcp/pydantic
combos, `typing.get_type_hints()` evaluates `"str | None"` to a
`types.UnionType` instance, which FastMCP/Pydantic then feeds to `issubclass()`.
Reported by a goose user (qwen3.6:27, Python 3.10).

- `mcp_server/server.py`: all `X | None` → `Optional[X]`; ops layer untouched.
- `<pkg>/cli.py` `mcp_cmd()`: hard guard — exits with installation fix command
  if Python < 3.11 (defense in depth, our actual lower bound).
- `pyproject.toml`: `mcp[cli]>=1.10,<2.0` (was `>=1.0`) so uv doesn't pick
  an ancient version that has the same issubclass bug.

**Tooling — family smoke gains MCP schema-build check** — `scripts/family_smoke.sh`
new Check 4b runs `asyncio.run(mcp.list_tools())` per skill, forcing FastMCP to
build Pydantic models for every declared tool. Supports both module-level `mcp`
and `build_server()` factory patterns.

**Docs — CLAUDE.md gains 踩坑 #33 (PEP 604 / Python 3.10) and #34 (CLI/MCP exposure parity).**

---

## v1.5.24 (2026-05-19)

**Family version alignment** — no code changes in this skill. Bumped together
with VMware-AIops and VMware-VKS, which received a pyVmomi 8.x `ManagedObject`
setattr fix (踩坑 #32). `family_smoke.sh` now enforces the no-setattr rule
across all 9 skills.

## v1.5.23 (2026-05-19)

**VCF 9.0 / 9.1 compatibility — scan path works; new 9.0 baselines planned.**

- **docs:** README clarifies that the existing `cis-vmware-esxi-8.0-subset` and `vsphere-scg-v8` baselines successfully scan VCF 9.0 / 9.1 clusters — most rules carry over since they target host advanced settings and config that are stable across 8.x → 9.x. A small subset of rules may produce false negatives if a control's setting key changed in 9.0; users should treat those as informational until 9.0 baselines ship.
- **planned:** `cis-vmware-esxi-9.0` and `vsphere-scg-v9` baselines are tracked for a future release once CIS Benchmark v1.0 for ESXi 9.0 and the VMware Security Configuration Guide v9 are published.
- **docs:** Added `Official Broadcom References` pointer to [vSphere Security Configuration Guide](https://core.vmware.com/security/) and the [VCF Python SDK](https://developer.broadcom.com/sdks).
- **align:** Family v1.5.23 — all 9 skills tracking VCF 9.0 / 9.1 compatibility declaration.

## v1.5.22 (2026-05-08)

**Smithery onboarding** — `vmware-harden` is now installable via Smithery.

- **feat:** Added `Dockerfile` (Python 3.12-slim + uv) for containerized stdio MCP server.
- **feat:** Added `smithery.yaml` declaring stdio transport + config schema for the Smithery registry.
- **feat:** Added `mcp_server/__main__.py` so `python -m mcp_server` works inside the container.
- **align:** Tracks v1.5.22 family bump.

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
