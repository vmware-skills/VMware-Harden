<!-- mcp-name: io.github.vmware-skills/vmware-harden -->

# vmware-harden

<!-- mcp-name: io.github.vmware-skills/vmware-harden -->

> **Disclaimer**: Community-maintained open-source project. **Not affiliated with, endorsed by, or sponsored by VMware, Inc. or Broadcom Inc.** "VMware", "vSphere", "ESXi", and "NSX" are trademarks of Broadcom. Source code is publicly auditable at [github.com/vmware-skills/VMware-Harden](https://github.com/vmware-skills/VMware-Harden) under the MIT license.

English | [中文](README-CN.md)

AI-native VMware compliance and baseline enforcement. Sibling to the `vmware-*` skill family.

- **Read-only against vSphere**: all 8 MCP tools carry the `[READ]` marker and none mutate managed VMware infrastructure; `scan_target` writes only to the local twin DB (a cache of its own observations). See [Read-only by design](#read-only-by-design).

## GA family member (since v1.5.18)

Production-ready compliance platform with **9 built-in baselines** (CIS ESXi 8.0 + 9.0, vSphere SCG v8 + v9, **vSphere 9 STIG-aligned**, **等保 2.0 三级**, PCI-DSS 4.0, **EU NIS2**, **BSI IT-Grundschutz**) carrying **99 rules**, multi-vCenter Twin, drift detection, **LLM Remediation Advisor**, **MCP server** with 8 audited tools, web dashboard, and `vmware-harden doctor` environment diagnostics.

## Quickstart

```bash
uv tool install vmware-harden

# List built-in baselines
vmware-harden baseline list

# Run a scan
vmware-harden scan --target <vcenter-name> --baseline cis-vmware-esxi-8.0-subset

# Or use 等保 2.0 三级 (国内合规独家)
vmware-harden scan --target <vc> --baseline dengbao-2.0-level3-vmware

# View results
vmware-harden report
vmware-harden drift

# Generate remediation suggestions
export ANTHROPIC_API_KEY=...  # optional; falls back to mock without
vmware-harden advise --all-critical

# Web dashboard
vmware-harden web --port 8080  # → http://127.0.0.1:8080
```

### Offline / Air-Gapped Install (from source)

This project uses the modern PEP 517 build system (hatchling), so there is **no
`setup.py`** by design — that is expected, not a missing file. If you cloned the
source and hit `ERROR: File "setup.py" or "setup.cfg" not found ... editable mode
currently requires a setuptools-based build`, your `pip` is older than 21.3 and
cannot do an *editable* (`-e`) install with a non-setuptools backend. Editable
mode is a developer convenience, not needed to run the tool — do one of:

```bash
# From the source tree — a normal (non-editable) install builds a wheel:
pip install .              # NOT  pip install -e .

# ...or upgrade pip first, and editable works too:
pip install --upgrade pip && pip install -e .
```

For a **truly air-gapped host**, build the wheels on a connected machine and copy
them over — the target then needs no network:

```bash
# On a connected machine, collect this package + its dependencies as wheels:
pip wheel . -w dist        # → dist/*.whl   (or: uv build, for just this package)

# Copy dist/ to the air-gapped host, then install offline:
pip install --no-index --find-links dist vmware-harden
```

## Read-Only by Design

vmware-harden is read-only against vSphere and NSX — all 8 MCP tools carry the `[READ]`
marker, and none mutate managed VMware infrastructure. `scan_target` writes only to the
local twin DB (`~/.vmware-harden/twin.duckdb`), a cache of its own observations rather than
managed infrastructure. Remediation is never applied by this skill; it is deferred to
vmware-pilot, which provides approval gating and audit trails for write operations.

## Built-in baselines

| Baseline | Rules | Applies to | Source |
|----------|-------|-----------|--------|
| `cis-vmware-esxi-8.0-subset` | 20 | host | CIS Benchmark v1.0 |
| `vsphere-scg-v8-subset` | 15 | host, vm | [VMware vcf-security-and-compliance-guidelines](https://github.com/vmware/vcf-security-and-compliance-guidelines) |
| `dengbao-2.0-level3-vmware` | 20 | host, vm, datastore, dfw_rule | GB/T 22239-2019 三级 |
| `pci-dss-4.0-vmware` | 10 | host, dfw_rule | PCI-DSS v4.0 |
| `eu-nis2-vmware` | 12 | host, dfw_rule | EU NIS2 Directive (Articles 21/23, Annex I) |
| `bsi-itgs-basisabsicherung-vmware` | 10 | host | BSI IT-Grundschutz (OPS.1.1.4 + SYS.1.1) |
| `cis-vmware-esxi-9.0-subset` | 20 | host | Inherits `cis-vmware-esxi-8.0-subset` via `extends:` |
| `vsphere-scg-v9-subset` | 15 | host, vm | Inherits `vsphere-scg-v8-subset` via `extends:` |
| `vsphere-stig-v9-subset` ⚠️ *experimental* | 12 | host | vSphere 9 STIG-aligned host advanced settings ([DoD/DISA STIG content](https://github.com/vmware/dod-compliance-and-automation)) — collector pending real-hardware verification |

`baseline list` returns 9 IDs: the 7 rule-bearing baselines above (99 rules total) plus the
two v9 aliases, which carry no rules of their own and resolve to their v8 parent's.

### VCF 9.0 / 9.1 Compatibility

The existing baselines (`cis-vmware-esxi-8.0-subset`, `vsphere-scg-v8`, `dengbao-2.0-level3-vmware`, `pci-dss-4.0-vmware`) scan VCF 9.0 / 9.1 clusters successfully — most rules target host advanced settings stable across 8.x → 9.x. `cis-vmware-esxi-9.0-subset` and `vsphere-scg-v9-subset` ship today as `extends:` aliases of their v8 parents — same rules, a v9-named ID to scan and report under. Rules specific to 9.x will be added to them as Broadcom publishes the v9 guides.

`vsphere-stig-v9-subset` is a rule-bearing STIG-aligned baseline: 12 host advanced-setting controls (account lockout, password policy, DCUI access, shell/DCUI timeouts, MOB, guest BPDU, remote syslog) mapped to the official open-source vSphere STIG content (MITRE InSpec / Cinc Auditor). **Status: experimental — collector pending real-hardware verification.** Its checks read ESXi host advanced settings the host collector fetches via a `config.option` PropertyCollector pass, a path not yet verified end-to-end against a live vCenter/ESXi. Until it is, treat results as **non-authoritative**: an uncollected setting makes a rule match zero rows, so a host can report *compliant* on a data gap rather than a real pass. The baseline's `status` field is surfaced by `list_baselines` and `describe_stig_content_sync` so a scan self-declares this caveat. It is a **content sync**, not an API wrapper — VCF Operations 9.1 Automated Configuration Compliance (ACC) / Security Posture Management (SPM) is UI- and schedule-driven and exposes **no public compliance REST API**. For continuous, fleet-wide enforcement and automated remediation, use **VCF Operations SPM/ACC (UI)**; vmware-harden is the API-scriptable, DuckDB-persisted, cross-target point-in-time scanner. See [references/stig-content-sync.md](skills/vmware-harden/references/stig-content-sync.md) and inspect the catalog with `vmware-harden stig controls`.

#### Official Broadcom References

- **Security Configuration Guides**: <https://core.vmware.com/security/> — vSphere SCG v8 / future v9
- **SDKs**: <https://developer.broadcom.com/sdks> — VCF Python SDK (for fetching host config via REST)
- **CIS Benchmarks**: <https://www.cisecurity.org/cis-benchmarks/> — CIS VMware ESXi Benchmark v1.0 (8.0 / future 9.0)

## Custom baselines

```bash
vmware-harden baseline validate ./my-strict.yaml
vmware-harden baseline import ./my-strict.yaml --name my-strict-cis
vmware-harden scan --target <vc> --baseline my-strict-cis
```

YAML supports `extends:` for inheriting from a built-in baseline. See `skills/vmware-harden/references/cli-reference.md`.

## MCP server

```bash
vmware-harden mcp  # stdio MCP server (legacy alias: vmware-harden-mcp)
```

Configure your MCP client with one of `examples/mcp-configs/*.json`. 8 read-only tools: `list_baselines`, `get_baseline_rules`, `list_stig_controls`, `describe_stig_content_sync`, `list_violations`, `get_remediation`, `list_drift_events`, `scan_target`.

## Architecture

- **Estate Digital Twin** — DuckDB single file at `~/.vmware-harden/twin.duckdb`. Multi-target safe via target prefix on all node IDs.
- **Collectors** — lazy-import sibling vmware-* skills (no spawn overhead). All scans are READ; writes deferred to vmware-pilot.
- **Baseline schema** — Pydantic v2, strict (`extra="forbid"`), `extends:` inheritance, user-dir override.
- **Drift** — pure diff function with optional persistence; auto-runs after every scan.
- **Advisor** — LLM-driven Suggestion generation; Anthropic provider with prompt caching; mock fallback for tests / no-API-key environments.
- **Audit** — every MCP tool wrapped with `@vmware_tool` from family vmware-policy.
- **Web** — FastAPI + Jinja2 + Tailwind/HTMX/ECharts CDN.

## Lab regression

```bash
export VMWARE_HARDEN_LAB_TARGET=<your-vc>
pytest tests/eval/regression -v -m lab
```

## Family

- **vmware-aiops** — host inventory + ops (used by harden's HostCollector)
- **vmware-monitor** — read-only counterpart
- **vmware-storage** — datastore inventory
- **vmware-nsx-security** — DFW inventory
- **vmware-pilot** — execute remediations (writes; out of scope for harden)
- **vmware-policy** — `@vmware_tool` audit decorator

## Acceptance criteria (v1.5.18 GA)

- 221 tests passing
- Bandit: 0 issues at any severity
- All 8 MCP tools audited
- SKILL.md ≤ 3000 words, family-convention compliant
- SECURITY.md with 6 elements + Broadcom disclaimer
- 9 built-in baselines (99 rules across 7 rule-bearing sets + 2 v9 aliases)
- `vmware-harden doctor` for environment diagnostics
- GA member of vmware-* family (version-aligned at 1.5.28)

## References

- Family CLAUDE.md: `CLAUDE.md` at the monorepo root

## License

MIT