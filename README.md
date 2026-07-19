<!-- mcp-name: io.github.zw008/vmware-harden -->

# vmware-harden

<!-- mcp-name: io.github.zw008/vmware-harden -->

> **Disclaimer**: Community-maintained open-source project. **Not affiliated with, endorsed by, or sponsored by VMware, Inc. or Broadcom Inc.** "VMware", "vSphere", "ESXi", and "NSX" are trademarks of Broadcom. Source code is publicly auditable at [github.com/zw008/VMware-Harden](https://github.com/zw008/VMware-Harden) under the MIT license.

English | [中文](README-CN.md)

AI-native VMware compliance and baseline enforcement. Sibling to the `vmware-*` skill family.

- **Read-only against vSphere — and provable** (v1.8.0): all 6 MCP tools carry the `[READ]` marker and none mutate managed VMware infrastructure; `scan_target` writes only to the local twin DB (a cache of its own observations). With `VMWARE_READ_ONLY=true` the family read-only gate verifies that at startup instead of taking the docs' word for it, and the same variable strips write tools from every write-capable sibling. See [Read-only mode](#read-only-mode).

## GA family member (since v1.5.18)

Production-ready compliance platform with **8 built-in baselines** (CIS ESXi 8.0 + 9.0, vSphere SCG v8 + v9, **等保 2.0 三级**, PCI-DSS 4.0, **EU NIS2**, **BSI IT-Grundschutz**) carrying **87 rules**, multi-vCenter Twin, drift detection, **LLM Remediation Advisor**, **MCP server** with 6 audited tools, web dashboard, and `vmware-harden doctor` environment diagnostics.

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

## Read-Only Mode

vmware-harden is read-only by design — all 6 MCP tools carry the `[READ]` marker, and
`scan_target` writes only to the local twin DB (a cache of observations, not managed
infrastructure). Since v1.8.0 that is **provable rather than merely documented**: set
`VMWARE_READ_ONLY=true` and the family read-only gate enumerates the registry at
startup and verifies that zero write tools are exposed — structural, not a prompt
instruction. **Off by default.** Fail-closed: if the mode is requested but cannot be
guaranteed, the server refuses to start rather than running open.

The same variable is family-wide: one env var also strips every write tool from the
write-capable siblings (aiops, storage, vks, nsx, ...), so a whole-estate audit posture
is a single setting.

```json
{
  "mcpServers": {
    "vmware-harden": {
      "command": "vmware-harden",
      "args": ["mcp"],
      "env": {
        "VMWARE_READ_ONLY": "true"
      }
    }
  }
}
```

- **Per-skill override**: `VMWARE_HARDEN_READ_ONLY` beats the family-wide `VMWARE_READ_ONLY`. vmware-harden has no config.yaml, so the env vars are the only switch. Precedence: per-skill env → family env → off.
- **Startup log**: nothing is logged as withheld because nothing is — the gate's empty result *is* the assertion (write-capable siblings log `Read-only mode active ... withheld N write tool(s)` instead).

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

`baseline list` returns 8 IDs: the 6 rule-bearing baselines above (87 rules total) plus the
two v9 aliases, which carry no rules of their own and resolve to their v8 parent's.

### VCF 9.0 / 9.1 Compatibility

The existing baselines (`cis-vmware-esxi-8.0-subset`, `vsphere-scg-v8`, `dengbao-2.0-level3-vmware`, `pci-dss-4.0-vmware`) scan VCF 9.0 / 9.1 clusters successfully — most rules target host advanced settings stable across 8.x → 9.x. `cis-vmware-esxi-9.0-subset` and `vsphere-scg-v9-subset` ship today as `extends:` aliases of their v8 parents — same rules, a v9-named ID to scan and report under. Rules specific to 9.x will be added to them as Broadcom publishes the v9 guides.

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

Configure your MCP client with one of `examples/mcp-configs/*.json`. 6 read-only tools: `list_baselines`, `list_violations`, `get_remediation`, `list_drift_events`, `get_baseline_rules`, `scan_target`.

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
- All 6 MCP tools audited
- SKILL.md ≤ 3000 words, family-convention compliant
- SECURITY.md with 6 elements + Broadcom disclaimer
- 8 built-in baselines (87 rules across 6 rule-bearing sets + 2 v9 aliases)
- `vmware-harden doctor` for environment diagnostics
- GA member of vmware-* family (version-aligned at 1.5.28)

## References

- Family CLAUDE.md: `CLAUDE.md` at the monorepo root

## License

MIT