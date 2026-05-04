# vmware-harden

<!-- mcp-name: io.github.zw008/vmware-harden -->

> **Disclaimer**: Community-maintained open-source project. **Not affiliated with, endorsed by, or sponsored by VMware, Inc. or Broadcom Inc.** "VMware", "vSphere", "ESXi", and "NSX" are trademarks of Broadcom. Source code is publicly auditable at [github.com/zw008/VMware-Harden](https://github.com/zw008/VMware-Harden) under the MIT license.

AI-native VMware compliance and baseline enforcement. Sibling to the `vmware-*` skill family.

## v1.5.15 — GA family member

Production-ready compliance platform with **4 built-in baselines** (CIS ESXi, vSphere SCG v8, **等保 2.0 三级**, PCI-DSS 4.0), **65 rules**, multi-vCenter Twin, drift detection, **LLM Remediation Advisor**, **MCP server** with 6 audited tools, and a 3-page web dashboard.

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

## Built-in baselines

| Baseline | Rules | Applies to | Source |
|----------|-------|-----------|--------|
| `cis-vmware-esxi-8.0-subset` | 20 | host | CIS Benchmark v1.0 |
| `vsphere-scg-v8-subset` | 15 | host, vm | [VMware vcf-security-and-compliance-guidelines](https://github.com/vmware/vcf-security-and-compliance-guidelines) |
| `dengbao-2.0-level3-vmware` | 20 | host, vm, datastore, dfw_rule | GB/T 22239-2019 三级 |
| `pci-dss-4.0-vmware` | 10 | host, dfw_rule | PCI-DSS v4.0 |

## Custom baselines

```bash
vmware-harden baseline validate ./my-strict.yaml
vmware-harden baseline import ./my-strict.yaml --name my-strict-cis
vmware-harden scan --target <vc> --baseline my-strict-cis
```

YAML supports `extends:` for inheriting from a built-in baseline. See `skills/vmware-harden/references/cli-reference.md`.

## MCP server

```bash
vmware-harden-mcp  # stdio MCP server
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

## Acceptance criteria for v1.0

- 189+ tests passing
- Bandit: 0 issues at any severity
- All 6 MCP tools audited
- SKILL.md ≤ 3000 words, family-convention compliant
- SECURITY.md with 6 elements + Broadcom disclaimer
- 4 built-in baselines

## References

- Design: parent monorepo `docs/plans/2026-05-03-vmware-harden-design.md`
- M1/M2/M3 plans: `docs/plans/2026-05-04-vmware-harden-{m1,m2,m3}-plan.md`
- Family CLAUDE.md: `/Users/zw/testany/myskills/CLAUDE.md`

## License

MIT
