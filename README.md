# vmware-harden

AI-native VMware compliance and baseline enforcement. Sibling to the `vmware-*` skill family.

## Status

**M2 complete.** Production-quality compliance platform with:

- **4 built-in baselines** — CIS ESXi 8.0, vSphere SCG v8, **等保 2.0 三级**, PCI-DSS 4.0 (65 rules total)
- **Custom baselines** — author your own YAML, extend any built-in via `extends:`
- **Multi-resource collectors** — host, VM, datastore, NSX DFW (sections + rules)
- **Drift detection** — config + inventory drift between snapshots, posture drift across baseline versions
- **Web dashboard** — compliance summary, violations list, drift timeline (FastAPI + HTMX + ECharts)

## Quickstart

```bash
uv tool install vmware-harden
# Or in a dev clone:
uv venv && source .venv/bin/activate && uv pip install -e ".[dev]"

# List built-in baselines
vmware-harden baseline list

# Run a scan (requires vmware-aiops/vmware-storage/vmware-nsx-security configured per baseline)
vmware-harden scan --target <vcenter-name> --baseline cis-vmware-esxi-8.0-subset

# Run with 等保 2.0 三级
vmware-harden scan --target <vcenter-name> --baseline dengbao-2.0-level3-vmware

# View violations + drift
vmware-harden report
vmware-harden drift
vmware-harden report --format json

# Custom baseline workflow
vmware-harden baseline validate ./my-strict.yaml
vmware-harden baseline import ./my-strict.yaml --name my-strict-cis
vmware-harden scan --target <vc> --baseline my-strict-cis

# Web dashboard
vmware-harden web --port 8080
# → http://127.0.0.1:8080/
```

## Built-in baselines

| Baseline | Rules | Applies to | Source |
|----------|-------|-----------|--------|
| `cis-vmware-esxi-8.0-subset` | 20 | host | CIS Benchmark v1.0 |
| `vsphere-scg-v8-subset` | 15 | host, vm | [VMware vcf-security-and-compliance-guidelines](https://github.com/vmware/vcf-security-and-compliance-guidelines) |
| `dengbao-2.0-level3-vmware` | 20 | host, vm, datastore, dfw_rule | GB/T 22239-2019 三级 |
| `pci-dss-4.0-vmware` | 10 | host, dfw_rule | PCI-DSS v4.0 (Reqs 1, 2, 7, 8, 10) |

## Architecture

- **Estate Digital Twin** — DuckDB single file at `~/.vmware-harden/twin.duckdb`. Multi-target safe (vCenter ID prefix on all node IDs).
- **Collectors** — lazy import sibling vmware-* skills; per-host transactions; typed errors.
- **Baseline schema** — Pydantic v2 models with strict (`extra="forbid"`) validation; `extends:` for inheritance; user-dir override of built-ins.
- **Drift** — pure diff function with optional persistence to `change_event` table; auto-runs after each scan against the prior snapshot.
- **Web** — FastAPI + Jinja2 + Tailwind/HTMX/ECharts CDN; reads the same Twin DB.

## Lab regression

```bash
export VMWARE_HARDEN_LAB_TARGET=<your-vc>
pytest tests/eval/regression -v -m lab
```

## Acceptance criteria (M2)

- 146+ tests passing (unit + integration)
- 4 built-in baselines, 65+ rules
- Multi-target Twin namespacing
- Custom baseline import + extends
- Drift detection (config + inventory + posture)
- 3-page web dashboard
- Bandit: 0 issues
- family_smoke: no regression

## References

- Design: parent monorepo `docs/plans/2026-05-03-vmware-harden-design.md`
- M1 plan: `docs/plans/2026-05-04-vmware-harden-m1-plan.md`
- M2 plan: `docs/plans/2026-05-04-vmware-harden-m2-plan.md`
- VMware official baseline source: https://github.com/vmware/vcf-security-and-compliance-guidelines

## License

MIT
