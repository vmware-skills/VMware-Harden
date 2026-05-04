# vmware-harden

AI-native VMware compliance and baseline enforcement. Sibling to the `vmware-*` skill family.

## Status

**M1 complete.** Local CLI scans a vCenter against the CIS VMware ESXi 8.0 baseline and reports violations.

M2 in progress: 4 baselines (incl. 等保 2.0 三级), custom YAML, drift detection, web dashboard.

## Quickstart

```bash
uv tool install vmware-harden
# Or in a dev clone:
uv venv && source .venv/bin/activate && uv pip install -e ".[dev]"

# List built-in baselines
vmware-harden baseline list

# Run a scan (requires vmware-aiops configured)
vmware-harden scan --target <vcenter-name>

# View violations
vmware-harden report
vmware-harden report --format json
```

## Built-in baselines

- `cis-vmware-esxi-8.0-subset` — 20 rules across time-sync / patching / logging / network / firewall / auth / encryption / misc

## Architecture

- DuckDB-backed Estate Digital Twin (`~/.vmware-harden/twin.duckdb`)
- Collectors lazy-import sibling vmware-* skills (no spawn overhead)
- Pydantic-validated baseline YAML
- All write operations deferred to vmware-pilot (M3+)

## Lab regression

Set `VMWARE_HARDEN_LAB_TARGET=<your-vc>` and run `pytest tests/eval/regression -v -m lab` to validate against a real vCenter.

## References

- Design: parent monorepo `docs/plans/2026-05-03-vmware-harden-design.md`
- M1 plan: parent monorepo `docs/plans/2026-05-04-vmware-harden-m1-plan.md`
- VMware official baseline source: https://github.com/vmware/vcf-security-and-compliance-guidelines

## License

MIT
