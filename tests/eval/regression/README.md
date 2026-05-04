# Lab Regression Tests

These tests exercise vmware-harden against a real VMware lab. They are
**skipped by default** so CI never tries to talk to a real vCenter.

## Prerequisites

1. `vmware-aiops` is installed and configured:
   - `~/.vmware-aiops/config.yaml` lists your vCenter target
   - `~/.vmware-aiops/.env` contains the password (chmod 600)

2. The target name from `vmware-aiops` config is exported:

   ```bash
   export VMWARE_HARDEN_LAB_TARGET=<name from your aiops config>
   ```

## Run

```bash
source .venv/bin/activate
pytest tests/eval/regression -v -m lab
```

If you don't set the env var, all tests in this directory are skipped.

## What to expect

- `test_real_vcenter_scan_completes` — proves the full pipeline talks to
  your vCenter and survives baseline evaluation.
- `test_real_vcenter_report_json_parses` — proves the JSON report output
  is well-formed against real data.

After a successful run, manually verify ≥ 1 violation in the report
matches reality (e.g., one of your test ESXi hosts genuinely has NTP
disabled). This is the hand-validation step that completes M1.
