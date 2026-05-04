"""Lab regression: real vCenter end-to-end scan.

These tests are skipped unless `VMWARE_HARDEN_LAB_TARGET` is set.
The target name must resolve via the user's vmware-aiops config:
    ~/.vmware-aiops/config.yaml
and credentials in:
    ~/.vmware-aiops/.env

Run manually:
    export VMWARE_HARDEN_LAB_TARGET=mylab-vc
    pytest tests/eval/regression -v -m lab
"""
import json
import os
from pathlib import Path

import pytest

from vmware_harden.cli.runner import run_report, run_scan

LAB_TARGET = os.getenv("VMWARE_HARDEN_LAB_TARGET")


@pytest.mark.lab
@pytest.mark.skipif(
    not LAB_TARGET,
    reason="set VMWARE_HARDEN_LAB_TARGET to enable lab regression",
)
def test_real_vcenter_scan_completes(tmp_path: Path, capsys):
    """Smoke: real vCenter inventory loads + baseline runs without exception."""
    db = str(tmp_path / "lab.duckdb")
    run_scan(
        target=LAB_TARGET,
        baseline="cis-vmware-esxi-8.0-subset",
        db=db,
    )
    out = capsys.readouterr().out
    assert "Collected" in out and "hosts" in out
    assert "Found" in out and "violations" in out


@pytest.mark.lab
@pytest.mark.skipif(
    not LAB_TARGET,
    reason="set VMWARE_HARDEN_LAB_TARGET to enable lab regression",
)
def test_real_vcenter_report_json_parses(tmp_path: Path, capsys):
    """Real-data JSON report must be parseable structured output."""
    db = str(tmp_path / "lab.duckdb")
    run_scan(
        target=LAB_TARGET,
        baseline="cis-vmware-esxi-8.0-subset",
        db=db,
    )
    capsys.readouterr()
    run_report(db=db, format="json")
    payload = json.loads(capsys.readouterr().out)
    assert isinstance(payload, list)
    # Each violation has the canonical fields
    for v in payload:
        assert "rule" in v
        assert "node" in v
        assert "severity" in v
