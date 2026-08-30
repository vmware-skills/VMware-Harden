"""Lab regression: real vCenter end-to-end scan.

These tests are skipped unless `VMWARE_HARDEN_LAB_TARGET` is set.
The target name must resolve via the user's vmware-aiops config:
    ~/.vmware-aiops/config.yaml
and credentials in:
    ~/.vmware-aiops/.env

Run manually:
    export VMWARE_HARDEN_LAB_TARGET=mylab-vc
    pytest tests/eval/regression -v -m lab

Both assertions below were stale, and stayed stale for as long as nobody had a
lab (2026-08-30: a tester with a real VCF 9.1 estate saw exactly these two
fail, and they failed identically on unmodified upstream code):

* the scan progress line reads "Collected 1 host entities" — the label comes
  from ``HostCollector.__name__``, so it is singular — while the test looked
  for "hosts";
* ``run_report(format="json")`` has emitted an object since the coverage work,
  ``{"violations": [...], "coverage": {...}}``, deliberately, so that a caller
  can tell "nothing was wrong" from "almost nothing was checked". The test
  still required a bare list.

Both are the same shape: a test that only runs where nobody looks stops being
checked, and then it is the *test* that is wrong when someone finally looks.
The assertions below now describe what the code does, and each says which
property it is protecting, so the next deliberate change updates them on
purpose rather than deleting them in confusion.
"""
import json
import os
import re
from pathlib import Path

import pytest
import typer

from vmware_harden.cli.runner import run_report, run_scan

LAB_TARGET = os.getenv("VMWARE_HARDEN_LAB_TARGET")


def _scan(db: str) -> None:
    """Run the lab scan the way `vmware-harden scan` runs it.

    ``progress=typer.echo`` is what the CLI passes. Without a sink ``run_scan``
    is silent by design — its other caller is the ``scan_target`` MCP tool,
    whose stdout carries JSON-RPC frames — so a lab test that wants to read the
    progress has to ask for it.
    """
    run_scan(
        target=LAB_TARGET,
        baseline="cis-vmware-esxi-8.0-subset",
        db=db,
        progress=typer.echo,
    )


@pytest.mark.lab
@pytest.mark.skipif(
    not LAB_TARGET,
    reason="set VMWARE_HARDEN_LAB_TARGET to enable lab regression",
)
def test_real_vcenter_scan_completes(tmp_path: Path, capsys):
    """Smoke: real vCenter inventory loads + baseline runs without exception."""
    _scan(str(tmp_path / "lab.duckdb"))
    out = capsys.readouterr().out

    collected = re.search(r"Collected (\d+) host entities", out)
    assert collected, f"no host collection line in scan output:\n{out}"
    assert int(collected.group(1)) > 0, (
        "the scan reported zero hosts against a real vCenter — a collector "
        f"that returns nothing is the failure this test exists to catch:\n{out}"
    )
    assert re.search(r"Found \d+ violations against ", out), out


@pytest.mark.lab
@pytest.mark.skipif(
    not LAB_TARGET,
    reason="set VMWARE_HARDEN_LAB_TARGET to enable lab regression",
)
def test_real_vcenter_report_json_parses(tmp_path: Path, capsys):
    """Real-data JSON report must be parseable structured output."""
    db = str(tmp_path / "lab.duckdb")
    _scan(db)
    capsys.readouterr()
    run_report(db=db, format="json")
    payload = json.loads(capsys.readouterr().out)

    # An object, not the bare list this used to be: a list gives a script no
    # way to tell "nothing was wrong" from "almost nothing was checked", since
    # both are []. Anything reading the top level as violations is reading the
    # pre-coverage shape.
    assert isinstance(payload, dict), type(payload)
    assert isinstance(payload["violations"], list)
    assert isinstance(payload["coverage"], dict)
    assert "complete" in payload["coverage"]

    for v in payload["violations"]:
        assert "rule" in v
        assert "node" in v
        assert "severity" in v
