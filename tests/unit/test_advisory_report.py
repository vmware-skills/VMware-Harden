"""Advisory results in `vmware-harden report` (text / json / csv)."""

import csv
import io
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vmware_harden.advisories.baseline import advisory_baseline
from vmware_harden.checks.runner import CheckRunner
from vmware_harden.cli.main import app
from vmware_harden.cli.runner import run_report
from vmware_harden.store.twin import Twin


def _seed(tmp_path: Path) -> Path:
    db = tmp_path / "t.duckdb"
    twin = Twin(db)
    try:
        snap = twin.start_snapshot("v.lab")
        for node_id, attrs in [
            ("v.lab:esx-old", {"name": "esx-old", "esxi_version": "8.0.3", "esxi_build": 24280767}),
            ("v.lab:esx-x", {"name": "esx-x", "esxi_version": "8.0.3", "esxi_build": "N/A"}),
        ]:
            twin.conn.execute(
                "INSERT INTO nodes (id, type, target, name, attrs) "
                "VALUES (?, 'host', 'v.lab', ?, ?)",
                [node_id, attrs["name"], json.dumps(attrs)],
            )
            twin.write_node_state(snap, node_id, attrs)
        CheckRunner(twin).run_baseline(snap, advisory_baseline())
        twin.finish_snapshot(snap)
    finally:
        twin.close()
    return db


def test_text_report_names_the_fix_and_kev(tmp_path, capsys):
    run_report(db=str(_seed(tmp_path)), format="text")
    out = capsys.readouterr().out
    assert "VMSA-2025-0004" in out
    assert "ESXi 8.0 Update 3d" in out
    assert "KEV" in out


def test_text_report_gives_the_reason_without_claiming_data_was_missing(tmp_path, capsys):
    run_report(db=str(_seed(tmp_path)), format="text")
    out = capsys.readouterr().out
    assert "(data missing)" not in out
    assert "version or build could not be read" in out


def test_csv_report_has_one_row_per_violation_with_advisory_columns(tmp_path, capsys):
    run_report(db=str(_seed(tmp_path)), format="csv")
    rows = list(csv.DictReader(io.StringIO(capsys.readouterr().out)))
    hit = [r for r in rows if r["rule"] == "VMSA-2025-0004" and r["status"] == "affected"]
    assert len(hit) == 1
    r = hit[0]
    assert r["node_name"] == "esx-old"
    assert r["fixed_in"] == "ESXi 8.0 Update 3d"
    assert r["kev"] == "true"
    assert r["build"] == "24280767"
    assert "CVE-2025-22224" in r["cves"]
    assert r["catalog_as_of"]


def test_csv_report_carries_the_unknowns_not_only_violations(tmp_path, capsys):
    run_report(db=str(_seed(tmp_path)), format="csv")
    rows = list(csv.DictReader(io.StringIO(capsys.readouterr().out)))
    unknown = [r for r in rows if r["status"] == "unknown" and r["node"] == "v.lab:esx-x"]
    assert unknown, rows
    assert "could not be read" in unknown[0]["reason"]
    # VMSA-2024-0019 covers only vCenter, none was collected: undetermined row.
    assert any(r["status"] == "undetermined" and r["rule"] == "VMSA-2024-0019" for r in rows)


def test_csv_neutralises_formula_injection(tmp_path, capsys):
    from vmware_harden.cli.runner import _csv_safe

    assert _csv_safe("=HYPERLINK(1)") == "'=HYPERLINK(1)"
    assert _csv_safe("@x") == "'@x"
    assert _csv_safe("esx-01") == "esx-01"


def test_unknown_format_is_refused_not_silently_text(tmp_path):
    db = _seed(tmp_path)
    result = CliRunner().invoke(app, ["report", "--db", str(db), "--format", "xml"])
    assert result.exit_code == 2
    assert "text, json or csv" in result.output


@pytest.mark.parametrize("fmt", ["json", "csv"])
def test_machine_formats_still_emit_when_there_are_no_advisory_rows(tmp_path, capsys, fmt):
    db = tmp_path / "empty.duckdb"
    twin = Twin(db)
    snap = twin.start_snapshot("v.lab")
    twin.finish_snapshot(snap)
    twin.close()
    run_report(db=str(db), format=fmt)
    assert capsys.readouterr().out.strip()
