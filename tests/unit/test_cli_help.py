"""CLI surface tests via Typer's CliRunner.

These verify the command tree is wired up correctly; deep behavior of
scan/report is tested in Task 10's integration tests.
"""
import pytest
from typer.testing import CliRunner

from vmware_harden.cli.main import app


runner = CliRunner()


@pytest.mark.unit
def test_root_help_lists_subcommands():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.stdout
    assert "report" in result.stdout
    assert "baseline" in result.stdout


@pytest.mark.unit
def test_baseline_list_runs():
    result = runner.invoke(app, ["baseline", "list"])
    assert result.exit_code == 0
    assert "cis-vmware-esxi-8.0-subset" in result.stdout


@pytest.mark.unit
def test_scan_help_runs():
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "target" in result.stdout.lower()
    assert "baseline" in result.stdout.lower()


@pytest.mark.unit
def test_report_help_runs():
    result = runner.invoke(app, ["report", "--help"])
    assert result.exit_code == 0


@pytest.mark.unit
def test_baseline_help_runs():
    result = runner.invoke(app, ["baseline", "--help"])
    assert result.exit_code == 0
    assert "list" in result.stdout
