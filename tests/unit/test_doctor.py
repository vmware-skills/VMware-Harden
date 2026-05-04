"""Doctor diagnostics tests."""
import pytest
from typer.testing import CliRunner

from vmware_harden.cli.main import app
from vmware_harden.doctor import run_diagnostics


@pytest.mark.unit
def test_run_diagnostics_returns_list():
    results = run_diagnostics()
    assert len(results) >= 8
    assert all(hasattr(r, "name") and hasattr(r, "status") for r in results)


@pytest.mark.unit
def test_built_in_baselines_check_ok():
    results = run_diagnostics()
    bl = next(r for r in results if r.name == "Built-in baselines")
    assert bl.status == "ok"


@pytest.mark.unit
def test_python_version_check_ok():
    results = run_diagnostics()
    py = next(r for r in results if r.name == "Python version")
    assert py.status == "ok"


@pytest.mark.unit
def test_doctor_cli_runs():
    runner = CliRunner()
    result = runner.invoke(app, ["doctor"])
    assert "Python version" in result.output
    assert "Built-in baselines" in result.output


@pytest.mark.unit
def test_doctor_anthropic_key_status_reflects_env(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    results = run_diagnostics()
    key = next(r for r in results if r.name == "ANTHROPIC_API_KEY")
    assert key.status == "warn"

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    results = run_diagnostics()
    key = next(r for r in results if r.name == "ANTHROPIC_API_KEY")
    assert key.status == "ok"
