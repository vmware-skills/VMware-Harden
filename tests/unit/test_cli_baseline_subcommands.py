"""Tests for `baseline import` and `baseline validate` CLI subcommands."""
import textwrap
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vmware_harden.baselines import loader
from vmware_harden.cli.main import app

runner = CliRunner()


@pytest.fixture
def good_yaml(tmp_path: Path) -> Path:
    p = tmp_path / "good.yaml"
    p.write_text(textwrap.dedent("""
        id: good
        name: Good
        version: 1.0.0
        applies_to: [host]
        rules:
          - id: g1
            title: x
            severity: low
            category: x
            check: {type: query, sql: "SELECT 1"}
            remediation: {summary: y}
    """).strip(), encoding="utf-8")
    return p


@pytest.fixture
def bad_yaml(tmp_path: Path) -> Path:
    p = tmp_path / "bad.yaml"
    p.write_text(textwrap.dedent("""
        id: bad
        name: Bad
        version: 1.0.0
        applies_to: [host]
        rules:
          - id: r1
            title: x
            severity: bogus      # invalid
            category: x
            check: {type: query, sql: "SELECT 1"}
            remediation: {summary: y}
    """).strip(), encoding="utf-8")
    return p


@pytest.mark.unit
def test_validate_good_yaml_exits_zero(good_yaml: Path):
    result = runner.invoke(app, ["baseline", "validate", str(good_yaml)])
    assert result.exit_code == 0
    assert "OK" in result.stdout


@pytest.mark.unit
def test_validate_bad_yaml_exits_nonzero(bad_yaml: Path):
    result = runner.invoke(app, ["baseline", "validate", str(bad_yaml)])
    assert result.exit_code != 0
    # Error should mention the bad field
    combined = (result.stdout + (result.stderr or "")).lower()
    assert "severity" in combined or "bogus" in combined


@pytest.mark.unit
def test_import_copies_to_user_dir(good_yaml: Path, tmp_path: Path, monkeypatch):
    user_dir = tmp_path / "user"
    monkeypatch.setattr(loader, "USER_DIR", user_dir)

    result = runner.invoke(app, ["baseline", "import", str(good_yaml)])
    assert result.exit_code == 0
    assert (user_dir / "good.yaml").exists()
    # And it's now discoverable via load_builtin
    b = loader.load_builtin("good")
    assert b.id == "good"


@pytest.mark.unit
def test_import_with_name_override(good_yaml: Path, tmp_path: Path, monkeypatch):
    user_dir = tmp_path / "user"
    monkeypatch.setattr(loader, "USER_DIR", user_dir)

    result = runner.invoke(
        app,
        ["baseline", "import", str(good_yaml), "--name", "renamed-baseline"],
    )
    assert result.exit_code == 0
    assert (user_dir / "renamed-baseline.yaml").exists()


@pytest.mark.unit
def test_import_validates_before_copy(bad_yaml: Path, tmp_path: Path, monkeypatch):
    """Bad YAML must NOT be copied to user dir."""
    user_dir = tmp_path / "user"
    monkeypatch.setattr(loader, "USER_DIR", user_dir)

    result = runner.invoke(app, ["baseline", "import", str(bad_yaml)])
    assert result.exit_code != 0
    # Importantly: should not have left any file in user dir
    if user_dir.exists():
        assert not list(user_dir.glob("*.yaml"))
