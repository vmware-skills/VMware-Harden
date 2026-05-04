"""Tests for user-dir baseline discovery."""
import textwrap
from pathlib import Path

import pytest

from vmware_harden.baselines import loader


@pytest.mark.unit
def test_list_builtins_includes_user_dir(tmp_path: Path, monkeypatch):
    user_dir = tmp_path / "user-baselines"
    user_dir.mkdir()
    (user_dir / "my-custom.yaml").write_text(textwrap.dedent("""
        id: my-custom
        name: My Custom
        version: 1.0.0
        applies_to: [host]
        rules: []
    """).strip())

    monkeypatch.setattr(loader, "USER_DIR", user_dir)

    names = loader.list_builtins()
    assert "my-custom" in names
    assert "cis-vmware-esxi-8.0-subset" in names  # built-ins still present


@pytest.mark.unit
def test_load_builtin_finds_user_baseline(tmp_path: Path, monkeypatch):
    user_dir = tmp_path / "user-baselines"
    user_dir.mkdir()
    (user_dir / "my-custom.yaml").write_text(textwrap.dedent("""
        id: my-custom
        name: My Custom
        version: 1.0.0
        applies_to: [host]
        rules: []
    """).strip())

    monkeypatch.setattr(loader, "USER_DIR", user_dir)

    b = loader.load_builtin("my-custom")
    assert b.id == "my-custom"


@pytest.mark.unit
def test_user_dir_overrides_builtin(tmp_path: Path, monkeypatch):
    """User dir baseline with same name as built-in takes precedence."""
    user_dir = tmp_path / "user"
    user_dir.mkdir()
    (user_dir / "cis-vmware-esxi-8.0-subset.yaml").write_text(textwrap.dedent("""
        id: cis-vmware-esxi-8.0-subset
        name: USER OVERRIDE
        version: 9.9.9
        applies_to: [host]
        rules: []
    """).strip())

    monkeypatch.setattr(loader, "USER_DIR", user_dir)

    b = loader.load_builtin("cis-vmware-esxi-8.0-subset")
    assert b.name == "USER OVERRIDE"
    assert len(b.rules) == 0  # user version, not the 20-rule built-in
