"""Regression: built-in baselines must always load cleanly."""
import pytest

from vmware_harden.baselines.loader import list_builtins, load_builtin


@pytest.mark.unit
def test_all_builtins_load_without_error():
    """Every shipped baseline parses + ScriptCheck-free."""
    for name in list_builtins():
        b = load_builtin(name)
        assert b.id == name
        assert b.applies_to
        assert b.rules
