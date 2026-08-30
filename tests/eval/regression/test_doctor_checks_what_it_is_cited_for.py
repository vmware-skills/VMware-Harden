"""`vmware-harden doctor` must check the things it is offered as the remedy for.

Real-hardware finding, 2026-08-30. Seven places in this repo tell the user to
run `vmware-harden doctor` — several of them after a scan failed on
connectivity, credentials or a wrong target name. The doctor checked the Python
version, whether the Twin file exists, how many baselines loaded, five module
imports, an API key and a writable directory. It checked **no target, no
connectivity and no authentication**, and then printed "All checks passed".

That is a loop, not advice: the error tells you to run the diagnostic, the
diagnostic cannot see the failure, and it reports green. The same shape was
found in four other skills in the same round.

Note the indirection that makes it easy to miss: harden does not own the
credentials it scans with. It borrows vmware-aiops' ConnectionManager and its
``~/.vmware-aiops/config.yaml``, so "which vCenter will `vmware-harden scan
--target lab` actually reach, and will it get in?" is a question about a config
file this repo never opens.
"""

from __future__ import annotations

import sys
import types

import pytest

from vmware_harden import doctor as doc


def _fake_aiops(monkeypatch, targets, *, connect_error=None, version="9.1.0"):
    """Install a stand-in vmware_aiops whose config lists ``targets``."""
    target_objs = [types.SimpleNamespace(name=n) for n in targets]

    class _Mgr:
        def __init__(self, config=None):
            self._config = config

        @classmethod
        def from_config(cls, config=None):
            return cls(config)

        def connect(self, name=None):
            if connect_error is not None:
                raise connect_error
            return types.SimpleNamespace(
                content=types.SimpleNamespace(
                    about=types.SimpleNamespace(version=version)
                )
            )

        def disconnect_all(self):
            pass

    conn_mod = types.ModuleType("vmware_aiops.connection")
    conn_mod.ConnectionManager = _Mgr
    cfg_mod = types.ModuleType("vmware_aiops.config")
    cfg_mod.load_config = lambda: types.SimpleNamespace(
        targets=tuple(target_objs),
        default_target=target_objs[0] if target_objs else None,
    )
    root = types.ModuleType("vmware_aiops")

    for name, mod in (
        ("vmware_aiops", root),
        ("vmware_aiops.connection", conn_mod),
        ("vmware_aiops.config", cfg_mod),
    ):
        monkeypatch.setitem(sys.modules, name, mod)


def _by_name(results):
    return {r.name: r for r in results}


@pytest.mark.unit
def test_every_configured_target_is_authenticated_not_just_the_default(monkeypatch):
    """The second half of the finding.

    Four skills authenticated only the default target. A user with five targets
    and three wrong passwords got "All checks passed", then a failure on the
    next call, whose message sent them back to the doctor that had just cleared
    them.
    """
    _fake_aiops(monkeypatch, ["lab", "prod", "dr"])

    results = _by_name(doc.run_diagnostics())

    for name in ("lab", "prod", "dr"):
        row = results.get(f"Scan target ({name})")
        assert row is not None, f"{name} was never checked"
        assert row.status == "ok"
        assert "9.1.0" in row.detail


@pytest.mark.unit
def test_an_unreachable_target_is_an_error_not_a_pass(monkeypatch):
    _fake_aiops(monkeypatch, ["lab"], connect_error=OSError("Cannot complete login"))

    results = doc.run_diagnostics()
    row = _by_name(results)[ "Scan target (lab)"]

    assert row.status == "error"
    assert "Cannot complete login" in row.detail
    assert any(r.status == "error" for r in results), (
        "a doctor that finds a broken target and still exits 0 is the defect "
        "this test exists for"
    )


@pytest.mark.unit
def test_a_missing_collector_config_is_reported_not_skipped(monkeypatch):
    """Absent configuration must not read as a clean bill of health — the
    family's most repeated failure (CLAUDE.md 形态 #1)."""
    _fake_aiops(monkeypatch, [])

    row = _by_name(doc.run_diagnostics())["Scan targets"]

    assert row.status in ("warn", "error")
    assert "no target" in row.detail.lower()


@pytest.mark.unit
def test_without_vmware_aiops_the_doctor_says_it_could_not_check(monkeypatch):
    """The collector dependency is optional, so its absence is a legitimate
    state — but "could not check" and "checked, fine" must not look alike."""
    for name in ("vmware_aiops", "vmware_aiops.connection", "vmware_aiops.config"):
        monkeypatch.setitem(sys.modules, name, None)

    row = _by_name(doc.run_diagnostics())["Scan targets"]

    assert row.status in ("warn", "error")
    assert "not check" in row.detail.lower() or "unknown" in row.detail.lower()


@pytest.mark.unit
def test_naming_one_target_checks_only_that_one(monkeypatch):
    """`doctor --target prod` after a failure on prod should not spend a
    connection attempt, and a timeout, on every other vCenter."""
    _fake_aiops(monkeypatch, ["lab", "prod", "dr"])

    results = _by_name(doc.run_diagnostics(target="prod"))

    assert "Scan target (prod)" in results
    assert "Scan target (lab)" not in results
    assert "Scan target (dr)" not in results


@pytest.mark.unit
def test_an_unknown_target_name_lists_the_real_ones(monkeypatch):
    """The wrong-target-name case is one of the failures that cites the doctor,
    so the doctor has to be able to answer it."""
    _fake_aiops(monkeypatch, ["lab", "prod"])

    row = _by_name(doc.run_diagnostics(target="lba"))["Scan targets"]

    assert row.status == "error"
    assert "lab" in row.detail and "prod" in row.detail


@pytest.mark.unit
def test_the_pre_existing_checks_are_untouched(monkeypatch):
    """The control. A doctor that now only talks about targets would pass every
    test above and lose the checks that already worked."""
    _fake_aiops(monkeypatch, ["lab"])

    names = {r.name for r in doc.run_diagnostics()}

    assert {"Python version", "Twin DB", "Built-in baselines", "Audit DB dir"} <= names
