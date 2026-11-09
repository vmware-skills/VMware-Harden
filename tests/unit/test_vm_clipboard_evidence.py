"""Explicit VMRC configuration is a fact; missing settings are not a pass."""

from types import SimpleNamespace

import pytest

from vmware_harden.baselines.loader import load_builtin
from vmware_harden.checks.runner import CheckRunner
from vmware_harden.collectors import vms
from vmware_harden.store.twin import Twin

COPY = "isolation.tools.copy.disable"
PASTE = "isolation.tools.paste.disable"


def props(*options, state="connected"):
    return {
        "runtime.connectionState": state,
        "config.extraConfig": [SimpleNamespace(key=k, value=v) for k, v in options],
    }


@pytest.mark.parametrize(
    "copy,paste,expected",
    [
        (True, True, True),
        ("TRUE", " true ", True),
        (False, True, False),
        (True, "FALSE", False),
        (False, False, False),
        (False, None, False),
        (None, False, False),
        (True, None, None),
        (None, True, None),
        (None, None, None),
        ("yes", True, None),
        (1, True, None),
        (True, "1", None),
    ],
)
def test_three_valued_clipboard_configuration(copy, paste, expected):
    settings = [(key, val) for key, val in ((COPY, copy), (PASTE, paste)) if val is not None]
    actual = vms._vm_security_attrs(props(*settings))
    if expected is None:
        assert "isolation_copy_disabled" not in actual
    else:
        assert actual["isolation_copy_disabled"] is expected


def test_duplicate_settings_are_unknown_and_unrelated_secrets_are_discarded():
    assert "isolation_copy_disabled" not in vms._vm_security_attrs(
        props((COPY, True), (COPY, False), (PASTE, True))
    )
    actual = vms._vm_security_attrs(
        props((COPY, True), (PASTE, True), ("guestinfo.password", "opaque-private-secret"))
    )
    assert actual == {"isolation_copy_disabled": True}
    assert "opaque-private-secret" not in str(actual)


def test_disconnected_vm_has_no_measured_clipboard_fact():
    assert vms._vm_security_attrs(props((COPY, True), (PASTE, True), state="disconnected")) == {}


@pytest.mark.parametrize(
    "options,violations,gaps",
    [
        ([(COPY, True), (PASTE, True)], 0, 0),
        ([(COPY, False), (PASTE, True)], 1, 0),
        ([], 0, 1),
    ],
)
def test_collector_to_rule_pipeline_distinguishes_clean_violation_and_gap(
    tmp_path, monkeypatch, options, violations, gaps
):
    monkeypatch.setattr(
        vms,
        "_fetch_vms",
        lambda target: [
            {
                "id": "vm-1",
                "name": "app",
                **vms._vm_security_attrs(
                    props(*options, ("guestinfo.password", "opaque-private-secret"))
                ),
            }
        ],
    )
    baseline = load_builtin("vsphere-scg-v8-subset")
    rule = next(r for r in baseline.rules if r.id == "scg-vm-5")
    baseline = baseline.model_copy(update={"rules": [rule]})
    twin = Twin(tmp_path / "clipboard.duckdb")
    try:
        snapshot = twin.start_snapshot("synthetic")
        vms.VMCollector(twin).collect(snapshot, "synthetic")
        found = CheckRunner(twin).run_baseline(snapshot, baseline)
        assert len(found) == violations
        assert twin.conn.execute("SELECT COUNT(*) FROM rule_node_gap").fetchone()[0] == gaps
        outcome = twin.conn.execute("SELECT outcome FROM rule_outcome").fetchone()[0]
        assert outcome == "evaluated"
        persisted = twin.conn.execute("SELECT attrs FROM nodes").fetchall()
        assert "opaque-private-secret" not in str(persisted)
    finally:
        twin.close()


def test_real_sdk_option_value_array_is_supported():
    pytest.importorskip("pyVmomi")
    from pyVmomi import vim

    options = vim.option.OptionValue.Array([
        vim.option.OptionValue(key=COPY, value="TRUE"),
        vim.option.OptionValue(key=PASTE, value=True),
    ])
    actual = vms._vm_security_attrs({
        "runtime.connectionState": "connected", "config.extraConfig": options})
    assert actual == {"isolation_copy_disabled": True}
