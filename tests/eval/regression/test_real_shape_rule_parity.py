"""Rules must judge correctly against the shapes collectors really emit.

Regression for the 2026-08-12 false-compliance defect (BACKLOG P0 [H-1]/[H-3]):
nine rules read ``nodes.attrs`` keys — or compared against value domains — that
no collector ever produces. A rule reading a key nobody writes matches zero rows,
so every node reports compliant regardless of its real configuration; a rule
comparing against the wrong value domain fires on every node instead.

The existing STIG parity test guards attribute *names* for one baseline. This
guards *behaviour* for the rules that were repaired: each is driven with a record
shaped exactly like its collector's real output, in both a compliant and a
violating configuration, and asserts on explicit rule ids. A rule that silently
stopped matching would pass a name-only check but fails here.

Fixture shapes are pinned to their upstream producers:
  host       vmware_harden.collectors.hosts     (-> vmware_aiops list_hosts)
  vm         vmware_harden.collectors.vms       (-> vmware_aiops list_vms)
  dfw_rule   vmware_harden.collectors.dfw       (-> vmware_nsx_security list_dfw_rules)

Full coverage of every baseline is design step 1 in
``design/LLD-harden-baseline-collector-contract.md``; this pins the repaired subset.
"""
import json
import re
from pathlib import Path

import pytest

from vmware_harden.baselines.loader import load_builtin
from vmware_harden.checks.runner import CheckRunner
from vmware_harden.store.twin import Twin

#: Where the shipped baselines live, for the source-level CAST check below.
_BUILTIN_DIR = Path(__file__).resolve().parents[3] / "vmware_harden" / "baselines" / "builtin"

#: Rules that flag an overly permissive ANY -> ANY firewall rule.
ANY_TO_ANY_RULES = [
    ("pci-dss-4.0-vmware", ["pci-r1-1"]),
    ("dengbao-2.0-level3-vmware", ["db-l3-net-2"]),
]

#: Rules that flag a missing default-deny catch-all (inverted NOT EXISTS form).
DEFAULT_DENY_RULES = [
    ("pci-dss-4.0-vmware", "pci-r1-2"),
    ("dengbao-2.0-level3-vmware", "db-l3-net-1"),
    ("eu-nis2-vmware", "nis2-net-1"),
]

#: Rules that flag a VM whose guest tools are not running.
VM_TOOLS_RULES = [
    ("vsphere-scg-v8-subset", "scg-vm-3"),
    ("dengbao-2.0-level3-vmware", "db-l3-vm-1"),
]


def _insert(twin: Twin, node_id: str, node_type: str, attrs: dict, snapshot_id: str) -> None:
    twin.conn.execute(
        "INSERT INTO nodes (id, type, target, name, attrs) VALUES (?, ?, 'v.lab', ?, ?)",
        [node_id, node_type, attrs.get("name", node_id), json.dumps(attrs)],
    )
    twin.write_node_state(snapshot_id, node_id, attrs)


def _dfw_rule(action: str = "ALLOW", sources=None, destinations=None) -> dict:
    """A row shaped like ``vmware_nsx_security.ops.dfw_policy.list_dfw_rules``.

    ``action`` is upper-case and source/destination are the *plural* list fields
    — the two mismatches that made the DFW rules non-functional.
    """
    return {
        "id": "r1", "display_name": "rule1", "name": "rule1",
        "action": action,
        "sources": ["ANY"] if sources is None else sources,
        "destinations": ["ANY"] if destinations is None else destinations,
        "services": ["ANY"], "scope": ["ANY"], "direction": "IN_OUT",
        "ip_protocol": "IPV4_IPV6", "disabled": False, "logged": True,
        "sequence_number": 10, "path": "/infra/domains/default/.../r1",
    }


def _host(**overrides) -> dict:
    """A row shaped like ``vmware_harden.collectors.hosts`` output."""
    rec = {"name": "esx01", "id": "esx01", "esxi_version": "8.0.3",
           "esxi_build": "24853646"}
    rec.update(overrides)
    return rec


def _vm(tools_status: str = "guestToolsRunning") -> dict:
    """A row shaped like ``vmware_aiops.ops.inventory.list_vms`` output."""
    return {"name": "web-01", "id": "564d-abcd", "uuid": "564d-abcd",
            "power_state": "poweredOn", "cpu": 4, "memory_mb": 8192,
            "guest_os": "Ubuntu 22.04", "ip_address": "10.0.0.5",
            "host": "esx01", "tools_status": tools_status}


def _fired(tmp_path: Path, baseline_id: str, nodes: list[tuple[str, str, dict]]) -> set[str]:
    twin = Twin(tmp_path / "t.duckdb")
    snap = twin.start_snapshot("v.lab")
    for node_id, node_type, attrs in nodes:
        _insert(twin, node_id, node_type, attrs, snap)
    violations = CheckRunner(twin).run_baseline(snap, load_builtin(baseline_id))
    return {v["rule_id"] for v in violations}


# --- DFW: plural sources/destinations fields ---------------------------------

@pytest.mark.unit
@pytest.mark.parametrize("baseline_id,rule_ids", ANY_TO_ANY_RULES)
def test_any_to_any_dfw_rule_is_detected(tmp_path: Path, baseline_id: str, rule_ids: list[str]):
    """An ANY->ANY rule must be flagged. Reading ``$.source`` (singular) matched
    nothing, so an entirely open firewall reported compliant."""
    fired = _fired(tmp_path, baseline_id,
                   [("r1", "dfw_rule", _dfw_rule(sources=["ANY"], destinations=["ANY"]))])
    assert fired & set(rule_ids), (
        f"{baseline_id}: ANY->ANY DFW rule did not trigger any of {rule_ids}; fired={fired}"
    )


@pytest.mark.unit
@pytest.mark.parametrize("baseline_id,rule_ids", ANY_TO_ANY_RULES)
def test_scoped_dfw_rule_is_not_flagged_as_any_to_any(
    tmp_path: Path, baseline_id: str, rule_ids: list[str]
):
    """A rule scoped to real groups must not be reported as overly permissive.

    Only the ANY->ANY rule ids are asserted on: a lone ALLOW rule legitimately
    trips the *default-deny* checks in the same baseline, which is correct
    behaviour and not what this test is about.
    """
    scoped = _dfw_rule(sources=["/infra/domains/default/groups/web"],
                       destinations=["/infra/domains/default/groups/db"])
    fired = _fired(tmp_path, baseline_id, [("r1", "dfw_rule", scoped)])
    assert not (fired & set(rule_ids)), (
        f"{baseline_id}: a scoped DFW rule was flagged as ANY->ANY: {fired & set(rule_ids)}"
    )


# --- DFW: upper-case action value domain -------------------------------------

@pytest.mark.unit
@pytest.mark.parametrize("baseline_id,rule_id", DEFAULT_DENY_RULES)
def test_uppercase_deny_action_satisfies_default_deny_check(
    tmp_path: Path, baseline_id: str, rule_id: str
):
    """NSX returns ``DROP``/``REJECT`` upper-case. Comparing against lower-case
    literals made the default-deny check fire even on estates that had one."""
    fired = _fired(tmp_path, baseline_id, [("r1", "dfw_rule", _dfw_rule(action="DROP"))])
    assert rule_id not in fired, (
        f"{baseline_id}: a DROP catch-all still tripped {rule_id} (missing default-deny)"
    )


@pytest.mark.unit
@pytest.mark.parametrize("baseline_id,rule_id", DEFAULT_DENY_RULES)
def test_allow_only_estate_still_reports_missing_default_deny(
    tmp_path: Path, baseline_id: str, rule_id: str
):
    """The inverse: with no deny rule anywhere the check must still fire, so the
    upper-case fix did not simply disable it."""
    fired = _fired(tmp_path, baseline_id, [("r1", "dfw_rule", _dfw_rule(action="ALLOW"))])
    assert rule_id in fired, f"{baseline_id}: an ALLOW-only estate did not trip {rule_id}"


# --- host: esxi_build ---------------------------------------------------------

@pytest.mark.unit
def test_outdated_esxi_build_is_detected(tmp_path: Path):
    """The collector emits ``esxi_build`` (a string); the rule read ``$.build``,
    so no host was ever judged out of date."""
    fired = _fired(tmp_path, "cis-vmware-esxi-8.0-subset",
                   [("h1", "host", _host(esxi_build="20000000"))])
    assert "cis-esxi-2.2.1" in fired


@pytest.mark.unit
def test_current_esxi_build_is_not_flagged(tmp_path: Path):
    fired = _fired(tmp_path, "cis-vmware-esxi-8.0-subset",
                   [("h1", "host", _host(esxi_build="24853646"))])
    assert "cis-esxi-2.2.1" not in fired


# --- vm: tools_status is an enum string, not a boolean ------------------------

@pytest.mark.unit
@pytest.mark.parametrize("baseline_id,rule_id", VM_TOOLS_RULES)
@pytest.mark.parametrize("status", ["guestToolsNotRunning", "N/A"])
def test_vm_without_running_tools_is_detected(
    tmp_path: Path, baseline_id: str, rule_id: str, status: str
):
    """``list_vms`` emits ``tools_status`` as a ``VirtualMachineToolsRunningStatus``
    string (or ``N/A`` when unknown) — never the boolean ``tools_running`` the
    rules used to cast."""
    fired = _fired(tmp_path, baseline_id, [("v1", "vm", _vm(status))])
    assert rule_id in fired, (
        f"{baseline_id}: VM with tools_status={status!r} did not trip {rule_id}"
    )


@pytest.mark.unit
@pytest.mark.parametrize("baseline_id,rule_id", VM_TOOLS_RULES)
def test_vm_with_running_tools_is_not_flagged(tmp_path: Path, baseline_id: str, rule_id: str):
    fired = _fired(tmp_path, baseline_id, [("v1", "vm", _vm("guestToolsRunning"))])
    assert rule_id not in fired, f"{baseline_id}: a VM with running tools tripped {rule_id}"


@pytest.mark.unit
def test_the_parametrised_rule_lists_are_populated():
    """Emptying a list turns its tests into silent skips, suite still green.

    This file is the only behavioural guard for the repaired rules; a fixture
    list that quietly becomes empty removes that guard without a red build
    (形态 #1).
    """
    assert ANY_TO_ANY_RULES
    assert DEFAULT_DENY_RULES
    assert VM_TOOLS_RULES


# --- one unreadable value must not take the scan down ------------------------

@pytest.mark.unit
def test_no_builtin_rule_uses_a_bare_cast():
    """A failed CAST aborts the whole query, and with it the scan.

    ``list_hosts`` returns the string ``"N/A"`` whenever a property is
    unavailable — a disconnected host, a permission gap — so
    ``CAST(json_extract_string(attrs, '$.esxi_build') AS BIGINT)`` is not a
    hypothetical failure. One such host ended the scan with a ConversionException
    and the snapshot marked failed: no report at all, for every other host too.

    ``TRY_CAST`` yields NULL instead, so the row simply does not match. Enforced
    across all baselines rather than fixed case by case, because the next rule
    author would reach for ``CAST`` again.
    """
    offenders = []
    for path in sorted(_BUILTIN_DIR.glob("*.yaml")):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"(?<!TRY_)\bCAST\s*\(", line):
                offenders.append(f"  {path.name}:{lineno} {line.strip()}")
    assert not offenders, (
        "Use TRY_CAST — a bare CAST on collector data aborts the scan when a "
        "value is not convertible:\n" + "\n".join(offenders)
    )


@pytest.mark.integration
def test_a_host_with_an_unreadable_build_does_not_abort_the_scan(tmp_path: Path):
    """The estate keeps its report when one host has an unusable value."""
    twin = Twin(tmp_path / "t.duckdb")
    snap = twin.start_snapshot("v.lab")
    _insert(twin, "h-ok", "host", {"name": "esx-ok", "esxi_build": "1"}, snap)
    _insert(twin, "h-bad", "host", {"name": "esx-bad", "esxi_build": "N/A"}, snap)

    violations = CheckRunner(twin).run_baseline(
        snap, load_builtin("cis-vmware-esxi-8.0-subset")
    )

    fired = {(v["rule_id"], v["node_id"]) for v in violations}
    assert ("cis-esxi-2.2.1", "h-ok") in fired      # outdated build still caught
    assert ("cis-esxi-2.2.1", "h-bad") not in fired  # unreadable, not judged
    twin.close()
