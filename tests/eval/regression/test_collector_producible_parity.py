"""The collectors' declared output must match what their producers really build.

The whole contract rests on these frozensets. A baseline rule is allowed to read
an attribute because the vocabulary says it is ACTIVE; the vocabulary says so
because the attribute is in ``PRODUCIBLE_*_ATTRS``; and that set is hand-written.
Nothing checked it — adding ``"tools_running"`` to ``PRODUCIBLE_VM_ATTRS`` or
``"source"`` to the DFW set legalised the exact names this release repaired,
with a green suite.

Each collector's docstring already claims parity ("the keys ``list_vms`` builds
into each entry"). This makes the claim checkable.

The upstream packages are optional (``vmware-harden[collectors]``) and normally
absent from the test environment, so importing them is not an option — and a
test that skips exactly when the thing it guards is unverifiable is no guard at
all. Instead the sibling repositories are read from disk and their entry dicts
extracted with ``ast``: exact, and needing nothing installed. When a sibling is
missing the test skips with the path it looked for, so the reason is visible
rather than silent.
"""
import ast
from pathlib import Path

import pytest

from vmware_harden.collectors.datastores import PRODUCIBLE_DATASTORE_ATTRS
from vmware_harden.collectors.dfw import (
    PRODUCIBLE_DFW_RULE_ATTRS,
    PRODUCIBLE_DFW_SECTION_ATTRS,
)
from vmware_harden.collectors.hosts import PRODUCIBLE_HOST_ATTRS
from vmware_harden.collectors.vms import PRODUCIBLE_VM_ATTRS

#: Family layout: sibling skills sit next to this repo.
#: parents = regression / eval / tests / VMware-Harden / <family root>
_FAMILY = Path(__file__).resolve().parents[4]

#: ``(declared_set, sibling_repo, module_path, function, keys_the_collector_adds)``
#:
#: The last element is what the harden-side collector stamps on afterwards —
#: ``id`` from ``_shape_vm``, ``name`` from ``_shape_dfw`` — so it is legitimately
#: producible without appearing in the upstream literal.
_CASES = [
    pytest.param(
        PRODUCIBLE_VM_ATTRS, "VMware-AIops",
        "vmware_aiops/ops/inventory.py", "list_vms", {"id"},
        id="vm",
    ),
    pytest.param(
        PRODUCIBLE_DATASTORE_ATTRS, "VMware-Storage",
        "vmware_storage/ops/inventory.py", "list_datastores", {"id"},
        id="datastore",
    ),
    pytest.param(
        PRODUCIBLE_DFW_RULE_ATTRS, "VMware-NSX-Security",
        "vmware_nsx_security/ops/dfw_policy.py", "list_dfw_rules", {"name"},
        id="dfw_rule",
    ),
    pytest.param(
        PRODUCIBLE_DFW_SECTION_ATTRS, "VMware-NSX-Security",
        "vmware_nsx_security/ops/dfw_policy.py", "list_dfw_policies", {"name"},
        id="dfw_section",
    ),
]


def _entry_keys(source: Path, function: str) -> set[str]:
    """The string keys of the record ``function`` builds for each item.

    Takes the largest all-string-keyed dict literal in the function body — the
    per-entry record, distinguishable from the small envelope dicts around it.
    Parsed rather than pattern-matched, for the same reason rule SQL is: a
    regex over source would go stale against a formatting change without saying
    so.
    """
    tree = ast.parse(source.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == function:
            best: set[str] | None = None
            for inner in ast.walk(node):
                if not isinstance(inner, ast.Dict) or not inner.keys:
                    continue
                if not all(
                    isinstance(k, ast.Constant) and isinstance(k.value, str)
                    for k in inner.keys
                ):
                    continue
                keys = {k.value for k in inner.keys}
                if best is None or len(keys) > len(best):
                    best = keys
            if best is None:
                raise AssertionError(f"{function}: no record dict found in {source}")
            return best
    raise AssertionError(f"{function} not found in {source}")


@pytest.mark.unit
@pytest.mark.parametrize(("declared", "repo", "module", "function", "stamped"), _CASES)
def test_declared_output_matches_the_upstream_record(
    declared, repo, module, function, stamped
):
    source = _FAMILY / repo / module
    if not source.exists():
        pytest.skip(f"sibling repo not present: {source}")

    upstream = _entry_keys(source, function)
    expected = upstream | stamped

    missing = expected - set(declared)
    invented = set(declared) - expected
    assert not missing and not invented, (
        f"{function} and the collector's declared output disagree.\n"
        f"  produced upstream but not declared: {sorted(missing)}\n"
        f"  declared but never produced:        {sorted(invented)}\n"
        "A name in the second list can be marked ACTIVE in vocabulary.py and "
        "then read by a rule that matches nothing — the defect this release "
        "repaired, re-legalised."
    )


@pytest.mark.unit
def test_host_declared_output_matches_its_two_sources():
    """Hosts are the one collector that adds to its upstream record.

    ``list_hosts`` supplies the inventory keys; the STIG advanced settings come
    from a second ``OptionManager`` pass in this repo. Both halves are checked,
    so neither can grow a name nothing writes.
    """
    import types

    from vmware_harden.collectors.hosts import (
        _BASE_HOST_ATTRS,
        _SERVICE_TIME_ATTRS,
        STIG_ADVANCED_SETTING_ATTRS,
        _service_and_time_attrs,
    )

    source = _FAMILY / "VMware-AIops" / "vmware_aiops/ops/inventory.py"
    if not source.exists():
        pytest.skip(f"sibling repo not present: {source}")

    assert _entry_keys(source, "list_hosts") == set(_BASE_HOST_ATTRS)
    assert PRODUCIBLE_HOST_ATTRS == (
        set(_BASE_HOST_ATTRS)
        | set(STIG_ADVANCED_SETTING_ATTRS.values())
        | set(_SERVICE_TIME_ATTRS)
        | {"id"}
    )

    # The third source is checked by RUNNING it, not by trusting its declaration.
    # A key listed in _SERVICE_TIME_ATTRS that the reducer never emits would be a
    # name nothing writes — exactly what this file exists to prevent — and a
    # declaration compared only against itself could not catch it.
    everything = _service_and_time_attrs({
        "config.service": types.SimpleNamespace(service=[
            types.SimpleNamespace(key=k, running=True, policy="on")
            for k in ("ntpd", "TSM-SSH")
        ]),
        "config.dateTimeInfo": types.SimpleNamespace(
            ntpConfig=types.SimpleNamespace(server=["10.0.0.1"])
        ),
        "config.firewall": types.SimpleNamespace(
            defaultPolicy=types.SimpleNamespace(incomingBlocked=True)
        ),
    })
    assert set(everything) == set(_SERVICE_TIME_ATTRS), (
        f"declared vs emitted disagree: declared-only "
        f"{set(_SERVICE_TIME_ATTRS) - set(everything)}, emitted-only "
        f"{set(everything) - set(_SERVICE_TIME_ATTRS)}"
    )


@pytest.mark.unit
def test_the_parity_cases_cover_every_declared_set():
    """A collector added later must not sit outside this check unnoticed."""
    covered = {id(case.values[0]) for case in _CASES} | {id(PRODUCIBLE_HOST_ATTRS)}
    every = {
        id(s) for s in (
            PRODUCIBLE_HOST_ATTRS, PRODUCIBLE_VM_ATTRS, PRODUCIBLE_DATASTORE_ATTRS,
            PRODUCIBLE_DFW_RULE_ATTRS, PRODUCIBLE_DFW_SECTION_ATTRS,
        )
    }
    assert covered == every
