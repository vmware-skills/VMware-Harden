"""The collectors' production import path must actually exist.

Why this file exists
--------------------
Every collector fetches inventory through a lazy import inside ``_fetch_*``::

    def _fetch_hosts(target: str) -> list[dict]:
        from vmware_aiops.ops.host_inventory import list_hosts   # noqa
        return list_hosts(target)

Nothing in the repository ever executed that line. Three independent layers of
checking all reported green over it:

* Every collector test patches the seam
  (``patch("vmware_harden.collectors.hosts._fetch_hosts", ...)``), so the import
  never runs — 31 patch sites across 8 files.
* ``family_smoke.sh`` Check 2 calls ``importlib.import_module`` on each module.
  That executes module-level imports only; an import nested in a function body
  is invisible to it (the shape recorded as 踩坑 #27).
* ``doctor`` probes the top-level package (``import vmware_aiops``) and prints
  "ok" — it never touches the submodule the collector actually names, so it
  reports green even when the import is unresolvable.

The result: ``vmware_aiops.ops.host_inventory`` has been imported by this
package since the collectors were first committed, and that module has never
existed in any release of vmware-aiops. Same for
``vmware_aiops.ops.vm_inventory``, ``vmware_storage.ops.datastore_inventory``
and ``vmware_nsx_security.ops.dfw_inventory``.

The tests below are that missing check. They failed against the tree that
shipped the fabricated paths; v1.8.7 repointed those imports to real modules and
declared the distributions behind the ``collectors`` extra, so they now pass and
stand guard against a regression. The dynamic layer skips a collector whose
optional distribution is not installed (nothing to resolve against) but fails
loudly when the distribution IS present and the module path inside it is wrong —
the actual defect. The static declaration layer always runs.

Two layers, because the defect has two independent causes
---------------------------------------------------------
``TestEveryImportedDistributionIsDeclared`` is static and always runs: an
import that names a distribution absent from ``pyproject.toml`` can never
resolve on a clean install, whatever the module path says.

``TestCollectorFetchImportsResolve`` is dynamic: it performs the very import
the production path performs and asserts the module and symbol exist.

Neither hardcodes a list of collectors. The dynamic layer walks
``cli.runner._COLLECTOR_MAP`` — the same wiring ``run_scan`` dispatches on — so
a collector added to, or removed from, the product is added to, or removed
from, this test automatically. There is no second list to keep in sync.
"""

from __future__ import annotations

import ast
import importlib
import importlib.metadata
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
PKG_ROOT = REPO_ROOT / "vmware_harden"

#: Import name → distribution name, for the cases where they differ. Anything
#: absent here is normalised by the usual ``_`` → ``-`` rule.
_DIST_ALIASES = {"yaml": "pyyaml"}


def _declared_distributions() -> set[str]:
    """Every distribution this project declares, required or optional.

    Read from the built distribution metadata rather than by parsing
    ``pyproject.toml``. Two reasons: ``tomllib`` is 3.11+, while this project
    supports 3.10; and metadata is what a user actually receives, so this
    checks the artefact rather than the intent behind it. ``uv run`` re-syncs
    before invoking pytest, so it tracks edits to pyproject.

    Extras count as declared: a dependency behind ``[project.optional-
    dependencies]`` carries an ``extra == "..."`` marker here and is
    installable by name, which is all this check asks. One declared nowhere at
    all is not installable by anyone.
    """
    specs = importlib.metadata.requires("vmware-harden") or []
    names = set()
    for spec in specs:
        name = re.split(r"[<>=!~\[;\s(]", spec, maxsplit=1)[0].strip()
        if name:
            names.add(name.lower().replace("_", "-"))
    return names


def _distribution_for(import_name: str) -> str:
    top = import_name.split(".")[0]
    return _DIST_ALIASES.get(top, top.replace("_", "-"))


def _third_party_imports() -> dict[str, set[str]]:
    """Map distribution name → {"<file>:<module>"} for every import in the
    package, **including imports nested inside function bodies**.

    ``ast.walk`` is the point of this helper. Walking the module namespace
    instead — which is what the family smoke check does — cannot see a lazy
    import, and a lazy import is exactly where this defect lived.
    """
    sources = sorted(PKG_ROOT.rglob("*.py"))
    # A scan that silently found nothing would report green forever. Fail loudly
    # instead of vacuously passing (the "empty result reads as no problem" shape).
    assert sources, f"no Python sources found under {PKG_ROOT} — check the path"

    found: dict[str, set[str]] = {}
    for path in sources:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                # level > 0 is a relative import — always in-package.
                if node.level or not node.module:
                    continue
                modules = [node.module]
            else:
                continue
            for module in modules:
                top = module.split(".")[0]
                if top in sys.stdlib_module_names or top == "vmware_harden":
                    continue
                rel = path.relative_to(REPO_ROOT)
                found.setdefault(_distribution_for(module), set()).add(f"{rel}:{module}")
    return found


def _collector_modules() -> list[str]:
    """Distinct module names behind the runner's collector map.

    Derived from the production wiring rather than restated here: whatever
    ``run_scan`` can dispatch to is what gets checked.
    """
    from vmware_harden.cli.runner import _COLLECTOR_MAP

    assert _COLLECTOR_MAP, (
        "cli.runner._COLLECTOR_MAP is empty — run_scan can no longer collect "
        "anything. If the collectors were removed deliberately, this file "
        "should be removed with them and replaced by a check that no document "
        "still advertises live scanning."
    )
    return sorted({cls.__module__ for cls in _COLLECTOR_MAP.values()})


def _lazy_imports_in(module_name: str) -> list[tuple[str, tuple[str, ...]]]:
    """Every function-body ``from X import a, b`` in a module.

    Returns ``[(module, (symbol, ...)), ...]``. Module-level imports are
    excluded: those already execute under the existing import checks, so the
    interesting ones are precisely the deferred ones nothing has ever run.
    """
    path = REPO_ROOT / (module_name.replace(".", "/") + ".py")
    assert path.is_file(), f"cannot locate source for {module_name} at {path}"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    results: list[tuple[str, tuple[str, ...]]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for inner in ast.walk(node):
            if isinstance(inner, ast.ImportFrom) and inner.module and not inner.level:
                if inner.module.split(".")[0] == "vmware_harden":
                    continue
                results.append((inner.module, tuple(a.name for a in inner.names)))
    return results


@pytest.mark.unit
class TestEveryImportedDistributionIsDeclared:
    """A distribution the code imports but the project never declares cannot be
    installed by anyone who installs this package. It does not matter whether
    the module path inside it is right — the import cannot resolve at all.
    """

    def test_no_undeclared_distributions(self) -> None:
        declared = _declared_distributions()
        assert declared, "pyproject declares no dependencies at all — parse failure?"

        imported = _third_party_imports()
        assert imported, (
            "no third-party imports discovered in vmware_harden/ — the AST walk "
            "found nothing, which means it is not checking anything"
        )

        undeclared = {
            dist: sorted(sites)
            for dist, sites in imported.items()
            if dist not in declared
        }
        assert not undeclared, (
            "these distributions are imported by vmware_harden but appear in "
            "no Requires-Dist of the built vmware-harden metadata, so they are "
            "absent on a clean install and every import of them raises "
            "ModuleNotFoundError. Declare them under [project] dependencies "
            "(or optional-dependencies) in pyproject.toml:\n"
            + "\n".join(
                f"  {dist}\n" + "\n".join(f"      {s}" for s in sites)
                for dist, sites in sorted(undeclared.items())
            )
        )

    def test_a_known_good_dependency_is_recognised(self) -> None:
        """Positive control: the check must be capable of saying "declared".

        Without this, a bug that made every lookup miss would turn the test
        above into an unconditional failure, and one that made every lookup hit
        would turn it into an unconditional pass. vmware-policy is imported at
        module level and declared, so it must land on the declared side.
        """
        assert "vmware-policy" in _declared_distributions()
        assert "vmware-policy" in _third_party_imports()


@pytest.mark.unit
class TestCollectorFetchImportsResolve:
    """Execute the import the collector executes, and require it to work.

    This is the check whose absence let a fabricated module path ship: the unit
    tests patch ``_fetch_*`` wholesale, so the body — and the import inside it —
    never runs under test.
    """

    def test_collector_map_is_covered(self) -> None:
        """Guard against this file quietly checking nothing.

        Every collector the runner can dispatch to must contribute at least one
        lazy import to inspect. If a collector stops having one — inlined,
        renamed, moved — the discovery below would silently examine fewer
        targets, and a test that examines nothing passes.
        """
        modules = _collector_modules()
        assert modules, "no collector modules resolved from _COLLECTOR_MAP"
        for module_name in modules:
            assert _lazy_imports_in(module_name), (
                f"{module_name} contributes no function-body import for this "
                "test to verify; if the fetch was refactored, update the "
                "discovery so the real path is still exercised"
            )

    @pytest.mark.parametrize("module_name", _collector_modules())
    def test_fetch_import_target_exists(self, module_name: str) -> None:
        lazy = _lazy_imports_in(module_name)
        assert lazy, f"{module_name}: nothing to check"

        for target, symbols in lazy:
            try:
                module = importlib.import_module(target)
            except ModuleNotFoundError as exc:
                missing = exc.name or target
                if missing == target.split(".")[0]:
                    # The optional collector distribution is not installed here
                    # (it lives behind the ``collectors`` extra). Its
                    # *declaration* is already asserted by
                    # TestEveryImportedDistributionIsDeclared, which always runs;
                    # with the package absent there is nothing more this dynamic
                    # check can resolve, so skip rather than fail. CI and the
                    # release install ``.[collectors]`` and do exercise the real
                    # path below — a wrong module path is still caught there.
                    pytest.skip(
                        f"{missing!r} not installed — install the 'collectors' "
                        f"extra to verify {target!r} resolves"
                    )
                pytest.fail(
                    f"{module_name} imports {target!r}, which cannot be "
                    f"resolved: {missing!r} does not exist inside the installed "
                    "distribution — the module path is wrong, not merely "
                    "uninstalled. This import is on the production scan path and "
                    "is patched out in every unit test, so nothing else in the "
                    "suite would notice."
                )

            for symbol in symbols:
                assert hasattr(module, symbol), (
                    f"{module_name} imports {symbol!r} from {target!r}, but "
                    f"that module defines no such name. Available public "
                    f"names: {sorted(n for n in vars(module) if not n.startswith('_'))}"
                )
