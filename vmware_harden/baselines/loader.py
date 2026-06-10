"""Baseline YAML loader with extends merge + user dir discovery."""
from pathlib import Path

import yaml

from vmware_harden.baselines.model import Baseline, ScriptCheck

BUILTIN_DIR = Path(__file__).parent / "builtin"
USER_DIR = Path("~/.vmware-harden/baselines").expanduser()


def _merge_with_parent(child: Baseline, parent: Baseline) -> Baseline:
    """Child rules override parent rules by id; new child rules append.

    Metadata (id, name, version, source, applies_to) comes from child.
    Returns a new Baseline; neither input is mutated.
    """
    child_rule_ids = {r.id for r in child.rules}
    merged_rules = [r for r in parent.rules if r.id not in child_rule_ids]
    merged_rules.extend(child.rules)
    return child.model_copy(update={"rules": merged_rules})


def load_baseline(path: Path | str) -> Baseline:
    """Parse a YAML file into a Baseline model.

    If the YAML has `extends: <parent-id>`, the parent baseline is
    loaded (user dir first, then built-in directory) and rules are merged
    (child overrides parent by rule id).

    Raises:
        FileNotFoundError: path or extends parent does not exist
        pydantic.ValidationError: YAML schema invalid
        NotImplementedError: any rule has a ScriptCheck (reserved for v2)
    """
    path = Path(path)
    with path.open() as f:
        raw = yaml.safe_load(f)
    baseline = Baseline(**raw)

    if baseline.extends:
        parent = load_builtin(baseline.extends)
        baseline = _merge_with_parent(baseline, parent)

    # ScriptCheck rejection — DEFERRED to v2.0 (tracked in RELEASE_NOTES "Known
    # limitations"). Implementing executable script checks requires a security
    # threat model (sandboxing arbitrary Python from baseline YAML) plus a
    # subprocess/AST-restricted executor. v1.0 limits checks to declarative SQL.
    for rule in baseline.rules:
        if isinstance(rule.check, ScriptCheck):
            raise NotImplementedError(
                f"{path}: rule {rule.id!r} uses script check; "
                "script checks reserved for v2 (see RELEASE_NOTES.md "
                "'Known limitations' for rationale and tracking)"
            )
    return baseline


def _resolve_baseline_path(name: str) -> Path:
    """User dir takes precedence over package builtin.

    ``name`` is an untrusted identifier (CLI arg, MCP param, or a YAML
    ``extends:`` value). Reject any path separators / traversal so it cannot
    escape the baseline directories and read arbitrary files.

    Raises FileNotFoundError if the baseline is not found in either location.
    """
    if not name or "/" in name or "\\" in name or name.startswith(".") or "\x00" in name:
        raise FileNotFoundError(
            f"Invalid baseline name {name!r}: must be a plain identifier "
            "(no path separators, leading dots, or null bytes)"
        )

    for base in (USER_DIR, BUILTIN_DIR):
        candidate = base / f"{name}.yaml"
        # Defence in depth: confirm the resolved path stays inside ``base``.
        try:
            candidate.resolve().relative_to(base.resolve())
        except ValueError:
            continue
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        f"Baseline {name!r} not found in {USER_DIR} or {BUILTIN_DIR}"
    )


def load_builtin(name: str) -> Baseline:
    """Load a baseline by name (without `.yaml` suffix).

    Searches user dir (~/.vmware-harden/baselines) first, then the
    package's built-in directory.
    """
    return load_baseline(_resolve_baseline_path(name))


def list_builtins() -> list[str]:
    """Return sorted names of all discoverable baselines.

    Includes both user dir (~/.vmware-harden/baselines) and package
    built-in directory; deduplicated by stem (user wins on collision).
    """
    names: set[str] = set()
    for base in (USER_DIR, BUILTIN_DIR):
        if not base.exists():
            continue
        for p in base.glob("*.yaml"):
            names.add(p.stem)
    return sorted(names)
