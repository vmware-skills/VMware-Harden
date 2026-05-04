"""Baseline YAML loader with extends merge."""
from pathlib import Path

import yaml

from vmware_harden.baselines.model import Baseline, ScriptCheck

BUILTIN_DIR = Path(__file__).parent / "builtin"


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
    loaded from the built-in directory and rules are merged
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

    for rule in baseline.rules:
        if isinstance(rule.check, ScriptCheck):
            raise NotImplementedError(
                f"{path}: rule {rule.id!r} uses script check; "
                "script checks reserved for v2"
            )
    return baseline


def load_builtin(name: str) -> Baseline:
    """Load a built-in baseline by name (without `.yaml` suffix)."""
    return load_baseline(BUILTIN_DIR / f"{name}.yaml")


def list_builtins() -> list[str]:
    """Return sorted names of all built-in baselines."""
    return sorted(p.stem for p in BUILTIN_DIR.glob("*.yaml"))
