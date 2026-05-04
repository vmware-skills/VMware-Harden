"""Baseline YAML loader.

Loads baseline definitions from YAML files into Pydantic models.
Built-in baselines live in `builtin/` next to this file.
"""
from pathlib import Path

import yaml

from vmware_harden.baselines.model import Baseline, ScriptCheck

BUILTIN_DIR = Path(__file__).parent / "builtin"


def load_baseline(path: Path | str) -> Baseline:
    """Parse a YAML file into a Baseline model.

    Raises:
        FileNotFoundError: if path does not exist
        pydantic.ValidationError: if YAML schema is invalid
        NotImplementedError: if any rule has a ScriptCheck (reserved for v2)
    """
    path = Path(path)
    with path.open() as f:
        raw = yaml.safe_load(f)
    baseline = Baseline(**raw)
    for rule in baseline.rules:
        if isinstance(rule.check, ScriptCheck):
            raise NotImplementedError(
                f"{path}: rule {rule.id!r} uses script check; "
                "script checks reserved for v2"
            )
    return baseline


def load_builtin(name: str) -> Baseline:
    """Load a built-in baseline by name (without `.yaml` suffix).

    Raises FileNotFoundError if no such built-in exists.
    """
    return load_baseline(BUILTIN_DIR / f"{name}.yaml")


def list_builtins() -> list[str]:
    """Return sorted names of all built-in baselines (without `.yaml` suffix)."""
    return sorted(p.stem for p in BUILTIN_DIR.glob("*.yaml"))
