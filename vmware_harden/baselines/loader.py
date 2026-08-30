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

    The file is read as UTF-8 explicitly. Letting ``open()`` pick the locale's
    codec is what killed 5 of 8 MCP tools on a cp936 (GBK) Windows host: all nine
    shipped baselines are undecodable as GBK, so every load raised
    ``UnicodeDecodeError`` — including the 等保 2.0 baseline, on the one locale
    that baseline exists to serve. Mojibake is the other half of the risk: many
    UTF-8 byte pairs *are* valid GBK, so a mis-decoded baseline can parse cleanly
    and carry corrupted rule titles into a compliance report.

    Raises:
        FileNotFoundError: path or extends parent does not exist
        UnicodeDecodeError: the file is not UTF-8
        pydantic.ValidationError: YAML schema invalid
        NotImplementedError: any rule has a ScriptCheck (reserved for v2)
    """
    path = Path(path)
    with path.open(encoding="utf-8") as f:
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
                "'Known limitations' for rationale and tracking). Remove that "
                "rule or convert its check to a declarative SQL check, then "
                f"verify with `vmware-harden baseline validate {path}`."
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
            "(no path separators, leading dots, or null bytes). Run "
            "list_baselines (or `vmware-harden baseline list`) and copy an "
            "exact id."
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
        f"Baseline {name!r} not found in {USER_DIR} or {BUILTIN_DIR}. Run "
        "list_baselines (or `vmware-harden baseline list`) and copy an exact "
        f"id, or add {name}.yaml to the user directory with "
        "`vmware-harden baseline import <file>`."
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

    This is *filename discovery*. It says nothing about whether any of those
    files can be parsed — see :func:`load_all_baselines` for that, and do not
    report a count from here as a number of working baselines.
    """
    names: set[str] = set()
    for base in (USER_DIR, BUILTIN_DIR):
        if not base.exists():
            continue
        for p in base.glob("*.yaml"):
            names.add(p.stem)
    return sorted(names)


def describe_load_failure(name: str, exc: BaseException) -> str:
    """One line an operator can act on, for a baseline that would not load.

    The encoding case gets its own wording: with ``encoding="utf-8"`` now forced,
    a ``UnicodeDecodeError`` means the *file* is not UTF-8, and "invalid YAML" is
    the wrong thing to send someone looking for.

    Collapsed to a single line — ``doctor`` prints one row per check, and a raw
    ``yaml.ParserError`` is five lines with the offending file quoted twice.
    """
    if isinstance(exc, UnicodeDecodeError):
        detail = f"not valid UTF-8 ({exc.reason} at byte {exc.start}) — re-save the file as UTF-8"
    elif isinstance(exc, NotImplementedError):
        detail = str(exc)
    else:
        detail = f"{type(exc).__name__}: {exc}"
    return f"{name}: {' '.join(detail.split())}"


def load_all_baselines() -> tuple[dict[str, Baseline], list[str]]:
    """Try to load every discoverable baseline.

    Returns ``(loaded_by_name, failure_descriptions)``. Nothing is raised: the
    caller is diagnosing, and one broken user baseline must not hide the eight
    working ones.

    This exists because ``doctor`` used to count the output of
    :func:`list_builtins` and report it as "N baselines loaded" — filenames it
    had never opened. On a cp936 host that read "9 loaded" while every tool that
    used a baseline was dying. A diagnostic may only report what it verified.
    """
    loaded: dict[str, Baseline] = {}
    failures: list[str] = []
    for name in list_builtins():
        try:
            loaded[name] = load_builtin(name)
        except Exception as exc:  # noqa: BLE001 — diagnosing, not executing
            failures.append(describe_load_failure(name, exc))
    return loaded, failures
