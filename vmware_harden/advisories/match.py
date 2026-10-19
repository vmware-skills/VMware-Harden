"""Judge one component's build against one advisory. Pure and offline.

The answer is one of five statuses, and only two of them say anything about
safety in either direction:

* ``affected``       — same line, on a branch the advisory fixes later, or the
                       line is listed with no fix at all
* ``fixed``          — same line and branch (or a later branch whose build is
                       past the newest fix), build at or past the fix
* ``not_affected``   — the advisory explicitly says so for this line
* ``not_applicable`` — the advisory does not cover this product at all
* ``unknown``        — everything else: unreadable version or build, a line the
                       advisory does not list, an end-of-life line, a branch
                       between two fixes, a later branch below the newest fix,
                       a branch the sources are uncertain about, a product the
                       advisory covers but this catalog does not carry

Build numbers are compared only inside one ``major.minor`` line: a 7.0 U3
patch can carry a larger build number than an 8.0 GA release.
"""

from dataclasses import dataclass

from vmware_harden.advisories.model import Advisory, Catalog

#: What a check reports when nothing can be said. Collected here so a reader of
#: the matcher sees every road to "unknown" in one place.
_UNREADABLE = "version or build could not be read"


@dataclass(frozen=True)
class Component:
    product: str
    version: object
    build: object


@dataclass(frozen=True)
class Verdict:
    status: str
    reason: str
    fixed_in: str | None = None


def parse_version(text: object) -> tuple[str, int] | None:
    """``"8.0.3"`` → ``("8.0", 3)``; anything unreadable → ``None``.

    A two-part version is update 0. A fourth part (vCenter's ``8.0.3.00500``)
    is ignored: the build number is what is compared.
    """
    if not isinstance(text, str):
        return None
    parts = text.strip().split(".")
    # ASCII digits only: str.isdigit() accepts "³" and "２", which int() then
    # rejects — an unreadable version must be unknown, not a crashed scan.
    if len(parts) < 2 or not all(p.isascii() and p.isdecimal() for p in parts[:3]):
        return None
    update = int(parts[2]) if len(parts) > 2 else 0
    return f"{int(parts[0])}.{int(parts[1])}", update


def _parse_build(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    if isinstance(value, str) and value.strip().isascii() and value.strip().isdecimal():
        n = int(value.strip())
        return n if n > 0 else None
    return None


def evaluate(component: Component, advisory: Advisory, catalog: Catalog) -> Verdict:
    """Return the verdict for ``component`` against ``advisory``."""
    if component.product not in advisory.products:
        return Verdict("not_applicable", f"{advisory.id} does not cover {component.product}")

    if component.product in advisory.uncatalogued_products:
        return Verdict(
            "unknown",
            f"{advisory.id} covers {component.product}, "
            f"but its {component.product} rows are not catalogued",
        )

    parsed = parse_version(component.version)
    build = _parse_build(component.build)
    if parsed is None or build is None:
        return Verdict("unknown", _UNREADABLE)
    line, update = parsed

    if any(n.product == component.product and n.line == line for n in advisory.not_affected):
        return Verdict(
            "not_affected", f"{advisory.id} states {component.product} {line} is not affected"
        )

    entry = next(
        (a for a in advisory.affected if a.product == component.product and a.line == line),
        None,
    )
    if entry is None:
        eol = catalog.eol.get(component.product, {}).get(line)
        if eol is not None and eol <= advisory.published:
            return Verdict(
                "unknown",
                f"{component.product} {line} reached end of general support on {eol}, "
                f"before {advisory.id} was published; the advisory does not list it",
            )
        return Verdict("unknown", f"{advisory.id} does not list {component.product} {line}")

    if not entry.fixed:
        return Verdict(
            "affected",
            f"{advisory.id} lists {component.product} {line} as affected with no fix available",
        )

    if update in entry.unknown_updates:
        return Verdict(
            "unknown",
            f"sources are uncertain whether {component.product} {line} "
            f"update {update} carries the {advisory.id} fix",
        )

    fixes = sorted(entry.fixed, key=lambda f: f.update)
    same = next((f for f in fixes if f.update == update), None)
    if same is not None:
        if build >= same.build:
            return Verdict(
                "fixed", f"build {build} is at or past {same.label} ({same.build})", same.label
            )
        return Verdict(
            "affected", f"build {build} is below {same.label} ({same.build})", same.label
        )

    if update < fixes[0].update:
        first = fixes[0]
        return Verdict(
            "affected",
            f"update {update} is older than every fixed update; "
            f"first fix is {first.label} ({first.build})",
            first.label,
        )

    newest = fixes[-1]
    if update > newest.update:
        if build >= newest.build:
            return Verdict(
                "fixed",
                f"later update, build {build} is past {newest.label} ({newest.build})",
                newest.label,
            )
        return Verdict(
            "unknown",
            f"update {update} is newer than every listed fix but build {build} "
            f"is below {newest.label} ({newest.build})",
            newest.label,
        )

    return Verdict(
        "unknown",
        f"update {update} has no fix of its own listed in {advisory.id}",
    )
