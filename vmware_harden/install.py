"""The install commands this package tells users to run.

One module, because the same instruction is printed from four places (the
doctor's module checks, the doctor's scan-target check, the collector
dependency error a scan raises, and the pilot client) and every one of them was
wrong in the same way: they named the missing sibling package.

    vmware-aiops not installed — install it with `uv tool install vmware-aiops`

A tester on real hardware ran exactly that, and the scan failed again,
identically (2026-08-30). ``uv tool install`` gives every tool its own isolated
environment; installing vmware-aiops builds a second environment containing
vmware-aiops, while harden keeps importing from the first. The only command
that changes what harden can import is one that names **vmware-harden**:

    uv tool install "vmware-harden[collectors]"

which upgrades an existing install in place — no ``--force`` needed (verified
in a sandboxed ``UV_TOOL_DIR``, 2026-08-30).

Keeping the strings here rather than at each site is not tidiness: it is what
lets ``tests/eval/regression/test_install_remedies_reach_hardens_environment.py``
tie every printed remedy to the extras actually declared in pyproject.toml,
instead of to four independently-drifting sentences.
"""

#: Extras declared in pyproject.toml. Named here so a rename breaks the tests
#: that read pyproject rather than silently printing a command that installs
#: nothing.
COLLECTORS_EXTRA = "collectors"
REMEDIATION_EXTRA = "remediation"


def install_extra(extra: str) -> str:
    """The command that adds ``extra`` to harden's own environment."""
    return f'uv tool install "vmware-harden[{extra}]"'


#: Why naming the sibling package instead does nothing. Deliberately does not
#: quote the wrong command: this text is what a user copies from.
ISOLATION_NOTE = (
    "Installing it as a tool of its own puts it in a separate environment "
    "vmware-harden cannot import from."
)


def collector_remedy(what: str) -> str:
    """Remedy for a missing collector package. ``what`` names what it unlocks."""
    return f"not importable — run: {install_extra(COLLECTORS_EXTRA)} ({what}). {ISOLATION_NOTE}"


def remediation_remedy() -> str:
    """Remedy for the optional pilot dependency."""
    return (
        f"optional — `vmware-harden apply --pilot real` needs it: "
        f"{install_extra(REMEDIATION_EXTRA)}"
    )


def reinstall_remedy(reason: str) -> str:
    """Remedy when a *required* dependency is missing: the install is broken.

    Nothing to add — it should already be there — so the instruction is to
    rebuild harden's environment rather than to install the package beside it.
    """
    return (
        f"missing though required ({reason}) — repair the install with: "
        "uv tool install --force vmware-harden"
    )
