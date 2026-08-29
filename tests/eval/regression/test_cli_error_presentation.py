"""Harden's teaching messages must reach the user as sentences, not tracebacks.

Found live, 2026-08-29. `vmware-harden scan --target home-vcenter --baseline
cis-vmware-esxi-8.0-subset` on a host without the collector dependency printed a
Rich traceback with source lines, and the actual message — which is a good one —
arrived underneath it:

    vmware-aiops not installed — install it with `uv tool install vmware-aiops`
    (collector dependency for baseline '...'). Snapshot ... was marked 'failed'
    and is excluded from reports.

That text names the dependency, the install command, and the fact that the
snapshot will not be mistaken for a clean scan. Burying it in a stack trace
wastes the work that went into writing it, and teaches the user that the tool
crashed rather than that they are missing a package.

Nine of the family's repos wrap their CLI so domain errors print as one line.
This one exposed `app` directly as its console script, so there was nowhere for
that to happen.
"""

from __future__ import annotations

import pytest

from vmware_harden.cli.main import main
from vmware_harden.collectors.base import CollectorDependencyError, CollectorError


def _run(monkeypatch, exc):
    def boom(*a, **k):
        raise exc

    monkeypatch.setattr("vmware_harden.cli.main.app", boom)
    with pytest.raises(SystemExit) as e:
        main()
    return e.value.code


def _captured(capsys) -> str:
    """Read the capture ONCE. `capsys.readouterr()` drains the buffer, so
    calling it twice and joining the halves silently yields only the first."""
    cap = capsys.readouterr()
    return " ".join((cap.out + cap.err).split())


def test_a_collector_dependency_error_exits_cleanly(monkeypatch, capsys):
    code = _run(monkeypatch, CollectorDependencyError("vmware-aiops not installed — install it"))
    assert code == 1
    out = _captured(capsys)
    assert "vmware-aiops not installed" in out
    assert "Traceback" not in out


def test_the_message_is_not_replaced_by_a_generic_one(monkeypatch, capsys):
    """The value here is the specific text. A handler that swallowed it in
    favour of 'an error occurred' would be worse than the traceback."""
    _run(monkeypatch, CollectorError("snapshot 42 has no node rows for esxi-03"))
    out = _captured(capsys)
    assert "snapshot 42 has no node rows for esxi-03" in out


def test_a_programming_error_still_raises(monkeypatch):
    """Not a blanket except. A NameError is a bug in this codebase and must not
    be dressed up as user-facing advice."""
    def boom(*a, **k):
        raise NameError("no such name")

    monkeypatch.setattr("vmware_harden.cli.main.app", boom)
    with pytest.raises(NameError):
        main()


def test_ctrl_c_is_not_reported_as_a_failure(monkeypatch, capsys):
    """A scan can take minutes. Interrupting one is a choice, not a crash, and
    must not print a stack trace over the user's terminal."""
    def boom(*a, **k):
        raise KeyboardInterrupt

    monkeypatch.setattr("vmware_harden.cli.main.app", boom)
    with pytest.raises(SystemExit) as e:
        main()
    assert e.value.code == 130
    out = _captured(capsys)
    assert "Traceback" not in out
