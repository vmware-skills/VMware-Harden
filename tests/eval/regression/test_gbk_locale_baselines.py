"""Baselines must load on a non-UTF-8 machine, and the doctor must not lie.

Reported from a VCF 9.1 re-test on Windows Server 2025 with locale cp936 (GBK):
5 of the 8 Harden MCP tools died, while ``vmware-harden doctor`` reported
**"9 baselines loaded"**.

Both halves are separate defects, and the second is the one that made the first
hard to find:

1. ``loader.load_baseline`` opened the YAML with no ``encoding=``, so it decoded
   with the machine's codec. Every one of the nine shipped baselines is
   undecodable as GBK (asserted below — including ``dengbao-2.0-level3-vmware``,
   the 等保 2.0 baseline this family exists to ship), so every load raised.

2. ``doctor._check_baselines`` counted ``*.yaml`` **filenames on disk**. It never
   opened one. "9 loaded" was therefore true of nothing — a health report for
   files the diagnostic had not read (CLAUDE.md 形态 #4: the label promised more
   than the check verified).

The locale reproduction is the same mechanism used in the Policy repo: a child
interpreter whose ``open()`` default is not UTF-8, reading the real files through
the real loader. cp936 does not exist on macOS/Linux, so ``LC_ALL=C`` with UTF-8
mode off is used instead; the child refuses to report anything if its default
codec turns out to be UTF-8 after all, so this file cannot pass by never entering
the decode path.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
BUILTIN_DIR = REPO_ROOT / "vmware_harden" / "baselines" / "builtin"

_CHILD = textwrap.dedent(
    """
    import json, locale, sys
    enc = locale.getencoding()
    if enc.lower().replace("-", "") == "utf8":
        print("CHILD-LOCALE-NOT-APPLIED:" + enc, file=sys.stderr)
        raise SystemExit(99)

    from vmware_harden.baselines.loader import list_builtins, load_builtin
    from vmware_harden.doctor import _check_baselines

    names = list_builtins()
    loaded, failed = [], {}
    for n in names:
        try:
            load_builtin(n)
            loaded.append(n)
        except Exception as exc:
            failed[n] = f"{type(exc).__name__}: {exc}"

    r = _check_baselines()
    print(json.dumps({
        "encoding": enc,
        "discovered": len(names),
        "actually_loaded": len(loaded),
        "failed": failed,
        "doctor_status": r.status,
        "doctor_detail": r.detail,
    }))
    """
)


def _run_under_ascii_locale() -> dict:
    env = dict(os.environ)
    env.pop("LANG", None)
    env.pop("LC_CTYPE", None)
    env.update(
        LC_ALL="C",
        PYTHONUTF8="0",
        PYTHONCOERCECLOCALE="0",
        PYTHONDONTWRITEBYTECODE="1",
    )
    proc = subprocess.run(
        [sys.executable, "-c", _CHILD],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(REPO_ROOT),
    )
    if proc.returncode == 99:
        pytest.fail(
            "this interpreter would not give the child a non-UTF-8 default codec, "
            "so the decode path was never entered: " + proc.stderr.strip()
        )
    assert proc.returncode == 0, f"child failed:\n{proc.stdout}\n{proc.stderr}"
    return json.loads(proc.stdout.strip().splitlines()[-1])


# ── fixture control ───────────────────────────────────────────────────


def test_shipped_baselines_are_utf8_and_undecodable_as_gbk():
    """Positive control on the corpus: these files really do fail on cp936.

    Without this, a future baseline set that happened to be pure ASCII would let
    the locale tests below pass while proving nothing.
    """
    files = sorted(BUILTIN_DIR.glob("*.yaml"))
    assert files, f"no baselines found under {BUILTIN_DIR}"

    gbk_safe = []
    for p in files:
        raw = p.read_bytes()
        raw.decode("utf-8")  # must be valid UTF-8
        try:
            raw.decode("gbk")
            gbk_safe.append(p.name)
        except UnicodeDecodeError:
            pass
    assert not gbk_safe, (
        "these baselines happen to decode under GBK, so they are not part of the "
        f"reproduction any more: {gbk_safe}"
    )


# ── finding 2a: the encoding ──────────────────────────────────────────


def test_every_baseline_loads_on_a_non_utf8_machine():
    out = _run_under_ascii_locale()
    assert out["discovered"] > 0
    assert out["actually_loaded"] == out["discovered"], (
        f"under {out['encoding']}, {out['discovered'] - out['actually_loaded']} of "
        f"{out['discovered']} baselines failed to load: {out['failed']}"
    )


def test_dengbao_baseline_survives_a_gbk_host():
    """Named separately because it is the one that matters most here.

    A cp936 host is, by definition, a Chinese-locale Windows box — the exact
    population the 等保 2.0 baseline was written for, and the population for whom
    it was the only baseline guaranteed not to load.
    """
    out = _run_under_ascii_locale()
    assert "dengbao-2.0-level3-vmware" not in out["failed"], out["failed"].get(
        "dengbao-2.0-level3-vmware"
    )


# ── finding 2b: the doctor must count what it can load ────────────────


def test_doctor_count_matches_what_actually_loads_on_a_non_utf8_machine():
    """The reported contradiction, asserted directly.

    Before the fix this child reported ``doctor_detail='9 loaded'`` with
    ``actually_loaded=0``: the doctor was reporting health for files it had never
    opened.
    """
    out = _run_under_ascii_locale()
    assert str(out["actually_loaded"]) in out["doctor_detail"], (
        f"doctor said {out['doctor_detail']!r} but only {out['actually_loaded']} of "
        f"{out['discovered']} baselines actually load"
    )
    if out["failed"]:
        assert out["doctor_status"] != "ok"


def test_doctor_does_not_count_a_baseline_it_cannot_parse(tmp_path, monkeypatch):
    """Plant one broken baseline and check the diagnostic notices.

    This is the locale-independent half: whatever the reason a baseline will not
    parse — bad encoding, bad YAML, a schema violation, a ScriptCheck — the count
    must exclude it and the report must name it.
    """
    from vmware_harden import doctor as doctor_mod
    from vmware_harden.baselines import loader

    user_dir = tmp_path / "baselines"
    user_dir.mkdir()
    (user_dir / "broken-baseline.yaml").write_text("id: [ unclosed\n", encoding="utf-8")
    monkeypatch.setattr(loader, "USER_DIR", user_dir)

    healthy = len(list(loader.BUILTIN_DIR.glob("*.yaml")))
    result = doctor_mod._check_baselines()

    assert result.status == "error", f"a baseline that will not parse reported {result.status!r}"
    assert "broken-baseline" in result.detail, (
        f"the failing baseline must be named, not just counted out: {result.detail!r}"
    )
    assert result.detail.startswith(f"{healthy} of {healthy + 1} loaded"), (
        f"the doctor counted a file it could not parse: {result.detail!r}"
    )
    assert "\n" not in result.detail, (
        "doctor renders one line per check; a multi-line YAML error breaks the table"
    )


def test_doctor_names_the_encoding_when_that_is_the_reason(tmp_path, monkeypatch):
    """"invalid YAML" is the wrong thing to send an operator looking for when the
    real problem is that the file is not UTF-8."""
    from vmware_harden import doctor as doctor_mod
    from vmware_harden.baselines import loader

    user_dir = tmp_path / "baselines"
    user_dir.mkdir()
    (user_dir / "gbk-encoded.yaml").write_bytes(
        "id: gbk-encoded\nname: 等保基线\nversion: '1'\napplies_to: [host]\nrules: []\n".encode(
            "gbk"
        )
    )
    monkeypatch.setattr(loader, "USER_DIR", user_dir)

    result = doctor_mod._check_baselines()
    assert result.status == "error"
    # Not just the token "utf-8": the raw UnicodeDecodeError message contains
    # that too ("'utf-8' codec can't decode byte ..."), so asserting on it alone
    # would pass with no teaching text at all — a check promising more than it
    # verifies (CLAUDE.md 形态 #4). Demand the instruction.
    assert "re-save" in result.detail.lower(), result.detail
    assert "utf-8" in result.detail.lower(), result.detail


# ── controls: a healthy install must still report its true count ──────


def test_healthy_install_reports_every_baseline_as_ok():
    """The control a fix that fails closed on everything cannot pass."""
    from vmware_harden.baselines.loader import list_builtins, load_builtin
    from vmware_harden.doctor import _check_baselines

    names = list_builtins()
    for name in names:
        load_builtin(name)  # raises if any of them genuinely will not load

    result = _check_baselines()
    assert result.status == "ok"
    assert result.detail == f"{len(names)} loaded"


def test_baseline_content_round_trips_non_ascii():
    """Mojibake control.

    GBK is not only a source of decode *errors*: many UTF-8 byte pairs are valid
    GBK, so a mis-decoded baseline can parse fine and quietly carry corrupted rule
    titles into a compliance report. Assert the Chinese survives intact.
    """
    from vmware_harden.baselines.loader import load_builtin

    b = load_builtin("dengbao-2.0-level3-vmware")
    text = " ".join(filter(None, [b.name, *(r.title or "" for r in b.rules)]))
    assert any("一" <= ch <= "鿿" for ch in text), (
        "the 等保 baseline lost its Chinese text on the way in"
    )
    assert "�" not in text, "replacement characters — the file was mis-decoded"


# ── the mechanical link ───────────────────────────────────────────────


def test_every_text_read_in_the_package_declares_utf8():
    """Sweep, not spot-fix — the same gate the Policy package now carries."""
    import ast

    pkg = REPO_ROOT / "vmware_harden"
    sources = sorted(pkg.rglob("*.py"))
    assert sources, f"no sources found under {pkg}"

    offenders: list[str] = []
    for src in sources:
        tree = ast.parse(src.read_text(encoding="utf-8"), filename=str(src))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = (
                func.id
                if isinstance(func, ast.Name)
                else func.attr
                if isinstance(func, ast.Attribute)
                else ""
            )
            if name not in ("open", "read_text", "write_text"):
                continue
            mode = ""
            for kw in node.keywords:
                if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                    mode = str(kw.value.value)
            if name == "open" and len(node.args) >= 2:
                arg = node.args[1]
                if isinstance(arg, ast.Constant):
                    mode = str(arg.value)
            if "b" in mode:
                continue
            if not any(kw.arg == "encoding" for kw in node.keywords):
                offenders.append(f"{src.relative_to(pkg.parent)}:{node.lineno} {name}()")

    assert not offenders, (
        "text I/O without encoding='utf-8' decodes with the machine's locale "
        "codec and breaks on cp936/Shift-JIS/latin-1 hosts:\n  "
        + "\n  ".join(offenders)
    )
