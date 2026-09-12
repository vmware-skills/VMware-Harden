"""Every way this package ships a running server must be able to scan.

`scan` reads the estate through sibling skills that only the `collectors` extra
installs (see vmware_harden/install.py). The README's install command carries
the extra, but three launch paths did not, and each started a server whose first
`scan_target` failed with CollectorDependencyError (review, 2026-09-11):

* `.mcp.json` — what a Claude Code plugin install runs: `uvx --from vmware-harden==X`
* `examples/mcp-configs/uvx-fallback.json` — `uvx --from vmware-harden`
* `Dockerfile` — `uv pip install --system .`

The MCP Registry entry (server.json) cannot name an extra — its package is a
bare identifier — so a registry client gets the same gap; the setup guide says so.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from vmware_harden.install import COLLECTORS_EXTRA

ROOT = Path(__file__).resolve().parents[3]
WITH_EXTRA = re.compile(rf"vmware-harden\[[^\]]*\b{re.escape(COLLECTORS_EXTRA)}\b[^\]]*\]")


def _uvx_from_args(config: Path) -> list[str]:
    servers = json.loads(config.read_text(encoding="utf-8"))["mcpServers"]
    found = []
    for block in servers.values():
        args = block.get("args") or []
        if block.get("command") == "uvx" and "--from" in args:
            found.append(args[args.index("--from") + 1])
    return found


def test_the_plugin_launch_installs_the_collectors():
    specs = _uvx_from_args(ROOT / ".mcp.json")
    assert specs, ".mcp.json has no `uvx --from` launch — this check verifies nothing"
    for spec in specs:
        assert WITH_EXTRA.match(spec), f".mcp.json launches {spec!r}, which cannot scan"


def test_the_uvx_fallback_example_installs_the_collectors():
    specs = _uvx_from_args(ROOT / "examples" / "mcp-configs" / "uvx-fallback.json")
    assert specs, "uvx-fallback.json has no `uvx --from` launch — this check verifies nothing"
    for spec in specs:
        assert WITH_EXTRA.match(spec), f"uvx-fallback.json launches {spec!r}, which cannot scan"


def test_the_image_installs_the_collectors():
    installs = [ln for ln in (ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines()
                if re.match(r"\s*RUN\b.*\bpip install\b", ln)]
    assert installs, "the Dockerfile installs nothing — this check verifies nothing"
    assert any(f"[{COLLECTORS_EXTRA}]" in ln for ln in installs), (
        f"the Dockerfile installs {installs!r} without [{COLLECTORS_EXTRA}] — the image cannot scan"
    )
