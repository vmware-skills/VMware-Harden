"""Where the Twin database lives: an explicit path, then VMWARE_HARDEN_DB, then the default.

The setup guide, SKILL.md, smithery.yaml, the Docker example and every MCP
example config documented VMWARE_HARDEN_DB as the override, and no code read it
(found 2026-09-11): the MCP server always used the default path, so a Smithery
user's `db_path` and a container's `-e VMWARE_HARDEN_DB=...` were ignored
without a word. Every reader of the path goes through here now.
"""

from __future__ import annotations

import os
from pathlib import Path

DB_ENV_VAR = "VMWARE_HARDEN_DB"
DEFAULT_DB = "~/.vmware-harden/twin.duckdb"


def resolve_db_path(explicit: str | Path | None = None) -> Path:
    """The Twin DB path, with ``~`` expanded (MCP clients pass env values verbatim)."""
    raw = explicit or os.environ.get(DB_ENV_VAR) or DEFAULT_DB
    return Path(os.path.expanduser(str(raw)))
