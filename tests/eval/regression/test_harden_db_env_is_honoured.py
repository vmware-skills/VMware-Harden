"""VMWARE_HARDEN_DB moves the Twin database for every reader, as documented.

SKILL.md, the setup guide, smithery.yaml, the Docker example and every MCP
example config name VMWARE_HARDEN_DB as the override; until 2026-09-11 no code
read it, so the MCP server, the CLI and doctor all used the default path while
the docs said otherwise. `~` in the value is expanded because MCP clients pass
env values verbatim.
"""

from __future__ import annotations

from pathlib import Path

import typer

from vmware_harden.db_path import DB_ENV_VAR, resolve_db_path


def test_precedence_explicit_then_env_then_default(monkeypatch, tmp_path):
    monkeypatch.delenv(DB_ENV_VAR, raising=False)
    assert resolve_db_path() == Path.home() / ".vmware-harden" / "twin.duckdb"
    monkeypatch.setenv(DB_ENV_VAR, "~/elsewhere/twin.duckdb")
    assert resolve_db_path() == Path.home() / "elsewhere" / "twin.duckdb"
    assert resolve_db_path(tmp_path / "x.duckdb") == tmp_path / "x.duckdb"


def test_the_mcp_entry_point_uses_the_variable(monkeypatch, tmp_path):
    from vmware_harden.mcp_server import server

    seen = []

    class _Server:
        def run(self):
            pass

    monkeypatch.setenv(DB_ENV_VAR, str(tmp_path / "mcp.duckdb"))
    def fake_build(db_path=None):
        seen.append(db_path)
        return _Server()

    monkeypatch.setattr(server, "build_server", fake_build)
    server.main()
    assert seen == [tmp_path / "mcp.duckdb"]


def test_every_cli_db_option_reads_the_variable():
    from vmware_harden.cli.main import app

    command = typer.main.get_command(app)
    db_options = []

    def walk(cmd, path):
        for param in getattr(cmd, "params", []):
            if param.name == "db":
                db_options.append((path, param))
        for name, sub in (getattr(cmd, "commands", None) or {}).items():
            walk(sub, f"{path} {name}")

    walk(command, "vmware-harden")
    assert len(db_options) >= 6, f"only {len(db_options)} --db options found: the walk is stale"
    missing = [path for path, param in db_options if param.envvar != DB_ENV_VAR]
    assert not missing, f"--db ignores {DB_ENV_VAR} on: {missing}"


def test_doctor_looks_where_the_variable_points(monkeypatch, tmp_path):
    from vmware_harden import doctor

    monkeypatch.setenv(DB_ENV_VAR, str(tmp_path / "doctor.duckdb"))
    result = doctor._check_twin_db()
    assert str(tmp_path / "doctor.duckdb") in result.detail
