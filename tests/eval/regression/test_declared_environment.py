"""vmware-harden declares a constant environment, and must keep doing so.

Policy rules scope by environment. The baseline treats a target that declares
none as unknown: today a state-changing operation against it runs but logs a
warning (``require_declared_environment: warn``), and the next major release
refuses it outright (``true``).

Every skill with a config answers this per target. vmware-harden has none and
cannot grow one honestly — it is backed by a local DuckDB twin, not a
connection to a managed estate. So it registers a constant ``local`` resolver.
That claim is true rather than a workaround: ``scan_target`` is the only
state-changing tool here, and its state change is the snapshot it records in
the twin DB; its vCenter interaction is read-only collection. No tool in this
skill mutates a remote VMware estate.

Why this file exists: under today's warn setting a missing registration is
INVISIBLE. ``scan_target`` would still run; the only symptom would be a log
line. It would surface for the first time when the enforcing release lands and
blocked every scan at once. So the registration is pinned here, and a refactor
that drops it — or that moves it inside ``build_server()``, where it would only
take effect once a server happens to be constructed — fails loudly instead.
"""

from __future__ import annotations

import importlib
from pathlib import Path
from unittest.mock import patch

import pytest

import vmware_policy.environment as env_mod
from vmware_harden.mcp_server import server
from vmware_policy.environment import resolve_environment, set_environment_resolver
from vmware_policy.policy import get_policy_engine, reset_policy_engine


@pytest.fixture()
def baseline():
    """The shipped policy baseline — currently the warn-only migration setting."""
    reset_policy_engine()
    get_policy_engine()
    yield
    reset_policy_engine()


@pytest.fixture()
def enforcing(tmp_path):
    """The same rules with the requirement switched on, as the next major
    release will ship it. This is the setting that makes a lost registration
    fatal, so harden's behaviour under it is the point of this file."""
    rules = tmp_path / "rules.yaml"
    rules.write_text("require_declared_environment: true\n")
    reset_policy_engine()
    get_policy_engine(rules)
    yield
    reset_policy_engine()


@pytest.fixture(autouse=True)
def _restore_resolver():
    """Tests here clear/reload the global resolver; put it back afterwards."""
    yield
    importlib.reload(server)


@pytest.mark.unit
class TestConstantResolverIsRegistered:
    def test_importing_the_server_registers_a_resolver(self) -> None:
        set_environment_resolver(None)
        importlib.reload(server)

        assert env_mod._resolver is not None, (
            "vmware_harden.mcp_server.server must call set_environment_resolver() at import. "
            "Without it every harden scan reads as undeclared — invisible under "
            "today's warn setting, and a total block once enforcement lands."
        )
        assert env_mod._resolver is server._environment_for

    def test_registration_is_at_module_level_not_inside_build_server(self) -> None:
        """Importing alone must be enough — no build_server() call required.

        The tools are decorated in vmware_harden.mcp.tools and can be invoked
        without ever constructing a FastMCP instance (the unit suite does
        exactly that), so a resolver registered only inside the factory would
        leave those paths undeclared.
        """
        set_environment_resolver(None)
        importlib.reload(server)  # import only — build_server() not called

        assert env_mod._resolver is not None
        assert resolve_environment("lab") == server.LOCAL_ENVIRONMENT

    def test_resolver_reports_a_non_empty_environment(self) -> None:
        importlib.reload(server)

        # "" is the sentinel for *undeclared*. Anything else is a declaration.
        assert resolve_environment("") != ""
        assert resolve_environment("anything") == server.LOCAL_ENVIRONMENT

    def test_declaration_is_constant_across_targets(self) -> None:
        """Harden has no per-target environment knowledge, so it must not
        pretend to — the scanned vCenter's label lives in that skill's config."""
        importlib.reload(server)

        for target in ("", "prod-vc01", "vcenter-lab", "nonsense"):
            assert resolve_environment(target) == server.LOCAL_ENVIRONMENT

    def test_declared_environment_is_not_a_production_label(self) -> None:
        """`local` must not collide with the environments real rules scope to.

        If harden claimed `production`, every scan would demand a named
        approver; if it claimed a name an operator also uses for a real estate,
        rules would cross-apply. `local` is deliberately neither.
        """
        assert server.LOCAL_ENVIRONMENT not in ("production", "prod", "staging", "")


@pytest.mark.unit
class TestScanIsNotBlocked:
    """The consequence that actually matters: scanning keeps working."""

    _FAKE_HOSTS = [
        {"id": "h-1", "name": "esx", "ntp_enabled": True, "build": 99999999,
         "ntp_servers": [], "ntp_service_policy": "on", "lockdown_mode": "normal",
         "syslog_remote_host": "syslog", "persistent_logs": True,
         "audit_retention_days": 90, "mgmt_vmk_isolated": True,
         "vswitch_promiscuous_mode": "reject", "forged_transmits": "reject",
         "firewall_enabled": True, "ssh_running": False, "ad_joined": True,
         "lockdown_exceptions_count": 0, "root_ssh_key_auth": False,
         "vsan_enabled": False, "vsan_encryption_enabled": False,
         "encrypted_vmotion": "required", "dcui_timeout_seconds": 600,
         "shell_timeout_seconds": 900, "console_keyboard": "US Default"},
    ]

    @pytest.mark.parametrize("mode", ["baseline", "enforcing"])
    def test_scan_target_runs(self, mode, request, tmp_path: Path) -> None:
        request.getfixturevalue(mode)
        importlib.reload(server)

        from vmware_harden.mcp import tools as srv

        srv._DB_PATH = tmp_path / "scan.duckdb"
        with patch(
            "vmware_harden.collectors.hosts._fetch_hosts",
            return_value=self._FAKE_HOSTS,
        ):
            out = srv.scan_target(target="lab", baseline="cis-vmware-esxi-8.0-subset")

        assert "snapshot_id" in out

    @pytest.mark.parametrize("mode", ["baseline", "enforcing"])
    def test_medium_risk_operation_is_allowed_by_policy(self, mode, request) -> None:
        request.getfixturevalue(mode)
        importlib.reload(server)

        result = get_policy_engine().check_allowed(
            "scan_target", env=resolve_environment("lab"), risk_level="medium"
        )
        assert result.allowed is True
        assert result.rule != "undeclared_environment_warning"


@pytest.mark.unit
class TestMissingRegistrationWouldBlockScans:
    """Proves the pin above is load-bearing rather than decorative."""

    def test_without_a_resolver_scans_are_refused_when_enforcing(
        self, enforcing
    ) -> None:
        set_environment_resolver(None)

        result = get_policy_engine().check_allowed(
            "scan_target", env=resolve_environment("lab"), risk_level="medium"
        )
        assert result.allowed is False
        assert result.rule == "undeclared_environment"

    def test_without_a_resolver_scans_only_warn_today(self, baseline) -> None:
        """And why the enforcing fixture is needed to catch it: under the
        shipped setting the same mistake is silent."""
        set_environment_resolver(None)

        result = get_policy_engine().check_allowed(
            "scan_target", env=resolve_environment("lab"), risk_level="medium"
        )
        assert result.allowed is True
        assert result.rule == "undeclared_environment_warning"


@pytest.mark.unit
class TestReadsAreNeverGated:
    @pytest.mark.parametrize("mode", ["baseline", "enforcing"])
    def test_reads_allowed_with_no_resolver_at_all(self, mode, request) -> None:
        request.getfixturevalue(mode)
        set_environment_resolver(None)

        assert get_policy_engine().check_allowed(
            "list_baselines", env="", risk_level="low"
        ).allowed
