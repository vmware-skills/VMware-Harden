"""DFW compliance must use each rule's actual parent policy, not the rule name."""

from unittest.mock import Mock
import pytest
from vmware_harden.collectors import dfw


def test_parent_policy_names_are_carried_and_missing_names_remain_unknown(monkeypatch):
    connection = pytest.importorskip("vmware_nsx_security.connection")
    operations = pytest.importorskip("vmware_nsx_security.ops.dfw_policy")
    manager = Mock()
    monkeypatch.setattr(connection.ConnectionManager, "from_config", lambda: manager)
    policies = [
        {"id": "p1", "display_name": "production"},
        {"id": "p2", "display_name": "test"},
        {"id": "p3"},
    ]
    monkeypatch.setattr(operations, "list_dfw_policies", lambda *a, **k: {"items": policies})

    def rules(client, policy_id, **kwargs):
        return {
            "items": [
                {
                    "id": policy_id + "-rule",
                    "display_name": "same-rule-name",
                    "section_name": "untrusted-child-value",
                }
            ]
        }

    monkeypatch.setattr(operations, "list_dfw_rules", rules)
    result = dfw._fetch_dfw("fixture")
    assert [r.get("section_name") for r in result["rules"]] == ["production", "test", None]
    assert all(r["name"] == "same-rule-name" for r in result["rules"])
    manager.disconnect_all.assert_called_once()


@pytest.mark.parametrize("parent,rule_name,violations", [("Production", "ordinary-rule", 0), ("Default", "Production-rule", 1)])
def test_business_policy_rule_reads_parent_evidence(tmp_path, parent, rule_name, violations):
    import json
    from vmware_harden.baselines.loader import load_builtin
    from vmware_harden.checks.query import execute_query_check
    from vmware_harden.store.twin import Twin

    rule = next(r for r in load_builtin("dengbao-2.0-level3-vmware").rules if r.id == "db-l3-policy-1")
    twin = Twin(tmp_path / "parent.duckdb")
    try:
        attrs = {"section_name": parent, "name": rule_name}
        twin.conn.execute(
            "INSERT INTO nodes (id, type, target, name, attrs) VALUES ('r', 'dfw_rule', 'fixture', ?, ?)",
            [rule_name, json.dumps(attrs)],
        )
        assert len(execute_query_check(twin, rule.check)) == violations
    finally:
        twin.close()


def _business_baseline():
    from vmware_harden.baselines.loader import load_builtin
    baseline = load_builtin("dengbao-2.0-level3-vmware")
    return baseline.model_copy(update={"rules": [r for r in baseline.rules if r.id == "db-l3-policy-1"]})


def _dfw_node(twin, snapshot, node, parent):
    import json
    attrs = {} if parent is None else {"section_name": parent}
    twin.conn.execute("INSERT INTO nodes (id,type,target,name,attrs) VALUES (?, 'dfw_rule', 'fixture', ?, ?)", [node, node, json.dumps(attrs)])
    twin.write_node_state(snapshot, node, attrs)


def test_missing_parent_cannot_be_reported_as_absent_business_policy(tmp_path):
    from vmware_harden.store.twin import Twin
    from vmware_harden.checks.runner import CheckRunner
    from vmware_harden.checks.coverage import coverage_for
    twin = Twin(tmp_path / "unknown.duckdb")
    try:
        snapshot = twin.start_snapshot("fixture")
        _dfw_node(twin, snapshot, "unknown-rule", None)
        assert CheckRunner(twin).run_baseline(snapshot, _business_baseline()) == []
        assert coverage_for(twin, snapshot).complete is False
    finally:
        twin.close()


def test_uncollected_dfw_does_not_establish_absence(tmp_path):
    from vmware_harden.store.twin import Twin
    from vmware_harden.checks.runner import CheckRunner
    from vmware_harden.checks.coverage import coverage_for
    twin = Twin(tmp_path / "uncollected.duckdb")
    try:
        snapshot = twin.start_snapshot("fixture")
        assert CheckRunner(twin).run_baseline(snapshot, _business_baseline(), uncollected={"dfw_rule": "source unavailable"}) == []
        assert coverage_for(twin, snapshot).complete is False
    finally:
        twin.close()


def test_measured_empty_dfw_still_reports_missing_policy(tmp_path):
    from vmware_harden.store.twin import Twin
    from vmware_harden.checks.runner import CheckRunner
    twin = Twin(tmp_path / "empty.duckdb")
    try:
        snapshot = twin.start_snapshot("fixture")
        assert CheckRunner(twin).run_baseline(snapshot, _business_baseline())[0]["rule_id"] == "db-l3-policy-1"
    finally:
        twin.close()


@pytest.mark.parametrize("old_parent", ["Production", None])
def test_other_scan_nodes_cannot_change_current_absence_verdict(tmp_path, old_parent):
    from vmware_harden.store.twin import Twin
    from vmware_harden.checks.runner import CheckRunner
    twin = Twin(tmp_path / "scope.duckdb")
    try:
        old = twin.start_snapshot("old-target")
        _dfw_node(twin, old, "old-rule", old_parent)
        current = twin.start_snapshot("current-target")
        _dfw_node(twin, current, "current-rule", "Default")
        violations = CheckRunner(twin).run_baseline(current, _business_baseline())
        assert len(violations) == 1
        assert violations[0]["rule_id"] == "db-l3-policy-1"
    finally:
        twin.close()


def test_snapshot_query_cursor_is_closed_after_query_failure(tmp_path):
    from vmware_harden.store.twin import Twin
    from vmware_harden.baselines.model import QueryCheck
    from vmware_harden.checks._snapshot_queries import snapshot_queries
    twin = Twin(tmp_path / "query-failure.duckdb")
    try:
        old = twin.start_snapshot("old")
        _dfw_node(twin, old, "old-rule", "Production")
        current = twin.start_snapshot("new")
        _dfw_node(twin, current, "new-rule", "Default")
        with pytest.raises(Exception, match="missing_table"):
            with snapshot_queries(twin, current) as query:
                assert query(QueryCheck(type="query", sql="SELECT id FROM nodes")) == [{"id": "new-rule"}]
                query(QueryCheck(type="query", sql="SELECT * FROM missing_table"))
        assert twin.conn.execute("SELECT count(*) FROM nodes").fetchone()[0] == 2
        with snapshot_queries(twin, old) as query:
            assert query(QueryCheck(type="query", sql="SELECT id FROM nodes")) == [{"id": "old-rule"}]
    finally:
        twin.close()
