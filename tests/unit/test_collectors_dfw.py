"""DFWCollector unit tests — DFW sections + rules from NSX-Security."""
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from vmware_harden.collectors.dfw import DFWCollector
from vmware_harden.store.twin import Twin


FAKE_DFW = {
    "sections": [
        {
            "id": "section-app",
            "name": "Application Tier",
            "category": "Application",
            "applied_to": ["vm-100", "vm-101"],
        },
    ],
    "rules": [
        {
            "id": "rule-1",
            "name": "Allow web → app",
            "section_id": "section-app",
            "action": "allow",
            "source": ["web-tier"],
            "destination": ["app-tier"],
            "services": ["TCP-8080"],
            "applied_to": ["vm-100"],
            "hit_count": 12345,
            "disabled": False,
        },
        {
            "id": "rule-2",
            "name": "Any → Any allow (anti-pattern)",
            "section_id": "section-app",
            "action": "allow",
            "source": ["ANY"],
            "destination": ["ANY"],
            "services": ["ANY"],
            "applied_to": ["vm-100"],
            "hit_count": 0,
            "disabled": False,
        },
    ],
}


@pytest.mark.unit
def test_dfw_collector_writes_sections_and_rules(tmp_path: Path):
    twin = Twin(tmp_path / "t.duckdb")
    snap = twin.start_snapshot("v.lab")
    with patch(
        "vmware_harden.collectors.dfw._fetch_dfw", return_value=FAKE_DFW
    ):
        n = DFWCollector(twin).collect(snap, target="v.lab")
    # collector returns total objects collected (sections + rules)
    assert n == 3

    sections = twin.conn.execute(
        "SELECT id, type, name, target FROM nodes WHERE type='dfw_section' "
        "ORDER BY id"
    ).fetchall()
    assert len(sections) == 1
    assert sections[0][0] == "v.lab:section-app"

    rules = twin.conn.execute(
        "SELECT id, type, name, target FROM nodes WHERE type='dfw_rule' "
        "ORDER BY id"
    ).fetchall()
    assert len(rules) == 2
    rule_ids = {r[0] for r in rules}
    assert rule_ids == {"v.lab:rule-1", "v.lab:rule-2"}
    twin.close()


@pytest.mark.unit
def test_dfw_collector_preserves_any_to_any_signal(tmp_path: Path):
    """Anti-pattern detection requires source/destination/services preserved verbatim."""
    twin = Twin(tmp_path / "t.duckdb")
    snap = twin.start_snapshot("v.lab")
    with patch(
        "vmware_harden.collectors.dfw._fetch_dfw", return_value=FAKE_DFW
    ):
        DFWCollector(twin).collect(snap, target="v.lab")

    row = twin.conn.execute(
        "SELECT attrs FROM nodes WHERE id = 'v.lab:rule-2'"
    ).fetchone()
    attrs = json.loads(row[0])
    assert attrs["source"] == ["ANY"]
    assert attrs["destination"] == ["ANY"]
    assert attrs["services"] == ["ANY"]
    assert attrs["action"] == "allow"
    twin.close()


@pytest.mark.unit
def test_dfw_collector_section_id_persisted_on_rule(tmp_path: Path):
    """Rule attrs must carry section_id for cross-baseline join."""
    twin = Twin(tmp_path / "t.duckdb")
    snap = twin.start_snapshot("v.lab")
    with patch(
        "vmware_harden.collectors.dfw._fetch_dfw", return_value=FAKE_DFW
    ):
        DFWCollector(twin).collect(snap, target="v.lab")

    row = twin.conn.execute(
        "SELECT attrs FROM nodes WHERE id = 'v.lab:rule-1'"
    ).fetchone()
    attrs = json.loads(row[0])
    assert attrs["section_id"] == "section-app"
    twin.close()


@pytest.mark.unit
def test_dfw_collector_raises_on_malformed_rule(tmp_path: Path):
    from vmware_harden.collectors.base import CollectorError
    twin = Twin(tmp_path / "t.duckdb")
    snap = twin.start_snapshot("v.lab")
    bad = {"sections": [], "rules": [{"name": "no-id-rule"}]}
    with patch(
        "vmware_harden.collectors.dfw._fetch_dfw", return_value=bad
    ):
        with pytest.raises(CollectorError, match="missing required field"):
            DFWCollector(twin).collect(snap, target="v.lab")
    twin.close()
