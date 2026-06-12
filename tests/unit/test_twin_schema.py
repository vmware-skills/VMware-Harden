"""Twin schema initialization tests."""
import pytest
from pathlib import Path

from vmware_harden.store.twin import Twin


@pytest.mark.unit
def test_twin_creates_all_tables(tmp_path: Path):
    db_path = tmp_path / "test.duckdb"
    twin = Twin(db_path)
    twin.init_schema()

    tables = twin.list_tables()
    expected = {
        "nodes",
        "snapshots",
        "node_state",
        "change_event",
        "violation",
        "remediation",
    }
    assert expected.issubset(set(tables)), f"Missing: {expected - set(tables)}"
    # `edges` (and nodes.parent_id) were removed as genuinely-dead schema:
    # nothing in the codebase ever wrote or read them.
    assert "edges" not in set(tables)
    twin.close()


@pytest.mark.unit
def test_init_schema_is_idempotent(tmp_path: Path):
    """Calling init_schema twice should not error (CREATE IF NOT EXISTS)."""
    db_path = tmp_path / "test.duckdb"
    twin = Twin(db_path)
    twin.init_schema()
    twin.init_schema()  # second call must not raise
    twin.close()
