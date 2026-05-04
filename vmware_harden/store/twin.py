"""Estate Digital Twin — DuckDB-backed persistent store."""
from pathlib import Path

import duckdb

from vmware_harden.store.schema import DDL


class Twin:
    """Single-file DuckDB-backed estate twin."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.conn = duckdb.connect(str(db_path))
        self.init_schema()  # idempotent; CREATE IF NOT EXISTS

    def init_schema(self) -> None:
        """Create all tables if they don't exist (idempotent)."""
        for stmt in DDL:
            self.conn.execute(stmt)

    def list_tables(self) -> list[str]:
        """Return names of all user tables in the database."""
        rows = self.conn.execute(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'main'"
        ).fetchall()
        return [r[0] for r in rows]

    def close(self) -> None:
        self.conn.close()
