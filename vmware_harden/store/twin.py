"""Estate Digital Twin — DuckDB-backed persistent store."""
import hashlib
import json
import uuid
from datetime import datetime, timezone
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

    def start_snapshot(self, target: str) -> str:
        """Begin a new scan snapshot. Returns the snapshot id (UUID)."""
        snap_id = str(uuid.uuid4())
        self.conn.execute(
            "INSERT INTO snapshots (id, target, scan_started_at) VALUES (?, ?, ?)",
            [snap_id, target, datetime.now(timezone.utc)],
        )
        return snap_id

    def finish_snapshot(self, snapshot_id: str, status: str = "completed") -> None:
        """Mark a snapshot finished with the given status."""
        self.conn.execute(
            "UPDATE snapshots SET scan_finished_at = ?, status = ? WHERE id = ?",
            [datetime.now(timezone.utc), status, snapshot_id],
        )

    def write_node_state(
        self, snapshot_id: str, node_id: str, state: dict
    ) -> str:
        """Write a node state for a snapshot. Returns the sha256 content hash.

        State is canonicalized via json.dumps(sort_keys=True) before hashing,
        so equivalent dicts produce identical hashes regardless of key order.
        """
        state_json = json.dumps(state, sort_keys=True)
        state_hash = hashlib.sha256(state_json.encode()).hexdigest()
        self.conn.execute(
            """INSERT INTO node_state (snapshot_id, node_id, state_hash, state_json)
               VALUES (?, ?, ?, ?)
               ON CONFLICT (snapshot_id, node_id) DO NOTHING""",
            [snapshot_id, node_id, state_hash, state_json],
        )
        return state_hash

    def save_suggestion(self, violation_id: str, suggestion) -> str:
        """Persist a Suggestion against a violation. Idempotent — replaces existing.

        Returns the remediation row id.
        """
        rid = str(uuid.uuid4())
        suggestion_json = suggestion.model_dump_json()
        self.conn.execute("BEGIN TRANSACTION")
        try:
            self.conn.execute(
                "DELETE FROM remediation WHERE violation_id = ?", [violation_id]
            )
            self.conn.execute(
                """INSERT INTO remediation
                   (id, violation_id, suggestion, confidence)
                   VALUES (?, ?, ?, ?)""",
                [rid, violation_id, suggestion_json, suggestion.confidence],
            )
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise
        return rid

    def get_suggestion(self, violation_id: str):
        """Load the saved Suggestion for a violation, or None if absent."""
        from vmware_harden.baselines.model import Suggestion

        row = self.conn.execute(
            "SELECT suggestion FROM remediation WHERE violation_id = ?",
            [violation_id],
        ).fetchone()
        if row is None or row[0] is None:
            return None
        return Suggestion.model_validate_json(row[0])

    def close(self) -> None:
        self.conn.close()
