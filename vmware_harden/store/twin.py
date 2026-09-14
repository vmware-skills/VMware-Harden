"""Estate Digital Twin — DuckDB-backed persistent store."""
import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import duckdb

from vmware_harden.store.schema import ADDED_COLUMNS, DDL


def _utc_label(value) -> str:
    """A snapshot timestamp as ``YYYY-MM-DD HH:MM UTC``. Stored values are naive UTC."""
    if value is None:
        return "unknown time"
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc)
        return value.strftime("%Y-%m-%d %H:%M UTC")
    return f"{value} UTC"

class Twin:
    """Single-file DuckDB-backed estate twin."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.conn = duckdb.connect(str(db_path))
        self.init_schema()  # idempotent; CREATE IF NOT EXISTS

    @classmethod
    def open_readonly(cls, db_path: Path) -> "Twin":
        """Open an existing Twin file read-only.

        DuckDB is single-writer; web/dashboard readers must use this so they
        never contend for the write lock held by a concurrent scan. Skips
        init_schema (DDL is a write). Raises duckdb.Error if the file does
        not exist or the write lock cannot be shared.
        """
        twin = cls.__new__(cls)
        twin.db_path = db_path
        twin.conn = duckdb.connect(str(db_path), read_only=True)
        return twin

    def init_schema(self) -> None:
        """Create all tables if they don't exist, then add any new columns.

        Idempotent. The second half matters for an upgrade: `CREATE TABLE IF NOT
        EXISTS` is a no-op on a table that already exists, so a column added to
        a shipped table would never appear in a user's database and every read
        of it would fail.
        """
        for stmt in DDL:
            self.conn.execute(stmt)
        for table, column, sql_type in ADDED_COLUMNS:
            present = self.conn.execute(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_name = ? AND column_name = ?",
                [table, column],
            ).fetchone()
            if present is None:
                # Interpolated, not bound: DDL identifiers cannot be
                # parameters. Every part comes from the ADDED_COLUMNS constant,
                # never from a caller.
                self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {sql_type}")

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

    def latest_snapshot(self, completed_only: bool = True) -> dict | None:
        """Return the most recent snapshot as a dict, or None if there is none.

        By default only status='completed' snapshots qualify, so a crashed or
        in-flight scan (status 'running'/'failed') never becomes the baseline
        for reports, drift views, or MCP tools.
        """
        sql = (
            "SELECT id, target, scan_started_at, scan_finished_at, status "
            "FROM snapshots "
        )
        if completed_only:
            sql += "WHERE status = 'completed' "
        sql += "ORDER BY scan_started_at DESC LIMIT 1"
        row = self.conn.execute(sql).fetchone()
        if row is None:
            return None
        return {
            "id": row[0],
            "target": row[1],
            "scan_started_at": row[2],
            "scan_finished_at": row[3],
            "status": row[4],
        }

    def snapshot_standing(self, snapshot: dict) -> dict:
        """Which snapshot a view reads, when it finished, and what came after it.

        ``latest_snapshot`` rightly skips failed and running scans — but a report
        that then prints that snapshot's results without naming it answers a
        scan the user just ran (and that failed) with results from weeks earlier
        (lab, 2026-09-14: two failed scans, report showed 2026-08-30's). So every
        view says which snapshot it is and, when later scans of the same target
        did not complete, says that too.

        Returns ``{id, target, finished_at, later_unfinished, headline, note}``;
        ``note`` is None when nothing later went wrong.
        """
        rows = self.conn.execute(
            "SELECT status, scan_started_at FROM snapshots "
            "WHERE target = ? AND scan_started_at > ? AND status != 'completed' "
            "ORDER BY scan_started_at DESC",
            [snapshot["target"], snapshot["scan_started_at"]],
        ).fetchall()
        finished = _utc_label(snapshot.get("scan_finished_at"))
        headline = f"Snapshot {snapshot['id']} · {snapshot['target']} · finished {finished}"
        note = None
        if rows:
            status, started = rows[0]
            scans = "scan" if len(rows) == 1 else "scans"
            state = "is still running" if status == "running" else str(status)
            note = (
                f"{len(rows)} later {scans} of {snapshot['target']} did not complete "
                f"(the latest, started {_utc_label(started)}, {state}). These results "
                f"are from the scan that finished {finished}."
            )
        return {
            "id": snapshot["id"],
            "target": snapshot["target"],
            "finished_at": finished,
            "later_unfinished": len(rows),
            "headline": headline,
            "note": note,
        }

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

    def write_node_states(
        self, snapshot_id: str, states: list[tuple[str, dict]]
    ) -> None:
        """Batch-write node states for a snapshot in one executemany.

        ``states`` is a list of (node_id, state_dict). Each state is hashed
        the same way as write_node_state. Caller is responsible for the
        surrounding transaction (collectors batch nodes + states together).
        """
        rows = []
        for node_id, state in states:
            state_json = json.dumps(state, sort_keys=True)
            state_hash = hashlib.sha256(state_json.encode()).hexdigest()
            rows.append([snapshot_id, node_id, state_hash, state_json])
        if not rows:
            return
        self.conn.executemany(
            """INSERT INTO node_state (snapshot_id, node_id, state_hash, state_json)
               VALUES (?, ?, ?, ?)
               ON CONFLICT (snapshot_id, node_id) DO NOTHING""",
            rows,
        )

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

    def update_pilot_task_id(self, violation_id: str, pilot_task_id: str) -> None:
        """Persist the pilot task id back onto the remediation row for tracking."""
        self.conn.execute(
            "UPDATE remediation SET pilot_task_id = ? WHERE violation_id = ?",
            [pilot_task_id, violation_id],
        )

    def close(self) -> None:
        self.conn.close()
