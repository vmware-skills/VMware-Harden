"""DuckDB DDL for Estate Digital Twin.

Schema reference: docs/plans/2026-05-03-vmware-harden-design.md §3.
"""

DDL: list[str] = [
    # Note: DuckDB has no ON UPDATE CURRENT_TIMESTAMP support; collectors must
    # set last_seen_at explicitly on upsert.
    """
    CREATE TABLE IF NOT EXISTS nodes (
        id VARCHAR PRIMARY KEY,
        type VARCHAR NOT NULL,
        target VARCHAR NOT NULL DEFAULT '_legacy',
        name VARCHAR,
        parent_id VARCHAR,
        attrs JSON,
        first_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS edges (
        from_id VARCHAR NOT NULL,
        to_id VARCHAR NOT NULL,
        relation VARCHAR NOT NULL,
        attrs JSON,
        PRIMARY KEY (from_id, to_id, relation)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS snapshots (
        id VARCHAR PRIMARY KEY,
        target VARCHAR NOT NULL,
        scan_started_at TIMESTAMP NOT NULL,
        scan_finished_at TIMESTAMP,
        status VARCHAR DEFAULT 'running'
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS node_state (
        snapshot_id VARCHAR NOT NULL,
        node_id VARCHAR NOT NULL,
        state_hash VARCHAR NOT NULL,
        state_json JSON,
        PRIMARY KEY (snapshot_id, node_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS change_event (
        id VARCHAR PRIMARY KEY,
        snapshot_id VARCHAR NOT NULL,
        node_id VARCHAR NOT NULL,
        field VARCHAR NOT NULL,
        old_value VARCHAR,
        new_value VARCHAR,
        detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS violation (
        id VARCHAR PRIMARY KEY,
        snapshot_id VARCHAR NOT NULL,
        baseline_id VARCHAR NOT NULL,
        rule_id VARCHAR NOT NULL,
        node_id VARCHAR NOT NULL,
        severity VARCHAR NOT NULL,
        evidence JSON,
        detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        status VARCHAR DEFAULT 'open'
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS remediation (
        id VARCHAR PRIMARY KEY,
        violation_id VARCHAR NOT NULL,
        suggestion JSON,
        confidence DOUBLE,
        executed_at TIMESTAMP,
        pilot_task_id VARCHAR
    )
    """,
    # snapshot_id is the hot filter for list/report/diff; without these indexes
    # the violation table degrades to full scan as scans accumulate.
    "CREATE INDEX IF NOT EXISTS idx_violation_snapshot ON violation(snapshot_id)",
    "CREATE INDEX IF NOT EXISTS idx_node_state_snapshot ON node_state(snapshot_id)",
    "CREATE INDEX IF NOT EXISTS idx_change_event_snapshot ON change_event(snapshot_id)",
    # node_id / violation_id are the other high-frequency WHERE paths
    # (per-node drift history, suggestion lookup per violation).
    "CREATE INDEX IF NOT EXISTS idx_change_event_node ON change_event(node_id)",
    "CREATE INDEX IF NOT EXISTS idx_remediation_violation ON remediation(violation_id)",
]

# Severity is stored as plain text; a bare `ORDER BY severity DESC` sorts
# alphabetically and puts 'critical' LAST. Use this CASE expression (with the
# severity column substituted for {col}) wherever violations are ranked.
SEVERITY_RANK_SQL = (
    "CASE {col} "
    "WHEN 'critical' THEN 0 "
    "WHEN 'high' THEN 1 "
    "WHEN 'medium' THEN 2 "
    "WHEN 'low' THEN 3 "
    "WHEN 'info' THEN 4 "
    "ELSE 5 END"
)
