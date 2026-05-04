"""DuckDB DDL for Estate Digital Twin.

Schema reference: docs/plans/2026-05-03-vmware-harden-design.md §3.
"""

DDL: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS nodes (
        id VARCHAR PRIMARY KEY,
        type VARCHAR NOT NULL,
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
]
