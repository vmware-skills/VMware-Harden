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
        attrs JSON,
        first_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
        -- RESERVED: `status` is intentionally unwired. Every violation is
        -- written 'open' and never transitioned; there is no resolve/ack flow
        -- yet (a scan re-derives the full violation set each run). The column
        -- is kept as the schema anchor for a future resolve/acknowledge
        -- workflow — it is NOT a missing-update bug.
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
    """
    -- Per-rule verdict for a scan: was the rule actually able to judge?
    --
    -- Deliberately NOT a row in `violation`. Every consumer of that table
    -- (web dashboard, list_violations, advisor, cli advise) selects from it
    -- expecting violations; writing non-violations there would silently change
    -- what all of them return. Keeping outcomes separate leaves those queries
    -- untouched and makes the new information opt-in.
    --
    -- Both outcomes are recorded, not just 'undetermined': storing only the
    -- bad case leaves "rule evaluated fine" and "scanned by a build that did
    -- not track this" indistinguishable, and a report cannot then state how
    -- much of the baseline it actually covered.
    --
    -- Written per scan rather than derived at render time on purpose: which
    -- attributes are collectable changes between releases, so re-deriving an
    -- old snapshot's coverage under today's vocabulary would relabel history
    -- with facts that were not true when it was taken.
    CREATE TABLE IF NOT EXISTS rule_outcome (
        id VARCHAR PRIMARY KEY,
        snapshot_id VARCHAR NOT NULL,
        baseline_id VARCHAR NOT NULL,
        rule_id VARCHAR NOT NULL,
        -- 'evaluated'    — every attribute it reads is collected; result is real
        -- 'undetermined' — an attribute is uncollected, so it was NOT executed
        outcome VARCHAR NOT NULL,
        reason VARCHAR,
        evaluated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    -- The node half of the same question. `rule_outcome` answers "could this
    -- rule judge anything at all?"; this answers "which nodes did it actually
    -- judge?".
    --
    -- A rule can pass the vocabulary check — every attribute it reads is
    -- declared ACTIVE, some collector demonstrably writes it — and still learn
    -- nothing about a particular host, because on THAT host the value came back
    -- absent (permission denied, the API missing on that build,
    -- PropertyCollector unable to read `config.option`) or as the `N/A`
    -- sentinel `list_hosts` returns for an unreadable property. The rule
    -- matches no row for that host, and no row is what the engine reports as a
    -- pass. Same false-compliance shape as the one 1.9.0 fixed, one level down.
    --
    -- Only the gaps are stored, not every judged pair: a row per (rule, node)
    -- across a large estate is tens of thousands of rows per scan that say
    -- nothing the counts on `rule_outcome` do not already say. The
    -- "was this even tracked?" question that argued for storing both outcomes
    -- at rule level is answered there instead, by `nodes_in_scope` being NULL
    -- on snapshots taken before this release.
    CREATE TABLE IF NOT EXISTS rule_node_gap (
        id VARCHAR PRIMARY KEY,
        snapshot_id VARCHAR NOT NULL,
        baseline_id VARCHAR NOT NULL,
        rule_id VARCHAR NOT NULL,
        node_id VARCHAR NOT NULL,
        -- Comma-separated attribute names that were missing on this node.
        missing_attributes VARCHAR NOT NULL,
        detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
    # Same hot filter as violation: every report scopes outcomes to one snapshot.
    "CREATE INDEX IF NOT EXISTS idx_rule_outcome_snapshot ON rule_outcome(snapshot_id)",
    "CREATE INDEX IF NOT EXISTS idx_rule_node_gap_snapshot ON rule_node_gap(snapshot_id)",
]

#: Columns added to an existing table after it first shipped. `CREATE TABLE IF
#: NOT EXISTS` leaves an already-created table alone, so a user upgrading from
#: 1.9.0 keeps the old `rule_outcome` shape until these run.
#:
#: NULL on the old rows is the intended value and is load-bearing: it is how a
#: snapshot taken before per-node tracking stays distinguishable from one where
#: every node was judged. Do not backfill it with 0.
#:
#: `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` is deliberately not used — the
#: floor in pyproject.toml is duckdb>=0.10 and the clause is not available
#: across that whole range. Applied via an information_schema probe instead
#: (see Twin.init_schema), which works on every version.
ADDED_COLUMNS: list[tuple[str, str, str]] = [
    # (table, column, type) — how many nodes the rule was scoped over ...
    ("rule_outcome", "nodes_in_scope", "INTEGER"),
    # ... and how many of those it could not judge for lack of data.
    ("rule_outcome", "nodes_undetermined", "INTEGER"),
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
