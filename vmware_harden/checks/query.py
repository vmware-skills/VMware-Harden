"""Pure-SQL check execution helper."""
from vmware_harden.baselines.model import QueryCheck
from vmware_harden.store.twin import Twin


def execute_query_check(twin: Twin, check: QueryCheck) -> list[dict]:
    """Run a query check's SQL against the Twin. Returns matched rows as dicts."""
    cursor = twin.conn.execute(check.sql)
    cols = [d[0] for d in cursor.description] if cursor.description else []
    return [dict(zip(cols, row)) for row in cursor.fetchall()]
