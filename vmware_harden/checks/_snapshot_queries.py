"""Keep aggregate and absence queries within the requested snapshot."""
from contextlib import contextmanager
from types import SimpleNamespace

from vmware_harden.checks.query import execute_query_check


@contextmanager
def snapshot_queries(twin, snapshot_id):
    """Yield a lazy query executor with a connection-local snapshot relation."""
    conn = None

    def query(check):
        nonlocal conn
        if conn is None:
            conn = twin.conn.cursor()
            conn.execute(
                """CREATE TEMP TABLE nodes AS
                SELECT n.* FROM main.nodes AS n
                WHERE EXISTS (
                    SELECT 1 FROM main.node_state AS ns
                    WHERE ns.node_id = n.id AND ns.snapshot_id = ?
                )""",
                [snapshot_id],
            )
        return execute_query_check(SimpleNamespace(conn=conn), check)

    try:
        yield query
    finally:
        if conn is not None:
            conn.close()
