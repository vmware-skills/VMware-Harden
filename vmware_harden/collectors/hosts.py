"""Host inventory collector. Pulls ESXi host data via vmware_aiops."""
import json
from datetime import datetime, timezone

from vmware_harden.collectors.base import Collector


def _fetch_hosts(target: str) -> list[dict]:
    """Fetch host inventory from vCenter. Patched in tests.

    Production wrapper around vmware_aiops; lazy-imports to avoid hard
    dependency at test time.
    """
    from vmware_aiops.ops.host_inventory import list_hosts

    return list_hosts(target)


class HostCollector(Collector):
    """Collect ESXi host inventory and write to Twin."""

    def collect(self, snapshot_id: str, target: str) -> int:
        hosts = _fetch_hosts(target)
        now = datetime.now(timezone.utc)
        for h in hosts:
            self.twin.conn.execute(
                """INSERT INTO nodes (id, type, name, attrs, last_seen_at)
                   VALUES (?, 'host', ?, ?, ?)
                   ON CONFLICT (id) DO UPDATE SET
                       name = excluded.name,
                       attrs = excluded.attrs,
                       last_seen_at = excluded.last_seen_at""",
                [h["id"], h["name"], json.dumps(h), now],
            )
            self.twin.write_node_state(snapshot_id, h["id"], h)
        return len(hosts)
