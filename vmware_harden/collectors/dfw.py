"""DFW (Distributed Firewall) inventory collector via vmware-nsx-security."""
import json
from datetime import datetime, timezone

from vmware_harden.collectors.base import Collector, CollectorError


def _fetch_dfw(target: str) -> dict:
    """Fetch DFW sections + rules from NSX. Patched in tests.

    Returns: {"sections": [...], "rules": [...]}
    """
    from vmware_nsx_security.ops.dfw_inventory import list_dfw

    return list_dfw(target)


class DFWCollector(Collector):
    """Collect DFW sections and rules and write to Twin."""

    def collect(self, snapshot_id: str, target: str) -> int:
        data = _fetch_dfw(target)
        sections = data.get("sections", [])
        rules = data.get("rules", [])
        now = datetime.now(timezone.utc)

        for sec in sections:
            try:
                moref = sec["id"]
                node_name = sec["name"]
            except KeyError as e:
                raise CollectorError(
                    f"DFWCollector: section record missing required field {e}; "
                    f"target={target}, record={sec!r}"
                ) from e
            self._upsert_node(
                snapshot_id, target, moref, node_name, "dfw_section", sec, now
            )

        for r in rules:
            try:
                moref = r["id"]
                node_name = r["name"]
            except KeyError as e:
                raise CollectorError(
                    f"DFWCollector: rule record missing required field {e}; "
                    f"target={target}, record={r!r}"
                ) from e
            self._upsert_node(
                snapshot_id, target, moref, node_name, "dfw_rule", r, now
            )

        return len(sections) + len(rules)

    def _upsert_node(
        self,
        snapshot_id: str,
        target: str,
        moref: str,
        name: str,
        node_type: str,
        attrs: dict,
        now,
    ) -> None:
        node_id = f"{target}:{moref}"
        self.twin.conn.execute("BEGIN TRANSACTION")
        try:
            self.twin.conn.execute(
                """INSERT INTO nodes (id, type, target, name, attrs, last_seen_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT (id) DO UPDATE SET
                       target = excluded.target,
                       name = excluded.name,
                       attrs = excluded.attrs,
                       last_seen_at = excluded.last_seen_at""",
                [node_id, node_type, target, name, json.dumps(attrs), now],
            )
            self.twin.write_node_state(snapshot_id, node_id, attrs)
            self.twin.conn.execute("COMMIT")
        except Exception:
            self.twin.conn.execute("ROLLBACK")
            raise
