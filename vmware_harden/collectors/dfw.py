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

        node_rows: list[list] = []
        state_rows: list[tuple[str, dict]] = []
        for sec in sections:
            try:
                moref = sec["id"]
                node_name = sec["name"]
            except KeyError as e:
                raise CollectorError(
                    f"DFWCollector: section record missing required field {e}; "
                    f"target={target}, record={sec!r}"
                ) from e
            node_id = f"{target}:{moref}"
            node_rows.append(
                [node_id, "dfw_section", target, node_name, json.dumps(sec), now]
            )
            state_rows.append((node_id, sec))

        for r in rules:
            try:
                moref = r["id"]
                node_name = r["name"]
            except KeyError as e:
                raise CollectorError(
                    f"DFWCollector: rule record missing required field {e}; "
                    f"target={target}, record={r!r}"
                ) from e
            node_id = f"{target}:{moref}"
            node_rows.append(
                [node_id, "dfw_rule", target, node_name, json.dumps(r), now]
            )
            state_rows.append((node_id, r))

        # One transaction + executemany for sections + rules together: large
        # DFW inventories used to issue one commit per section/rule.
        self.twin.conn.execute("BEGIN TRANSACTION")
        try:
            if node_rows:
                self.twin.conn.executemany(
                    """INSERT INTO nodes (id, type, target, name, attrs, last_seen_at)
                       VALUES (?, ?, ?, ?, ?, ?)
                       ON CONFLICT (id) DO UPDATE SET
                           target = excluded.target,
                           name = excluded.name,
                           attrs = excluded.attrs,
                           last_seen_at = excluded.last_seen_at""",
                    node_rows,
                )
            self.twin.write_node_states(snapshot_id, state_rows)
            self.twin.conn.execute("COMMIT")
        except Exception:
            self.twin.conn.execute("ROLLBACK")
            raise

        return len(sections) + len(rules)
