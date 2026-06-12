"""DFW (Distributed Firewall) inventory collector via vmware-nsx-security."""
from vmware_harden.collectors.base import Collector


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
        # Sections + rules share ONE transaction via the base helper.
        return self._persist_groups(
            snapshot_id,
            target,
            [(sections, "dfw_section", "section"), (rules, "dfw_rule", "rule")],
        )
