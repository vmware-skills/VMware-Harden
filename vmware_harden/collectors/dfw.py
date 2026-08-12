"""DFW (Distributed Firewall) inventory collector via vmware-nsx-security."""
from vmware_harden.collectors.base import Collector

#: Page size when draining every DFW policy/rule. The sibling list functions
#: default to 50 to protect agent context; a compliance scan needs them all, so
#: it pages explicitly rather than accept a silent 50-item cap.
_PAGE = 200

#: Every ``nodes.attrs`` key this collector can populate for a ``dfw_section``
#: node: the keys ``vmware_nsx_security.ops.dfw_policy.list_dfw_policies``
#: builds, plus the ``name`` stamped by :func:`_shape_dfw`.
PRODUCIBLE_DFW_SECTION_ATTRS: frozenset[str] = frozenset(
    {
        "id",
        "display_name",
        "category",
        "sequence_number",
        "stateful",
        "tcp_strict",
        "rule_count",
        "path",
        "name",
    }
)

#: Same for a ``dfw_rule`` node, from ``list_dfw_rules``. Note ``sources`` and
#: ``destinations`` are plural lists and ``action`` is upper case
#: (``ALLOW``/``DROP``/``REJECT``/``JUMP_TO_APPLICATION``) — baselines that
#: assumed singular keys or lower-case actions were repaired in 1.8.10.
PRODUCIBLE_DFW_RULE_ATTRS: frozenset[str] = frozenset(
    {
        "id",
        "display_name",
        "action",
        "sources",
        "destinations",
        "services",
        "scope",
        "direction",
        "ip_protocol",
        "disabled",
        "logged",
        "sequence_number",
        "path",
        "name",
    }
)


def _fetch_dfw(target: str) -> dict:
    """Fetch every DFW policy (section) + rule for ``target``. Patched in tests.

    Connects with vmware-nsx-security's own ``ConnectionManager``, drains all
    policies, then all rules under each policy, and returns
    ``{"sections": [...], "rules": [...]}`` with each record carrying the
    ``id``/``name`` the Twin requires. Lazy-imported so vmware-nsx-security
    stays an optional collector dependency.
    """
    from vmware_nsx_security.connection import ConnectionManager
    from vmware_nsx_security.ops.dfw_policy import list_dfw_policies, list_dfw_rules

    mgr = ConnectionManager.from_config()
    try:
        client = mgr.connect(target)
        policies = _drain(
            lambda offset: list_dfw_policies(client, limit=_PAGE, offset=offset)
        )
        rules: list[dict] = []
        for policy in policies:
            pid = policy["id"]
            rules.extend(
                _drain(
                    lambda offset, pid=pid: list_dfw_rules(
                        client, pid, limit=_PAGE, offset=offset
                    )
                )
            )
    finally:
        mgr.disconnect_all()
    return {
        "sections": [_shape_dfw(p) for p in policies],
        "rules": [_shape_dfw(r) for r in rules],
    }


def _drain(fetch) -> list[dict]:
    """Collect every ``items`` element across offset pages.

    ``fetch(offset)`` returns one page of the family list envelope. A compliance
    scan must not stop at the API's default page size, so this keeps paging until
    a short (or empty) page signals the end.
    """
    items: list[dict] = []
    offset = 0
    while True:
        page = fetch(offset).get("items", [])
        if not page:
            break
        items.extend(page)
        if len(page) < _PAGE:
            break
        offset += len(page)
    return items


def _shape_dfw(item: dict) -> dict:
    """Stamp a DFW policy/rule with ``name``.

    Policies and rules already carry a stable ``id`` from NSX; they name it
    ``display_name``, which is mapped to the ``name`` the Twin requires. The
    full sibling record (action, sources, destinations, …) is preserved.
    """
    return {**item, "name": item.get("display_name", item.get("id", ""))}


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
