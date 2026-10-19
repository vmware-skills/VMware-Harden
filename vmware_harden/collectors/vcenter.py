"""Collect the vCenter itself as a node: its version and build.

The only reader of this record today is the advisory baseline
(``vmsa-advisories``): a vCenter is a component with its own VMSAs, and no
other collector records its build. A standalone ESXi target answers
``apiType == "HostAgent"`` and yields no record — the host collector covers it.
"""

from vmware_harden.collectors.base import Collector

#: Keys this collector can write, beside ``id``/``name``.
PRODUCIBLE_VCENTER_ATTRS: frozenset[str] = frozenset(
    {"id", "name", "vcenter_version", "vcenter_build", "vcenter_full_name", "api_type"}
)


def shape_about(about: object, target: str) -> list[dict]:
    """One record for a vCenter's ``AboutInfo``; none for anything else.

    A value that could not be read is omitted, never defaulted: an absent
    build leaves the advisory rules unable to judge this vCenter, which is
    the honest answer.
    """
    api_type = getattr(about, "apiType", None)
    if api_type != "VirtualCenter":
        return []
    rec: dict = {
        "id": getattr(about, "instanceUuid", None) or target,
        "name": target,
        "api_type": api_type,
    }
    for attr, key in (
        ("version", "vcenter_version"),
        ("build", "vcenter_build"),
        ("fullName", "vcenter_full_name"),
    ):
        value = getattr(about, attr, None)
        if value not in (None, ""):
            rec[key] = value
    return [rec]


def _fetch_vcenter(target: str) -> list[dict]:
    """Read ``content.about`` for ``target``. Patched in tests.

    REAL-HARDWARE-GATED, like the host collector's fetch: connects with
    vmware-aiops' ``ConnectionManager`` (the collectors extra).
    """
    from vmware_aiops.connection import ConnectionManager

    mgr = ConnectionManager.from_config()
    try:
        si = mgr.connect(target)
        return shape_about(si.content.about, target)
    finally:
        mgr.disconnect_all()


class VCenterCollector(Collector):
    """Collect the vCenter node and write to Twin."""

    def collect(self, snapshot_id: str, target: str) -> int:
        records = _fetch_vcenter(target)
        return self._persist_groups(snapshot_id, target, [(records, "vcenter", "vcenter")])
