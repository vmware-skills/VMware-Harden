"""The advisory catalog presented as a scannable baseline, and its evaluator.

`vmware-harden scan --baseline vmsa-advisories` runs one rule per catalogued
advisory over the collected ESXi hosts and vCenter. Verdicts go to the same
tables the YAML baselines use, so reports, drift, the dashboard and the MCP
tools need no second code path:

* ``affected``                → a violation, with the fix in its evidence
* ``fixed`` / ``not_affected`` → judged, no violation
* ``unknown``                 → a ``rule_node_gap`` row with the reason, and
                                 counted in ``nodes_undetermined``
* ``not_applicable``          → outside the rule's scope (another product)
"""

from dataclasses import dataclass

from vmware_harden.advisories.catalog import load_catalog
from vmware_harden.advisories.match import Component, Verdict, evaluate
from vmware_harden.advisories.model import Advisory, Catalog
from vmware_harden.baselines.model import AdvisoryCheck, Baseline, Remediation, Rule
from vmware_harden.checks.nodescope import is_unmeasured

ADVISORY_BASELINE_ID = "vmsa-advisories"

#: VMware's advisory scale → the engine's severity scale.
_SEVERITY = {"critical": "critical", "important": "high", "moderate": "medium", "low": "low"}

#: Node type → (product, version attr, build attr) the collectors write.
NODE_COMPONENTS: dict[str, tuple[str, str, str]] = {
    "host": ("esxi", "esxi_version", "esxi_build"),
    "vcenter": ("vcenter", "vcenter_version", "vcenter_build"),
}

#: 等保 2.0 三级 安全计算环境·入侵防范 on known vulnerabilities. Quoted in each
#: rule's rationale so a report reader sees which control the result evidences.
_DENGBAO = (
    "等保 2.0 三级（GB/T 22239-2019）安全计算环境·入侵防范："
    "应能发现可能存在的已知漏洞，并在经过充分测试评估后，及时修补漏洞。"
)


def _rationale(adv: Advisory, catalog: Catalog) -> str:
    cves = ", ".join(c.id for c in adv.cves)
    kev = "；已列入 CISA KEV（已被在野利用）" if adv.kev else ""
    return (
        f"{adv.title}（{cves}{kev}）。{_DENGBAO}"
        f"本结果依据离线公告目录（截至 {catalog.as_of.isoformat()}）：未报出不等于没有漏洞，"
        f"该日期之后发布的公告不在目录中。Not finding an advisory here does not mean the "
        f"component is not vulnerable."
    )


def _fixes(adv: Advisory) -> str:
    labels = [f.label for line in adv.affected for f in line.fixed]
    return "、".join(labels) if labels else "（无公开修复版本）"


def _rule(adv: Advisory, catalog: Catalog) -> Rule:
    return Rule(
        id=adv.id,
        title=f"{adv.id}: {adv.title}",
        severity=_SEVERITY[adv.severity],
        category="入侵防范",
        rationale=_rationale(adv, catalog),
        check=AdvisoryCheck(type="advisory", advisory_id=adv.id),
        remediation=Remediation(
            summary=f"升级到修复版本：{_fixes(adv)}",
            manual_steps=(
                "按 vSphere 生命周期管理（vLCM）或补丁流程升级；"
                "先在测试环境验证，再按维护窗口分批升级。"
            ),
            risk="升级需要维护窗口；主机需进入维护模式。",
        ),
    )


def advisory_baseline(catalog: Catalog | None = None) -> Baseline:
    """One rule per catalogued advisory."""
    cat = catalog or load_catalog()
    return Baseline(
        id=ADVISORY_BASELINE_ID,
        name="VMware 安全公告（VMSA）比对",
        version=cat.as_of.isoformat(),
        source="Offline VMSA catalog: vmware_harden/advisories/catalog.yaml",
        applies_to=["host", "vcenter"],
        rules=[_rule(a, cat) for a in cat.advisories],
    )


def _advisory(catalog: Catalog, advisory_id: str) -> Advisory:
    for a in catalog.advisories:
        if a.id == advisory_id:
            return a
    raise KeyError(
        f"{advisory_id} is not in the advisory catalog (as of {catalog.as_of}). "
        f"Run `vmware-harden baseline list` and scan `{ADVISORY_BASELINE_ID}`; "
        "its rules are generated from the catalog."
    )


def covered_node_types(advisory_id: str, catalog: Catalog | None = None) -> list[str]:
    """Node types whose product the advisory covers."""
    adv = _advisory(catalog or load_catalog(), advisory_id)
    return [t for t, (product, _, _) in NODE_COMPONENTS.items() if product in adv.products]


@dataclass(frozen=True)
class NodeVerdict:
    node_id: str
    verdict: Verdict
    version: object
    build: object


def judge_nodes(
    advisory_id: str,
    nodes_by_type: dict[str, list[tuple[str, dict]]],
    catalog: Catalog | None = None,
) -> list[NodeVerdict]:
    """Verdicts for every collected node the advisory applies to.

    ``not_applicable`` nodes are dropped: they are out of the rule's scope.
    An unmeasured node (a host vCenter cannot reach) is unknown whatever its
    record says — nothing it carries is an observation.
    """
    cat = catalog or load_catalog()
    adv = _advisory(cat, advisory_id)
    out: list[NodeVerdict] = []
    for node_type, (product, version_attr, build_attr) in NODE_COMPONENTS.items():
        if product not in adv.products:
            continue
        for node_id, attrs in nodes_by_type.get(node_type, []):
            version, build = attrs.get(version_attr), attrs.get(build_attr)
            if is_unmeasured(attrs):
                verdict = Verdict(
                    "unknown", "host was not reachable; its configuration is vCenter's cached copy"
                )
            else:
                verdict = evaluate(Component(product, version, build), adv, cat)
            if verdict.status != "not_applicable":
                out.append(NodeVerdict(node_id, verdict, version, build))
    return out


def evidence(adv_id: str, nv: NodeVerdict, catalog: Catalog | None = None) -> dict:
    """What a violation row carries for an affected node."""
    cat = catalog or load_catalog()
    adv = _advisory(cat, adv_id)
    return {
        "status": nv.verdict.status,
        "reason": nv.verdict.reason,
        "fixed_in": nv.verdict.fixed_in,
        "version": nv.version,
        "build": nv.build,
        "cves": [c.id for c in adv.cves],
        "kev": adv.kev,
        "catalog_as_of": cat.as_of.isoformat(),
        "sources": list(adv.sources),
    }
