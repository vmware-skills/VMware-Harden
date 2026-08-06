"""vSphere 9 / VCF 9 STIG catalog helpers + InSpec/Cinc content-sync stub.

harden's STIG integration is *content*, not an API: VCF Operations 9.1
ACC/SPM exposes no public compliance REST endpoint (see
tests/eval/spec/vcf91_compliance.py). This module reads the shipped STIG
baseline YAML and presents its controls as a flat catalog — each control paired
with the ESXi *advanced setting* it governs — and documents (but defers) the
mechanism for importing upstream MITRE InSpec / Cinc Auditor STIG profiles.
"""
from __future__ import annotations

from vmware_harden.baselines.loader import load_builtin

#: Id of the built-in STIG baseline (filename stem under baselines/builtin/).
STIG_BASELINE_ID = "vsphere-stig-v9-subset"

#: Single source of truth mapping each STIG rule to the ESXi advanced-setting key
#: it governs. Kept here rather than parsed from prose so the linkage is explicit
#: and machine-checkable: tests/eval/regression/test_stig_baseline.py asserts
#: (a) these keys equal the baseline's rule ids exactly, and (b) every value is
#: in the verified-settings set in the spec module — so a control can never cite
#: an advanced setting nobody verified.
CONTROL_SETTINGS: dict[str, str] = {
    "stig-esxi9-account-lock-failures": "Security.AccountLockFailures",
    "stig-esxi9-account-unlock-time": "Security.AccountUnlockTime",
    "stig-esxi9-password-quality": "Security.PasswordQualityControl",
    "stig-esxi9-password-history": "Security.PasswordHistory",
    "stig-esxi9-dcui-access": "DCUI.Access",
    "stig-esxi9-shell-interactive-timeout": "UserVars.ESXiShellInteractiveTimeOut",
    "stig-esxi9-shell-timeout": "UserVars.ESXiShellTimeOut",
    "stig-esxi9-dcui-timeout": "UserVars.DcuiTimeOut",
    "stig-esxi9-mob-disabled": "Config.HostAgent.plugins.solo.enableMob",
    "stig-esxi9-suppress-shell-warning": "UserVars.SuppressShellWarning",
    "stig-esxi9-block-guest-bpdu": "Net.BlockGuestBPDU",
    "stig-esxi9-syslog-loghost": "Syslog.global.logHost",
}

#: Verified open-source STIG content harden syncs its catalog against — content,
#: not an API. Mirrors tests/eval/spec/vcf91_compliance.py so runtime callers
#: (CLI/MCP) can surface the routing without importing the test package.
STIG_CONTENT_SOURCES: tuple[str, ...] = (
    "https://github.com/vmware/dod-compliance-and-automation",
    "https://github.com/vmware/vcf-security-and-compliance-guidelines",
)


def stig_catalog() -> list[dict]:
    """Return the STIG baseline's controls as a flat, high-signal catalog.

    Each row is {id, title, severity, category, advanced_setting}. Defensive
    throughout: a rule missing from CONTROL_SETTINGS degrades to an empty
    advanced_setting rather than raising, so a future rule added to the YAML
    without a mapping is still listed (and the regression test flags the gap).
    """
    baseline = load_builtin(STIG_BASELINE_ID)
    catalog: list[dict] = []
    for rule in getattr(baseline, "rules", []):
        rule_id = getattr(rule, "id", "")
        catalog.append(
            {
                "id": rule_id,
                "title": getattr(rule, "title", ""),
                "severity": getattr(rule, "severity", ""),
                "category": getattr(rule, "category", ""),
                "advanced_setting": CONTROL_SETTINGS.get(rule_id, ""),
            }
        )
    return catalog


def describe_content_sync() -> dict:
    """Describe how harden aligns with upstream STIG content (no API dependency).

    Returns a small, self-contained explanation an agent can relay to a user:
    why there is no compliance API to call, where the authoritative STIG content
    lives, the (currently manual / deferred-importer) sync mechanism, and the
    baseline's maturity status — so a scan self-declares that the STIG baseline
    is experimental and its results are not yet authoritative.
    """
    baseline = load_builtin(STIG_BASELINE_ID)
    status = getattr(baseline, "status", None)
    return {
        "compliance_api_available": False,
        "baseline_id": STIG_BASELINE_ID,
        "baseline_status": status,
        "authoritative": status is None,
        "status_caveat": (
            "The STIG baseline is EXPERIMENTAL: its host advanced-setting checks "
            "depend on a real-hardware-gated collector fetch that is not yet "
            "verified end-to-end. If a setting is not collected the rule matches "
            "zero rows and the host reports compliant, so a green result may be a "
            "data gap rather than a pass. Treat findings as indicative, not "
            "authoritative, until the collector is verified against a live "
            "vCenter/ESXi."
        )
        if status is not None
        else None,
        "why_no_api": (
            "VCF Operations 9.1 Automated Configuration Compliance (ACC) / "
            "Security Posture Management (SPM) is UI- and schedule-driven with a "
            "paid Salt engine; it exposes no public compliance REST endpoint. "
            "harden therefore syncs open-source STIG *content* instead of "
            "wrapping a non-existent API."
        ),
        "content_sources": list(STIG_CONTENT_SOURCES),
        "mechanism": (
            "1. Pull the official MITRE InSpec / Cinc Auditor vSphere STIG "
            "profiles from the content source. "
            "2. For each InSpec control, read the ESXi advanced-setting it "
            "asserts and its expected value. "
            "3. Emit an equivalent harden rule (declarative SQL check against "
            "the DuckDB twin's nodes.attrs) into a baseline YAML. "
            "The built-in vsphere-stig-v9-subset baseline is the hand-curated "
            "result of this process for a representative control set."
        ),
        "routing_note": (
            "For continuous, fleet-wide enforcement and automated remediation "
            "use VCF Operations SPM/ACC (UI). harden is the API-scriptable, "
            "DuckDB-persisted, cross-target point-in-time scanner."
        ),
        "importer_status": "deferred",
    }


def import_inspec_profile(profile_path: str) -> dict:
    """Deferred: translate an InSpec/Cinc STIG profile into a harden baseline.

    The full importer is deferred (see references/stig-content-sync.md). It is a
    content transform, not an API call — safe to build later without touching any
    network dependency. Raises NotImplementedError with a teaching next step so a
    caller is never left guessing.
    """
    raise NotImplementedError(
        "InSpec/Cinc profile import is deferred to a future release. For now, "
        "hand-author or override baseline YAML under ~/.vmware-harden/baselines/ "
        "and load it with `vmware-harden baseline import <file>`. See "
        "references/stig-content-sync.md for the mapping mechanism. "
        f"(requested profile: {profile_path})"
    )
