"""Verified spec — VCF 9.1 Security Posture / STIG integration (section C).

Source of truth: the family's verified-endpoints spec, section C
("ACC / Security Posture Management → vmware-harden: KEEP-OWN, no public
compliance API"). Verified 2026-08-06 against the Broadcom VCF Operations 9.1
OpenAPI (343 paths, zero Compliance/Benchmark/Baseline/Posture/Scan classes) and
the open-source DoD/DISA STIG automation content.

The one-line reverification (rerun when a VCF dot-release drops):
    curl -sL <vcf-operations-openapi.json> | grep -oic complian   # expect 0

Why this file exists
--------------------
harden does content/definition work, not endpoint work — but the phantom risk is
the same shape (踩坑 #36 / 形态 #1): a rule that references a *compliance control*
nobody verified silently matches nothing, and a future contributor tempted to
"just wrap ACC" would wire an endpoint that does not exist. This module pins:

1. the *fact* that there is no compliance API to wrap (COMPLIANCE_API_AVAILABLE);
2. the verified open-source STIG *content* sources harden syncs against;
3. the exact set of ESXi advanced-setting controls the STIG baseline may cite —
   any rule mapping to a setting outside this set fails the regression test;
4. endpoint-path fragments that would betray a hallucinated compliance API, so a
   scan of the shipped package can prove none were introduced.
"""

from __future__ import annotations

#: Verdict from section C. There is NO public compliance REST API in VCF
#: Operations 9.1 ACC/SPM — it is UI + schedule + paid Salt engine. harden must
#: not grow an HTTP client against a compliance endpoint; it stays the
#: API-scriptable, DuckDB-persisted, cross-target *scanner* of its own catalog.
COMPLIANCE_API_AVAILABLE: bool = False

#: Broadcom / community open-source STIG content harden aligns its catalog with
#: (content sync, NOT an API dependency). A baseline's ``source`` must be one of
#: these. See references/stig-content-sync.md for the mechanism.
VERIFIED_STIG_CONTENT_SOURCES: tuple[str, ...] = (
    # Official Broadcom/VMware DoD STIG automation: MITRE InSpec / Cinc Auditor
    # profiles + Ansible + PowerCLI + SAF. This is the STIG-specific repo.
    "https://github.com/vmware/dod-compliance-and-automation",
    # vSphere Security Configuration & Hardening Guide (SCG) — the source the
    # sibling scg/cis subsets already cite; STIG controls trace back to it.
    "https://github.com/vmware/vcf-security-and-compliance-guidelines",
)

#: The exact ESXi host *advanced-setting* keys the vSphere STIG line governs and
#: that harden's STIG baseline is permitted to reference. Each is a stable,
#: publicly documented setting (not a fabricated DISA V-ID). A STIG rule whose
#: mapped setting is absent here is treated as a phantom control and fails
#: tests/eval/regression/test_stig_baseline.py.
VERIFIED_STIG_ADVANCED_SETTINGS: frozenset[str] = frozenset(
    {
        "Security.AccountLockFailures",
        "Security.AccountUnlockTime",
        "Security.PasswordQualityControl",
        "Security.PasswordHistory",
        "DCUI.Access",
        "UserVars.ESXiShellInteractiveTimeOut",
        "UserVars.ESXiShellTimeOut",
        "UserVars.DcuiTimeOut",
        "Config.HostAgent.plugins.solo.enableMob",
        "UserVars.SuppressShellWarning",
        "Net.BlockGuestBPDU",
        "Syslog.global.logHost",
    }
)

#: URL-path fragments that only appear if someone wired a hallucinated compliance
#: API against ACC/SPM. The regression test asserts none occur anywhere in the
#: shipped ``vmware_harden`` package. Kept endpoint-shaped (leading slash / path
#: segments) so ordinary domain words like "remediation" or "posture" in prose,
#: model names, or the drift module do not false-positive.
FORBIDDEN_COMPLIANCE_API_MARKERS: tuple[str, ...] = (
    "/suite-api/api/compliance",
    "/api/spm/",
    "/api/acc/",
    "/compliance/benchmark",
    "/compliance/scan",
    "/posture/query",
    "/posture/scan",
    "/remediation/execute",
)

#: Canonical id of the STIG baseline this spec pins.
STIG_BASELINE_ID: str = "vsphere-stig-v9-subset"
