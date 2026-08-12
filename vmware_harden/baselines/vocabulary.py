"""Canonical attribute vocabulary — the contract between baselines and collectors.

A baseline rule may only read ``nodes.attrs`` keys declared here. Every entry is
keyed by ``(node_type, name)``: the same name can legitimately belong to more
than one node type (``encryption_enabled`` is asked of both a VM and a
datastore, and every node has ``name``/``id``), so a name alone is not an
identity.

Each entry declares whether a collector produces it today:

``Status.ACTIVE``
    A collector writes this key. Rules reading it judge real configuration.

``Status.PENDING``
    Declared and intended, but no collector writes it yet. A rule reading it
    matches zero rows — which reads as *compliant* — so the check runner must
    refuse to execute such a rule and report it as undetermined rather than let
    it silently pass. ``source`` records where the value will come from when the
    collector is written.

This exists because 76 of 99 builtin rules read keys no collector produced, and
the only guard was a parity test that loaded one baseline. See
``design/LLD-harden-baseline-collector-contract.md`` and BACKLOG P0 [H-1].

Synonym consolidation is deliberately *not* done here. Several pending names are
almost certainly the same underlying fact (see ``aliases``), but collapsing them
requires checking node type, SQL value semantics and collection path one by one —
a first attempt at it merged six pairs wrongly. Only pairs verified in both
directions carry ``aliases``; the rest stay independent until design step 4
reviews them.
"""

from dataclasses import dataclass
from enum import Enum

from vmware_harden.collectors.datastores import PRODUCIBLE_DATASTORE_ATTRS
from vmware_harden.collectors.dfw import (
    PRODUCIBLE_DFW_RULE_ATTRS,
    PRODUCIBLE_DFW_SECTION_ATTRS,
)
from vmware_harden.collectors.hosts import PRODUCIBLE_HOST_ATTRS
from vmware_harden.collectors.vms import PRODUCIBLE_VM_ATTRS


class Status(str, Enum):
    ACTIVE = "active"
    PENDING = "pending-collector"


@dataclass(frozen=True)
class Attribute:
    """One ``(node_type, name)`` pair a baseline rule is allowed to read."""

    name: str
    node_type: str
    status: Status
    description: str
    #: Where the value comes from — pyVmomi path or REST field. The instruction
    #: for whoever implements the collector. ``待核实`` where not yet confirmed;
    #: never invent one.
    source: str
    #: Allowed values for an enum-valued attribute. Empty means unconstrained.
    #: A rule comparing against a literal outside this set can never match —
    #: three DFW rules shipped comparing lower-case actions against NSX's
    #: upper-case values and fired on every estate.
    #:
    #: Only declared once the real values are known — in practice only for
    #: ACTIVE attributes. Guessing the domain of an uncollected attribute would
    #: fail rules on speculation and pin a form the eventual collector may
    #: contradict; that gap between assumed and actual values is the defect this
    #: module exists to prevent, so it must not be reintroduced here.
    value_domain: tuple[str, ...] = ()
    #: Confirmed other spellings of this same fact. Migration aid only: rules
    #: must use the canonical name. Never used for runtime rewriting — an
    #: implicit read-side rename would mean the SQL says one thing and queries
    #: another (踩坑 #38).
    aliases: tuple[str, ...] = ()


def _a(
    node_type: str,
    producible: frozenset[str],
    name: str,
    description: str,
    source: str,
    value_domain: tuple[str, ...] = (),
) -> Attribute:
    """Declare an ACTIVE attribute, asserting the collector really produces it.

    Guards against this file drifting away from the collectors it describes: a
    key renamed in a collector but left ACTIVE here fails at import.
    """
    if name not in producible:
        raise AssertionError(
            f"vocabulary declares {node_type}.{name} ACTIVE but the collector's "
            f"producible set does not contain it — update one of the two."
        )
    return Attribute(
        name=name,
        node_type=node_type,
        status=Status.ACTIVE,
        description=description,
        source=source,
        value_domain=value_domain,
    )


def _p(
    node_type: str,
    name: str,
    description: str,
    source: str,
    aliases: tuple[str, ...] = (),
) -> Attribute:
    """Declare a PENDING attribute — intended, but no collector writes it yet."""
    return Attribute(
        name=name,
        node_type=node_type,
        status=Status.PENDING,
        description=description,
        source=source,
        aliases=aliases,
    )


_HOST = PRODUCIBLE_HOST_ATTRS
_VM = PRODUCIBLE_VM_ATTRS
_DS = PRODUCIBLE_DATASTORE_ATTRS
_RULE = PRODUCIBLE_DFW_RULE_ATTRS
_SECTION = PRODUCIBLE_DFW_SECTION_ATTRS

#: ESXi advanced settings, fetched in one batched OptionManager call.
_ADV = "HostSystem.config.option"
#: Host services (ssh/ntp) expose both a start policy and a running flag.
_SVC = "HostServiceSystem.serviceInfo.service"
#: Standard vSwitch security policy triplet.
_VSW = "HostSystem.config.network.vswitch.spec.policy.security"

_ENTRIES: tuple[Attribute, ...] = (
    # --- host: ACTIVE (STIG advanced settings + base inventory) --------------
    _a("host", _HOST, "account_lock_failures", "失败登录锁定阈值",
       f"{_ADV} Security.AccountLockFailures"),
    _a("host", _HOST, "account_unlock_time", "账号解锁等待秒数",
       f"{_ADV} Security.AccountUnlockTime"),
    _a("host", _HOST, "password_quality_control", "密码复杂度策略串",
       f"{_ADV} Security.PasswordQualityControl"),
    _a("host", _HOST, "password_history", "密码历史保留数",
       f"{_ADV} Security.PasswordHistory"),
    _a("host", _HOST, "dcui_access", "允许 DCUI 访问的账号",
       f"{_ADV} DCUI.Access"),
    _a("host", _HOST, "shell_timeout_seconds", "ESXi Shell 交互超时",
       f"{_ADV} UserVars.ESXiShellInteractiveTimeOut"),
    _a("host", _HOST, "esxi_shell_timeout_seconds", "ESXi Shell 空闲超时",
       f"{_ADV} UserVars.ESXiShellTimeOut"),
    _a("host", _HOST, "dcui_timeout_seconds", "DCUI 空闲超时",
       f"{_ADV} UserVars.DcuiTimeOut"),
    _a("host", _HOST, "mob_enabled", "Managed Object Browser 是否启用",
       f"{_ADV} Config.HostAgent.plugins.solo.enableMob"),
    _a("host", _HOST, "suppress_shell_warning", "是否抑制 Shell 告警",
       f"{_ADV} UserVars.SuppressShellWarning"),
    _a("host", _HOST, "block_guest_bpdu", "是否阻断 guest BPDU",
       f"{_ADV} Net.BlockGuestBPDU"),
    _a("host", _HOST, "syslog_remote_host", "远端 syslog 目标",
       f"{_ADV} Syslog.global.logHost"),
    _a("host", _HOST, "esxi_build", "ESXi build 号（字符串，比较前须 CAST）",
       "HostSystem.config.product.build"),

    # --- host: PENDING — access control --------------------------------------
    # value_domain omitted on purpose: the collector is unwritten, so whether it
    # stores the pyVmomi enum (lockdownNormal) or a normalised form is undecided.
    _p("host", "lockdown_mode", "锁定模式（字符串枚举）",
       "HostSystem.config.lockdownMode"),
    _p("host", "lockdown_mode_enabled", "锁定模式是否启用（布尔写法）",
       "HostSystem.config.lockdownMode，判非 disabled"),
    _p("host", "lockdown_exceptions_count", "锁定模式例外账号数（数值）",
       "HostAccessManager.QueryLockdownExceptions"),
    _p("host", "ad_joined", "是否加入 AD 域",
       "HostSystem.config.authenticationManagerInfo → domainMembershipStatus"),
    _p("host", "named_admin_accounts", "具名管理员账号数/列表",
       "HostLocalAccountManager + HostAuthorizationManager（待核实）"),
    _p("host", "shared_root_in_use", "是否在共用 root 账号",
       "会话审计推断（待核实，可能不可采）"),
    _p("host", "default_admin_disabled", "默认管理员账号是否禁用",
       "HostLocalAccountManager（待核实）"),

    # --- host: PENDING — remote access ---------------------------------------
    _p("host", "ssh_enabled", "SSH 服务是否设为随主机启动",
       f"{_SVC}[TSM-SSH].policy"),
    _p("host", "ssh_running", "SSH 服务当前是否运行",
       f"{_SVC}[TSM-SSH].running"),
    _p("host", "root_ssh_enabled", "是否允许 root 直接 SSH 登录",
       "sshd_config PermitRootLogin（无公开 API，待核实采集方式）"),
    _p("host", "root_ssh_key_auth", "root 是否配置了 SSH 公钥认证",
       "sshd authorized_keys（待核实）",
       aliases=("root_ssh_key_auth_enabled",)),
    _p("host", "root_ssh_key_auth_enabled", "同 root_ssh_key_auth（别名写法）",
       "见 root_ssh_key_auth"),

    # --- host: PENDING — time, logging, audit --------------------------------
    _p("host", "ntp_enabled", "NTP 服务是否运行", f"{_SVC}[ntpd].running"),
    _p("host", "ntp_service_policy_on", "NTP 服务是否随主机启动",
       f"{_SVC}[ntpd].policy"),
    _p("host", "ntp_servers", "已配置的 NTP 服务器列表",
       "HostSystem.config.dateTimeInfo.ntpConfig.server"),
    _p("host", "persistent_logs", "日志是否落到持久存储",
       f"{_ADV} Syslog.global.logDir（判非 scratch）"),
    _p("host", "audit_retention_days", "审计记录保留天数",
       f"{_ADV} Syslog.global.auditRecord.storageCapacity（待核实）",
       aliases=("audit_log_retention_days",)),
    _p("host", "audit_log_retention_days", "同 audit_retention_days（别名写法）",
       "见 audit_retention_days"),

    # --- host: PENDING — platform integrity ----------------------------------
    _p("host", "secure_boot_enabled", "主机 UEFI Secure Boot 是否启用",
       "HostSystem.capability / runtime bootDeviceInfo（待核实）",
       aliases=("host_secure_boot",)),
    _p("host", "host_secure_boot", "同 secure_boot_enabled（别名写法）",
       "见 secure_boot_enabled"),
    _p("host", "host_tpm_attested", "TPM 证明是否通过",
       "HostSystem.runtime.tpmPcrValues / attestation（待核实）"),
    # value_domain omitted: the API form (community) and the esxcli form
    # (CommunitySupported) differ; which lands in attrs is the collector's call.
    _p("host", "image_profile_acceptance", "镜像 profile 接受级别",
       "HostImageConfigManager.HostImageConfigGetAcceptance",
       aliases=("vib_acceptance",)),
    _p("host", "vib_acceptance", "同 image_profile_acceptance（别名写法）",
       "见 image_profile_acceptance"),
    _p("host", "nx_enabled", "NX/XD 位是否启用", "HostSystem.capability（待核实）"),
    _p("host", "patch_status", "补丁合规状态",
       "vLCM software/compliance（见 BACKLOG [S-5]）"),

    # --- host: PENDING — crypto ----------------------------------------------
    _p("host", "tls_min_version", "最低 TLS 版本",
       f"{_ADV} UserVars.ESXiVPsDisabledProtocols 反推（待核实）"),
    _p("host", "encrypted_vmotion", "vMotion 加密设置",
       "HostSystem.config.vmotion / VM 级 migrateEncryption（待核实）",
       aliases=("vmotion_encryption",)),
    _p("host", "vmotion_encryption", "同 encrypted_vmotion（别名写法）",
       "见 encrypted_vmotion"),
    _p("host", "datastore_encryption", "主机侧存储加密是否启用",
       "HostSystem.config.cryptoState（待核实）"),
    _p("host", "vsan_enabled", "vSAN 是否启用", "HostVsanSystem.config.enabled"),
    _p("host", "vsan_encryption_enabled", "vSAN 静态加密是否启用",
       "VsanClusterConfig dataEncryptionConfig（待核实）"),

    # --- host: PENDING — networking ------------------------------------------
    _p("host", "mgmt_vmk_isolated", "管理 vmk 是否与业务网隔离",
       "HostSystem.config.network.vnic + portgroup VLAN"),
    _p("host", "mgmt_isolated", "管理网是否隔离（另一写法）", "见 mgmt_vmk_isolated"),
    _p("host", "mgmt_vlan_tagged", "管理网是否打了 VLAN tag",
       "HostSystem.config.network.portgroup.spec.vlanId"),
    _p("host", "vswitch_promiscuous_mode", "标准 vSwitch 混杂模式",
       f"{_VSW}.allowPromiscuous"),
    _p("host", "forged_transmits", "标准 vSwitch 伪造发送", f"{_VSW}.forgedTransmits"),
    _p("host", "mac_address_changes", "标准 vSwitch MAC 变更", f"{_VSW}.macChanges"),
    _p("host", "standard_vswitch_count", "标准 vSwitch 数量",
       "len(HostSystem.config.network.vswitch)"),
    _p("host", "firewall_enabled", "ESXi 防火墙默认策略是否启用",
       "HostSystem.config.firewall.defaultPolicy"),

    # --- host: PENDING — not a vSphere fact ----------------------------------
    _p("host", "console_keyboard", "DCUI 键盘布局",
       "待核实（CIS 引用，未找到对应 API）"),
    _p("host", "backup_policy_present", "是否存在备份策略",
       "非 vSphere 事实——需外部输入或人工确认（待定是否可采）"),

    # --- vm -------------------------------------------------------------------
    _a("vm", _VM, "tools_status", "VMware Tools 运行状态（字符串枚举，非布尔）",
       "guest.toolsRunningStatus",
       value_domain=("guestToolsRunning", "guestToolsNotRunning",
                     "guestToolsExecutingScripts", "N/A")),
    _p("vm", "secure_boot", "VM EFI Secure Boot（VM 级，区别于 host）",
       "VirtualMachine.config.bootOptions.efiSecureBootEnabled"),
    _p("vm", "hw_version_int", "VM 硬件版本号（数值）",
       "VirtualMachine.config.version 去掉 vmx- 前缀"),
    _p("vm", "isolation_copy_disabled", "是否禁用复制粘贴",
       "config.extraConfig isolation.tools.copy.disable"),
    _p("vm", "encryption_enabled", "VM 是否加密",
       "VirtualMachine.config.keyId 是否存在"),
    _p("vm", "tags", "VM 标签", "vSphere Tagging REST 或 NSX tag（待定归属）"),

    # --- datastore ------------------------------------------------------------
    _p("datastore", "encryption_enabled", "数据存储是否加密",
       "vSAN dataEncryptionConfig / VMFS 无对应字段（待核实）"),

    # --- dfw_rule -------------------------------------------------------------
    _a("dfw_rule", _RULE, "action", "DFW 规则动作（大写）", "NSX rules → action",
       value_domain=("ALLOW", "DROP", "REJECT", "JUMP_TO_APPLICATION")),
    _a("dfw_rule", _RULE, "sources", "源组列表（复数）", "NSX rules → source_groups"),
    _a("dfw_rule", _RULE, "destinations", "目的组列表（复数）",
       "NSX rules → destination_groups"),
    _p("dfw_rule", "section_name", "规则所属策略（section）名",
       "需在 DFWCollector 落 rule 时带上父 policy 的 display_name"),
)


#: The vocabulary, keyed by ``(node_type, name)``.
VOCABULARY: dict[tuple[str, str], Attribute] = {
    (entry.node_type, entry.name): entry for entry in _ENTRIES
}

#: Producible key sets per node type, for callers that need the collector view.
PRODUCIBLE_BY_NODE_TYPE: dict[str, frozenset[str]] = {
    "host": _HOST,
    "vm": _VM,
    "datastore": _DS,
    "dfw_rule": _RULE,
    "dfw_section": _SECTION,
}


def lookup(node_type: str, name: str) -> Attribute | None:
    """Return the declared attribute, or ``None`` if the pair is not declared."""
    return VOCABULARY.get((node_type, name))


def is_active(node_type: str, name: str) -> bool:
    """True only if a collector writes this key today."""
    entry = VOCABULARY.get((node_type, name))
    return entry is not None and entry.status is Status.ACTIVE


def suggest(node_type: str, name: str) -> str:
    """Best-effort hint for an undeclared key, for teaching error messages."""
    same_name = sorted(nt for (nt, n) in VOCABULARY if n == name)
    if same_name:
        return f"'{name}' 存在于节点类型 {same_name}，但不属于 '{node_type}'"
    for (nt, n), entry in VOCABULARY.items():
        if nt == node_type and name in entry.aliases:
            return f"'{name}' 是 '{n}' 的历史别名，请改用 '{n}'"
    near = sorted(n for (nt, n) in VOCABULARY if nt == node_type and (n in name or name in n))
    if near:
        return f"是否想写 {near}？"
    return "该属性未在 vocabulary.py 中声明；若确为新采集项，请先在那里登记"
