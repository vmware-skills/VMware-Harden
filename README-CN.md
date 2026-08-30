<!-- mcp-name: io.github.vmware-skills/vmware-harden -->

# vmware-harden

> **声明**：本项目为社区维护的开源项目，**与 VMware, Inc. 或 Broadcom Inc. 无任何隶属、
> 背书或赞助关系。** "VMware"、"vSphere"、"ESXi"、"NSX" 为 Broadcom 商标。源码以 MIT 许可证
> 公开可审计，见 [github.com/vmware-skills/VMware-Harden](https://github.com/vmware-skills/VMware-Harden)。

[English](README.md) | 中文

AI 原生的 VMware 合规与基线核查工具，`vmware-*` skill 家族成员。

- **对 vSphere 只读**：全部 8 个 MCP 工具均带 `[READ]` 标记，没有任何一个会修改受管的 VMware
  基础设施；`scan_target` 只写本地 twin DB（它自己观测结果的缓存）。详见[只读设计](#只读设计)。

## GA 家族成员（自 v1.5.18 起）

生产可用的合规平台：**9 个内置基线**（CIS ESXi 8.0/9.0、vSphere SCG v8/v9、**等保 2.0 三级**、PCI-DSS 4.0、
**EU NIS2**、**BSI IT-Grundschutz**）、**99 条规则**、多 vCenter Twin、drift 检测、
**LLM Remediation Advisor**、带 8 个受审计工具的 **MCP server**、Web dashboard，以及
`vmware-harden doctor` 环境诊断。

## 快速开始

```bash
# scan 依赖 collectors extra：harden 通过 vmware-aiops / vmware-storage /
# vmware-nsx-security 读取清单，而 `uv tool install` 为每个工具单独建环境——
# 单独安装这些兄弟包，harden 是 import 不到的。
uv tool install "vmware-harden[collectors]"

# 只在已有 twin DB 上出报告，则不需要 collectors：
#   uv tool install vmware-harden

# 列出内置基线
vmware-harden baseline list

# 执行一次扫描
vmware-harden scan --target <vcenter-name> --baseline cis-vmware-esxi-8.0-subset

# 或使用等保 2.0 三级（国内合规独家）
vmware-harden scan --target <vc> --baseline dengbao-2.0-level3-vmware

# 查看结果
vmware-harden report
vmware-harden drift

# 生成修复建议
export ANTHROPIC_API_KEY=...  # 可选；未设置时回落到 mock 模板
vmware-harden advise --all-critical

# Web dashboard
vmware-harden web --port 8080  # → http://127.0.0.1:8080
```

### 读结果：只看 violations 不构成结论

规则只能判定「真的采到了的配置」，而这件事有两种独立的失败方式。**没有任何采集器产出**
该属性的规则，压根不会执行。而**能执行**的规则，仍可能对某一台主机什么都没判定——
那台主机上取回的是空值或 `N/A` 哨兵（主机失联、账号权限不足、该 ESXi 版本没有这个设置）。
两种情况都不算通过：

```
$ vmware-harden report
No violations among the checks that could be made.

16 of 20 rules could not be evaluated — no collector provides the data they
check, so their result is unknown, not compliant. 6 of 8 per-node checks could
not be made across 2 node(s): the rules ran, but the values they read were
missing on those nodes, so those nodes are unknown rather than compliant.
Not evaluated:
  cis-esxi-2.1.1   no collector writes host.ntp_enabled
  ...
Not judged on these nodes (data missing):
  cis-esxi-2.2.1   esx-02    esxi_build
  ...
```

`--format json` 返回 `{"violations": [...], "coverage": {...}}`，MCP 工具返回同样的
`coverage` 块——所以 agent 读到 `violations: 0` 也不能据此判定合规。v1.9.0 之前，
「无人采集」那类规则匹配 0 行并被静默算作通过；v1.10.0 之前，「按节点缺数据」那类同样如此。
详见 RELEASE_NOTES.md。

两份清单对应的处理动作不同：前者等采集器补齐，后者查那台节点的连通性与扫描账号权限。


## 只读设计

vmware-harden 在设计上就是只读的 —— 8 个 MCP 工具全部带 `[READ]` 标记，没有任何一个会修改受管的
VMware 基础设施。`scan_target` 也只写本地 twin DB（`~/.vmware-harden/twin.duckdb`，观测结果的缓存，
不是受管基础设施）。本 skill 从不执行修复，修复一律交由 vmware-pilot。

## 内置基线

| 基线 ID | 规则数 | 适用对象 | 来源 |
|---------|-------|---------|------|
| `cis-vmware-esxi-8.0-subset` | 20 | host | CIS Benchmark v1.0 |
| `vsphere-scg-v8-subset` | 15 | host, vm | [VMware vcf-security-and-compliance-guidelines](https://github.com/vmware/vcf-security-and-compliance-guidelines) |
| `dengbao-2.0-level3-vmware` | 20 | host, vm, datastore, dfw_rule | GB/T 22239-2019 三级 |
| `pci-dss-4.0-vmware` | 10 | host, dfw_rule | PCI-DSS v4.0 |
| `eu-nis2-vmware` | 12 | host, dfw_rule | EU NIS2 指令（第 21/23 条，附件 I） |
| `bsi-itgs-basisabsicherung-vmware` | 10 | host | BSI IT-Grundschutz（OPS.1.1.4 + SYS.1.1） |
| `vsphere-stig-v9-subset` ⚠️ *实验性* | 12 | host | vSphere 9 STIG 对齐的主机高级设置（[DoD/DISA STIG 内容](https://github.com/vmware/dod-compliance-and-automation)）—— 采集路径已在 ESXi 8.0.3 真机验证；9.x 尚未跑过 |
| `cis-vmware-esxi-9.0-subset` | 20 | host | 通过 `extends:` 继承 `cis-vmware-esxi-8.0-subset` |
| `vsphere-scg-v9-subset` | 15 | host, vm | 通过 `extends:` 继承 `vsphere-scg-v8-subset` |

`baseline list` 返回 9 个 ID：上表 7 组含规则的基线（共 **99 条规则**）加两个 v9 别名，别名自身不含规则，解析为其 v8 父基线的规则。

### 等保 2.0 三级（国内合规）

`dengbao-2.0-level3-vmware` 依据 **GB/T 22239-2019《信息安全技术 网络安全等级保护基本要求》第三级**
编写，把标准条款映射为可在 VMware 环境中自动取证的检查项，20 条规则按标准章节组织：

| 标准章节 | 规则数 | 覆盖内容（举例） |
|---------|:-----:|-----------------|
| 8.1.2 网络与通信安全 | 5 | 区域边界访问控制：DFW 默认拒绝策略是否存在、是否残留 ANY-to-ANY 放行规则 |
| 8.1.3 设备和计算安全 | 9 | 主机身份鉴别与访问控制：lockdown 模式、SSH 姿态、DCUI/Shell 超时、远程日志 |
| 8.1.3 恶意代码防范 + 可信验证（VM 级） | 2 | VM 层可信启动与防护相关配置 |
| 8.1.4 应用和数据安全 | 2 | 数据完整性/保密性：存储与传输加密 |
| 8.1.5 安全管理中心 | 1 | 集中审计与日志留存 |
| 8.1.6 安全管理制度 | 1 | 制度落地的可见证据 |

每条规则都带 `rationale`（引用标准原文表述）、`remediation`（含 `manual_steps` 与 `risk` 风险提示）
以及 `review_policy`（高危项要求人工复核 `human_review_required: true`）。因此扫描输出可以直接作为
等保测评的**佐证材料**，而不只是一个通过/失败的布尔值。

规则跨越多个 collector（vCenter 高级设置 + ESXi NTP + NSX DFW）。若只跑了 vCenter collector，
缺少对应采集器时，那些规则没有节点可匹配 —— 这是预期行为，不是误报。另需区分：属性无人采集的规则会记为「无法判定」(`coverage.undetermined`)，报告会点名是哪个属性。

```bash
vmware-harden scan --target <vc> --baseline dengbao-2.0-level3-vmware
vmware-harden report --format json > dengbao-violations.json
```

### VCF 9.0 / 9.1 兼容性

现有基线（`cis-vmware-esxi-8.0-subset`、`vsphere-scg-v8-subset`、`dengbao-2.0-level3-vmware`、
`pci-dss-4.0-vmware`）可以正常扫描 VCF 9.0 / 9.1 集群 —— 多数规则针对的是在 8.x → 9.x 之间保持
稳定的主机高级设置。此外还提供 `cis-vmware-esxi-9.0-subset` 与 `vsphere-scg-v9-subset` 两个基线，
它们通过 `extends:` **逐条继承**对应的 v8 规则（不臆造 v9 专属编号），可直接用于 9.x 环境；
待 CIS / Broadcom 发布正式的 vSphere 9 基准后再替换为官方编号规则。

#### Broadcom 官方参考

- **Security Configuration Guides**：<https://core.vmware.com/security/> —— vSphere SCG v8 / 未来的 v9
- **SDKs**：<https://developer.broadcom.com/sdks> —— VCF Python SDK（通过 REST 获取主机配置）
- **CIS Benchmarks**：<https://www.cisecurity.org/cis-benchmarks/> —— CIS VMware ESXi Benchmark v1.0

## 自定义基线

```bash
vmware-harden baseline validate ./my-strict.yaml
vmware-harden baseline import ./my-strict.yaml --name my-strict-cis
vmware-harden scan --target <vc> --baseline my-strict-cis
```

YAML 支持 `extends:` 从内置基线继承。用户目录下的同名基线优先于内置基线，因此可以复制一份内置基线到
`~/.vmware-harden/baselines/` 再按站点要求覆写个别规则。schema 详见
`skills/vmware-harden/references/cli-reference.md`。

## MCP Server

```bash
vmware-harden mcp  # stdio MCP server（旧入口 vmware-harden-mcp 仍兼容）
```

MCP 客户端配置模板见 `examples/mcp-configs/*.json`。8 个 MCP 工具全部只读：
`list_baselines`、`list_violations`、`get_remediation`、`list_drift_events`、
`get_baseline_rules`、`scan_target`。

> **公司 TLS 代理网络下？** 不要用 `uvx` 启动 MCP server（可能报
> `invalid peer certificate: UnknownIssuer`）。改用 `uv tool install` 装好后的入口
> `vmware-harden mcp`（无需联网 resolve），或 `export UV_NATIVE_TLS=true`。

## 架构

- **Estate Digital Twin** —— 单文件 DuckDB，位于 `~/.vmware-harden/twin.duckdb`。所有 node ID 带
  target 前缀，多 target 并存安全。
- **Collectors** —— 惰性导入兄弟 `vmware-*` skill（无进程 spawn 开销）。所有采集都是 READ，写操作
  一律交由 vmware-pilot。
- **Baseline schema** —— Pydantic v2 严格模式（`extra="forbid"`），支持 `extends:` 继承与用户目录覆盖。
- **Drift** —— 纯 diff 函数，持久化可选；每次扫描后自动运行。
- **Advisor** —— LLM 驱动的 Suggestion 生成；Anthropic provider 带 prompt caching，无 API key
  或测试环境下回落到 mock。
- **Audit** —— 每个 MCP 工具都由家族 vmware-policy 的 `@vmware_tool` 包裹，写入 `~/.vmware/audit.db`。
- **Web** —— FastAPI + Jinja2 + Tailwind/HTMX/ECharts（CDN）。

## 实验室回归测试

```bash
export VMWARE_HARDEN_LAB_TARGET=<your-vc>
pytest tests/eval/regression -v -m lab
```

## 家族成员

- **vmware-aiops** —— 主机清单 + 运维（harden 的 HostCollector 依赖它）
- **vmware-monitor** —— 只读监控对照组
- **vmware-storage** —— 数据存储清单
- **vmware-nsx-security** —— DFW 清单
- **vmware-pilot** —— 执行修复（写操作；不在 harden 职责范围内）
- **vmware-policy** —— `@vmware_tool` 审计装饰器

## GA 验收标准（v1.5.18）

- 221 项测试通过
- Bandit：任意严重级别下 0 issue
- 全部 8 个 MCP 工具均被审计
- SKILL.md ≤ 3000 词，符合家族规范
- SECURITY.md 含 6 个要素 + Broadcom 声明
- 6 组内置基线（99 条规则）
- `vmware-harden doctor` 环境诊断
- `vmware-*` 家族 GA 成员（版本对齐至 1.5.28）

## 参考

- 家族规范：monorepo 根目录 `CLAUDE.md`

## 许可证

MIT
