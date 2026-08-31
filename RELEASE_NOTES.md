## v1.10.6 — the test suite runs on a non-UTF-8 machine, and the guardrail tests with it


**The suite now runs on a cp936 machine.** Round 3 of the VCF 9 field testing ran
on Windows Server 2025 with locale cp936. Across the family four repos' suites --
1687 tests -- never executed at all, dying at collection reading our own UTF-8
sources, and 101 more failed the same way. Most of those were the tests that
verify the destructive-operation guardrails: the guardrails were fine, the tests
that check them could not open a file. On the UTF-8 CI every one of them was
green. A security test that cannot run is not a security test.

Every text read and write here names its encoding now, `tests/` included -- the
previous round fixed only the package, which is why this came back. A gate in
`family_smoke` scans both trees by AST, and the whole family's suites were re-run
under an ASCII locale to confirm: 15 of 15 green, from 1 of 15.

**`--help` no longer dies on a console that cannot encode it.** On any console
whose encoding cannot carry the characters in our own help text, `--help` exited
with a `UnicodeEncodeError` traceback -- unavailable exactly on the machines
where it is most needed. Four repos were affected; the handler is now relaxed in
all fifteen so a glyph degrades instead of killing the command.

**Its environment resolver no longer answers for other skills.**
`set_environment_resolver` wrote one process-global slot and twelve servers
registered into it at import time, so the last one won for all of them --
measured taking a `freeze-production-writes` rule from DENY to ALLOW on another
skill's production target. Registration is keyed by skill now (requires
vmware-policy 1.12.0).

**Unknown tool arguments are refused instead of dropped.** The schema declared
`additionalProperties: false` and the runtime accepted them anyway, so a filter
argument whose name a model guessed wrong returned the *unfiltered* result with
nothing to indicate anything had been discarded. Fixed in vmware-policy 1.12.0
and in force here.

Requires vmware-policy 1.12.0.

## v1.10.5 — the doctor counted baselines it had never opened

Baselines are read as UTF-8, and the doctor counts the ones that parse. On a
cp936 host all nine shipped baselines failed to load — including the 等保 2.0
baseline, the one that exists for that locale — while `doctor` reported "9
loaded", because it was counting filenames it had never opened.

**The `vmware-policy` floor moves to >=1.11.0.** Policy 1.11.0 stops the engine
failing open: on a host whose locale is not UTF-8, reading `rules.yaml` raised a
decode error that was swallowed, and a `freeze-production-writes` rule came back
ALLOW. No new API is used here, so the floor could have stayed — it is raised
because leaving it low means a user resolving 1.10.0 keeps the permissive engine
and the fix never reaches them. One behaviour travels with it: on a host whose
rules file cannot be read, operations move from all-allowed to all-denied.
`VMWARE_POLICY_DISABLED=1` is checked above the rules, so the escape hatch does
not itself depend on them loading.

Also in this release: the suite no longer appends to the operator's real
`~/.vmware/audit.db`. It held over 30,000 rows dominated by tool names nobody
had invoked, including 1,400 entries for a destructive operation that never
happened — an audit trail carrying test fiction cannot answer the question it is
kept for.

## v1.10.4 — the schema an agent reads now carries the descriptions

Parameter descriptions reach the JSON schema for the first time. An MCP client
sees the schema, not the docstring, and this repo's coverage of `description`
and `additionalProperties` was 0% — while nearly every parameter was already
described in an `Args:` block no client ever receives.

Measured on a real VCF 9.1 estate, the gap produced a silent failure with no
error at any stage: a parameter name guessed wrong is discarded and the tool
returns the full unfiltered result; a value guessed wrong (`power_state=
"running"`) returns 0 rows where there were 11.

vmware-policy 1.10.0's `describe_tool_parameters` copies what is already
written, so the docstring is now load-bearing and the two cannot drift apart. It
removes the `Args:` block from the description once copied — both travel in
every `tools/list` response, so leaving it bills the same sentences twice
against the manifest's token budget. `additionalProperties` is closed: an open
schema is room for a model to invent arguments that are then silently
discarded, which is the other half of the same failure.

**The `vmware-policy` floor moves to >=1.10.0.** Older releases have no
`describe_tool_parameters`, and resolving one gives an ImportError at server
start rather than a missing feature.

Also in this release: every tool parameter is documented for the first time, and
the docstrings that now feed the schema were written by reading the code rather
than the parameter names.

## v1.10.3 — a compliance report that certified four machines it could not talk to

Found against a real VCF 9.1 estate where four of eight ESXi hosts were
`notResponding`.

**The STIG/BSI scan reported 8 HIGH violations that were never observed.**
vCenter answers `config.option`, `config.service` and `config.product` for a
host it has lost contact with, out of its own cache, with no error and no
marker — so the collector wrote last-known values into `nodes.attrs`, the
baseline SQL read them as measurements, and the same host appeared in both the
violations list and the missing-data list at once. A compliance report's whole
claim is that it looked.

The engine already knew the right answer — a node whose attributes are absent is
a gap, not a pass — and it never fired, because the attributes were not absent,
they were stale. Unreachable hosts now keep only their identity and their
connection state. That alone moves the phantom rather than removing it
(`syslog_remote_host IS NULL` fires on a host with no data at all), so such a
node is marked unmeasured and the runner refuses findings against it — unless
every attribute the rule reads is one the record still carries. "This host is
not responding" is a real finding about an unmeasured host; "this host has no
remote syslog" is not. Twelve violations became six, all on the reachable host,
which has the identical configuration and is still flagged.

**`scan_target` wrote six lines of progress to stdout**, which under MCP stdio
is the exclusive JSON-RPC channel — protocol frames were being corrupted in a
real session. Progress now goes to a caller-supplied sink: the CLI passes its
echo, the MCP path passes nothing, and the *default is silence*, because
forgetting on a terminal loses text while forgetting on the MCP surface breaks
the protocol. The guard captures file descriptor 1 around a real dispatch of
every tool, so a C-level write counts too.

**`doctor` checked none of the things it was offered as the remedy for.** Seven
messages point at it, several reached by a scan that failed on connectivity,
credentials or a wrong target name — and it checked no target, no connectivity
and no authentication, then printed "All checks passed". It now lists the
configured targets and logs into every one of them, with `--target` to check
just one.

**The collector install instruction did not work when followed.** The error said
`uv tool install vmware-aiops`, which creates a separate environment harden
cannot import from — so following it failed identically. Every remedy now says
`uv tool install "vmware-harden[collectors]"` and explains why, verified in a
sandboxed tool directory. The commands live in one module so the regression ties
each *printed* remedy to the extras in the built metadata.

Also: two lab-marked integration tests carried stale assertions (a singular
collector label, and a JSON report that has been an object since v1.9.0), both
reproduced at unmodified HEAD against a live vCenter before being rewritten.

## v1.10.2 — NTP, SSH and firewall are collected now, so their rules are judged

A real compliance scan reported "16 of 20 rules could not be evaluated", each
naming the fact it wanted: `no collector writes host.ntp_enabled`,
`host.ssh_running`, `host.firewall_enabled`. The baselines already declared where
each comes from — `baselines/vocabulary.py` names
`HostServiceSystem.serviceInfo.service[ntpd].running` and its siblings — so what
was missing was the collector, not the design.

Six attributes now come from the same batched PropertyCollector pass that
already fetched the STIG advanced settings, so this costs no extra round trip:
`ntp_enabled`, `ntp_service_policy_on`, `ntp_servers`, `ssh_running`,
`ssh_enabled`, `firewall_enabled`.

Nine rules across five frameworks moved from "cannot be evaluated" to judged —
CIS ESXi 8.0, BSI IT-Grundschutz, 等保 2.0 level 3, and PCI-DSS 4.0. On the CIS
subset that is 16 unevaluated down to 12; across all builtin baselines, 29
evaluable rules up to 38.

**A fact that could not be read is still omitted, never defaulted.** ESXi reports
the services it has, and a build without ntpd simply omits it; writing
`ntp_enabled: false` there would report a violation for something nobody
measured, which is the defect v1.9.0 was released to remove. `ntp_servers` is
the one place empty means something — time sync configured with nothing to sync
to is a finding — so `[]` is recorded and only an unreadable `dateTimeInfo` is
omitted.

Verified against a live vCenter 8.0.3: all six facts populated from the real
host (NTP running against 192.168.60.74, SSH stopped, firewall on), and the four
newly-live CIS rules judged against that data rather than against nothing.

### Also in v1.10.2 — three findings from the MCP-side hardware round

- **`scan_target` no longer writes to stdout.** Under the MCP stdio transport
  stdout is the JSON-RPC channel, and the scan's six progress lines were landing
  inside protocol frames — reproduced as frame corruption in a real session.
  Progress now goes to a caller-supplied sink: `vmware-harden scan` passes one
  and prints exactly what it always printed, the MCP tool passes none and is
  silent. All eight tools are swept by a test that captures file descriptor 1.
- **Install instructions name `vmware-harden[collectors]`.** Every message that
  told a user to run `uv tool install vmware-aiops` was an instruction that
  fails when followed: `uv tool install` isolates each tool's environment, so
  the collector landed where harden cannot import it from. The doctor, the
  scan's `CollectorDependencyError`, the pilot client, both READMEs, SKILL.md
  and the setup guide now name the extra that installs into harden's own
  environment.
- **`vmware-harden doctor` stops calling it a pass while a collector is
  missing.** "All checks passed (5 warning(s))" is now "No errors. 5 warning(s)
  above — each names something harden cannot do until it is resolved." Exit code
  is unchanged (0 unless there is an error).

The two `lab`-marked regressions, which only run against a real vCenter, were
themselves stale and failed on the estate: the scan progress line says
"Collected 1 host entities" (singular) where the test looked for `hosts`, and
the JSON report has been `{"violations": …, "coverage": …}` since v1.9.0 where
the test still required a bare list. Both now assert what the code does, and
pass against a live vCenter 8.0.3 and a standalone ESXi.

## v1.10.1 — teaching messages arrived under a stack trace

`vmware-harden scan` against a host missing a collector dependency printed a
Rich traceback, with the useful part underneath it: which package is missing,
the command to install it, and the fact that the snapshot was marked failed and
excluded from reports so it cannot be mistaken for a clean scan.

Nine of the family's fifteen repos wrap their CLI so a domain error prints as
one line. This one exposed the Typer app directly as its console script, so
there was nowhere for that to happen. Adds a `main()` wrapper.

Only `CollectorError` and `CollectorDependencyError` are translated — a
`NameError` is a bug in this codebase and dressing it up as user-facing advice
would hide it. `KeyboardInterrupt` exits 130 with one line: a scan runs for
minutes, and interrupting one is a decision, not a crash.

Found by running a real compliance scan against a live vCenter.

## v1.10.0 (2026-08-13) — 按节点判定：规则跑了，不等于每台主机都被判定了

> **v1.9.0 修的是「没人采集这个属性」。这一版修的是「采集了，但这台主机上是空的」。**
> 合规率会再降一次。同样是修正，不是回归。

### 发生了什么

v1.9.0 之后，一条规则只要它读的每个属性都有采集器声明产出，就会被执行，结果算数。
**这个判定是规则级的。** 属性声明了、采集器也真跑了，但在**某一台**主机上取回空值时
（主机失联、扫描账号权限不足、该 ESXi 版本没有这个设置），规则对那台主机匹配 0 行——
而 0 行，还是被当作通过。

和 v1.9.0 修掉的是同一个形态，低一层：

```
规则级（v1.9.0 修）  没有采集器产出 password_quality_control  → 规则不执行，记 undetermined
节点级（本版修）      采集器产出了，但 esx-02 上取回 "N/A"     → 规则执行了，esx-02 静默通过
```

`list_hosts` 属性取不到时返回字符串 `"N/A"`。v1.9.0 把基线里 50 处 `CAST` 改成
`TRY_CAST`，避免一台主机的 `"N/A"` 抛异常终止整次扫描——但改完之后那台主机的值变成
NULL、规则不匹配，**它就静默通过了**。这一版补上的正是这半边。

### 你会看到的变化

```
# 此前
No violations among the rules that could be evaluated.
16 of 20 rules could not be evaluated — ...

# 现在
No violations among the checks that could be made.

16 of 20 rules could not be evaluated — ... 6 of 8 per-node checks could not be
made across 2 node(s): the rules ran, but the values they read were missing on
those nodes, so those nodes are unknown rather than compliant.
Not evaluated:
  cis-esxi-2.1.1   no collector writes host.ntp_enabled
  ...
Not judged on these nodes (data missing):
  cis-esxi-2.2.1   esx-02    esxi_build
  cis-esxi-3.1.1   esx-02    syslog_remote_host
  ...
```

两份清单对应的处理动作不同，所以分开列：上面那份等采集器补齐，下面那份查那台节点的
连通性与扫描账号权限。

`coverage` 块新增字段（CLI JSON / MCP `list_violations` / `scan_target` / web 一致）：

| 字段 | 含义 |
|---|---|
| `node_checks_evaluated` / `node_checks_undetermined` / `node_checks_total` | 按 `(规则, 节点)` 计的判定对数。一台主机缺一个属性、四条规则读它 = 4 对未判定 |
| `nodes_affected` | 出现缺口的**不同节点**数（上面那三个是判定对数，不是主机数） |
| `undetermined_node_checks` | `[{rule, node, missing}]`，分页，配 `undetermined_node_checks_truncated` |
| `rules_without_targets` | 规则跑了、无违规、但它那个类型一个节点都没有——「0 违规」覆盖的是空集 |
| `node_tracked` | `false` = 该快照由 1.10.0 之前的版本扫的，没量过按节点 |

**`coverage.complete` 的含义变严**：现在还要求「每条跑了的规则在其作用域内的每个节点上
都得出了结论」，且要求 `node_tracked`。1.9.0 扫出来的旧快照会显示为 not complete —— 那不是
它变差了，是它从来没量过这一维度。重扫即可。

### 判定规则（三条容易搞反的）

- **空字符串不是缺失。** `syslog_remote_host = ''` 是采到的真值，含义是「没配远程 syslog」——
  正是若干规则要抓的违规。按 falsy 判会把发现压掉，等于用一个假合规去修另一个假合规。
- **已被判为违规的节点不算缺口。** 它的结论已经确定，缺别的属性改变不了这一点。
- **不读任何属性的规则没有按节点缺口。** estate 级 absence check（`WHERE NOT EXISTS`）
  断言的是「哪些行存在」，不是某一行的内容；它在空 estate 上 fire 也是判定了，不进
  `rules_without_targets`。

### 升级

自动。首次以读写方式打开旧库时，`rule_outcome` 会补上两列
（`nodes_in_scope` / `nodes_undetermined`），并建 `rule_node_gap` 表。旧行保持 NULL —— 这个
NULL 是承重的，它把「没量过」和「量过、零缺口」区分开，**不要回填成 0**。
web dashboard 以只读方式打开，无法迁移；它对未迁移的库如实报 `node_tracked: false`，
而不是报「全覆盖」。

### 这一版**不**保证的

按节点判定回答的是「这台主机上，这条规则读的值存在吗」，**不**回答值是否正确。
STIG 那 12 个 advanced setting 的真机验证仍然必须（BACKLOG `[BV-harden]`）——本版保证的是
采集路径回空时会显示为「未判定的主机」而不是一份干净报告。

### 变更清单

- 新增 `vmware_harden/checks/nodescope.py`；新增 `rule_node_gap` 表 + 索引；
  `rule_outcome` 加 `nodes_in_scope` / `nodes_undetermined`（带 `information_schema` 探测迁移）
- `Evaluability` 携带已解析的 node type 与属性集，运行器不再二次解析同一段 SQL
- `Coverage` 增加节点维度；`complete` 加两个条件；`summary_line()` 由一句变为按需分句
- 呈现面：CLI `scan` / `report`（text + json）、MCP `list_violations` / `scan_target`、
  web summary + violations 页
- 测试：新增 `tests/eval/regression/test_node_level_outcomes.py`（16 例），全仓 480 passed；
  9 个缺陷注入变异测试全部变红；ruff 零新增；bandit 0 Medium+

---

## v1.9.0 (2026-08-12) — 合规判定诚实化：76/99 条规则此前静默报「合规」

> **⚠️ 升级后你的合规率会下降。这是修正，不是回归——此前的高合规率是假的。**

### 发生了什么

harden 的 99 条内置规则中，**76 条引用了任何采集器都不产出的 `nodes.attrs` 键**。
这类规则的 SQL 匹配 0 行，而引擎把「0 行」当作「全部合规」——于是它们为**从未真正检查过**的
配置签发合规结论。其中 74 条静默通过（假阴性，危险），2 条恒报违规（噪音）。

唯一健康的是 STIG 基线（12/12），因为只有它有 parity 测试——而那个测试**只加载它自己**，
其余 7 个基线从未被检查过。

复现方式（不依赖真机）：把每条规则 SQL 里的 `$.<attr>` 按其 `WHERE type='<node>'` 作用域，
与该节点采集器实际产出的键集合比对。

### 你会看到的变化

**扫描与报告**

```
# 此前
Found 0 violations against cis-vmware-esxi-8.0-subset
No violations.

# 现在
Found 0 violations against cis-vmware-esxi-8.0-subset
  16 of 20 rules could not be evaluated — no collector provides the data they
  check, so their result is unknown, not compliant.

No violations among the rules that could be evaluated.
Not evaluated:
  cis-esxi-2.1.1   no collector writes host.ntp_enabled
  ...
```

**⚠️ JSON 报告结构变更（破坏性）** — `vmware-harden report --format json` 从裸数组
改为对象：

```json
{"violations": [...], "coverage": {"evaluated": 4, "undetermined": 16,
 "total": 20, "tracked": true, "complete": false, "undetermined_rules": [...]}}
```

遍历顶层数组的脚本需改读 `["violations"]`。这个破坏是**刻意的**：数组让调用方无法区分
「没有问题」和「几乎没检查」——两者都是 `[]`。

**MCP** — `list_violations` / `scan_target` 新增 `coverage` 与 `note` 字段。
agent 读到 `violations: 0` 时不再能单独据此判定合规。

**Web** — 面板显示「已判定 N / 共 M 条规则」；违规页把
"the estate is fully compliant" 换成部分覆盖横幅 + 可展开的未判定清单。

### 修好的规则（9 条，现在真的会判定）

| 问题 | 规则 |
|---|---|
| `$.source`/`$.destination` → 采集器实为 `sources`/`destinations`（复数） | `pci-r1-1`, `nis2-rm-2`, `db-l3-net-2` |
| `action` 比较用小写，NSX 返回大写 | `pci-r1-2`, `nis2-net-1`, `db-l3-net-1`, `pci-r1-1`, `db-l3-net-2` |
| `$.build` → `$.esxi_build`（字符串，需 CAST） | `cis-esxi-2.2.1` |
| `tools_running` 布尔 → `tools_status` 枚举 | `scg-vm-3`, `db-l3-vm-1` |

同时删除了 `DENY` —— NSX 没有这个 action（合法值仅 `ALLOW`/`DROP`/`REJECT`/`JUMP_TO_APPLICATION`）。

### 仍无法判定的 70 条（等待采集器）

这些规则的意图有效，但没有采集器提供它们检查的数据。**它们此前一直报「合规」。**

- **bsi-itgs-basisabsicherung-vmware** — 9 条: bsi-itgs-malware-1, bsi-itgs-malware-2, bsi-itgs-malware-3, bsi-itgs-server-1, bsi-itgs-server-2, bsi-itgs-server-3, bsi-itgs-server-4, bsi-itgs-server-6, bsi-itgs-server-7
- **cis-vmware-esxi-8.0-subset** — 16 条: cis-esxi-2.1.1, cis-esxi-2.1.2, cis-esxi-2.2.2, cis-esxi-3.1.2, cis-esxi-3.1.3, cis-esxi-4.1.1, cis-esxi-4.1.2, cis-esxi-4.1.3, cis-esxi-5.1.1, cis-esxi-5.1.2, cis-esxi-6.1.1, cis-esxi-6.1.2, cis-esxi-6.1.3, cis-esxi-7.1.1, cis-esxi-7.1.2, cis-esxi-8.1.3
- **dengbao-2.0-level3-vmware** — 15 条: db-l3-data-1, db-l3-host-1, db-l3-host-2, db-l3-host-3, db-l3-host-4, db-l3-host-6, db-l3-host-7, db-l3-host-8, db-l3-host-9, db-l3-net-3, db-l3-net-4, db-l3-net-5, db-l3-policy-1, db-l3-vm-2, db-l3-vm-3
- **eu-nis2-vmware** — 10 条: nis2-ac-1, nis2-ac-2, nis2-ir-1, nis2-ir-2, nis2-ir-3, nis2-net-2, nis2-net-3, nis2-rm-1, nis2-rm-3, nis2-sc-1
- **pci-dss-4.0-vmware** — 6 条: pci-r10-2, pci-r2-1, pci-r2-2, pci-r7-1, pci-r8-1, pci-r8-2
- **vsphere-scg-v8-subset** — 14 条: scg-enc-1, scg-enc-2, scg-host-1, scg-host-2, scg-host-3, scg-host-4, scg-host-5, scg-net-1, scg-net-2, scg-net-3, scg-vm-1, scg-vm-2, scg-vm-4, scg-vm-5

需要补的采集项按批次排在 `design/LLD-harden-baseline-collector-contract.md`
（lockdown / SSH 状态 / NTP / ESXi 防火墙 / secure boot / TPM / vSwitch 安全策略 / 加密 / AD 加域 等）。

### 防止复发

- **`vmware_harden/baselines/vocabulary.py`** — 规范属性词汇表，65 条按
  `(节点类型, 属性名)` 复合键（`encryption_enabled` 同时属于 VM 和 datastore，
  按名字全局索引会判错）。17 条 ACTIVE / 48 条 PENDING，每条 PENDING 记录采集来源。
- **三层契约测试**（CI）：① 引用的属性必须已声明 ② 比较的字面量必须在值域内
  ③ 待采集规则必须与冻结清单双向精确匹配（修好一条就必须划掉，清单不会腐化成永久豁免）。
- **运行时拒绝执行**（保护 CI 看不到的外部基线）：不可判定的规则**不执行**，
  记入新的 `rule_outcome` 表。该表独立于 `violation`——写进去会静默改变
  web / MCP / advisor 全部既有查询的返回。

### 兼容性

- 旧快照（无 `rule_outcome` 记录）报告为 `tracked: false`，**不**当作全覆盖——
  「不知道」不等于「都判定了」。重新扫描即可获得覆盖率。
- `violation` 表结构未变，既有查询不受影响。

---

## v1.8.9 (2026-08-06) — vSphere 9 / VCF 9 STIG-aligned baseline + catalog tools (experimental, collector-pending)

Adds a vSphere 9 / VCF 9 STIG-aligned host baseline and two read-only MCP tools
for inspecting and routing it. This is **content sync, not an API wrapper**: VCF
Operations 9.1 Automated Configuration Compliance (ACC) / Security Posture
Management (SPM) is UI- and schedule-driven with a paid Salt engine and exposes
**no public compliance REST API** — the VCF Operations 9.1 OpenAPI (343 paths)
has zero Compliance / Benchmark / Baseline / Posture / Scan / Remediation
classes. There is nothing to wrap, so harden keeps its own DuckDB-persisted
scan engine and aligns its rule catalog with the open-source DISA/DoD STIG
content instead. For continuous, fleet-wide enforcement and automated
remediation, use VCF Operations SPM/ACC (UI); harden is the API-scriptable,
cross-target **point-in-time** scanner for CI and agent workflows.

### Added — `vsphere-stig-v9-subset` baseline (12 host controls) ⚠ EXPERIMENTAL

A rule-bearing STIG-aligned baseline of **12 ESXi host advanced-setting
controls**: account lockout / unlock time, password quality + history, DCUI
access, ESXi shell / DCUI idle timeouts, MOB disabled, shell-warning
suppression, guest BPDU blocking, and remote syslog. Each rule maps to the
**public, documented ESXi advanced-setting key** it governs (e.g.
`Security.AccountLockFailures`), evaluated with a declarative SQL check against
the twin — the same mechanism as the CIS / SCG subsets. Rule ids use harden's
own `stig-esxi9-<control>` namespace; they are **not** invented DISA V-IDs /
STIG-IDs (`ESXI-90-000xxx`), which would require cross-referencing the published
XCCDF. `baseline list` now returns **9 ids / 99 rules** (7 rule-bearing sets +
2 v9 aliases).

**Marked `status: experimental-collector-pending`.** The checks read host
advanced settings that a new collector pass fetches, and **that fetch is
verified at the code level only, not against a live 9.1 appliance** (see the
caveats below). The `status` field is surfaced through `list_baselines` and
`describe_stig_content_sync` so a scan self-declares that its STIG results are
not yet authoritative.

### Added — STIG advanced-settings host collector (real-hardware-gated)

The host collector gained an advanced-settings enrichment step: one batched
PropertyCollector pass over `config.option` per host (a single server-side call
for the whole fleet, not an `OptionManager.QueryOptions` round-trip per host —
踩坑 #31), reduced to the twelve snake_case `nodes.attrs` keys the STIG rules
read and merged into each host record. The pure reducer
(`_advanced_settings_to_attrs`) is unit-tested offline; the live
connect-and-fetch wrapper (`_fetch_advanced_settings`) is **REAL-HARDWARE-GATED
and exercised only against a live vCenter/ESXi.**

### Added — two read-only MCP tools + `vmware-harden stig` CLI (MCP 6 → 8)

- `list_stig_controls` — the STIG baseline's controls as a flat, paginated
  catalog `{id, title, severity, category, advanced_setting}`.
- `describe_stig_content_sync` — states that no compliance API exists, names the
  open-source STIG content sources harden syncs against, explains the
  InSpec→rule mapping mechanism, and routes continuous enforcement to SPM/ACC.

Both are `[READ]`, parse local baseline YAML only (no database, network, or
compliance API), and are audited via `@vmware_tool`. All **8 MCP tools remain
read-only** with respect to vSphere/NSX (verified: `mcp.list_tools()` returns 8;
SKILL.md and README updated to match — 踩坑 #34). CLI adds `vmware-harden stig
controls` / `vmware-harden stig sync-info`. The InSpec/Cinc profile importer is
**deferred** (`import_inspec_profile` raises `NotImplementedError` with a
teaching next step); hand-author or override baseline YAML for now.

### Fixed — review findings from today's Fable5 pass

- **`list_stig_controls` reported "more remaining" forever past page one.**
  `paginated()` computes `truncated = returned < total`, which is
  offset-unaware: every slice past the first page is partial, so the final page
  would still say `truncated: true` and an agent paging to the end would never
  learn it was done. The tool now recomputes `truncated` against the absolute
  position (`offset + len(page) < total`) and clears the `hint` on the last page.
- **A partial host config could abort the whole collection.** The advanced-
  settings reducer now skips a `None` option list or an entry missing `.key`
  rather than raising, so one malformed host cannot fail the fleet scan.
- **A "compliant" STIG result could be a data gap, not a pass.** If an advanced
  setting is not collected (older ESXi without the key, a permissions/version
  gap, or the fetch not yet run on real hardware), the rule's SQL matches zero
  rows and the host reports compliant. This is now (a) self-declared via the
  `status` field on the baseline and in `describe_stig_content_sync`
  (`authoritative: false` + an explicit caveat), and (b) guarded by a doc-vs-code
  parity test that fails CI if any STIG rule reads a `nodes.attrs` key the
  collector cannot populate (形态 #6 / #1).

### Verification honesty — what is and isn't proven

- **Verified at the PATH / OpenAPI level, not against a live 9.1 appliance.**
  The "no public compliance API" fact is pinned against the VCF Operations 9.1
  OpenAPI in `tests/eval/spec/vcf91_compliance.py` (a one-line reverification is
  documented there). The STIG advanced-setting keys are public, stable, and
  cross-checked against a verified-settings allowlist — but the end-to-end
  **collect → evaluate** path has not been run against a real vCenter/ESXi 9.1.
- **The collector fetch is real-hardware-gated.** Treat STIG scan results as
  indicative, not authoritative, until validated on your estate on first use;
  a green result may reflect an uncollected setting rather than a real pass.
- Regression coverage: baseline discoverability + pinned 12-rule count, every
  control maps to a verified advanced setting (anti-phantom), source is a
  verified content source, no hallucinated compliance-API path fragment anywhere
  in the package, offset-aware pagination, and the experimental-status marker.
  No feature is claimed beyond what these tests exercise.

## v1.8.8 — moved to vmware-skills org + MCP Registry namespace io.github.vmware-skills/vmware-harden

Repo transferred from github.com/zw008 to github.com/vmware-skills (redirects preserve old links).
MCP Registry server renamed to `io.github.vmware-skills/*`; the old `io.github.zw008/*` entry is deprecated.
All in-repo links updated. No functional code change on this line beyond the org move.

## v1.8.7 (2026-07-21) — the live-scan collectors actually work now; read-only switch removed

Harden rejoins the family at v1.8.7 (there was no 1.8.6). The headline is a real
bug fix: every scan collector has been importing a module that does not exist.

### Fixed — collectors repaired: each imported a module path that never existed

`vmware-harden scan` collects host / VM / datastore / DFW posture into the Twin
through four collectors. Each imported a **fabricated** module path — e.g.
`vmware_aiops.ops.host_inventory` (the real module is `vmware_aiops.ops.inventory`)
and `vmware_nsx_security.ops.dfw_inventory.list_dfw` (no such symbol at all). The
collectors have been dead since they were first committed: every unit test patched
the fetch seam, so the broken import never ran under test and three layers of
checking all reported green over it.

This release repoints all four to the real inventory functions and makes them
actually collect:

- **hosts / VMs / datastores** connect through the sibling skill's own
  `ConnectionManager` (reusing its `~/.vmware-<skill>/config.yaml`), call the real
  inventory function, and stamp each record with the stable `id` the Twin needs
  (VM `config.uuid`; host / datastore name, unique per vCenter). VM collection
  defeats aiops' auto-compaction so `uuid` is never dropped.
- **DFW** assembles sections + rules from `list_dfw_policies` / `list_dfw_rules`,
  paging past the default 50-item cap so a compliance scan is not silently truncated.

The sibling skills are declared as an optional `collectors` extra — install
`vmware-harden[collectors]` on a host that will scan a live estate (scan reports a
teaching error naming the missing package otherwise). A guard test
(`test_collector_imports_resolve`) now executes the real import path so a
fabricated module can never ship silently again; reshape unit tests pin the
`id`/`name` contract offline.

> **Verification note.** The pure reshape/pagination logic is unit-tested offline.
> The live connect-and-scan path runs only against a real vCenter/NSX
> (`test_lab_scan.py`, skipped without `VMWARE_HARDEN_LAB_TARGET`) — validate it
> against your estate on first use.

### Removed — the skill-level read-only switch and approval tiers

Harden joins the family v1.8.7 change: the `read_only` switch (and
`VMWARE_HARDEN_READ_ONLY`) plus the approval-tier / declared-environment gates are
removed. Harden's scan/report/suggest path is read-only by design regardless; to
run any skill read-only, give it a read-only vCenter/NSX service account (RBAC).
The `environment` field survives only as an optional label a `deny` rule may match.

### Added — offline / air-gapped install docs

The README now covers installing from source and building wheels for an air-gapped host.

## v1.8.5 (2026-07-20) — the two fixes v1.8.4 announced now actually work

Four adversarial reviews of v1.8.4 found that both of its headline fixes were
incomplete in ways the release notes did not reflect. This release makes them
real. If you are on 1.8.4, this is the one to take.

### Fixed — a failure that was *returned* was still audited as a success

vmware-policy 1.8.4 added `report_tool_failure()` for tools that catch an
exception and return an error payload instead of raising. **No skill called it.**

Every string-returning tool therefore kept doing exactly what 1.8.4 said it had
stopped doing: writing `status=ok` to `~/.vmware/audit.db` for an operation that
failed, recording an undo token for a change that never happened, and telling the
circuit breaker the call succeeded so repeated failures never tripped it.

The surface this covered is not marginal:

| Skill | What was mis-audited |
|---|---|
| vmware-aiops | 25 of 49 tools, including **every undo-bearing write** — a failed `vm_power_on` left an undo token saying "power it back off" |
| vmware-avi | all 28 tools, including `vs_toggle` and `ako_restart` |
| vmware-storage | all 4 write tools |
| vmware-nsx | the 5 delete tools |

vmware-avi is worth calling out: before 1.8.4 its exceptions propagated and the
audit was correct. 1.8.4 caught them and returned a string, so **that release made
its audit trail worse than it had been.**

Skills whose tools already return dict payloads (vmware-monitor, vmware-vks,
vmware-aria, vmware-log-insight, vmware-harden, vmware-debug, vmware-pilot) were
already detected correctly. They gained a test proving it rather than a redundant
call.

### Fixed — narrowing `OSError` did not close the leak it was meant to close

1.8.4 narrowed the `_safe_error` passthrough because bare `OSError` let TLS and
DNS failures reach the agent with hostnames and certificate subjects in them.
That narrowing had no effect on the error it was written for:

```
ssl.SSLCertVerificationError → ssl.SSLError → OSError, ValueError
```

`ValueError` has been on every allowlist since long before 1.8.4, so a
certificate failure kept passing through — the commonest self-signed-certificate
failure in this family, carrying the hostname it was checked against. An
allowlist structurally cannot express "not this one".

Where `ssl.SSLError` can actually surface — the pyVmomi skills — it is now
reduced *ahead* of the allowlist. In the httpx skills TLS arrives wrapped as
`httpx.ConnectError`, and in vmware-avi as `requests.exceptions.SSLError`, so the
guard cannot fire there; in those skills the leak was the raw exception
interpolated into an already-allowlisted `*ApiError`, and that is now authored
text naming the config target and `verify_ssl` instead of the exception.

The missing-password error — this family's most common first-run failure, whose
entire remedy is the environment variable name it carries — keeps its message
through a narrow `ConfigError(OSError)` rather than the base class. Connection
failures are translated at the connection layer into an authored remedy that
names the target and the setting to change, with the raw detail left on
`__cause__` for the server log.

### Also fixed

- **vmware-vks**: the quickstart documented a password variable the code never
  reads — following `README.md` verbatim produced "Password not found". Five
  places, plus six references to a `doctor` command this CLI has never had, two
  descriptions promising fields the tools do not return, and eight teaching
  messages that `RuntimeError` was masking.
- **vmware-nsx**: an error cited `--route-advertisement`; the flag is `--advertise`.
- **vmware-pilot**: `get_workflow_status` told the model to call `approve` — a
  tool the read-only gate withholds — as the required next step; and a hint
  pointed at a filename that could never appear in that message.
- **vmware-aiops**: `vm_task_status` polling a *failed task* returned
  `{"state": "error", "error": ...}` from a successful read, which the new
  detection read as the call itself failing. The field is now `task_error`.
  **This is a breaking change for anything parsing that payload.**
- Several remedies that were still being cut by the 300-character cap the 1.8.4
  notes claimed to have addressed.

### Known and not fixed

`ConnectionError` remains one type from two sources in several skills — a
skill's own authored message and urllib3's `HTTPSConnectionPool(host=..., port=...)`
share it, and an allowlist cannot separate them. vmware-vks is converted; the
rest need their own domain type and are deferred rather than half-done.

## v1.8.4 (2026-07-20) — errors that teach, and tool descriptions a small model can route from

A capability eval was rolled out across the family and asked two open questions:
when a call fails, is the model told enough to fix it, and can it pick the right
tool from the description alone? Both answers were worse than anyone thought, and
in several places the reason was that the measurement was looking somewhere other
than where the model reads.

### Fixed — teaching messages were being discarded on the way to the agent

`_safe_error` reduces unrecognised exceptions to `"<Class>: operation failed."`
so raw API text, credentials in URLs and internal paths cannot reach an agent.
Its allowlist held only the builtin validation errors — so this skill's **own**
domain exceptions, the ones that exist precisely to carry a corrected next step,
had their messages replaced by their class names.

The effect was invisible from the CLI, which prints those messages in full.

The worst case was shared by nine skills: `config.py` raises exactly one
`OSError`, the missing-password error, whose entire remedy is the environment
variable name it names. An agent hitting an unconfigured target received
`OSError: operation failed.` and had nothing to act on. That is the family's most
common first-run failure, and it landed one release after the documented variable
names were corrected — so the message that would have unstuck the operator was
the one being thrown away.

The rule is now the property it always meant: **every exception this skill raises
on purpose passes through**, and only genuinely unplanned ones are reduced.
`RuntimeError` stays reduced — it is the generic catch-all and in several skills
carries raw upstream text.

### Fixed — error messages now carry the correction

Every message that reported a failure without saying how to recover was
rewritten: it names the offending value, gives an imperative remedy, and names
something concrete to act on — a tool that exists, a real CLI command, a config
file, an environment variable. Recovery becomes an instruction-following problem
rather than an inference one, which is what a weak model can still do.

Three classes of defect surfaced while doing it:

- **Remedies that were never delivered.** `_safe_error` truncates with no
  ellipsis, so a message longer than the cap loses its closing sentence
  silently. One message had been shipping at 396 characters against a 300-char
  cap — its remedy had never once reached an agent. Messages now lead with the
  remedy so a long interpolated value truncates the expendable detail instead.
- **Commands that do not exist.** One skill's error hints named a `doctor`
  subcommand it does not have.
- **Tools that do not exist.** A tool description pointed at two sibling-skill
  tools that had been renamed, and another named a tool that had moved to a
  different skill entirely.

### Improved — tool descriptions state when to use them and what to call next

The description is the API for a small model: an unstated routing rule is a
routing rule that does not exist, and a tool with no stated next hop is one the
model stops at. Descriptions now say when to prefer this tool over a sibling,
what shape comes back, the caveat that bites, and which tool to call after.

**Manifest size did not grow.** Descriptions load into every session, so the
routing clauses were paid for by cutting duplicated reference material —
repeated boilerplate, examples that restated the parameter list, and prose
copies of the pagination contract.

### Note

Every tool and CLI command named anywhere in this release was verified against
the live MCP registry and the live command tree, not against documentation.

## v1.8.3 (2026-07-20) — credentials resolve as a pair; documented env vars now exist

### Changed — version alignment

No functional change in this skill. The family release adds an env-var override for the per-target username in the credential-bearing skills; this package has no per-target credentials.

## v1.8.2 (2026-07-20) — the MCP server moves into the package namespace

### Fixed — co-installing two skills broke all but the last one

Every skill shipped its MCP server as a **top-level `mcp_server` package**. Python
has one top-level namespace, so installing any two of them into one environment let
the second overwrite the first — silently, with no error and no warning.

    uv tool install vmware-aiops   ->  49 tools   (correct)
    uv pip  install vmware-aiops   ->  27 tools   (Monitor's read-only server)

vmware-aiops depends on vmware-monitor, so this was not an edge case: **every pip
install hit it**, and the operator got 27 read-only tools where 49 were expected,
with all 35 write tools missing. Docker images, shared MCP hosts and CI runners that
install more than one skill were affected the same way.

The server now lives at `vmware_<skill>/mcp_server/`, a name only this package can
claim. Introduced 2026-02-26; it survived 70 releases because every test ran against
a single package in its own repo, where the local directory shadows site-packages —
the conflict was invisible by construction.

**Migration.** Console scripts are unchanged: `vmware-<skill>` and
`vmware-<skill>-mcp` work exactly as before, as does `"command": "vmware-<skill>",
"args": ["mcp"]` in an MCP client config. Only a direct `python -m mcp_server`
breaks; use `python -m vmware_<skill>.mcp_server`.

### Added — `references/agent-guardrails.md` in every skill

The operating rules for local and small models (Llama 3.3 70B, Qwen, Mistral via
Goose / Ollama / OpenShift AI) existed in two skills. They now ship in all 13, each
with its own tool counts and failure modes, and are linked from every SKILL.md.

### Fixed — the baseline count understated what ships

`baseline list` returns 8 IDs, not 6: `cis-vmware-esxi-9.0-subset` and
`vsphere-scg-v9-subset` have been in the package as `extends:` aliases of their v8
parents, while the README still said they were "planned for a future release". Also
added `README-CN.md` (the last skill without one) and removed a local absolute path
from the References section.

## v1.8.1 (2026-07-19) — read-only mode reaches the surfaces that teach it

v1.8.0 put read-only mode in the code and documented it in the README only.
Every other layer was empty, and each serves a different reader: SKILL.md is what
the agent loads, setup-guide is what an operator reads while configuring, `doctor`
is where they verify it took. The gap had two concrete costs.

An agent read SKILL.md, called a write tool the gate had withheld, and got nothing
back — with no way to learn that the absence was a deliberate lockdown rather than
a fault. It reads as a broken tool, so the model retries or hunts for a workaround.

An operator who set the switch had no way to confirm it. The only signal was a line
in the MCP server's start-up log.

### Added — the feature is now documented where each reader looks

- **SKILL.md** — a short section telling the agent that a missing write tool is a
  lockdown, not a fault: name the blocked operation, do not retry, do not route
  around it.
- **references/setup-guide.md** — the operator's view: how to enable it, the
  precedence chain, and how to verify.
- **references/capabilities.md** — which tools the gate withholds.

### Added — `doctor` reports the read-only state

`vmware-harden doctor` now shows whether read-only mode is on, **which** of the three
switches decided it, and the value as written. A typo'd value (`ture`) is called
out as a typo rather than reported as a confident ON — it resolves to on, which is
fail-closed but almost never what was meant.

The resolution runs through `vmware_policy.read_only_status()` rather than a local
copy of the precedence chain: a doctor that disagrees with the gate it reports on is
worse than no doctor. Requires `vmware-policy>=1.8.1`.

## v1.8.0 (2026-07-18) — read-only mode, working policy defaults, declared environments

Family release driven by [VMware-AIops#31](https://github.com/vmware-skills/VMware-AIops/issues/31),
where an operator running Llama 3.3 70B (Goose / OpenShift AI, on-prem H100) had to
hand-write 17 prompt guardrails to make tool calling reliable. A prompt is advisory — a
model can ignore it. Every guardrail that could move into the harness has.

### Added
- **Read-only mode.** Set `VMWARE_READ_ONLY=true` (or the per-skill
  `VMWARE_HARDEN_READ_ONLY`) and every write tool is removed from the MCP registry at
  start-up. `list_tools()` never offers them, so the model cannot call what it cannot
  see. **Off by default** — nothing changes unless you turn it on. Fail-closed: if the
  mode is requested but cannot be guaranteed, the server refuses to start rather than
  running open. **vmware-harden has no `config.yaml`, so the environment variables are
  the only switch** — precedence is per-skill env → family env → off. All 6 tools are
  `[READ]`, so the gate withholds nothing here; its empty result *is* the assertion.
- **`environment:` scoping for policy rules.** Policy rules now scope by the environment
  a target declares (production / staging / lab). Skills that connect to a VMware estate
  declare it per target in their own `config.yaml`; vmware-harden has no such config and
  no estate connection of its own, so it reports a constant `local`.

### Added — list results now state whether they are complete

Every `[READ]` list tool returns the family envelope instead of a bare array:

    {"items": [...], "returned": 50, "limit": 50, "total": 213,
     "truncated": true, "hint": "Showing 50 of 213. Raise limit or narrow the query..."}

This closes the reported failure where long responses were summarised as "no data
returned": a bare list gives a model no way to tell a complete answer from page one, so
it guessed. `truncated: false` now positively states completeness — including when
`items` is empty, which means "checked, found none", not "the call failed".

- **3 tool(s) converted** across ops, MCP and CLI. `list_drift_events` counts with an indexed `SELECT COUNT(*)` on the same predicate;
  the other two already load their collection whole. `list_violations` keeps its own
  pre-existing `{violations, total, limit, offset, has_more}` shape.

### Changed — migration, read this
- **Approval tiers now actually run.** They shipped in v1.6.0 but the engine only ever
  read `~/.vmware/rules.yaml`, and a fresh install has no such file — so every deny rule,
  maintenance window and approval tier had been inert on every install that never
  hand-authored one. A packaged baseline now loads when you have written no rules of your
  own. Writes at medium risk and above are stamped with their tier in the audit log;
  irreversible work and guest execution against a target declared `production` require a
  named approver via `VMWARE_AUDIT_APPROVED_BY`.
- **`environment:` will become required for writes — but not here.** Across the family, a
  state-changing operation against a target that declares no `environment:` still runs and
  logs a warning, and **the next major release refuses it**. vmware-harden exposes no tool
  that changes a remote VMware estate, and has no config in which to declare anything, so
  there is nothing to migrate — it reports a constant `local` and the upgrade is a no-op
  for this package. Read-only operations are never affected, in this release or the next.
  Check what applies to your write-capable siblings before upgrading:
  `vmware-audit policy --operation vm_delete --env <env>`.

### Fixed
- **Policy glob patterns with a leading wildcard silently matched nothing.** A rule written
  `operations: ["*_delete"]` parsed fine, read correctly, and never fired — only a trailing
  `*` was honoured. Now full glob matching, for operations and environments alike.

### Notes
- Requires `vmware-policy>=1.8.0`; publish that package first.
- `vmware-audit policy` reports which rules are in force and where they came from —
  including the case where your rules file exists but failed to parse, which previously
  looked identical to "policy is working".

## v1.7.5 (2026-07-13) — family version alignment (no code change)

Version-alignment release only; no functional change since v1.7.4.

## v1.7.4 (2026-07-13) — family version alignment

## v1.7.3 (2026-07-03) — family version alignment

## v1.7.2 (2026-07-02) — bounded output (no more unbounded dumps to the agent)

### Changed
- **`list_violations` MCP tool now returns a paginated envelope**
  `{violations, total, limit, offset, has_more}` instead of a bare list, with
  `limit` defaulting to 50. On a large estate it no longer serializes tens of
  thousands of violations straight into agent context. The web dashboard's
  violations/drift pages now paginate, `advise --all-critical` gained a `--limit`
  cap (with a disclosed "advising on X of Y" message), and the `report` / `drift`
  CLI commands gained `--limit`. DuckDB schema/indexes unchanged.

## v1.7.1 (2026-07-02) — family version alignment

No code changes. Version bump to stay aligned with the v1.7.1 family release
(VMware-AIops + VMware-Monitor large-inventory scale fix — PropertyCollector
batching to stop per-object lazy SOAP round-trips, GitHub issue #31).

## v1.7.0 (2026-06-27) — vSphere 9 baselines

### Added
- **Built-in vSphere 9 baselines:** `cis-vmware-esxi-9.0-subset` and
  `vsphere-scg-v9-subset`. Each `extends` its v8 counterpart and inherits the
  stable host/VM hardening controls (NTP, lockdown, syslog, firewall, SSH,
  promiscuous/forged-transmit reject, vSAN/vMotion encryption, timeouts) that
  carry forward unchanged to the 9.x line. No fabricated v9-specific rule IDs or
  build thresholds — when CIS/Broadcom publish the official v9 numbering, the
  subsets will be replaced with it.

## v1.6.1 (2026-06-24) — version alignment

No functional changes — version bumped to stay aligned with the VMware skill family release.

## v1.6.0 (2026-06-22) — family alignment + harness trust architecture

No skill code changes. Aligns to the v1.6.0 family release and automatically picks up the
vmware-policy 1.6.0 governance upgrades (token/runaway budget guard, audit accountability fields,
graduated-autonomy risk tiers) on next install. Read-only compliance engine — no undo tokens applicable.

## v1.5.39 (2026-06-22) — family version alignment

No code changes. Version bump to stay aligned with the v1.5.39 family release
(AIops snapshot-delete async + honest-timeout token-burn fix; Storage datastore-browse timeout fix).

## v1.5.38 (2026-06-12) — backlog finish: collector de-duplication

### Changed
- Lifted the duplicated collect + batch-persist logic into the `Collector` base class; the host/vm/
  datastore/dfw collectors shed ~113 lines (~39%) with identical behavior. (#2)

## v1.5.37 (2026-06-12) — backlog: batched writes, dead-schema cleanup, offline evals

### Fixed
- **Collectors batch their writes** into one transaction + `executemany` (was one transaction per node —
  thousands of commits on large inventories); the drift dashboard's 5 COUNT queries collapsed to one
  GROUP BY. (#1)

### Changed
- Removed dead schema (`edges` table, `nodes.parent_id`); `violation.status` / `posture_drift` are
  documented as reserved-but-unwired. (#4)

### Added
- Offline regression evals (no live-lab env var needed) pinning the v1.5.36 compliance-correctness fixes
  and the approval-gate truth table. (#5)

## v1.5.36 (2026-06-12) — compliance-correctness fixes: scoping, severity, approval gate

### Fixed
- **Absence-check violations are no longer dropped** — the snapshot-scoping filter wrongly removed
  "control entirely absent" findings (e.g. PCI default-deny, no-encryption, no-segmentation) because
  they emit a synthetic node id; the most severe estate-wide gaps could report as CLEAN.
- **Cross-target / decommissioned-node bleed fixed** — rule SQL ran against the cumulative node store,
  so one target's scan reported another target's violations.
- **Failed scans no longer masquerade as the latest clean snapshot** — a collector failure now marks
  the snapshot `failed`, and every "latest snapshot" consumer filters to completed scans.
- **Severity ordering** was alphabetical (critical sorted *last*); now critical-first everywhere.
- **Approval gate no longer trusts the LLM alone** — a rule's `review_policy` (human-review-required /
  min-confidence) is enforced; unresolvable rules default to requiring review for high/critical.
- `list_violations(severity=…)` validates the value; teaching errors for missing dependency / DB.

### Added
- Indexes on `change_event(node_id)` and `remediation(violation_id)`; read-only DuckDB access for the
  web dashboard (no lock conflict with a running scan).

## v1.5.35 (2026-06-10) — security fix: baseline loader path traversal

### Fixed
- **Baseline name path traversal**: `_resolve_baseline_path()` now rejects names containing
  path separators, leading dots, or null bytes and confirms the resolved path stays inside the
  baseline directory. Closes a read-arbitrary-file vector reachable via the CLI, MCP, or a
  malicious `extends:` field.

This release aligns the whole family back to a single version (1.5.35); vmware-policy and vmware-pilot return to the shared number after sitting at 1.5.22.

## v1.5.32 (2026-06-08) — Family version alignment + test hygiene

No functional changes. Version-alignment release with the v1.5.32 family
(spec-audit fixes in sibling skills).

### Tests
- Smoke test no longer pins a stale version literal — asserts semver shape +
  agreement with pyproject.toml.

## v1.5.30 (2026-06-07) — Tool description quality (Glama TDQS)

### Improved
- Rewrote MCP tool descriptions flagged by Glama's Tool Description Quality Score review:
  per-parameter semantics (format, defaults, valid values), return-field documentation,
  sibling-tool routing guidance, and behavioral transparency (side effects, audit logging,
  async semantics). Corrected descriptions that overstated or misstated actual behavior.
- No functional changes; descriptions only.

## v1.5.29 (2026-05-29) — Doctor / Smithery / Python 3.10 Troubleshooting Docs

### Documentation
- README.md: refreshed v1.5.18 framing to make it clear the project is at v1.5.28-aligned (now v1.5.29), not v1.5.18 (commit `27035a1`).
- `references/cli-reference.md`: added full `doctor` command section — synopsis, no-options note, table of 10 environment checks from `vmware_harden/doctor.py::run_diagnostics`, example output, exit codes.
- `references/setup-guide.md`: new "Alternative Deployment: Container / Smithery" section mirroring AVI style (Docker build/run with Twin DB volume mount note, Smithery config schema, deployment-choice table); new "Troubleshooting" section above Security with the Python 3.10 / `subclass() arg 1 must be a class` fix (upgrade to v1.5.28+ or `mcp[cli]>=1.14`).
- `references/capabilities.md`: "Performance & Correctness Notes" section covering v1.5.19 snapshot_id indexes (`IF NOT EXISTS`, idempotent, no migration) and LEFT JOIN + COALESCE orphan-preservation in `list_violations` / `report` (踩坑 #28 / #29 cross-refs).

### No code changes
Documentation-only release.

## v1.5.28 (2026-05-20)

**Fix `subclass() arg 1 must be a class` in goose/old mcp environments** —
v1.5.25–1.5.27 replaced `X | None` with `Optional[X]` but kept
`from __future__ import annotations` at the top of `mcp_server/server.py`.
Under mcp 1.10–1.13 (which Goose and some sandboxes pin), `Tool.from_function`
calls `issubclass(param.annotation, Context)` without resolving forward refs,
so string annotations crash the entire server load. Removed
`from __future__ import annotations` from `mcp_server/server.py` so annotations
are real classes; verified all tools load under mcp 1.10 and 1.14.

Traceback location: `mcp/server/fastmcp/tools/base.py:67`. CLAUDE.md 踩坑 #33
updated. family_smoke.sh Check 4b now installs `mcp==1.10.0` to catch this
regression class.

## v1.5.27 (2026-05-20)

**Loosen Python requirement: now supports Python >= 3.10** — v1.5.25/26 fixed
the PEP 604 root cause in MCP tool signatures (Optional[X] instead of X | None),
but kept `requires-python = ">=3.11"` and a 3.11 hard guard in `mcp_cmd`. Both
relaxed to 3.10 so users on Python 3.10 (e.g. Goose default sandbox, Ubuntu
22.04 system python) can install and run directly without a Python upgrade.

- `pyproject.toml`: `requires-python = ">=3.10"` (was `>=3.11`; VMware-VKS
  was `>=3.12`, now also `>=3.10` for family alignment).
- `<pkg>/cli.py` `mcp_cmd()`: version guard now triggers on `< (3, 10)`.
- Behavior on Python 3.10 matches 3.11/3.12 — the Optional[X] fix from v1.5.25
  is what actually enables this; this release just stops blocking installs.

---

## v1.5.26

**Family-wide MCP server fix — Python 3.10 compatibility (踩坑 #33)** — `vmware-harden mcp`
crashed at decorator time on Python 3.10 with `subclass() arg 1 must be a class`.
Root cause: `mcp_server/server.py` used PEP 604 `X | None` in tool signatures
plus `from __future__ import annotations`; on Python 3.10 + older mcp/pydantic
combos, `typing.get_type_hints()` evaluates `"str | None"` to a
`types.UnionType` instance, which FastMCP/Pydantic then feeds to `issubclass()`.
Reported by a goose user (qwen3.6:27, Python 3.10).

- `mcp_server/server.py`: all `X | None` → `Optional[X]`; ops layer untouched.
- `<pkg>/cli.py` `mcp_cmd()`: hard guard — exits with installation fix command
  if Python < 3.11 (defense in depth, our actual lower bound).
- `pyproject.toml`: `mcp[cli]>=1.10,<2.0` (was `>=1.0`) so uv doesn't pick
  an ancient version that has the same issubclass bug.

**Tooling — family smoke gains MCP schema-build check** — `scripts/family_smoke.sh`
new Check 4b runs `asyncio.run(mcp.list_tools())` per skill, forcing FastMCP to
build Pydantic models for every declared tool. Supports both module-level `mcp`
and `build_server()` factory patterns.

**Docs — CLAUDE.md gains 踩坑 #33 (PEP 604 / Python 3.10) and #34 (CLI/MCP exposure parity).**

---

## v1.5.24 (2026-05-19)

**Family version alignment** — no code changes in this skill. Bumped together
with VMware-AIops and VMware-VKS, which received a pyVmomi 8.x `ManagedObject`
setattr fix (踩坑 #32). `family_smoke.sh` now enforces the no-setattr rule
across all 9 skills.

## v1.5.23 (2026-05-19)

**VCF 9.0 / 9.1 compatibility — scan path works; new 9.0 baselines planned.**

- **docs:** README clarifies that the existing `cis-vmware-esxi-8.0-subset` and `vsphere-scg-v8` baselines successfully scan VCF 9.0 / 9.1 clusters — most rules carry over since they target host advanced settings and config that are stable across 8.x → 9.x. A small subset of rules may produce false negatives if a control's setting key changed in 9.0; users should treat those as informational until 9.0 baselines ship.
- **planned:** `cis-vmware-esxi-9.0` and `vsphere-scg-v9` baselines are tracked for a future release once CIS Benchmark v1.0 for ESXi 9.0 and the VMware Security Configuration Guide v9 are published.
- **docs:** Added `Official Broadcom References` pointer to [vSphere Security Configuration Guide](https://core.vmware.com/security/) and the [VCF Python SDK](https://developer.broadcom.com/sdks).
- **align:** Family v1.5.23 — all 9 skills tracking VCF 9.0 / 9.1 compatibility declaration.

## v1.5.22 (2026-05-08)

**Smithery onboarding** — `vmware-harden` is now installable via Smithery.

- **feat:** Added `Dockerfile` (Python 3.12-slim + uv) for containerized stdio MCP server.
- **feat:** Added `smithery.yaml` declaring stdio transport + config schema for the Smithery registry.
- **feat:** Added `mcp_server/__main__.py` so `python -m mcp_server` works inside the container.
- **align:** Tracks v1.5.22 family bump.

## v1.5.21 (2026-05-08)

**Family alignment** — no source changes in this skill.

- **deps:** Bumped `python-multipart` 0.0.26 → 0.0.27 (transitive, fixes GHSA HIGH DoS via unbounded multipart headers).
- **align:** Tracks v1.5.21 family bump driven by vmware-monitor folder_path feature (community PR #11).

## v1.5.20 (2026-05-08)

**Family alignment** — no source changes in this skill.

- **align:** Tracks v1.5.20 family bump driven by vmware-nsx-security and vmware-aria PyPI README `mcp-name:` ownership marker fix required by MCP Registry validation. Other 7 skills already had the marker; this release re-publishes them to keep the family version aligned per CLAUDE.md policy.
- **registry:** All 9 skills now registered on registry.modelcontextprotocol.io as `isLatest=true`.

# Release Notes

## v1.5.19 (2026-05-06)

**Performance + correctness fixes** — Twin DB query speed and report completeness.

- **perf(store):** Added `CREATE INDEX IF NOT EXISTS` for `violation.snapshot_id`, `node_state.snapshot_id`, `change_event.snapshot_id` in `store/schema.py`. Without these, every `list_violations` / `report` / drift diff query performed a full table scan, with cost scaling linearly in scan history (yjs review 2026-05-06; CLAUDE.md 踩坑 #28).
- **fix(cli):** `vmware-harden report` now uses `LEFT JOIN nodes` with `COALESCE(name, '[orphan]')`. Previously the INNER JOIN silently dropped violations whose node had been deleted between scans — drift scenarios appeared falsely clean (CLAUDE.md 踩坑 #29).
- **smoke:** Family `scripts/family_smoke.sh` now recursively walks every Typer subcommand to trigger lazy imports.
- **align:** Family version bump to v1.5.19.

## v1.5.18 — 2026-05-04

GA promotion + new EU baselines + doctor command.

- **Promoted to GA family** — vmware-harden is now part of `FAMILY` array in family_smoke.sh; version bumped to 1.5.18 for family-wide alignment (all family skills share this version).
- **EU NIS2 Directive baseline** (12 rules) — for "essential entities" under Articles 21/23/24.
- **BSI IT-Grundschutz Basis-Absicherung baseline** (10 rules) — German federal baseline for VMware ESXi hosts.
- **`vmware-harden doctor` command** — environment diagnostics (Python, deps, Twin, audit DB, ANTHROPIC_API_KEY).
- 6 baselines now ship: CIS ESXi, vSphere SCG, GB/T 22239 三级, PCI-DSS 4.0, EU NIS2, BSI IT-Grundschutz (87 rules total).

No breaking changes from 1.0.1.

## v1.0.1 — 2026-05-04

Patch release for MCP Registry submission.

- Add `mcp-name: io.github.zw008/vmware-harden` marker to README for MCP Registry ownership validation.
- No code or behavior changes; identical to 1.0.0 functionally.

## v1.0.0 — 2026-05-04

First public release. Production-ready compliance platform for VMware infrastructure with AI-native remediation guidance.

### M3 highlights (this release)

- **Remediation Advisor** — LLM-driven Suggestion generation per violation. Provider abstraction (Anthropic + Mock); falls back to mock with stderr warning when `ANTHROPIC_API_KEY` unset. Persisted to Twin alongside violations.
- **MCP server** — Real FastMCP-based server (replaced the v0.x stub). 6 read-only tools: `list_baselines`, `list_violations`, `get_remediation`, `list_drift_events`, `get_baseline_rules`, `scan_target`. All wrapped with `@vmware_tool` for audit logging to `~/.vmware/audit.db`.
- **CLI: `vmware-harden advise`** — generates Suggestions with `--violation-id` or `--all-critical`.
- **Web Remediation panel** — HTMX-driven inline expansion on the violations page.
- **Documentation** — comprehensive `SKILL.md`, `SECURITY.md`, and `references/` directory (cli-reference, capabilities, setup-guide).
- **Publish artifacts** — `server.json` for MCP Registry; example configs for Claude Code/Cursor/Cline/VS Code Copilot/Goose; uvx fallback for corporate TLS environments.

### M2 (recap — already in main)

- 4 baselines (CIS ESXi, vSphere SCG v8, **等保 2.0 三级**, PCI-DSS 4.0) — 65 rules
- 4 collectors: host, VM, datastore, NSX DFW
- Multi-target Twin (target:moref namespacing)
- Custom YAML import + extends inheritance
- Drift detection (config + inventory + posture)
- Web dashboard (FastAPI + HTMX + Tailwind + ECharts) — 3 pages

### M1 (recap)

- DuckDB Estate Twin
- Pydantic-validated baseline schema
- SQL-based query check executor
- Initial CIS ESXi 8.0 baseline (20 rules)

### Acceptance criteria for v1.0

- 189+ tests passing
- Bandit: 0 issues
- 6 MCP tools, all audited
- SKILL.md ≤ 3000 words, frontmatter compliant
- SECURITY.md with 6 elements + Broadcom disclaimer
- 4 built-in baselines

### Known limitations (deferred to v1.1)

- **MCP audit `skill` field** logs as `unknown` due to `vmware_policy._infer_skill` looking for `vmware_<skill>` package layout (we use `mcp_server`). Same as sibling skills; not a regression.
- **vmware-pilot integration** is in this release (v1.0) but real Pilot endpoint integration may need adjustment based on Pilot v1.x API. Mock client is fully functional.
- **ScriptCheck rules rejected at load time** — declarative SQL (`QueryCheck`)
  covers all v1.0 baselines (CIS, SCG, 等保, PCI). Implementing executable
  script checks is a v2 feature gated on a security threat model
  (sandboxing arbitrary Python from baseline YAML). Tracked at
  `vmware_harden/baselines/loader.py` (search for "DEFERRED to v2.0").

### Upgrade notes

This is the first public release; nothing to migrate from. New deployments:

```bash
uv tool install vmware-harden
vmware-harden baseline list
vmware-harden scan --target <vc> --baseline cis-vmware-esxi-8.0-subset
```