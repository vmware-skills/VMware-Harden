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
