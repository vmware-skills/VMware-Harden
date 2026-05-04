# Setup Guide

How to install, configure, and wire `vmware-harden` into your AI agent.

## Prerequisites

- **Python 3.10+** and `uv` (https://docs.astral.sh/uv/).
- **Sibling VMware skills** must be installed and configured for the
  collectors that your chosen baseline references:

  | Baseline | Required sibling skill(s) |
  |----------|---------------------------|
  | `cis-vmware-esxi-8.0-subset` | `vmware-aiops` (host inventory + advanced settings) |
  | `vsphere-scg-v8-subset` | `vmware-aiops` |
  | `dengbao-2.0-level3-vmware` | `vmware-aiops`, `vmware-nsx-security` (DFW evidence) |
  | `pci-dss-4.0-vmware-subset` | `vmware-aiops`, `vmware-nsx-security` |
  | Custom YAML | Whatever node types you reference in `applies_to` |

  `vmware-harden` itself **never** opens a vSphere or NSX session — it
  reuses the collectors and credentials owned by the upstream skills.
  This is the single most important property of the install: harden has
  zero credentials of its own.

- **Optional**: `ANTHROPIC_API_KEY` if you want real LLM advice from
  `vmware-harden advise`. Without it, the advisor falls back to a
  deterministic mock template (and writes a stderr warning).

## Installation

### Recommended: PyPI via `uv tool install`

```bash
uv tool install vmware-harden
vmware-harden --help
vmware-harden-mcp --help   # MCP server entry point (separate console script)
```

This installs both `vmware-harden` (CLI) and `vmware-harden-mcp` (MCP
stdio server) into a single isolated venv that `uv tool` manages.

### Source install (development)

```bash
git clone https://github.com/zw008/VMware-Harden.git
cd VMware-Harden
uv venv && source .venv/bin/activate
uv pip install -e .
```

## Configuration

`vmware-harden` is intentionally near-stateless. The only on-disk
artifacts it owns are:

| Path | Purpose | Created by |
|------|---------|-----------|
| `~/.vmware-harden/twin.duckdb` | Twin store: snapshots, violations, drift, suggestions | First `scan` |
| `~/.vmware-harden/baselines/*.yaml` | User-imported baselines | `baseline import` |

Override the Twin path either per-command (`--db /path/to/twin.duckdb`)
or globally via the `VMWARE_HARDEN_DB` environment variable consumed by
the MCP server.

### Anthropic API key for the advisor

```bash
export ANTHROPIC_API_KEY=sk-ant-...
# or persist in ~/.vmware-harden/.env (chmod 600) and source it in your shell.
```

When the variable is unset, the advisor uses `MockProvider` and prints
`WARN: ANTHROPIC_API_KEY not set — using MockProvider (stub suggestions).`

## MCP client setup

The MCP server is a single console script: `vmware-harden-mcp`.
Spawning the entry point directly (rather than `uvx --from ...`) avoids
re-resolving PyPI on every launch and is **strongly recommended in
corporate environments with TLS proxies** — see the workaround section
below.

Working configuration templates ship under
`examples/mcp-configs/` in the repository.

### Claude Desktop / Claude Code

`~/.claude/settings.json` (Claude Code) or the MCP section of your
Claude Desktop config:

```json
{
  "mcpServers": {
    "vmware-harden": {
      "command": "vmware-harden-mcp",
      "args": [],
      "env": {
        "VMWARE_HARDEN_DB": "~/.vmware-harden/twin.duckdb"
      }
    }
  }
}
```

### Cursor

`.cursor/mcp.json` in your project (or the global `~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "vmware-harden": {
      "command": "vmware-harden-mcp",
      "env": { "VMWARE_HARDEN_DB": "~/.vmware-harden/twin.duckdb" }
    }
  }
}
```

### Cline / Continue / Goose / VS Code Copilot

Use the same `command: vmware-harden-mcp` shape; consult the agent's
own MCP docs for the precise key names. Ready-made templates are in
`examples/mcp-configs/`.

## Multi-target Twin

The Twin namespaces every node by `target` (the upstream `vmware-aiops`
target name). You can scan many vCenters into the same DuckDB without
collisions:

```bash
vmware-harden scan --target lab-vc01 --baseline cis-vmware-esxi-8.0-subset
vmware-harden scan --target prod-vc  --baseline dengbao-2.0-level3-vmware
vmware-harden report                 # shows the most recent snapshot's violations
```

Drift is computed **per target**: each `scan` call diffs against the
prior snapshot whose `target` matches.

## Aria-aware fallback

If the customer already runs **VMware Aria Operations**, harden is
designed to *complement*, not replace, Aria's compliance pack:

| Capability | Aria Operations | vmware-harden |
|------------|:--:|:--:|
| Real-time inventory & metrics | Yes | No (delegates to vmware-aiops) |
| Anomaly detection / capacity | Yes | No (use **vmware-aria** skill) |
| 等保 2.0 三级 baseline | No (not bundled) | **Yes** |
| Custom YAML baseline | Limited | **Yes** |
| LLM-driven remediation advice | No | **Yes** (`advise`) |
| Approval-gated remediation execution | No | Out of scope — use **vmware-pilot** |

Recommended pattern when Aria is present: keep using Aria for live
monitoring, point harden at the same vCenter for **compliance posture
+ drift + remediation advice**, and surface harden's findings into your
AI agent through MCP.

## Corporate TLS workaround

If `uvx --from vmware-harden vmware-harden-mcp` reports
`invalid peer certificate: UnknownIssuer`, your network has a MitM TLS
proxy whose CA is not in `uv`'s bundled webpki store (踩坑 #25).

**Preferred fix**: don't use `uvx` for the MCP server. Install once with
`uv tool install vmware-harden` and configure the MCP client to spawn
`vmware-harden-mcp` directly — that path goes through your shell `PATH`
and never hits PyPI again.

**Fallback**: if you must use `uvx`, set:

```bash
export UV_NATIVE_TLS=true
```

This makes `uv` consult the system CA store (which your IT department's
proxy CA is presumably in), and PyPI resolution works again.

## Security

> **Disclaimer**: This is a community-maintained open-source project and
> is **not affiliated with, endorsed by, or sponsored by VMware, Inc. or
> Broadcom Inc.** "VMware" and "vSphere" are trademarks of Broadcom.
> Source code is publicly auditable at
> [github.com/zw008/VMware-Harden](https://github.com/zw008/VMware-Harden)
> under the MIT license.

- **No credentials of its own.** All vSphere / NSX authentication lives
  in the upstream skills (`~/.vmware-aiops/.env`,
  `~/.vmware-nsx-security/.env`, etc.) under `chmod 600`.
- **No outbound network calls** beyond:
  1. Upstream sibling-skill collectors during `scan`.
  2. Optional `api.anthropic.com` calls when `ANTHROPIC_API_KEY` is set
     and the user invokes `advise`.
  3. The local web dashboard, bound to `127.0.0.1` by default.
- **TLS verification**: full system TLS verification on the Anthropic
  call. Vendor TLS handling for vSphere/NSX is delegated to the upstream
  skills (no opt-out path lives in this codebase).
- **Prompt-injection protection**: the advisor builds its LLM context
  exclusively from typed Twin queries (rule id, severity, structured
  evidence). Any free-text fields are passed through `_sanitize()` —
  truncation to 500 chars and stripping C0/C1 control characters.
- **Least privilege**: all 6 MCP tools are read-only with respect to
  managed VMware resources. Remediation execution is intentionally not
  exposed; agents that need to apply a fix must invoke **vmware-pilot**,
  which adds approval gates and audit logging.
- **Audit log**: every MCP tool call is recorded by the `@vmware_tool`
  decorator into `~/.vmware/audit.db` (SQLite WAL via `vmware-policy`).
  View with `vmware-audit log --last 20`.
