<!-- mcp-name: io.github.vmware-skills/vmware-harden -->

# VMware-Harden

<a id="readme-overview"></a>

Turn VMware compliance checks into findings with visible coverage gaps.

English · [简体中文](https://github.com/vmware-skills/VMware-Harden/blob/main/README-CN.md)

Community-maintained · MIT · Not an official VMware/Broadcom product.

[![24-second illustrative investigation demo](https://raw.githubusercontent.com/vmware-skills/marketplace/main/assets/demos/vmware-skills-en.gif)](https://github.com/vmware-skills/marketplace/releases/download/demos-2026-11-13-operations/vmware-skills-en.mp4)

Synthetic-data GIF; video includes redacted historical screenshots. [Download the AI-narrated family introduction (~3 min)](https://github.com/vmware-skills/marketplace/releases/download/demos-2026-11-13-operations/vmware-skills-en.mp4)

<a id="readme-capabilities-and-workflows"></a>

## Why use it?

- Scan supported baselines and vulnerability/build evidence.
- Track configuration drift in a local Twin.
- Separate remediation suggestions from remote execution.

<a id="readme-quick-start"></a>

## Get started

Install the published CLI and inspect its commands:

```sh
uv tool install "vmware-harden[collectors]==1.20.1"
vmware-harden --help
```

Requires uv and Python >=3.10. Configure targets and credentials locally before remote queries. [Setup guide](https://github.com/vmware-skills/VMware-Harden/blob/main/skills/vmware-harden/references/setup-guide.md).

One-click installs, after local setup: [Claude Desktop extension (.mcpb)](https://github.com/vmware-skills/VMware-Harden/releases/download/v1.20.1/vmware-harden-1.20.1.mcpb) · [Install in VS Code](https://insiders.vscode.dev/redirect/mcp/install?name=vmware-harden&config=%7B%22type%22%3A%22stdio%22%2C%22command%22%3A%22uvx%22%2C%22args%22%3A%5B%22--from%22%2C%22vmware-harden%5Bcollectors%5D%3D%3D1.20.1%22%2C%22vmware-harden-mcp%22%5D%7D). Both run the same pinned 1.20.1 server.

For agent-host installation, use the [setup guide](https://github.com/vmware-skills/VMware-Harden/blob/main/skills/vmware-harden/references/setup-guide.md) and [Cursor, Codex, Gemini CLI, Cline and local-model examples](https://github.com/vmware-skills/marketplace/blob/main/docs/agent-hosts.md).

Choose a model with the [shared model-fit workflow](https://github.com/vmware-skills/marketplace/blob/main/model-fit/RUNNER.md): compare the same tasks, review quality and safety, then select the smallest tested passing configuration per task group; this is not a production guarantee.

<a id="readme-safety-and-audit"></a>

## Know the boundaries

Incomplete or unknown checks are not passes. Optional AI remediation advice can send findings to an external provider; review that data flow. Remote remediation is separate.

<a id="readme-mcp-configuration"></a> <a id="readme-troubleshooting"></a> <a id="readme-reference"></a>

## Go deeper

- [Capabilities](https://github.com/vmware-skills/VMware-Harden/blob/main/skills/vmware-harden/references/capabilities.md)
- [CLI reference](https://github.com/vmware-skills/VMware-Harden/blob/main/skills/vmware-harden/references/cli-reference.md)
- [Agent guardrails](https://github.com/vmware-skills/VMware-Harden/blob/main/skills/vmware-harden/references/agent-guardrails.md)
- [Detailed usage and architecture](https://github.com/vmware-skills/VMware-Harden/blob/main/skills/vmware-harden/references/detailed-guide.md)
- [MCP launch configuration](https://github.com/vmware-skills/VMware-Harden/blob/main/.mcp.json)
- [Canonical skill instructions](https://github.com/vmware-skills/VMware-Harden/blob/main/skills/vmware-harden/SKILL.md)

<a id="readme-companion-skills"></a>

Part of [VMware Skills](https://github.com/vmware-skills/marketplace): 15 skills, 14 MCP servers and one shared Policy library. If it helps your work, star the family portal.

<a id="readme-license"></a>

[Issues and feedback](https://github.com/vmware-skills/VMware-Harden/issues) · [MIT](https://github.com/vmware-skills/VMware-Harden/blob/main/LICENSE)

## MCP result contract

Offset-capable listings expose `next_offset`; stop when it is null rather than looping on `truncated`. Failed calls provide `structuredContent.vmware_error` through Policy 1.26.0. Existing text, legacy flags, success values and confirmation checks remain unchanged. See the [contract](skills/vmware-harden/references/mcp-result-contract.md).
