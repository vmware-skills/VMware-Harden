<!-- mcp-name: io.github.vmware-skills/vmware-harden -->

# VMware-Harden

Turn VMware compliance checks into findings with visible coverage gaps.

English · [简体中文](README-CN.md)

Community-maintained · MIT · Not an official VMware/Broadcom product.

[![18-second illustrative investigation demo](https://raw.githubusercontent.com/vmware-skills/marketplace/main/assets/demos/vmware-skills-en.gif)](https://github.com/vmware-skills/marketplace/blob/main/assets/demos/vmware-skills-en.mp4)

Synthetic-data animation, not a live recording. [Watch the AI-narrated family introduction (~2 min)](https://github.com/vmware-skills/marketplace/blob/main/assets/demos/vmware-skills-en.mp4)

## Why use it?

- Scan supported baselines and vulnerability/build evidence.
- Track configuration drift in a local Twin.
- Separate remediation suggestions from remote execution.

## Get started

Install the published CLI and inspect its commands:

```sh
uv tool install 'vmware-harden[collectors]==1.20.0'
vmware-harden --help
```

Requires uv and Python >=3.10. Configure targets and credentials locally before remote queries. [Setup guide](skills/vmware-harden/references/setup-guide.md).

For Claude Code and other host installation paths, see the [family portal](https://github.com/vmware-skills/marketplace).

## Know the boundaries

Incomplete or unknown checks are not passes. Optional AI remediation advice can send findings to an external provider; review that data flow. Remote remediation is separate.

## Go deeper

- [Capabilities](skills/vmware-harden/references/capabilities.md)
- [CLI reference](skills/vmware-harden/references/cli-reference.md)
- [Agent guardrails](skills/vmware-harden/references/agent-guardrails.md)
- [Detailed usage and architecture](skills/vmware-harden/references/detailed-guide.md)
- [Canonical skill instructions](skills/vmware-harden/SKILL.md)

Part of [VMware Skills](https://github.com/vmware-skills/marketplace): 15 skills, 14 MCP servers and one shared Policy library. If it helps your work, star the family portal.

[Issues and feedback](https://github.com/vmware-skills/VMware-Harden/issues) · [MIT](LICENSE)
