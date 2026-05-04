# Security Policy

## Disclaimer

This is a community-maintained open-source project and is **not affiliated with, endorsed by, or sponsored by VMware, Inc. or Broadcom Inc.** "VMware" and "vSphere" are trademarks of Broadcom Inc.

**Author**: Wei Zhou, VMware by Broadcom — wei-wz.zhou@broadcom.com

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it privately:

- **Email**: wei-wz.zhou@broadcom.com
- **GitHub**: Open a [private security advisory](https://github.com/zw008/VMware-Harden/security/advisories/new)

Do **not** open a public GitHub issue for security vulnerabilities.

## Security Design

### Credential Management

- `vmware-harden` does **not** hold or read vSphere/NSX/Aria credentials directly. All infrastructure access is delegated to sibling skills (`vmware-aiops`, `vmware-monitor`, `vmware-nsx`, etc.), each of which manages its own `~/.vmware-<skill>/.env` with `chmod 600` enforcement.
- The only credential consumed by this skill is the LLM provider API key (e.g. `ANTHROPIC_API_KEY`), which **must** be supplied via environment variable. It is never read from config files, never logged, and never persisted to disk.
- Audit entries written to `~/.vmware/audit.db` contain operation metadata only — never credentials, raw prompts containing secrets, or LLM API keys.

### Read-Only by Design

This skill is **strictly non-destructive**. Every MCP tool and every CLI command performs only read operations: it reads compliance baselines (YAML), queries sibling skills' read-only twin APIs, runs LLM analysis, and writes findings to local report files. **No tool in this codebase can modify vSphere, NSX, Aria, or Kubernetes state.** Remediation work is intentionally deferred to `vmware-pilot`, which provides approval gating and audit trails for write operations.

### Compliance Baselines as Data

- Compliance baselines (CIS, DISA STIG, vendor hardening guides) ship as **YAML files** under `vmware_harden/baselines/`.
- Baselines are loaded through Pydantic models in **strict mode** — unknown fields are rejected, types are enforced, and no field is ever passed to `eval()`, `exec()`, or a shell.
- User-supplied baseline overrides go through the same Pydantic validation gate before being merged.

### LLM Integration

- The only LLM integration is the **Anthropic API** via the official SDK. No alternate providers, no proxies, no shell-out to local models.
- LLM prompts are constructed from **typed Twin query results** (Pydantic-validated dataclasses from sibling skills), never from raw user free-text.
- LLM responses are parsed back through Pydantic validators before being persisted as findings; malformed responses are rejected with a structured error rather than being trusted blindly.
- The skill never executes LLM-generated code, shell commands, or API calls. LLM output is treated as data (text findings + structured severity), not as instructions.

### Audit Logging

- Every MCP tool invocation is wrapped with the `@vmware_tool` decorator from `vmware-policy`.
- Each call appends an entry to `~/.vmware/audit.db` (SQLite WAL): timestamp, tool name, parameters (sanitized), result status, agent context.
- Audit-write failures degrade to stderr warnings and never block the primary operation.

### SSL/TLS Verification

- `vmware-harden` makes **no direct TLS connections to vSphere, NSX, or Aria** — TLS verification policy is owned by the sibling skills it delegates to.
- The Anthropic API client uses the system CA bundle and full certificate verification by default.

### Transitive Dependencies

- The only family-internal dependency is `vmware-policy` (the `@vmware_tool` decorator + audit logging).
- All other dependencies are standard Python packages (Pydantic, PyYAML, anthropic, Click, Rich).
- No post-install scripts, no background services, no daemons.

### Prompt Injection Protection

- Twin query results consumed by the LLM are **typed Pydantic objects**, not raw API blobs. Free-form text fields (VM names, event messages, host log lines) are sanitized via the upstream skill's `_sanitize()` (≤500 chars, C0/C1 stripped) before crossing the skill boundary.
- LLM-side defense in depth: prompts wrap untrusted fields in explicit boundary markers (`[ASSET_NAME]`, `[EVENT_TEXT]`, …) so the model can distinguish data from instructions.
- Findings returned by the LLM are validated through Pydantic before being persisted; any field that fails type/length/enum validation is rejected, not stored.

## Static Analysis

This project is scanned with [Bandit](https://bandit.readthedocs.io/) before every release, targeting 0 Medium+ issues:

```bash
uvx bandit -r vmware_harden/ mcp_server/
```

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.5.x   | Yes       |
| < 1.5   | No        |
