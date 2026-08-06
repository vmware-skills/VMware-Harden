"""MCP tool implementations for the vSphere 9 STIG catalog (read-only).

In the `vmware_harden` package (like mcp/tools.py) so the @vmware_tool
decorator tags audit rows with skill="harden". Both tools read local baseline
YAML only — no database, no network, no compliance API (there is none; see
vmware_harden.baselines.stig.describe_content_sync).
"""
from vmware_policy import paginated, vmware_tool


@vmware_tool(risk_level="low")
def list_stig_controls(limit: int = 50, offset: int = 0) -> dict:
    """[READ] List the vSphere 9 / VCF 9 STIG baseline's host controls.

    Returns the family list envelope; each item is {id, title, severity,
    category, advanced_setting} where advanced_setting is the ESXi advanced
    setting the control governs. The whole catalog is paged locally, so `total`
    is exact.
    """
    from vmware_harden.baselines.stig import stig_catalog

    if limit < 1:
        raise ValueError(
            f"limit must be >= 1 (got {limit}). Re-run list_stig_controls with "
            "limit=50 (the default) or a larger page size."
        )
    if offset < 0:
        raise ValueError(
            f"offset must be >= 0 (got {offset}). Re-run list_stig_controls with "
            "offset=0 for the first page."
        )
    catalog = stig_catalog()
    page = catalog[offset : offset + limit]
    env = paginated(page, limit=limit, total=len(catalog))
    # paginated() flags truncation as (returned < total), which is offset-unaware:
    # every page past the first is a partial slice, so it would report
    # truncated=true forever — even on the final page where nothing follows.
    # Recompute against the absolute position in the catalog.
    still_more = offset + len(page) < len(catalog)
    env["truncated"] = still_more
    if not still_more:
        env["hint"] = None
    return env


@vmware_tool(risk_level="low")
def describe_stig_content_sync() -> dict:
    """[READ] Explain harden's STIG integration and route continuous enforcement.

    Returns {compliance_api_available, why_no_api, content_sources, mechanism,
    routing_note, importer_status}. Takes no parameters. Local, static content.
    """
    from vmware_harden.baselines.stig import describe_content_sync

    return describe_content_sync()
