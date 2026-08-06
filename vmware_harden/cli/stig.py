"""`vmware-harden stig` — inspect the vSphere 9 STIG-aligned catalog (read-only).

Content, not an API: VCF Operations 9.1 ACC/SPM exposes no public compliance
REST endpoint, so these subcommands read local baseline YAML only. Run an actual
scan with `vmware-harden scan --baseline vsphere-stig-v9-subset --target <vc>`.
"""
import json

import typer

from vmware_harden.baselines.stig import (
    STIG_BASELINE_ID,
    describe_content_sync,
    stig_catalog,
)

app = typer.Typer()


@app.command("controls")
def controls_cmd() -> None:
    """List the STIG baseline's host controls (id, severity, advanced setting)."""
    catalog = stig_catalog()
    for row in catalog:
        typer.echo(
            f"{row['id']:<40} {row['severity']:<8} "
            f"{row['category']:<16} {row['advanced_setting']}"
        )
    typer.echo(f"\n{len(catalog)} controls in {STIG_BASELINE_ID}")


@app.command("sync-info")
def sync_info_cmd() -> None:
    """Show how harden syncs with upstream STIG content + routing to SPM/ACC."""
    typer.echo(json.dumps(describe_content_sync(), indent=2, ensure_ascii=False))
