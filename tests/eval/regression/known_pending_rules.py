"""Rules that cannot judge anything yet — the collector backlog, frozen.

Each entry reads at least one attribute declared ``PENDING`` in
``vmware_harden.baselines.vocabulary``: intended, but no collector writes it.
Such a rule matches zero rows, which reads as *compliant*, so it must not be
presented as a passing check.

The contract test asserts this set matches reality **exactly**, both ways:

  * a rule that starts citing a pending attribute and is not listed -> fail
    (new breakage cannot be introduced quietly)
  * a rule that is listed but no longer cites one -> fail
    (a repaired rule must be struck off, so the list cannot rot into a
    permanent excuse — the same guarantee ``xfail(strict=True)`` would give,
    without turning the whole test into one that can no longer fail)

Shrinking this list is the measure of progress for collector batches B1-B5 in
``design/LLD-harden-baseline-collector-contract.md``. Delete entries as their
attributes become ACTIVE; never add one to make a build green.

Current: 70 rules across 6 baselines.
   9  bsi-itgs-basisabsicherung-vmware
  16  cis-vmware-esxi-8.0-subset
  15  dengbao-2.0-level3-vmware
  10  eu-nis2-vmware
   6  pci-dss-4.0-vmware
  14  vsphere-scg-v8-subset
"""

#: ``(baseline_id, rule_id)`` pairs, with the pending attributes that block each.
KNOWN_PENDING_RULES: frozenset[tuple[str, str]] = frozenset(
    {
        # --- bsi-itgs-basisabsicherung-vmware ---
        ("bsi-itgs-basisabsicherung-vmware", "bsi-itgs-malware-1"),  # image_profile_acceptance
        ("bsi-itgs-basisabsicherung-vmware", "bsi-itgs-malware-2"),  # nx_enabled
        ("bsi-itgs-basisabsicherung-vmware", "bsi-itgs-malware-3"),  # image_profile_acceptance
        ("bsi-itgs-basisabsicherung-vmware", "bsi-itgs-server-1"),  # lockdown_mode
        ("bsi-itgs-basisabsicherung-vmware", "bsi-itgs-server-3"),  # ad_joined
        ("bsi-itgs-basisabsicherung-vmware", "bsi-itgs-server-6"),  # patch_status
        ("bsi-itgs-basisabsicherung-vmware", "bsi-itgs-server-7"),  # secure_boot_enabled
        # --- cis-vmware-esxi-8.0-subset ---
        ("cis-vmware-esxi-8.0-subset", "cis-esxi-2.2.2"),  # lockdown_mode_enabled
        ("cis-vmware-esxi-8.0-subset", "cis-esxi-3.1.2"),  # persistent_logs
        ("cis-vmware-esxi-8.0-subset", "cis-esxi-3.1.3"),  # audit_retention_days
        ("cis-vmware-esxi-8.0-subset", "cis-esxi-4.1.1"),  # mgmt_vmk_isolated
        ("cis-vmware-esxi-8.0-subset", "cis-esxi-4.1.2"),  # vswitch_promiscuous_mode
        ("cis-vmware-esxi-8.0-subset", "cis-esxi-4.1.3"),  # forged_transmits
        ("cis-vmware-esxi-8.0-subset", "cis-esxi-6.1.1"),  # ad_joined
        ("cis-vmware-esxi-8.0-subset", "cis-esxi-6.1.2"),  # lockdown_exceptions_count
        ("cis-vmware-esxi-8.0-subset", "cis-esxi-6.1.3"),  # root_ssh_key_auth
        ("cis-vmware-esxi-8.0-subset", "cis-esxi-7.1.1"),  # vsan_enabled, vsan_encryption_enabled
        ("cis-vmware-esxi-8.0-subset", "cis-esxi-7.1.2"),  # encrypted_vmotion
        ("cis-vmware-esxi-8.0-subset", "cis-esxi-8.1.3"),  # console_keyboard
        # --- dengbao-2.0-level3-vmware ---
        ("dengbao-2.0-level3-vmware", "db-l3-net-3"),  # encrypted_vmotion
        ("dengbao-2.0-level3-vmware", "db-l3-net-4"),  # tls_min_version
        ("dengbao-2.0-level3-vmware", "db-l3-net-5"),  # mgmt_vlan_tagged
        ("dengbao-2.0-level3-vmware", "db-l3-host-1"),  # root_ssh_key_auth
        ("dengbao-2.0-level3-vmware", "db-l3-host-2"),  # ad_joined
        ("dengbao-2.0-level3-vmware", "db-l3-host-3"),  # lockdown_mode_enabled
        ("dengbao-2.0-level3-vmware", "db-l3-host-6"),  # audit_retention_days
        ("dengbao-2.0-level3-vmware", "db-l3-host-7"),  # host_secure_boot
        ("dengbao-2.0-level3-vmware", "db-l3-host-8"),  # host_tpm_attested
        ("dengbao-2.0-level3-vmware", "db-l3-vm-2"),  # secure_boot
        ("dengbao-2.0-level3-vmware", "db-l3-vm-3"),  # encryption_enabled, tags
        ("dengbao-2.0-level3-vmware", "db-l3-data-1"),  # encryption_enabled
        ("dengbao-2.0-level3-vmware", "db-l3-policy-1"),  # section_name
        # --- eu-nis2-vmware ---
        ("eu-nis2-vmware", "nis2-rm-1"),  # patch_status
        ("eu-nis2-vmware", "nis2-rm-3"),  # named_admin_accounts, shared_root_in_use
        ("eu-nis2-vmware", "nis2-ir-1"),  # audit_log_retention_days
        ("eu-nis2-vmware", "nis2-ir-2"),  # backup_policy_present
        ("eu-nis2-vmware", "nis2-ir-3"),  # datastore_encryption
        ("eu-nis2-vmware", "nis2-net-2"),  # mgmt_isolated
        ("eu-nis2-vmware", "nis2-net-3"),  # vmotion_encryption
        ("eu-nis2-vmware", "nis2-ac-1"),  # ad_joined
        ("eu-nis2-vmware", "nis2-ac-2"),  # root_ssh_enabled
        ("eu-nis2-vmware", "nis2-sc-1"),  # secure_boot_enabled
        # --- pci-dss-4.0-vmware ---
        ("pci-dss-4.0-vmware", "pci-r2-1"),  # default_admin_disabled
        ("pci-dss-4.0-vmware", "pci-r7-1"),  # ad_joined
        ("pci-dss-4.0-vmware", "pci-r8-1"),  # root_ssh_key_auth_enabled
        ("pci-dss-4.0-vmware", "pci-r8-2"),  # lockdown_mode
        ("pci-dss-4.0-vmware", "pci-r10-2"),  # audit_log_retention_days
        # --- vsphere-scg-v8-subset ---
        ("vsphere-scg-v8-subset", "scg-host-1"),  # host_tpm_attested
        ("vsphere-scg-v8-subset", "scg-host-2"),  # host_secure_boot
        ("vsphere-scg-v8-subset", "scg-host-3"),  # image_profile_acceptance
        ("vsphere-scg-v8-subset", "scg-host-4"),  # vib_acceptance
        ("vsphere-scg-v8-subset", "scg-host-5"),  # tls_min_version
        ("vsphere-scg-v8-subset", "scg-vm-1"),  # secure_boot
        ("vsphere-scg-v8-subset", "scg-vm-2"),  # hw_version_int
        ("vsphere-scg-v8-subset", "scg-vm-4"),  # encryption_enabled, tags
        ("vsphere-scg-v8-subset", "scg-vm-5"),  # isolation_copy_disabled
        ("vsphere-scg-v8-subset", "scg-net-1"),  # mgmt_vlan_tagged
        ("vsphere-scg-v8-subset", "scg-net-2"),  # mac_address_changes
        ("vsphere-scg-v8-subset", "scg-net-3"),  # standard_vswitch_count
        ("vsphere-scg-v8-subset", "scg-enc-1"),  # vsan_enabled, vsan_encryption_enabled
        ("vsphere-scg-v8-subset", "scg-enc-2"),  # encrypted_vmotion
    }
)
