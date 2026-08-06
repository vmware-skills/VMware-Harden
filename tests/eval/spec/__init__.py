"""Verified-spec data modules for vmware-harden regression tests.

These modules encode facts verified against external sources *before* code was
written (踩坑 #36 guard: a prior family skill shipped hallucinated endpoints,
half of which 404'd). Tests import from here and assert the shipped code touches
only what was verified — never the reverse.
"""
