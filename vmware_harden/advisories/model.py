"""Pydantic models for the offline VMware security advisory catalog.

The catalog is data, shipped inside the package (``catalog.yaml``) so it lands
in the wheel. Every entry carries the sources it was taken from; the shipped
file is checked mechanically by ``tests/unit/test_advisory_catalog.py``.
"""

from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Product = Literal["esxi", "vcenter"]

#: VMware's own advisory severity scale, as printed on each VMSA.
VendorSeverity = Literal["critical", "important", "moderate", "low"]


class Cve(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    cvss: float | None = Field(default=None, ge=0.0, le=10.0)
    #: In CISA's Known Exploited Vulnerabilities catalog as of the catalog date.
    kev: bool = False
    #: Empty preserves legacy advisory-wide applicability.
    products: list[Product] = Field(default_factory=list)

    @field_validator("id")
    @classmethod
    def _cve_id(cls, v: str) -> str:
        if not v.startswith("CVE-"):
            raise ValueError(f"not a CVE id: {v!r}")
        return v


class FixedRelease(BaseModel):
    """The first release on one update branch of a line that carries the fix."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    #: Update number within the line: ``3`` for "8.0 Update 3".
    update: int = Field(ge=0)
    build: int = Field(gt=0)
    #: Human-readable release name, e.g. "ESXi 8.0 Update 3d".
    label: str


class AffectedLine(BaseModel):
    """One product line the advisory lists as affected, with its fixes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    product: Product
    #: ``major.minor``, e.g. "8.0". Builds are only ever compared inside a line.
    line: str
    #: Empty means the advisory lists the line as affected with no fix.
    fixed: list[FixedRelease] = Field(default_factory=list)
    #: Update branches whose status the sources do not settle (e.g. they
    #: disagree on whether a release carries the fix). Always judged unknown.
    unknown_updates: list[int] = Field(default_factory=list)
    #: Empty applies the mapping to every CVE covering this product.
    cves: list[str] = Field(default_factory=list)


class NotAffectedLine(BaseModel):
    """A line the advisory explicitly states is not affected."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    product: Product
    line: str


class Advisory(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    published: date
    title: str
    severity: VendorSeverity
    cves: list[Cve]
    #: Where every fact in this entry was read. At least one is required.
    sources: list[str] = Field(min_length=1)
    affected: list[AffectedLine] = Field(min_length=1)
    not_affected: list[NotAffectedLine] = Field(default_factory=list)
    #: Products the advisory covers whose rows this catalog does not carry.
    #: Judged unknown rather than not_applicable: the advisory does cover them.
    uncatalogued_products: list[Product] = Field(default_factory=list)

    def cves_for_product(self, product: str) -> list[Cve]:
        return [c for c in self.cves if not c.products or product in c.products]

    @model_validator(mode="after")
    def _validate_cve_scopes(self) -> "Advisory":
        ids = {c.id for c in self.cves}
        if len(ids) != len(self.cves):
            raise ValueError("duplicate CVE IDs in advisory")
        mappings: set[tuple[str, str, str]] = set()
        for row in self.affected:
            applicable = {c.id for c in self.cves_for_product(row.product)}
            selected = set(row.cves) if row.cves else applicable
            if selected - ids:
                raise ValueError("affected-line mapping references an unknown CVE")
            if selected - applicable:
                raise ValueError("affected-line CVE does not cover this product")
            for cve_id in selected:
                key = (row.product, row.line, cve_id)
                if key in mappings:
                    raise ValueError("overlapping product/line/CVE mappings")
                mappings.add(key)
        return self

    @property
    def products(self) -> frozenset[str]:
        return (
            frozenset(a.product for a in self.affected)
            | frozenset(n.product for n in self.not_affected)
            | frozenset(self.uncatalogued_products)
            | frozenset(p for c in self.cves for p in c.products)
        )

    @property
    def kev(self) -> bool:
        return any(c.kev for c in self.cves)


class Catalog(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    #: The date the catalog was last checked against its sources. Advisories
    #: published after it are not in it — a clean result means "no open advisory
    #: known as of this date", never "not vulnerable".
    as_of: date
    #: End-of-general-support date per product line. An advisory published after
    #: a line's EOL does not list that line, so its absence means nothing.
    eol: dict[Product, dict[str, date]] = Field(default_factory=dict)
    advisories: list[Advisory]
    #: Provenance of the shipped KEV flags, distinct from a user's online cache.
    shipped_kev_checked_at: datetime | None = None
    shipped_kev_catalog_version: str | None = None
    #: Set only when an online refresh cache was overlaid (see
    #: :mod:`vmware_harden.advisories.refresh`): when it was fetched and which
    #: CISA KEV catalog version it read. None means the shipped catalog alone.
    kev_refreshed_at: datetime | None = None
    kev_catalog_version: str | None = None
