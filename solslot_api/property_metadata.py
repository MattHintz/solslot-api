"""Typed contracts and validation for chain-verifiable property dossiers."""
from __future__ import annotations

from datetime import date
from urllib.parse import urlsplit
from typing import Annotated, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

from .collection_display_units import DisplayUnitError, allocate_par_mojos

from solslot_puzzles.property_metadata import (
    MAX_CANONICAL_METADATA_BYTES,
    PROPERTY_AMENDMENT_SCHEMA,
    PROPERTY_DOSSIER_SCHEMA,
    TARGET_ALLOCATION_PPM,
    MetadataCommitment,
    MetadataValidationError,
    commit_metadata,
)
from solslot_puzzles.real_estate_profiles import (
    ASSET_CLASS_DILIGENCE_KEYS,
    ASSET_CLASS_CODES,
    COMMON_DILIGENCE_KEYS,
    OVERLAY_DILIGENCE_KEYS,
    PROJECT_STAGES,
    PROPERTY_SUBTYPES,
    PROGRAM_OVERLAYS,
    STAGE_DILIGENCE_KEYS,
    required_diligence_keys,
    validate_classification,
)


DecimalString = Annotated[str, StringConstraints(pattern=r"^-?(0|[1-9][0-9]*)$")]
HexSha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-fA-F]{64}$")]
HexBytes32 = Annotated[str, StringConstraints(pattern=r"^0x[0-9a-fA-F]{64}$")]


def _to_camel(value: str) -> str:
    head, *tail = value.split("_")
    return head + "".join(part.capitalize() for part in tail)


class ContractModel(BaseModel):
    model_config = ConfigDict(
        alias_generator=_to_camel,
        populate_by_name=True,
        extra="forbid",
        str_strip_whitespace=True,
    )


class AddressV1(ContractModel):
    line1: str = Field(min_length=1, max_length=180)
    line2: Optional[str] = Field(default=None, max_length=180)
    city: str = Field(min_length=1, max_length=100)
    region: str = Field(min_length=1, max_length=100)
    postal_code: str = Field(min_length=1, max_length=32)
    country: str = Field(min_length=2, max_length=2)


class PropertyIdentityV1(ContractModel):
    address: AddressV1
    property_type: str = Field(min_length=1, max_length=80)
    year_built: Optional[int] = Field(default=None, ge=1000, le=3000)
    bedrooms: Optional[DecimalString] = None
    bathrooms: Optional[DecimalString] = None
    interior_square_feet: Optional[DecimalString] = None
    lot_square_feet: Optional[DecimalString] = None
    latitude: Optional[str] = None
    longitude: Optional[str] = None


class AssetDescriptorV1(ContractModel):
    asset_id: str = Field(min_length=1, max_length=120)
    uris: list[str] = Field(min_length=2, max_length=8)
    sha256: HexSha256
    cid: str = Field(min_length=10, max_length=200)
    mime_type: str = Field(min_length=3, max_length=120)
    byte_size: int = Field(gt=0, le=100 * 1024 * 1024)

    @field_validator("uris")
    @classmethod
    def validate_uris(cls, uris: list[str]) -> list[str]:
        if not any(uri.startswith("https://") for uri in uris):
            raise ValueError("asset requires at least one HTTPS URI")
        if not any(uri.startswith("ipfs://") for uri in uris):
            raise ValueError("asset requires at least one IPFS URI")
        if any(not uri.startswith(("https://", "ipfs://")) for uri in uris):
            raise ValueError("asset URIs must use HTTPS or IPFS")
        return uris


class MediaAssetV1(AssetDescriptorV1):
    role: Literal["hero", "gallery", "site", "rendering", "plan", "floorplan", "other"]
    alt: str = Field(min_length=1, max_length=240)


class DocumentAssetV1(AssetDescriptorV1):
    title: str = Field(min_length=1, max_length=180)
    category: str = Field(min_length=1, max_length=80)


class DraftMediaAssetV1(ContractModel):
    """An upload slot while a collection is still being assembled.

    The immutable descriptor fields become required when the draft is sealed
    as :class:`PropertyDossierV1`.  Keeping a separate draft shape lets the
    desk autosave immediately after file selection without inventing a CID or
    claiming that unverified bytes are investor-ready.
    """

    asset_id: str = Field(min_length=1, max_length=120)
    role: Literal["hero", "gallery", "site", "rendering", "plan", "floorplan", "other"]
    alt: str = Field(min_length=1, max_length=240)
    uris: Optional[list[str]] = Field(default=None, min_length=2, max_length=8)
    sha256: Optional[HexSha256] = None
    cid: Optional[str] = Field(default=None, min_length=10, max_length=200)
    mime_type: Optional[str] = Field(default=None, min_length=3, max_length=120)
    byte_size: Optional[int] = Field(default=None, gt=0, le=100 * 1024 * 1024)


class DraftDocumentAssetV1(ContractModel):
    asset_id: str = Field(min_length=1, max_length=120)
    title: str = Field(min_length=1, max_length=180)
    category: str = Field(min_length=1, max_length=80)
    uris: Optional[list[str]] = Field(default=None, min_length=2, max_length=8)
    sha256: Optional[HexSha256] = None
    cid: Optional[str] = Field(default=None, min_length=10, max_length=200)
    mime_type: Optional[str] = Field(default=None, min_length=3, max_length=120)
    byte_size: Optional[int] = Field(default=None, gt=0, le=100 * 1024 * 1024)


class DraftAddressV1(ContractModel):
    line1: Optional[str] = Field(default=None, min_length=1, max_length=180)
    line2: Optional[str] = Field(default=None, min_length=1, max_length=180)
    city: Optional[str] = Field(default=None, min_length=1, max_length=100)
    region: Optional[str] = Field(default=None, min_length=1, max_length=100)
    postal_code: Optional[str] = Field(default=None, min_length=1, max_length=32)
    country: Optional[str] = Field(default=None, min_length=2, max_length=2)


class DraftPropertyIdentityV1(ContractModel):
    address: DraftAddressV1 = Field(default_factory=DraftAddressV1)
    property_type: Optional[str] = Field(default=None, min_length=1, max_length=80)
    year_built: Optional[int] = Field(default=None, ge=1000, le=3000)
    bedrooms: Optional[DecimalString] = None
    bathrooms: Optional[DecimalString] = None
    interior_square_feet: Optional[DecimalString] = None
    lot_square_feet: Optional[DecimalString] = None
    latitude: Optional[str] = None
    longitude: Optional[str] = None


class ClassificationV1(ContractModel):
    asset_class: str = Field(min_length=1, max_length=64)
    property_subtype: str = Field(min_length=1, max_length=80)
    project_stage: str = Field(min_length=1, max_length=80)
    program_overlays: list[str] = Field(default_factory=list, max_length=10)

    @model_validator(mode="after")
    def validate_profile(self) -> "ClassificationV1":
        validate_classification(
            asset_class=self.asset_class,
            property_subtype=self.property_subtype,
            project_stage=self.project_stage,
            overlays=self.program_overlays,
        )
        self.asset_class = self.asset_class.strip().upper()
        return self


class DraftClassificationV1(ContractModel):
    asset_class: Optional[str] = Field(default=None, min_length=1, max_length=64)
    property_subtype: Optional[str] = Field(default=None, min_length=1, max_length=80)
    project_stage: Optional[str] = Field(default=None, min_length=1, max_length=80)
    program_overlays: list[str] = Field(default_factory=list, max_length=10)


class DiligenceItemV1(ContractModel):
    key: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$", max_length=100)
    value: str = Field(min_length=1, max_length=4000)
    unit: Optional[str] = Field(default=None, max_length=40)
    as_of_date: Optional[str] = None
    evidence_asset_ids: list[str] = Field(default_factory=list, max_length=40)

    @field_validator("as_of_date")
    @classmethod
    def validate_date(cls, value: Optional[str]) -> Optional[str]:
        return _iso_date(value, "diligence.asOfDate") if value else value


class DraftDiligenceItemV1(ContractModel):
    key: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$", max_length=100)
    value: Optional[str] = Field(default=None, min_length=1, max_length=4000)
    unit: Optional[str] = Field(default=None, max_length=40)
    as_of_date: Optional[str] = None
    evidence_asset_ids: list[str] = Field(default_factory=list, max_length=40)

    @field_validator("as_of_date")
    @classmethod
    def validate_date(cls, value: Optional[str]) -> Optional[str]:
        return _iso_date(value, "diligence.asOfDate") if value else value


class DraftValuationV1(ContractModel):
    as_of_date: Optional[str] = None
    market_value_minor: Optional[DecimalString] = None
    currency: Optional[str] = Field(default=None, min_length=3, max_length=3)
    method: Optional[str] = Field(default=None, min_length=1, max_length=100)
    source: Optional[str] = Field(default=None, min_length=1, max_length=180)

    @field_validator("as_of_date")
    @classmethod
    def validate_date(cls, value: Optional[str]) -> Optional[str]:
        return _iso_date(value, "valuation.asOfDate") if value else value


class DraftOfferingV1(ContractModel):
    target_raise_minor: Optional[DecimalString] = None
    currency: Optional[str] = Field(default=None, min_length=3, max_length=3)
    par_value_mojos: Optional[DecimalString] = None
    asset_class: Optional[str] = Field(default=None, min_length=1, max_length=64)
    jurisdiction: Optional[str] = Field(default=None, min_length=1, max_length=64)
    royalty_puzhash: Optional[HexBytes32] = None
    royalty_bps: Optional[DecimalString] = None
    governance_quorum: Optional[DecimalString] = None
    minimum_investment_minor: Optional[DecimalString] = None
    projected_return_bps: Optional[DecimalString] = None
    term_months: Optional[DecimalString] = None


class DraftOperationsV1(ContractModel):
    occupancy_status: Optional[str] = Field(default=None, min_length=1, max_length=80)
    monthly_gross_rent_minor: Optional[DecimalString] = None
    annual_operating_expense_minor: Optional[DecimalString] = None
    currency: Optional[str] = Field(default=None, min_length=3, max_length=3)
    lease_summary: Optional[str] = Field(default=None, min_length=1, max_length=2000)
    manager: Optional[str] = Field(default=None, min_length=1, max_length=180)


class DraftPlannedUseV1(ContractModel):
    label: Optional[str] = Field(default=None, min_length=1, max_length=180)
    amount_minor: Optional[DecimalString] = None


class DraftCapitalV1(ContractModel):
    debt_balance_minor: Optional[DecimalString] = None
    debt_rate_bps: Optional[DecimalString] = None
    debt_maturity_date: Optional[str] = None
    currency: Optional[str] = Field(default=None, min_length=3, max_length=3)
    planned_uses: list[DraftPlannedUseV1] = Field(default_factory=list, max_length=40)

    @field_validator("debt_maturity_date")
    @classmethod
    def validate_date(cls, value: Optional[str]) -> Optional[str]:
        return _iso_date(value, "capital.debtMaturityDate") if value else value


class DraftLegalV1(ContractModel):
    issuer_legal_name: Optional[str] = Field(default=None, min_length=1, max_length=240)
    security_structure: Optional[str] = Field(default=None, min_length=1, max_length=80)
    collateral_summary: Optional[str] = Field(default=None, min_length=1, max_length=4000)
    filing_status: Optional[str] = Field(default=None, min_length=1, max_length=80)
    filing_reference: Optional[str] = Field(default=None, min_length=1, max_length=240)
    priority_description: Optional[str] = Field(default=None, min_length=1, max_length=2000)
    settlement_basis: Optional[str] = Field(default=None, min_length=1, max_length=120)
    transfer_policy: Optional[str] = Field(default=None, min_length=1, max_length=4000)


class ValuationV1(ContractModel):
    as_of_date: str
    market_value_minor: DecimalString
    currency: str = Field(min_length=3, max_length=3)
    method: str = Field(min_length=1, max_length=100)
    source: str = Field(min_length=1, max_length=180)

    _date = field_validator("as_of_date")(
        lambda value: _iso_date(value, "valuation.asOfDate")
    )


class OfferingV1(ContractModel):
    target_raise_minor: DecimalString
    currency: str = Field(min_length=3, max_length=3)
    par_value_mojos: DecimalString
    asset_class: str = Field(min_length=1, max_length=64)
    jurisdiction: str = Field(min_length=1, max_length=64)
    royalty_puzhash: HexBytes32
    royalty_bps: DecimalString
    governance_quorum: DecimalString
    minimum_investment_minor: Optional[DecimalString] = None
    projected_return_bps: Optional[DecimalString] = None
    term_months: Optional[DecimalString] = None

    @model_validator(mode="after")
    def validate_fee_and_class(self) -> "OfferingV1":
        if self.asset_class.strip().upper() not in ASSET_CLASS_CODES:
            raise ValueError("offering asset class is not enabled for RC20")
        if int(self.royalty_bps) > 1_000:
            raise ValueError("primary technology fee cannot exceed 1000 bps")
        return self


class OperationsV1(ContractModel):
    occupancy_status: str = Field(min_length=1, max_length=80)
    monthly_gross_rent_minor: DecimalString
    annual_operating_expense_minor: DecimalString
    currency: str = Field(min_length=3, max_length=3)
    lease_summary: Optional[str] = Field(default=None, max_length=2000)
    manager: Optional[str] = Field(default=None, max_length=180)


class PlannedUseV1(ContractModel):
    label: str = Field(min_length=1, max_length=180)
    amount_minor: DecimalString


class CapitalV1(ContractModel):
    debt_balance_minor: DecimalString
    debt_rate_bps: DecimalString
    debt_maturity_date: Optional[str] = None
    currency: str = Field(min_length=3, max_length=3)
    planned_uses: list[PlannedUseV1] = Field(default_factory=list, max_length=40)

    @field_validator("debt_maturity_date")
    @classmethod
    def validate_maturity(cls, value: Optional[str]) -> Optional[str]:
        return _iso_date(value, "capital.debtMaturityDate") if value else value


class LegalV1(ContractModel):
    issuer_legal_name: str = Field(min_length=1, max_length=240)
    security_structure: str = Field(min_length=1, max_length=80)
    collateral_summary: str = Field(min_length=1, max_length=4000)
    filing_status: str = Field(min_length=1, max_length=80)
    filing_reference: Optional[str] = Field(default=None, max_length=240)
    priority_description: Optional[str] = Field(default=None, max_length=2000)
    settlement_basis: Optional[str] = Field(default=None, max_length=120)
    transfer_policy: str = Field(min_length=1, max_length=4000)


class RiskV1(ContractModel):
    risk_id: str = Field(min_length=1, max_length=120)
    title: str = Field(min_length=1, max_length=180)
    severity: Literal["low", "medium", "high"]
    detail: str = Field(min_length=1, max_length=5000)


class HistoryEventV1(ContractModel):
    date: str
    title: str = Field(min_length=1, max_length=180)
    detail: str = Field(min_length=1, max_length=3000)

    _date = field_validator("date")(lambda value: _iso_date(value, "history.date"))


class DataSourceV1(ContractModel):
    name: str = Field(min_length=1, max_length=180)
    as_of_date: str
    url: str = Field(pattern=r"^https://")

    _date = field_validator("as_of_date")(
        lambda value: _iso_date(value, "dataSources.asOfDate")
    )


class DeedAllocationV1(ContractModel):
    deed_id: str = Field(min_length=1, max_length=120)
    share_ppm: int = Field(ge=1, le=TARGET_ALLOCATION_PPM)
    par_value_mojos: DecimalString
    proposal_id: Optional[str] = None
    deed_launcher_id: Optional[HexBytes32] = None


class DraftRiskV1(ContractModel):
    risk_id: Optional[str] = Field(default=None, min_length=1, max_length=120)
    title: Optional[str] = Field(default=None, min_length=1, max_length=180)
    severity: Optional[Literal["low", "medium", "high"]] = None
    detail: Optional[str] = Field(default=None, min_length=1, max_length=5000)


class DraftHistoryEventV1(ContractModel):
    date: Optional[str] = None
    title: Optional[str] = Field(default=None, min_length=1, max_length=180)
    detail: Optional[str] = Field(default=None, min_length=1, max_length=3000)

    @field_validator("date")
    @classmethod
    def validate_date(cls, value: Optional[str]) -> Optional[str]:
        return _iso_date(value, "history.date") if value else value


class DraftDataSourceV1(ContractModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=180)
    as_of_date: Optional[str] = None
    url: Optional[str] = Field(default=None, pattern=r"^https://")

    @field_validator("as_of_date")
    @classmethod
    def validate_date(cls, value: Optional[str]) -> Optional[str]:
        return _iso_date(value, "dataSources.asOfDate") if value else value


class DraftDeedAllocationV1(ContractModel):
    deed_id: Optional[str] = Field(default=None, min_length=1, max_length=120)
    share_ppm: Optional[int] = Field(default=None, ge=1, le=TARGET_ALLOCATION_PPM)
    par_value_mojos: Optional[DecimalString] = None
    proposal_id: Optional[str] = None
    deed_launcher_id: Optional[HexBytes32] = None


class ProjectPartyV1(ContractModel):
    """Public professional profile; private contacts belong in restricted evidence."""

    legal_name: str = Field(min_length=1, max_length=240)
    display_name: Optional[str] = Field(default=None, min_length=1, max_length=180)
    website: Optional[str] = Field(default=None, max_length=500)
    summary: Optional[str] = Field(default=None, max_length=1200)
    license_reference: Optional[str] = Field(default=None, max_length=180)
    license_jurisdiction: Optional[str] = Field(default=None, max_length=100)

    @field_validator("website")
    @classmethod
    def public_website(cls, value: Optional[str]) -> Optional[str]:
        if value:
            parsed = urlsplit(value)
            if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
                raise ValueError("website must be a public HTTPS URL without credentials")
        return value


class DraftProjectPartyV1(ProjectPartyV1):
    legal_name: Optional[str] = Field(default=None, min_length=1, max_length=240)


class ProjectTeamV1(ContractModel):
    sponsor: ProjectPartyV1
    builder_status: Literal["selected", "not-appointed", "not-applicable"]
    builder_is_sponsor: bool = False
    builder: Optional[ProjectPartyV1] = None

    @model_validator(mode="after")
    def validate_roles(self) -> "ProjectTeamV1":
        if self.builder_is_sponsor:
            if self.builder_status != "selected" or self.builder is not None:
                raise ValueError("a shared sponsor/builder uses the sponsor profile and selected status")
        elif self.builder_status == "selected" and self.builder is None:
            raise ValueError("identify the selected builder")
        elif self.builder_status != "selected" and self.builder is not None:
            raise ValueError("builder profile requires selected status")
        return self


class DraftProjectTeamV1(ContractModel):
    sponsor: DraftProjectPartyV1 = Field(default_factory=DraftProjectPartyV1)
    builder_status: Optional[Literal["selected", "not-appointed", "not-applicable"]] = None
    builder_is_sponsor: bool = False
    builder: Optional[DraftProjectPartyV1] = None


class PropertyDossierV1(ContractModel):
    schema_version: Literal[PROPERTY_DOSSIER_SCHEMA]
    collection_id: str = Field(min_length=1, max_length=120)
    revision: int = Field(ge=1)
    title: str = Field(min_length=1, max_length=180)
    summary: str = Field(min_length=1, max_length=4000)
    classification: Optional[ClassificationV1] = None
    project_team: Optional[ProjectTeamV1] = None
    property: PropertyIdentityV1
    media: list[MediaAssetV1] = Field(min_length=1, max_length=40)
    valuation: ValuationV1
    offering: OfferingV1
    operations: OperationsV1
    capital: CapitalV1
    legal: LegalV1
    risks: list[RiskV1] = Field(min_length=1, max_length=80)
    documents: list[DocumentAssetV1] = Field(min_length=1, max_length=100)
    history: list[HistoryEventV1] = Field(default_factory=list, max_length=200)
    disclosures: list[str] = Field(min_length=1, max_length=100)
    data_sources: list[DataSourceV1] = Field(min_length=1, max_length=100)
    diligence: list[DiligenceItemV1] = Field(default_factory=list, max_length=200)
    deed_allocation: list[DeedAllocationV1] = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def validate_allocation(self) -> "PropertyDossierV1":
        ids = [deed.deed_id.strip().upper() for deed in self.deed_allocation]
        if len(ids) != len(set(ids)):
            raise ValueError("deed allocation contains duplicate deed IDs")
        total = sum(deed.share_ppm for deed in self.deed_allocation)
        if total != TARGET_ALLOCATION_PPM:
            raise ValueError(
                f"deed allocation totals {total} ppm; expected {TARGET_ALLOCATION_PPM}"
            )
        media_ids = [asset.asset_id for asset in [*self.media, *self.documents]]
        if len(media_ids) != len(set(media_ids)):
            raise ValueError("media and document asset IDs must be unique")
        diligence_keys = [item.key for item in self.diligence]
        if len(diligence_keys) != len(set(diligence_keys)):
            raise ValueError("diligence keys must be unique")
        if self.classification is not None:
            required = required_diligence_keys(
                asset_class=self.classification.asset_class,
                project_stage=self.classification.project_stage,
                overlays=self.classification.program_overlays,
            )
            missing = sorted(required - set(diligence_keys))
            if missing:
                raise ValueError("missing required diligence: " + ", ".join(missing))
        issues = metadata_consistency_issues(self)
        if issues:
            raise MetadataConsistencyError(issues)
        return self

    def canonical_payload(self) -> dict:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)

    def commitment(self) -> MetadataCommitment:
        return commit_metadata(self.canonical_payload())


class PropertyDossierDraftV1(ContractModel):
    """Revisioned, structured autosave shape for the Admin Desk.

    Sections are optional only during drafting. ``to_sealed_dossier`` is the
    single boundary that upgrades this document to the strict public contract.
    """

    schema_version: Literal[PROPERTY_DOSSIER_SCHEMA] = PROPERTY_DOSSIER_SCHEMA
    collection_id: str = Field(min_length=1, max_length=120)
    revision: int = Field(ge=1)
    title: str = Field(min_length=1, max_length=180)
    summary: Optional[str] = Field(default=None, min_length=1, max_length=4000)
    classification: Optional[DraftClassificationV1] = None
    project_team: Optional[DraftProjectTeamV1] = None
    property: Optional[DraftPropertyIdentityV1] = None
    media: list[DraftMediaAssetV1] = Field(default_factory=list, max_length=40)
    valuation: Optional[DraftValuationV1] = None
    offering: Optional[DraftOfferingV1] = None
    operations: Optional[DraftOperationsV1] = None
    capital: Optional[DraftCapitalV1] = None
    legal: Optional[DraftLegalV1] = None
    risks: list[DraftRiskV1] = Field(default_factory=list, max_length=80)
    documents: list[DraftDocumentAssetV1] = Field(default_factory=list, max_length=100)
    private_documents: list[DraftDocumentAssetV1] = Field(default_factory=list, max_length=100)
    history: list[DraftHistoryEventV1] = Field(default_factory=list, max_length=200)
    disclosures: list[str] = Field(default_factory=list, max_length=100)
    data_sources: list[DraftDataSourceV1] = Field(default_factory=list, max_length=100)
    diligence: list[DraftDiligenceItemV1] = Field(default_factory=list, max_length=200)
    deed_allocation: list[DraftDeedAllocationV1] = Field(default_factory=list, max_length=1000)

    @model_validator(mode="after")
    def validate_unique_ids(self) -> "PropertyDossierDraftV1":
        deed_ids = [
            deed.deed_id.strip().upper()
            for deed in self.deed_allocation
            if deed.deed_id
        ]
        if len(deed_ids) != len(set(deed_ids)):
            raise ValueError("deed allocation contains duplicate deed IDs")
        asset_ids = [asset.asset_id for asset in [*self.media, *self.documents, *self.private_documents]]
        if len(asset_ids) != len(set(asset_ids)):
            raise ValueError("media and document asset IDs must be unique")
        diligence_keys = [item.key for item in self.diligence]
        if len(diligence_keys) != len(set(diligence_keys)):
            raise ValueError("diligence keys must be unique")
        return self

    def to_sealed_dossier(self) -> PropertyDossierV1:
        payload = self.model_dump(mode="json", by_alias=True, exclude_none=True)
        payload.pop("privateDocuments", None)
        return PropertyDossierV1.model_validate(
            payload
        )


class MetadataConsistencyError(ValueError):
    """Carry field-specific checks through Pydantic's sealed-dossier boundary."""

    def __init__(self, issues: list[dict[str, str]]) -> None:
        self.issues = issues
        super().__init__("; ".join(issue["message"] for issue in issues))


def metadata_consistency_issues(
    dossier: PropertyDossierDraftV1 | PropertyDossierV1,
) -> list[dict[str, str]]:
    """Check duplicated facts and references without completing an unfinished draft."""
    issues: list[dict[str, str]] = []

    def mismatch(code: str, path: str, message: str) -> None:
        issues.append({"code": code, "path": path, "message": message})

    classification, property_, offering = dossier.classification, dossier.property, dossier.offering
    if classification is not None:
        if (offering and classification.asset_class and offering.asset_class
                and classification.asset_class.upper() != offering.asset_class.upper()):
            mismatch("ASSET_CLASS_MISMATCH", "/offering/assetClass",
                     "Offering asset class must match Property type classification.")
        if (property_ and classification.property_subtype and property_.property_type
                and classification.property_subtype.lower() != property_.property_type.lower()):
            mismatch("PROPERTY_SUBTYPE_MISMATCH", "/property/propertyType",
                     "Property type must match the classified property subtype.")

    if offering and offering.currency:
        for section in ("valuation", "operations", "capital"):
            values = getattr(dossier, section)
            if values and values.currency and values.currency.upper() != offering.currency.upper():
                mismatch("CURRENCY_MISMATCH", f"/{section}/currency",
                         f"{section.capitalize()} currency must match offering currency; no FX conversion is recorded.")
    if (offering and offering.par_value_mojos is not None and dossier.deed_allocation
            and all(deed.par_value_mojos is not None for deed in dossier.deed_allocation)):
        total = sum(int(deed.par_value_mojos) for deed in dossier.deed_allocation)
        if total != int(offering.par_value_mojos):
            mismatch("ALLOCATION_PAR_MISMATCH", "/deedAllocation",
                     f"SmartDeed par totals {total} mojos; it must equal collection par {offering.par_value_mojos}.")
        elif (all(deed.share_ppm is not None for deed in dossier.deed_allocation)
              and sum(deed.share_ppm for deed in dossier.deed_allocation) == TARGET_ALLOCATION_PPM):
            shares = {f"deed.{index}": deed.share_ppm for index, deed in enumerate(dossier.deed_allocation)}
            try:
                expected = allocate_par_mojos(total, shares)
            except DisplayUnitError as exc:
                mismatch("ALLOCATION_PAR_INVALID", "/deedAllocation", str(exc))
            else:
                for index, deed in enumerate(dossier.deed_allocation):
                    if int(deed.par_value_mojos) != expected[f"deed.{index}"]:
                        mismatch("DEED_PAR_SHARE_MISMATCH", f"/deedAllocation/{index}/parValueMojos",
                                 "SmartDeed par must match its ownership share using the standard allocation rounding.")

    public_assets = {asset.asset_id for asset in [*dossier.media, *dossier.documents]}
    for index, item in enumerate(dossier.diligence):
        path = f"/diligence/{index}/evidenceAssetIds"
        if len(item.evidence_asset_ids) != len(set(item.evidence_asset_ids)):
            mismatch("DUPLICATE_EVIDENCE_REFERENCE", path,
                     "Link each evidence asset only once in this diligence item.")
        if any(asset_id not in public_assets for asset_id in item.evidence_asset_ids):
            mismatch("EVIDENCE_REFERENCE_MISSING", path,
                     "Public diligence evidence must reference media or documents included in the public dossier. Private originals stay in administrator review.")
    return issues


class Eip712AmendmentSignatureV1(ContractModel):
    scheme: Literal["eip712"]
    signer: str
    signature: str
    chain_id: DecimalString
    typed_data_hash: HexBytes32


class BlsAmendmentSignatureV1(ContractModel):
    scheme: Literal["bls"]
    signer: str
    signature: str
    message_hash: HexBytes32


class PropertyAmendmentV1(ContractModel):
    schema_version: Literal[PROPERTY_AMENDMENT_SCHEMA]
    collection_id: str
    previous_root: HexBytes32
    new_root: HexBytes32
    reason: str = Field(min_length=8, max_length=2000)
    effective_date: str
    changed_fields: list[str] = Field(min_length=1, max_length=100)
    signature: Eip712AmendmentSignatureV1 | BlsAmendmentSignatureV1 = Field(
        discriminator="scheme"
    )

    _date = field_validator("effective_date")(
        lambda value: _iso_date(value, "effectiveDate")
    )


PROTECTED_AMENDMENT_PATHS = frozenset(
    {
        "/deedAllocation",
        "/classification",
        "/offering/parValueMojos",
        "/offering/assetClass",
        "/offering/jurisdiction",
        "/offering/royaltyPuzhash",
        "/offering/royaltyBps",
        "/offering/governanceQuorum",
        "/offering/targetRaiseMinor",
        "/legal/securityStructure",
        "/legal/settlementBasis",
    }
)


def validate_amendment_paths(paths: list[str]) -> None:
    for path in paths:
        normalized = path.rstrip("/") or "/"
        if any(
            normalized == protected or normalized.startswith(protected + "/")
            for protected in PROTECTED_AMENDMENT_PATHS
        ):
            raise MetadataValidationError(
                f"owner-signed amendments cannot change protected field {path}"
            )


def _iso_date(value: str, field: str) -> str:
    try:
        date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 date") from exc
    return value


__all__ = [
    "ASSET_CLASS_DILIGENCE_KEYS",
    "ASSET_CLASS_CODES",
    "COMMON_DILIGENCE_KEYS",
    "MAX_CANONICAL_METADATA_BYTES",
    "OVERLAY_DILIGENCE_KEYS",
    "PROTECTED_AMENDMENT_PATHS",
    "PropertyAmendmentV1",
    "PropertyDossierDraftV1",
    "PropertyDossierV1",
    "PROJECT_STAGES",
    "PROPERTY_SUBTYPES",
    "PROGRAM_OVERLAYS",
    "STAGE_DILIGENCE_KEYS",
    "validate_amendment_paths",
]
