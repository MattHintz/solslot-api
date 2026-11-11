"""Explicitly incomplete Testnet11 editions. Never a production qualification.

Dollar economics have one source: offering.targetRaiseMinor, allocation shares
and fsreTerms. Displays derive per-deed prices; diligence references those
fields rather than carrying another editable copy.
"""
from __future__ import annotations

from typing import Literal
from pydantic import Field, field_validator, model_validator
from solslot_puzzles.property_metadata import commit_metadata
from solslot_puzzles.real_estate_profiles import (required_diligence_keys, COMMON_DILIGENCE_KEYS,
    ASSET_CLASS_DILIGENCE_KEYS, STAGE_DILIGENCE_KEYS, OVERLAY_DILIGENCE_KEYS)
from .property_metadata import (
    ContractModel, HexBytes32, DecimalString, PropertyDossierDraftV1,
    PropertyIdentityV1, ClassificationV1, ProjectTeamV1, DraftOfferingV1,
    MediaAssetV1, DocumentAssetV1, DeedAllocationV1, RiskV1,
    MetadataConsistencyError, metadata_consistency_issues,
    DraftValuationV1, DraftCapitalV1, DraftOperationsV1, DraftLegalV1,
    DraftDiligenceItemV1,
)

TEST_EDITION_SCHEMA = 'solslot.testnet-property-dossier.v1'
TEST_DISCLOSURE = 'TESTNET ONLY: no real investment, ownership or legal rights.'
CANONICAL_DILIGENCE = {
    'valuation': ['/valuation', '/valuationBasis', '/valuationEvidence'],
    'as-completed-valuation': ['/valuation', '/valuationBasis', '/valuationEvidence'],
    'debt': ['/capital'],
    'occupancy': ['/operations/occupancyStatus'],
    'building-details': ['/property'],
}
UNKNOWN_PATHS = {
    f'/{section}/{field.alias}'
    for section, model in [('valuation', DraftValuationV1), ('capital', DraftCapitalV1),
        ('operations', DraftOperationsV1), ('legal', DraftLegalV1)]
    for field in model.model_fields.values()
} | {
    f'/diligence/{key}' for key in set(COMMON_DILIGENCE_KEYS).union(
        *ASSET_CLASS_DILIGENCE_KEYS.values(), *STAGE_DILIGENCE_KEYS.values(), *OVERLAY_DILIGENCE_KEYS.values())
}


class EditionProvenance(ContractModel):
    source_collection_id: str = Field(min_length=1, max_length=120)
    source_revision: int = Field(ge=1)
    source_draft_hash: HexBytes32
    source_generation_id: str = Field(min_length=1, max_length=120)


class UnknownField(ContractModel):
    path: str = Field(pattern=r'^/(valuation|capital|operations|legal|diligence)/[A-Za-z0-9-]+$', max_length=160)
    status: Literal['UNKNOWN'] = 'UNKNOWN'
    reason: str = Field(min_length=8, max_length=500)

    @field_validator('path')
    @classmethod
    def supported_field(cls, value):
        if value not in UNKNOWN_PATHS:
            raise ValueError('unresolved field must name an existing property or diligence field')
        return value


class TestDiligenceItem(DraftDiligenceItemV1):
    references: list[str] = Field(default_factory=list, max_length=8)

    @model_validator(mode='after')
    def one_source(self):
        expected = CANONICAL_DILIGENCE.get(self.key)
        if expected:
            if self.references != expected or self.value is not None or self.unit is not None or self.as_of_date is not None:
                raise ValueError(f'{self.key} must reference its canonical fields instead of copying their values')
        elif self.references:
            raise ValueError('unsupported diligence reference')
        return self


class FsreDraftTerms(ContractModel):
    structure: Literal['FSRE'] = 'FSRE'
    return_basis: Literal['MARKET_VALUE'] = 'MARKET_VALUE'
    participation_bps: int | None = Field(default=None, gt=0, le=10000)
    outside_term_months: int | None = Field(default=None, gt=0, le=120)
    projected_months_min: int | None = Field(default=None, gt=0, le=120)
    projected_months_max: int | None = Field(default=None, gt=0, le=120)


class FsreTestTerms(FsreDraftTerms):
    structure: Literal['FSRE'] = 'FSRE'
    return_basis: Literal['MARKET_VALUE'] = 'MARKET_VALUE'
    participation_bps: int = Field(gt=0, le=10000)
    outside_term_months: int = Field(gt=0, le=120)
    projected_months_min: int = Field(gt=0, le=120)
    projected_months_max: int = Field(gt=0, le=120)

    @model_validator(mode='after')
    def coherent_projection(self):
        if not self.projected_months_min <= self.projected_months_max <= self.outside_term_months:
            raise ValueError('projected duration must fit the outside term')
        return self


class TestOffering(DraftOfferingV1):
    target_raise_minor: DecimalString
    currency: Literal['USD']
    par_value_mojos: DecimalString
    asset_class: str = Field(min_length=1, max_length=64)
    jurisdiction: str = Field(min_length=1, max_length=64)
    royalty_puzhash: HexBytes32
    royalty_bps: DecimalString
    # These are derived from consensus / fsreTerms, not editable metadata copies.
    governance_quorum: None = None
    projected_return_bps: None = None
    term_months: None = None

    @model_validator(mode='after')
    def positive_economics(self):
        if int(self.target_raise_minor) <= 0 or int(self.par_value_mojos) <= 0:
            raise ValueError('raise and par must be positive')
        if not 0 <= int(self.royalty_bps) <= 1000:
            raise ValueError('technology fee must be within the protocol ceiling')
        return self


class TestPropertyDraftV1(PropertyDossierDraftV1):
    __test__ = False
    schema_version: Literal[TEST_EDITION_SCHEMA] = TEST_EDITION_SCHEMA
    purpose: Literal['TEST_ONLY'] = 'TEST_ONLY'
    network: Literal['testnet11'] = 'testnet11'
    generation_id: HexBytes32
    pricing_round_hash: HexBytes32 | None = None
    provenance: EditionProvenance
    unknown_fields: list[UnknownField] = Field(default_factory=list, max_length=200)
    fsre_terms: FsreDraftTerms | None = None
    valuation_basis: Literal['TO_BE_BUILT', 'AS_IS'] | None = None
    valuation_evidence: Literal['USER_CONFIRMED', 'REPORT_REVIEWED'] | None = None
    diligence: list[TestDiligenceItem] = Field(default_factory=list, max_length=200)

    @model_validator(mode='after')
    def validate_unknowns(self):
        paths = [item.path for item in self.unknown_fields]
        if len(paths) != len(set(paths)):
            raise ValueError('unknown-field paths must be unique')
        payload = self.model_dump(by_alias=True)
        for path in paths:
            _, section, field = path.split('/')
            if section == 'diligence':
                known = next((item.value for item in self.diligence if item.key == field), None)
            else:
                known = (payload.get(section) or {}).get(field)
            if known is not None:
                raise ValueError(f'{path} cannot be both known and unknown')
        return self

    def to_sealed_dossier(self):
        payload = self.model_dump(mode='json', by_alias=True, exclude_none=True)
        payload.pop('privateDocuments', None)
        return TestPropertyDossierV1.model_validate(payload)


class TestPropertyDossierV1(TestPropertyDraftV1):
    """Public test contract with strict economics and explicitly unknown diligence."""
    summary: str = Field(min_length=1, max_length=4000)
    property: PropertyIdentityV1
    classification: ClassificationV1
    project_team: ProjectTeamV1
    media: list[MediaAssetV1] = Field(min_length=1, max_length=40)
    documents: list[DocumentAssetV1] = Field(default_factory=list, max_length=100)
    private_documents: list = Field(default_factory=list, max_length=0)
    deed_allocation: list[DeedAllocationV1] = Field(min_length=1, max_length=1000)
    risks: list[RiskV1] = Field(min_length=1, max_length=80)
    offering: TestOffering
    pricing_round_hash: HexBytes32
    fsre_terms: FsreTestTerms
    valuation_basis: Literal['TO_BE_BUILT', 'AS_IS']
    valuation_evidence: Literal['USER_CONFIRMED', 'REPORT_REVIEWED']

    @model_validator(mode='after')
    def test_seal(self):
        if not self.title.endswith(' — Testnet Edition') or TEST_DISCLOSURE not in self.disclosures:
            raise ValueError('test edition title and public test-only disclosure are required')
        if sum(deed.share_ppm for deed in self.deed_allocation) != 1_000_000:
            raise ValueError('deed shares must total 1,000,000 ppm')
        if any(int(deed.par_value_mojos) <= 0 for deed in self.deed_allocation):
            raise ValueError('each deed must have positive par')
        if self.valuation is None or not self.valuation.market_value_minor or int(self.valuation.market_value_minor) <= 0:
            raise ValueError('explicit valuation amount and evidence classification are required')
        issues = metadata_consistency_issues(self)
        if issues:
            raise MetadataConsistencyError(issues)
        required = {
            'valuation': ['asOfDate', 'currency', 'method', 'source'],
            'capital': ['debtBalanceMinor', 'debtRateBps', 'currency'],
            'operations': ['occupancyStatus', 'monthlyGrossRentMinor', 'annualOperatingExpenseMinor', 'currency'],
            'legal': ['issuerLegalName', 'securityStructure', 'collateralSummary', 'filingStatus', 'transferPolicy'],
        }
        payload = self.model_dump(by_alias=True)
        unknowns = {item.path for item in self.unknown_fields}
        for section, fields in required.items():
            for field in fields:
                path = f'/{section}/{field}'
                if (payload.get(section) or {}).get(field) is None and path not in unknowns:
                    raise ValueError(f'{path} needs a value or an explicit unresolved reason')
        diligence_keys = required_diligence_keys(asset_class=self.classification.asset_class,
            project_stage=self.classification.project_stage, overlays=self.classification.program_overlays)
        known_keys = {item.key for item in self.diligence if item.value or item.references}
        for key in diligence_keys - known_keys:
            if f'/diligence/{key}' not in unknowns:
                raise ValueError(f'/diligence/{key} needs review or an explicit unresolved reason')
        if self.valuation_evidence == 'REPORT_REVIEWED' and any(item.path.startswith('/valuation/') for item in self.unknown_fields):
            raise ValueError('a reviewed appraisal report needs its report details')
        return self

    def canonical_payload(self):
        payload = self.model_dump(mode='json', by_alias=True, exclude_none=True)
        payload.pop('privateDocuments', None)
        return payload

    def commitment(self):
        return commit_metadata(self.canonical_payload())


def parse_collection_draft(payload: dict) -> PropertyDossierDraftV1 | TestPropertyDraftV1:
    if payload.get('schemaVersion') == TEST_EDITION_SCHEMA:
        return TestPropertyDraftV1.model_validate(payload)
    return PropertyDossierDraftV1.model_validate(payload)


def require_edition_binding(draft, *, network: str, generation_id: str | None):
    if isinstance(draft, TestPropertyDraftV1):
        if network != 'testnet11' or not generation_id or draft.generation_id.lower() != generation_id.lower():
            raise ValueError('test edition does not belong to this Testnet11 generation')
