"""Prepare the private two-item Sepolia test edition from its reviewed sealed source."""
from .collection_store import CollectionConflict, CollectionForbidden, CollectionNotFound, CollectionStore
from .test_collection_metadata import TEST_DISCLOSURE, TestPropertyDraftV1

GENERATION = '0x2219d1e2dba64ceb4df84e70ce14b6b2d8d94b0e99350664dd3371c2f3234d57'
SOURCE_ID = 'TEST-88DD05ABFA6B91DDE96118BC'
SOURCE_ROOT = '0x86570ba629b3c4e2cd9f35b081cbba7963f1a0b9a62830d92d2460b8d4bbf74d'
SOURCE_REVISION = 14
EDITION_ID = 'TEST-EASTMORELAND-SEPOLIA-QA-20261124'
TITLE = '127 Eastmoreland St · Base Sepolia checkout test pair'
REVIEW = '0x33a7848779aee94471000cdf729733a2e17a708ccf4b01357c94aa95a0155a75'
SUMMARY = (
    'Private checkout test for two SmartDeeds at 1.000000 Circle test USDC total on Base Sepolia '
    '(chain 84532, token 0x036CbD53842c5426634e7929541eC2318f3dCF7e). Each test deed costs '
    '0.49 test USDC plus a 0.01 test USDC technology fee. Each represents half of this test pair. '
    'The items confer no property, investment, voting or redemption rights. '
    'Delivery network is Chia Testnet11. Private order review ' + REVIEW + '.'
)


def prepare(store: CollectionStore, *, source_id: str, revision: int, root: str, subject: str, auth_type: str):
    if store.network != 'testnet11' or store.generation_id != GENERATION:
        raise CollectionConflict('This test edition belongs to a different workspace.')
    if (source_id, revision, root) != (SOURCE_ID, SOURCE_REVISION, SOURCE_ROOT):
        raise CollectionConflict('The source differs from the reviewed Eastmoreland edition.')
    source = store.get(source_id, include_related=False)
    if source['ownerSubject'] != subject.lower():
        raise CollectionForbidden('Only the administrator who owns this source can prepare its test pair.')
    if (source['generationId'], source['state'], source['revision'], source['metadataRoot']) != (GENERATION, 'SEALED', revision, root):
        raise CollectionConflict('The sealed source changed. Review it again.')
    draft = TestPropertyDraftV1(
        collectionId=EDITION_ID, generationId=GENERATION, title=TITLE, revision=1, summary=SUMMARY,
        provenance=dict(sourceCollectionId=SOURCE_ID, sourceGenerationId=GENERATION,
                        sourceRevision=revision, sourceDraftHash=source['draftHash']),
        offering=dict(targetRaiseMinor='98', currency='USD', royaltyBps='100'),
        disclosures=[TEST_DISCLOSURE],
        deedAllocation=[dict(deedId=f'{EDITION_ID}-{index:02d}', sharePpm=500000) for index in (1, 2)],
    )
    expected = draft.model_dump(mode='json', by_alias=True, exclude_none=True)
    try:
        return store.create(collection_id=EDITION_ID, title=TITLE, owner_subject=subject,
                            owner_auth_type=auth_type, initial_draft=draft)
    except CollectionConflict:
        try:
            existing = store.get(EDITION_ID)
        except CollectionNotFound:
            raise CollectionConflict('The test edition identifier is already in use.') from None
        if (existing['ownerSubject'] != subject.lower() or existing['state'] != 'DRAFT'
                or existing['dossier'] != expected):
            raise CollectionConflict('The saved test edition has changed. Open it from Properties.') from None
        return existing
