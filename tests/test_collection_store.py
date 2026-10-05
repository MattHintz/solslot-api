from __future__ import annotations

from copy import deepcopy

import pytest

from solslot_api.collection_store import (
    CollectionConflict,
    CollectionForbidden,
    CollectionInvalidState,
    CollectionStore,
)
from solslot_api.property_metadata import (
    PropertyAmendmentV1,
    PropertyDossierDraftV1,
    PropertyDossierV1,
)


def dossier_payload() -> dict:
    return {
        "schemaVersion": "solslot.property-dossier.v1",
        "collectionId": "HARBOR-17",
        "revision": 1,
        "title": "17 Harbor Street",
        "summary": "Two-unit residential property with a documented renovation plan.",
        "projectTeam": {
            "sponsor": {"legalName": "Harbor Project Sponsor LLC"},
            "builderStatus": "not-applicable",
            "builderIsSponsor": False,
        },
        "classification": {
            "assetClass": "RWA-RE-RES",
            "propertySubtype": "duplex",
            "projectStage": "stabilized",
            "programOverlays": [],
        },
        "property": {
            "address": {
                "line1": "17 Harbor Street",
                "city": "Oakland",
                "region": "CA",
                "postalCode": "94607",
                "country": "US",
            },
            "propertyType": "duplex",
            "yearBuilt": 1928,
            "bedrooms": "4",
            "bathrooms": "2",
            "interiorSquareFeet": "2410",
        },
        "media": [
            {
                "assetId": "hero-exterior",
                "role": "hero",
                "alt": "Front exterior of 17 Harbor Street",
                "uris": [
                    "https://assets.example/harbor-17/exterior.jpg",
                    "ipfs://bafyhero123",
                ],
                "sha256": "11" * 32,
                "cid": "bafyhero123",
                "mimeType": "image/jpeg",
                "byteSize": 100,
            }
        ],
        "valuation": {
            "asOfDate": "2026-07-01",
            "marketValueMinor": "82500000",
            "currency": "USD",
            "method": "independent-appraisal",
            "source": "North Bay Valuation LLC",
        },
        "offering": {
            "targetRaiseMinor": "50000000",
            "currency": "USD",
            "parValueMojos": "250000000000",
            "assetClass": "RWA-RE-RES",
            "jurisdiction": "US-CA",
            "royaltyPuzhash": "0x" + "77" * 32,
            "royaltyBps": "250",
            "governanceQuorum": "5000",
        },
        "operations": {
            "occupancyStatus": "leased",
            "monthlyGrossRentMinor": "585000",
            "annualOperatingExpenseMinor": "2190000",
            "currency": "USD",
        },
        "capital": {
            "debtBalanceMinor": "31000000",
            "debtRateBps": "675",
            "currency": "USD",
        },
        "legal": {
            "issuerLegalName": "Harbor 17 Property LLC",
            "securityStructure": "entity_ucc",
            "collateralSummary": "First-priority pledge of issuer membership interests.",
            "filingStatus": "recorded",
            "transferPolicy": "Transfers require eligibility and protocol settlement.",
        },
        "risks": [
            {
                "riskId": "liquidity",
                "title": "Limited liquidity",
                "severity": "high",
                "detail": "A secondary market may not develop.",
            }
        ],
        "documents": [
            {
                "assetId": "appraisal-2026",
                "title": "Independent appraisal",
                "category": "valuation",
                "uris": [
                    "https://assets.example/harbor-17/appraisal.pdf",
                    "ipfs://bafyappraisal",
                ],
                "sha256": "22" * 32,
                "cid": "bafyappraisal",
                "mimeType": "application/pdf",
                "byteSize": 200,
            }
        ],
        "history": [],
        "disclosures": ["Projected returns are not guaranteed."],
        "dataSources": [
            {
                "name": "North Bay Valuation LLC",
                "asOfDate": "2026-07-01",
                "url": "https://assets.example/harbor-17/appraisal.pdf",
            }
        ],
        "diligence": [
            {"key": key, "value": "Reviewed", "evidenceAssetIds": []}
            for key in (
                "building-details",
                "comparable-sales",
                "debt",
                "insurance",
                "occupancy",
                "operating-history",
                "property-condition",
                "title",
                "valuation",
            )
        ],
        "deedAllocation": [
            {"deedId": "HARBOR-17-A", "sharePpm": 600000, "parValueMojos": "150000000000"},
            {"deedId": "HARBOR-17-B", "sharePpm": 400000, "parValueMojos": "100000000000"},
        ],
    }


def verified_store() -> tuple[CollectionStore, dict]:
    store = CollectionStore(":memory:")
    store.create(
        collection_id="HARBOR-17",
        title="17 Harbor Street",
        owner_subject="0xowner",
        owner_auth_type="evm",
    )
    collection = store.update_draft(
        "HARBOR-17",
        draft=PropertyDossierDraftV1.model_validate(dossier_payload()),
        expected_revision=1,
        actor_subject="0xreviewer",
        submit_for_review=True,
    )
    store.submit_review(
        "HARBOR-17",
        reviewer_subject="0xreviewer",
        decision="APPROVED",
        note="Current revision reviewed.",
    )
    for asset_id, kind, digest, mime, size, url, cid in (
        (
            "hero-exterior", "MEDIA", "11" * 32, "image/jpeg", 100,
            "https://assets.example/harbor-17/exterior.jpg", "bafyhero123",
        ),
        (
            "appraisal-2026", "DOCUMENT", "22" * 32, "application/pdf", 200,
            "https://assets.example/harbor-17/appraisal.pdf", "bafyappraisal",
        ),
    ):
        store.declare_asset(
            "HARBOR-17",
            asset_id=asset_id,
            kind=kind,
            expected_sha256=digest,
            expected_mime_type=mime,
            expected_byte_size=size,
            actor_subject="0xreviewer",
        )
        store.mark_asset_uploaded(
            "HARBOR-17", asset_id, object_key=f"objects/{asset_id}", actor_subject="0xreviewer"
        )
        store.mark_asset_verified(
            "HARBOR-17",
            asset_id,
            actual_sha256=digest,
            actual_mime_type=mime,
            actual_byte_size=size,
            malware_status="CLEAN",
            verified_https_url=url,
            ipfs_cid=cid,
            availability_status="HEALTHY",
            actor_subject="0xreviewer",
        )
    return store, collection


def test_draft_uses_optimistic_concurrency_and_keeps_owner_only_seal() -> None:
    store, collection = verified_store()
    assert collection["revision"] == 2
    assert store.readiness("HARBOR-17")["ready"] is True

    with pytest.raises(CollectionConflict, match="revision conflict"):
        store.update_draft(
            "HARBOR-17",
            draft=PropertyDossierDraftV1.model_validate(dossier_payload()),
            expected_revision=1,
            actor_subject="0xreviewer",
        )
    with pytest.raises(CollectionForbidden):
        store.seal(
            "HARBOR-17", expected_revision=2, actor_subject="0xreviewer"
        )

    sealed = store.seal("HARBOR-17", expected_revision=2, actor_subject="0xowner")
    assert sealed["state"] == "SEALED"
    assert sealed["metadataRoot"].startswith("0x")
    assert sealed["canonicalByteSize"] > 100
    store.close()


def test_first_proposal_locks_allocation_and_creates_issuance_version() -> None:
    store, _ = verified_store()
    store.seal("HARBOR-17", expected_revision=2, actor_subject="0xowner")
    published = store.record_proposal_publication(
        "HARBOR-17",
        "HARBOR-17-A",
        actor_subject="0xowner",
        proposal_id="proposal-a",
        proposal_hash=b"\x31" * 32,
        proposal_launcher_id=b"\x32" * 32,
        deed_launcher_id=b"\x33" * 32,
        output_coin_id=b"\x33" * 32,
        publish_bundle_id="0x" + "34" * 32,
    )
    assert published["state"] == "PUBLISHED"
    assert published["allocationLocked"] is True
    assert published["metadataAnchorId"] == "0x" + "33" * 32
    assert published["deeds"][0]["outputCoinId"] == "0x" + "33" * 32
    assert [version["kind"] for version in published["metadataVersions"]] == ["ISSUANCE"]

    with pytest.raises(CollectionInvalidState):
        store.update_draft(
            "HARBOR-17",
            draft=PropertyDossierDraftV1.model_validate(dossier_payload()),
            expected_revision=2,
            actor_subject="0xowner",
        )
    store.close()


def test_execution_is_mirrored_without_regressing_on_anchor_refresh() -> None:
    store, _ = verified_store()
    sealed = store.seal("HARBOR-17", expected_revision=2, actor_subject="0xowner")
    store.record_proposal_publication(
        "HARBOR-17",
        "HARBOR-17-A",
        actor_subject="0xowner",
        proposal_id="proposal-a",
        proposal_hash=b"\x35" * 32,
        proposal_launcher_id=b"\x36" * 32,
        deed_launcher_id=b"\x37" * 32,
        output_coin_id=b"\x37" * 32,
        publish_bundle_id="0x" + "38" * 32,
    )
    executed = store.record_proposal_execution(
        "proposal-a",
        execute_bundle_id="0x" + "39" * 32,
        actor_subject="0xreviewer",
    )
    assert executed is not None
    assert executed["deeds"][0]["proposalState"] == "EXECUTED"
    assert executed["deeds"][0]["executeBundleId"] == "0x" + "39" * 32

    store.record_anchor_evidence(
        "HARBOR-17",
        "HARBOR-17-A",
        anchor_coin_id=b"\x37" * 32,
        status="CONFIRMED",
        reconstructed_root=bytes.fromhex(sealed["metadataRoot"][2:]),
        spend_bundle_id="0x" + "38" * 32,
        confirmation_height=321,
        puzzle_solution_hash="0x" + "3a" * 32,
        details={"source": "coinset-puzzle-solution"},
    )
    refreshed = store.get("HARBOR-17")
    assert refreshed["deeds"][0]["proposalState"] == "EXECUTED"
    assert store.record_proposal_execution(
        "legacy-proposal",
        execute_bundle_id="0x" + "3b" * 32,
        actor_subject="0xreviewer",
    ) is None
    with pytest.raises(CollectionConflict, match="different execute bundle"):
        store.record_proposal_execution(
            "proposal-a",
            execute_bundle_id="0x" + "3c" * 32,
            actor_subject="0xreviewer",
        )
    store.close()


def test_owner_amendment_is_append_only_and_protected_fields_are_rejected() -> None:
    store, _ = verified_store()
    sealed = store.seal("HARBOR-17", expected_revision=2, actor_subject="0xowner")
    store.record_proposal_publication(
        "HARBOR-17",
        "HARBOR-17-A",
        actor_subject="0xowner",
        proposal_id="proposal-a",
        proposal_hash=b"\x41" * 32,
        proposal_launcher_id=b"\x42" * 32,
        deed_launcher_id=b"\x43" * 32,
        output_coin_id=b"\x43" * 32,
        publish_bundle_id="0x" + "44" * 32,
    )
    amended_payload = deepcopy(dossier_payload())
    amended_payload["revision"] = 3
    amended_payload["operations"]["occupancyStatus"] = "partially-leased"
    amended = PropertyDossierV1.model_validate(amended_payload)
    root = "0x" + amended.commitment().metadata_root.hex()
    envelope = PropertyAmendmentV1.model_validate(
        {
            "schemaVersion": "solslot.property-amendment.v1",
            "collectionId": "HARBOR-17",
            "previousRoot": sealed["metadataRoot"],
            "newRoot": root,
            "reason": "One unit became vacant after the issuance snapshot.",
            "effectiveDate": "2026-07-15",
            "changedFields": ["/operations/occupancyStatus"],
            "signature": {
                "scheme": "eip712",
                "signer": "0xowner",
                "signature": "0xdeadbeef",
                "chainId": "11155111",
                "typedDataHash": "0x" + "55" * 32,
            },
        }
    )
    updated = store.append_amendment(
        "HARBOR-17",
        dossier=amended,
        amendment=envelope,
        expected_revision=2,
        actor_subject="0xowner",
    )
    assert updated["revision"] == 3
    assert [version["kind"] for version in updated["metadataVersions"]] == [
        "ISSUANCE",
        "OWNER_AMENDMENT",
    ]
    assert updated["metadataVersions"][0]["metadataRoot"] == sealed["metadataRoot"]

    protected_payload = deepcopy(amended_payload)
    protected_payload["revision"] = 4
    protected_payload["offering"]["royaltyBps"] = "999"
    protected = PropertyDossierV1.model_validate(protected_payload)
    bad_envelope = envelope.model_copy(
        update={
            "previous_root": updated["metadataRoot"],
            "new_root": "0x" + protected.commitment().metadata_root.hex(),
            "changed_fields": ["/offering/royaltyBps"],
        }
    )
    with pytest.raises(ValueError, match="protected field"):
        store.append_amendment(
            "HARBOR-17",
            dossier=protected,
            amendment=bad_envelope,
            expected_revision=3,
            actor_subject="0xowner",
        )
    store.close()


def test_public_verification_requires_chain_reconstruction() -> None:
    store, _ = verified_store()
    sealed = store.seal("HARBOR-17", expected_revision=2, actor_subject="0xowner")
    store.record_proposal_publication(
        "HARBOR-17",
        "HARBOR-17-A",
        actor_subject="0xowner",
        proposal_id="proposal-a",
        proposal_hash=b"\x61" * 32,
        proposal_launcher_id=b"\x62" * 32,
        deed_launcher_id=b"\x63" * 32,
        output_coin_id=b"\x63" * 32,
        publish_bundle_id="0x" + "64" * 32,
    )
    assert store.public_collection("17-harbor-street")["verification"]["verified"] is False
    store.record_anchor_evidence(
        "HARBOR-17",
        "HARBOR-17-A",
        anchor_coin_id=b"\x63" * 32,
        status="CONFIRMED",
        reconstructed_root=bytes.fromhex(sealed["metadataRoot"][2:]),
        spend_bundle_id="0x" + "64" * 32,
        confirmation_height=123,
        puzzle_solution_hash="0x" + "65" * 32,
        details={"source": "coinset-puzzle-solution"},
    )
    public = store.public_collection("17-harbor-street")
    assert public["verification"]["chainReconstructed"] is True
    assert public["verification"]["verified"] is True

    # Abandoned upload declarations are not part of the canonical dossier and
    # therefore cannot invalidate otherwise healthy referenced media.
    store.declare_asset(
        "HARBOR-17",
        asset_id="unused-upload",
        kind="MEDIA",
        expected_sha256="66" * 32,
        expected_mime_type="image/png",
        expected_byte_size=10,
        actor_subject="0xowner",
    )
    assert store.public_collection("17-harbor-street")["verification"]["verified"] is True

    store.declare_asset(
        "HARBOR-17",
        asset_id="unredacted-title",
        kind="DOCUMENT",
        visibility="PRIVATE",
        expected_sha256="67" * 32,
        expected_mime_type="application/pdf",
        expected_byte_size=300,
        actor_subject="0xowner",
    )
    store.mark_asset_uploaded(
        "HARBOR-17",
        "unredacted-title",
        object_key="private/collections/HARBOR-17/unredacted-title.pdf",
        actor_subject="0xowner",
    )
    store.mark_asset_verified(
        "HARBOR-17",
        "unredacted-title",
        actual_sha256="67" * 32,
        actual_mime_type="application/pdf",
        actual_byte_size=300,
        malware_status="CLEAN",
        verified_https_url=None,
        ipfs_cid=None,
        availability_status="PRIVATE",
        actor_subject="0xowner",
    )
    private = store.authorize_private_asset_download(
        "HARBOR-17", "unredacted-title", actor_subject="0xreviewer"
    )
    assert private["visibility"] == "PRIVATE"
    assert all(
        asset["assetId"] != "unredacted-title"
        for asset in store.public_collection("17-harbor-street")["assets"]
    )
    assert store.audit_events("HARBOR-17")[-1]["action"] == "PRIVATE_DOCUMENT_ACCESSED"

    # Every canonical media descriptor matters. A failed hero must remove the
    # public verified state even when the referenced document remains healthy.
    store.mark_asset_failed(
        "HARBOR-17",
        "hero-exterior",
        reason="gateway hash mismatch",
        actor_subject="0xowner",
    )
    verification = store.public_collection("17-harbor-street")["verification"]
    assert verification["mediaVerified"] is False
    assert verification["verified"] is False
    store.close()


def test_private_document_descriptor_stays_out_of_canonical_and_public_metadata() -> None:
    store, collection = verified_store()
    payload = dossier_payload()
    payload["revision"] = collection["revision"]
    payload["privateDocuments"] = [
        {
            "assetId": "unredacted-title",
            "title": "Unredacted title report",
            "category": "title",
            "sha256": "68" * 32,
            "mimeType": "application/pdf",
            "byteSize": 300,
        }
    ]
    reviewed = store.update_draft(
        "HARBOR-17",
        draft=PropertyDossierDraftV1.model_validate(payload),
        expected_revision=collection["revision"],
        actor_subject="0xowner",
        submit_for_review=True,
    )
    store.submit_review(
        "HARBOR-17",
        reviewer_subject="0xreviewer",
        decision="APPROVED",
        note="Private original and redacted public evidence reviewed.",
    )
    store.declare_asset(
        "HARBOR-17",
        asset_id="unredacted-title",
        kind="DOCUMENT",
        visibility="PRIVATE",
        expected_sha256="68" * 32,
        expected_mime_type="application/pdf",
        expected_byte_size=300,
        actor_subject="0xowner",
    )
    store.mark_asset_uploaded(
        "HARBOR-17",
        "unredacted-title",
        object_key="private/collections/HARBOR-17/unredacted-title.pdf",
        actor_subject="0xowner",
    )
    store.mark_asset_verified(
        "HARBOR-17",
        "unredacted-title",
        actual_sha256="68" * 32,
        actual_mime_type="application/pdf",
        actual_byte_size=300,
        malware_status="CLEAN",
        verified_https_url=None,
        ipfs_cid=None,
        availability_status="PRIVATE",
        actor_subject="0xowner",
    )
    sealed = store.seal(
        "HARBOR-17",
        expected_revision=reviewed["revision"],
        actor_subject="0xowner",
    )
    store.record_proposal_publication(
        "HARBOR-17",
        "HARBOR-17-A",
        actor_subject="0xowner",
        proposal_id="proposal-private-boundary",
        proposal_hash=b"\x69" * 32,
        proposal_launcher_id=b"\x6a" * 32,
        deed_launcher_id=b"\x6b" * 32,
        output_coin_id=b"\x6b" * 32,
        publish_bundle_id="0x" + "6c" * 32,
    )

    admin = store.get("HARBOR-17")
    public = store.public_collection("HARBOR-17")
    issuance = public["metadataVersions"][0]["canonicalMetadata"]

    assert admin["dossier"]["privateDocuments"][0]["assetId"] == (
        "unredacted-title"
    )
    assert "privateDocuments" not in public["dossier"]
    assert "privateDocuments" not in issuance
    assert all(
        asset["assetId"] != "unredacted-title" for asset in public["assets"]
    )
    assert sealed["metadataRoot"] == public["metadataRoot"]
    store.close()
