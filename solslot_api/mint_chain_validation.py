"""Canonical validation for the disposable V2 mint lifecycle.

The portal builds and signs bundles, but it is not an authority for protocol
coordinates or proposal metadata.  These helpers re-derive the immutable mint
artifacts from the signed genesis artifact and inspect the exact coin topology
before the API submits anything to Coinset.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from chia.consensus.condition_tools import (
    conditions_dict_for_solution,
    pkm_pairs_for_conditions_dict,
)
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
)
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import SpendBundle
from chia_rs.sized_bytes import bytes32

from .mint_proposals import StoredMintProposal
from .mint_publish_validation import PublishProposalMetadata, metadata_bytes
from solslot_puzzles.real_estate_profiles import ASSET_CLASS_CODES

ALPHA_ASSET_CLASS_CODES = {name: int(code) for name, code in ASSET_CLASS_CODES.items()}


@dataclass(frozen=True)
class CanonicalPublish:
    smart_deed_inner_puzhash: bytes32
    eve_inner_puzhash: bytes32
    deed_full_puzhash: bytes32
    proposal_hash: bytes32
    proposal_data_hash: bytes32
    proposal_singleton_launcher_id: bytes32
    deed_launcher_id: bytes32
    proposal_tracker_coin_id: bytes32
    sgt_lock_coin_id: bytes32
    property_registry_coin_id: bytes32
    property_registry_puzzle_hash: bytes32
    voting_deadline: int


@dataclass(frozen=True)
class CanonicalKosMintExecution:
    """The one MINT execution a KoS signer may attest to.

    This deliberately carries no generic coin-spend or arbitrary-message
    signing capability. The values are re-derived from the canonical bundle
    and signed genesis artifact before the coordinator contacts the isolated
    signer.
    """

    governance_coin_id: bytes32
    proposal_hash: bytes32
    cosigner_pubkey: bytes
    visible_message: bytes
    signing_message: bytes


def validate_publish_bundle(
    *,
    bundle: SpendBundle,
    metadata: PublishProposalMetadata,
    proposal: StoredMintProposal,
    artifact: dict[str, Any],
    authenticated_owner: str,
) -> CanonicalPublish:
    """Validate and re-derive the four-spend proposal publication bundle."""
    from solslot_puzzles import load_puzzle
    from solslot_puzzles.eip712_helpers import (
        compute_eip712_member_leaf_hash,
        eip712_prefix_and_domain_separator,
        eip712_type_hash,
        genesis_challenge_for_network,
    )
    from solslot_puzzles.mint_publish_driver import (
        build_mint_publish_artifacts,
        deed_launcher_puzzle_hash,
    )
    from solslot_puzzles.property_registry_driver import canonicalise_property_id
    from solslot_puzzles.protocol_deployment import (
        quorum_did_inner_puzzle,
        singleton_struct,
    )

    if len(bundle.coin_spends) != 4:
        raise ValueError(
            "mint proposal publication must contain exactly four spends "
            "(funding, proposal launcher, governance tracker, SGT lock)"
        )
    _validate_reveals_match_coins(bundle)

    launchers = [
        cs for cs in bundle.coin_spends
        if bytes(cs.coin.puzzle_hash) == bytes(SINGLETON_LAUNCHER_HASH)
    ]
    if len(launchers) != 1:
        raise ValueError("publish bundle must spend exactly one standard singleton launcher")
    launcher_spend = launchers[0]
    funding_spends = [
        cs for cs in bundle.coin_spends
        if bytes(cs.coin.name()) == bytes(launcher_spend.coin.parent_coin_info)
    ]
    if len(funding_spends) != 1:
        raise ValueError("proposal launcher must be created by the bundled funding spend")
    funding_spend = funding_spends[0]

    launcher_ids = _artifact_mapping(artifact, "launcherIds")
    puzzle_hashes = _artifact_mapping(artifact, "puzzleHashes")
    did_launcher_id = _artifact_bytes32(launcher_ids, "did")
    governance_launcher_id = _artifact_bytes32(launcher_ids, "governance")

    values = metadata_bytes(metadata)
    property_id = bytes32(values["property_id_canon"])
    collection_id = bytes32(values["collection_id_canon"])
    registry_ph = bytes32(values["property_registry_puzzle_hash"])
    registry_coin_id = bytes32(values["property_registry_coin_id"])
    owner_member_hash = bytes32(values["owner_member_hash"])
    gov_member_hash = bytes32(values["gov_member_hash"])

    if property_id != canonicalise_property_id(proposal.property_id):
        raise ValueError("property_id_canon does not match the persisted draft")
    if collection_id != canonicalise_property_id(proposal.collection_id):
        raise ValueError("collection_id_canon does not match the persisted draft")
    if int(values["share_ppm"]) != proposal.share_ppm:
        raise ValueError("share_ppm does not match the persisted draft")
    if int(values["par_value_mojos"]) != proposal.par_value:
        raise ValueError("par_value_mojos does not match the persisted draft")
    expected_asset_class = ALPHA_ASSET_CLASS_CODES.get(proposal.asset_class.upper())
    if expected_asset_class is None or int(values["asset_class"]) != expected_asset_class:
        raise ValueError("asset_class is unsupported or does not match the persisted draft")
    if bytes(values["jurisdiction"]) != proposal.jurisdiction.encode("utf-8"):
        raise ValueError("jurisdiction does not match the persisted draft")
    if bytes(values["royalty_puzhash"]) != proposal.royalty_puzhash:
        raise ValueError("royalty_puzhash does not match the persisted draft")
    if int(values["royalty_bps"]) != proposal.royalty_bps:
        raise ValueError("royalty_bps does not match the persisted draft")
    if int(values["quorum_threshold"]) != proposal.quorum_required:
        raise ValueError("quorum_threshold does not match the persisted draft")

    expected_owner_hash = _admin_member_hash(
        artifact=artifact,
        authenticated_owner=authenticated_owner,
        compute_leaf=compute_eip712_member_leaf_hash,
        prefix=eip712_prefix_and_domain_separator(
            genesis_challenge_for_network(str(artifact.get("network", "")))
        ),
        type_hash=eip712_type_hash(),
    )
    if owner_member_hash != expected_owner_hash:
        raise ValueError("owner_member_hash does not belong to the authenticated administrator")
    if gov_member_hash != bytes32.zeros:
        raise ValueError("gov_member_hash must be the disabled zero member for this test release")

    did_struct = singleton_struct(did_launcher_id)
    governance_struct = singleton_struct(governance_launcher_id)
    did_inner = quorum_did_inner_puzzle(governance_launcher_id)
    did_inner_hash = bytes32(did_inner.get_tree_hash())
    if did_inner_hash != _artifact_bytes32(puzzle_hashes, "didInnerPuzzleHash"):
        raise ValueError("signed artifact DID inner puzzle hash is inconsistent")

    funding_coin_id = bytes32(funding_spend.coin.name())
    primary_purchase = primary_purchase_mint_config(values, artifact)
    artifacts = build_mint_publish_artifacts(
        property_id_canon=property_id,
        collection_id_canon=collection_id,
        share_ppm=int(values["share_ppm"]),
        par_value_mojos=int(values["par_value_mojos"]),
        asset_class=int(values["asset_class"]),
        jurisdiction=bytes(values["jurisdiction"]),
        royalty_puzhash=bytes32(values["royalty_puzhash"]),
        royalty_bps=int(values["royalty_bps"]),
        quorum_threshold=int(values["quorum_threshold"]),
        owner_member_hash=owner_member_hash,
        gov_member_hash=gov_member_hash,
        deed_launcher_parent_coin_name=funding_coin_id,
        proposal_launcher_parent_coin_name=funding_coin_id,
        protocol_did_singleton_struct=did_struct,
        protocol_did_puzhash=_artifact_bytes32(puzzle_hashes, "didFullPuzzleHash"),
        protocol_did_inner_puzhash=did_inner_hash,
        governance_singleton_struct=governance_struct,
        pool_singleton_launcher_id=_artifact_bytes32(launcher_ids, "pool"),
        pool_singleton_launcher_puzzle_hash=bytes32(SINGLETON_LAUNCHER_HASH),
        p2_pool_mod_hash=_artifact_bytes32(puzzle_hashes, "p2PoolModHash"),
        p2_vault_mod_hash=bytes32(load_puzzle("p2_vault.clsp").get_tree_hash()),
        property_registry_puzzle_hash=registry_ph,
        metadata_root=(
            bytes32(values["metadata_root"])
            if "metadata_root" in values
            else None
        ),
        metadata_anchor_id=(
            bytes32(values["metadata_anchor_id"])
            if "metadata_anchor_id" in values
            else None
        ),
        primary_purchase=primary_purchase,
    )

    launcher_solution = list(_program(launcher_spend.solution).as_iter())
    if len(launcher_solution) < 2:
        raise ValueError("proposal launcher solution is malformed")
    if bytes(launcher_solution[0].as_atom()) != bytes(artifacts.eve_inner_puzhash):
        raise ValueError("proposal launcher does not create the re-derived eve inner")
    if launcher_solution[1].as_int() != 1:
        raise ValueError("proposal singleton amount must be one mojo")

    funding_additions = compute_additions(funding_spend)
    funding_addition_ids = {bytes(coin.name()) for coin in funding_additions}
    if bytes(artifacts.proposal_singleton_launcher_id) not in funding_addition_ids:
        raise ValueError("funding spend does not create the canonical proposal launcher")
    if bytes(artifacts.deed_launcher_id) not in funding_addition_ids:
        raise ValueError("funding spend does not create the canonical deed launcher")
    expected_deed_launcher_ph = deed_launcher_puzzle_hash(
        protocol_did_singleton_struct=did_struct
    )
    deed_launcher_outputs = [
        coin for coin in funding_additions
        if bytes(coin.name()) == bytes(artifacts.deed_launcher_id)
    ]
    if (
        len(deed_launcher_outputs) != 1
        or bytes(deed_launcher_outputs[0].puzzle_hash) != bytes(expected_deed_launcher_ph)
        or int(deed_launcher_outputs[0].amount) != 1
    ):
        raise ValueError("canonical one-mojo deed launcher output is missing")

    tracker_spend = _single_spend_for_launcher(bundle, governance_launcher_id)
    proposal_hash, bill, first_vote_amount, deadline = _parse_tracker_propose(
        tracker_spend
    )
    if proposal_hash != artifacts.proposal_hash:
        raise ValueError("governance tracker proposal hash does not match re-derived artifacts")
    if bill != artifacts.bill_op_program:
        raise ValueError("governance tracker MINT bill does not match re-derived artifacts")
    if deadline != int(values["voting_deadline"]):
        raise ValueError("voting_deadline does not match the tracker solution")

    tracker_children = [coin for coin in compute_additions(tracker_spend) if coin.amount == 1]
    if len(tracker_children) != 1:
        raise ValueError("governance tracker spend must create exactly one singleton child")
    tracker_child_id = bytes32(tracker_children[0].name())

    used = {id(funding_spend), id(launcher_spend), id(tracker_spend)}
    sgt_spends = [cs for cs in bundle.coin_spends if id(cs) not in used]
    if len(sgt_spends) != 1:
        raise ValueError("publish bundle must contain exactly one SGT lock spend")
    sgt_children = [
        coin for coin in compute_additions(sgt_spends[0])
        if int(coin.amount) == first_vote_amount
    ]
    if len(sgt_children) != 1:
        raise ValueError("SGT spend does not create the first-vote locked coin")
    sgt_lock_coin_id = bytes32(sgt_children[0].name())

    if any(bytes(cs.coin.name()) == bytes(registry_coin_id) for cs in bundle.coin_spends):
        raise ValueError("property registration is reserved for quorum-authorized EXECUTE")

    return CanonicalPublish(
        smart_deed_inner_puzhash=artifacts.smart_deed_inner_puzhash,
        eve_inner_puzhash=artifacts.eve_inner_puzhash,
        deed_full_puzhash=artifacts.deed_full_puzhash,
        proposal_hash=artifacts.proposal_hash,
        proposal_data_hash=artifacts.proposal_data_hash,
        proposal_singleton_launcher_id=artifacts.proposal_singleton_launcher_id,
        deed_launcher_id=artifacts.deed_launcher_id,
        proposal_tracker_coin_id=tracker_child_id,
        sgt_lock_coin_id=sgt_lock_coin_id,
        property_registry_coin_id=registry_coin_id,
        property_registry_puzzle_hash=registry_ph,
        voting_deadline=deadline,
    )


def primary_purchase_mint_config(values: dict, artifact: dict):
    """Derive new purchase terms from already-authenticated release and metadata."""
    from solslot_puzzles.mint_publish_driver import PrimaryPurchaseMintConfig
    from solslot_puzzles.stripe_settlement_v1_driver import PRIMARY_PURCHASE_PROVIDER_ID as INVENTORY_PROVIDER_ID
    primary_purchase = None
    puzzle_hashes = _artifact_mapping(artifact, "puzzleHashes")
    if "primary_purchase_usd_amount_minor" in values:
        if values.get("inventory_puzzle_version", 1) != 2:
            raise ValueError("new purchase publication requires governed inventory V2")
        from solslot_puzzles.inventory_activation import validate_inventory_activation
        validate_inventory_activation(artifact, required=True)
        if values["royalty_bps"] != 100:
            raise ValueError("inventory V2 alpha technology fee must be 100 basis points")
        validator_set = _artifact_mapping(artifact, "validatorSet")
        if int(validator_set.get("threshold", 0)) != 2:
            raise ValueError("signed artifact primary purchase threshold must be two")
        raw_pubkeys = validator_set.get("pubkeys")
        if not isinstance(raw_pubkeys, list) or len(raw_pubkeys) != 3:
            raise ValueError("signed artifact must contain three primary purchase validators")
        validator_pubkeys: list[bytes] = []
        for value in raw_pubkeys:
            normalized = str(value).removeprefix("0x")
            try:
                pubkey = bytes.fromhex(normalized)
            except ValueError as exc:
                raise ValueError("signed artifact contains an invalid validator pubkey") from exc
            if len(pubkey) != 48:
                raise ValueError("signed artifact validator pubkeys must be 48 bytes")
            validator_pubkeys.append(pubkey)
        primary_purchase = PrimaryPurchaseMintConfig(
            network=str(artifact.get("network", "")),
            usd_amount_minor=int(values["primary_purchase_usd_amount_minor"]),
            inventory_version=2,
            technology_fee_bps=100,
            protocol_treasury_puzhash=_artifact_bytes32(
                puzzle_hashes,
                "protocolTreasuryPuzzleHash",
            ),
            validator_pubkeys=tuple(validator_pubkeys),
            provider_id=INVENTORY_PROVIDER_ID,
        )
    return primary_purchase


def validate_execute_bundle(
    *,
    bundle: SpendBundle,
    proposal: StoredMintProposal,
    artifact: dict[str, Any],
) -> None:
    """Validate the exact five-spend quorum-authorized mint execution."""
    from solslot_puzzles.mint_proposal_v2_driver import (
        STATE_DRAFT,
        parse_inner_puzzle as parse_proposal_inner,
    )
    from solslot_puzzles.mint_publish_driver import deed_launcher_puzzle_hash
    from solslot_puzzles.protocol_deployment import singleton_struct

    required = (
        proposal.proposal_hash,
        proposal.deed_full_puzhash,
        proposal.proposal_singleton_launcher_id,
        proposal.deed_launcher_id,
        proposal.property_registry_coin_id,
        proposal.property_registry_puzzle_hash,
    )
    if any(value is None for value in required):
        raise ValueError("proposal lacks persisted canonical publish coordinates")
    if len(bundle.coin_spends) != 5:
        raise ValueError(
            "mint execution must contain exactly five spends "
            "(governance, DID, property registry, proposal, deed launcher)"
        )
    _validate_reveals_match_coins(bundle)

    launcher_ids = _artifact_mapping(artifact, "launcherIds")
    did_launcher_id = _artifact_bytes32(launcher_ids, "did")
    governance_launcher_id = _artifact_bytes32(launcher_ids, "governance")
    property_registry_launcher_id = _artifact_bytes32(
        launcher_ids, "propertyRegistry"
    )
    proposal_launcher_id = bytes32(proposal.proposal_singleton_launcher_id)

    singleton_spends: dict[bytes32, Any] = {}
    non_singletons: list[Any] = []
    for coin_spend in bundle.coin_spends:
        launcher_id = _singleton_launcher_id(coin_spend)
        if launcher_id is None:
            non_singletons.append(coin_spend)
        else:
            if launcher_id in singleton_spends:
                raise ValueError("execute bundle spends a singleton lineage more than once")
            singleton_spends[launcher_id] = coin_spend

    expected_singletons = {
        governance_launcher_id,
        did_launcher_id,
        property_registry_launcher_id,
        proposal_launcher_id,
    }
    if set(singleton_spends) != expected_singletons:
        raise ValueError("execute bundle singleton lineages do not match the signed artifact")
    if len(non_singletons) != 1:
        raise ValueError("execute bundle must contain exactly one deed launcher spend")

    registry_spend = singleton_spends[property_registry_launcher_id]
    if bytes(registry_spend.coin.name()) != bytes(proposal.property_registry_coin_id):
        raise ValueError("execute bundle spends a different property registry coin")
    if bytes(registry_spend.coin.puzzle_hash) != bytes(
        proposal.property_registry_puzzle_hash
    ):
        raise ValueError("execute property registry puzzle hash differs from the MINT bill")

    proposal_spend = singleton_spends[proposal_launcher_id]
    _, proposal_args = _program(proposal_spend.puzzle_reveal).uncurry()
    proposal_inner = list(proposal_args.as_iter())[1]
    proposal_state = parse_proposal_inner(proposal_inner)
    if proposal_state.proposal_state != STATE_DRAFT:
        raise ValueError("proposal singleton must execute from DRAFT")
    if proposal_state.governance_proposal_hash != bytes32(proposal.proposal_hash):
        raise ValueError("proposal singleton governance hash mismatch")
    if proposal_state.deed_launcher_id != bytes32(proposal.deed_launcher_id):
        raise ValueError("proposal singleton deed launcher mismatch")
    if proposal_state.deed_full_puzzle_hash != bytes32(proposal.deed_full_puzhash):
        raise ValueError("proposal singleton deed puzzle hash mismatch")

    deed_spend = non_singletons[0]
    if bytes(deed_spend.coin.name()) != bytes(proposal.deed_launcher_id):
        raise ValueError("execute bundle spends a different deed launcher")
    expected_deed_launcher_ph = deed_launcher_puzzle_hash(
        protocol_did_singleton_struct=singleton_struct(did_launcher_id)
    )
    if bytes(deed_spend.coin.puzzle_hash) != bytes(expected_deed_launcher_ph):
        raise ValueError("deed launcher puzzle hash is not DID-bound to this deployment")
    deed_outputs = [
        coin for coin in compute_additions(deed_spend)
        if bytes(coin.puzzle_hash) == bytes(proposal.deed_full_puzhash)
        and int(coin.amount) == 1
    ]
    if len(deed_outputs) != 1:
        raise ValueError("deed launcher does not create the committed one-mojo deed singleton")


def validate_kos_mint_execute_bundle(
    *,
    bundle: SpendBundle,
    proposal: StoredMintProposal,
    artifact: dict[str, Any],
    network: str,
) -> CanonicalKosMintExecution:
    """Re-derive the sole KoS MINT-execution signing request.

    The protocol itself enforces the resulting ``AGG_SIG_ME`` condition. This
    validator prevents the coordinator from asking its isolated signer to
    attest to a different singleton, stale coin, proposal, or network.
    Existing wallet signatures are intentionally not trusted here: consensus
    still verifies the aggregate after the returned signature is attached.
    """
    from chia.types.blockchain_format.program import INFINITE_COST
    from solslot_puzzles.protocol_deployment import singleton_struct
    from solslot_puzzles.sgt_driver import (
        kos_mint_execute_message,
        kos_mint_execute_signing_message,
    )

    from .faucet import AGG_SIG_ME_DATA

    validate_execute_bundle(bundle=bundle, proposal=proposal, artifact=artifact)
    if artifact.get("network") != network:
        raise ValueError("signed artifact network does not match KoS signer network")
    additional_data = AGG_SIG_ME_DATA.get(network)
    if additional_data is None:
        raise ValueError("KoS MINT execute signer does not support this network")

    launchers = _artifact_mapping(artifact, "launcherIds")
    governance = _artifact_mapping(artifact, "governanceStruct")
    governance_launcher_id = _artifact_bytes32(launchers, "governance")
    cosigner_pubkey = _artifact_bytes(governance, "mintExecuteCosignerPubkey", 48)
    if proposal.proposal_hash is None:
        raise ValueError("proposal lacks a canonical governance proposal hash")
    proposal_hash = bytes32(proposal.proposal_hash)
    governance_spend = _single_spend_for_launcher(bundle, governance_launcher_id)
    governance_coin_id = bytes32(governance_spend.coin.name())
    governance_struct = singleton_struct(governance_launcher_id)
    visible_message = kos_mint_execute_message(
        governance_singleton_struct=governance_struct,
        governance_coin_id=governance_coin_id,
        proposal_hash=proposal_hash,
    )
    signing_message = kos_mint_execute_signing_message(
        governance_singleton_struct=governance_struct,
        governance_coin_id=governance_coin_id,
        proposal_hash=proposal_hash,
        agg_sig_me_additional_data=bytes32(additional_data),
    )

    conditions = conditions_dict_for_solution(
        _program(governance_spend.puzzle_reveal),
        _program(governance_spend.solution),
        INFINITE_COST,
    )
    matches = [
        message
        for pubkey, message in pkm_pairs_for_conditions_dict(
            conditions,
            governance_spend.coin,
            additional_data,
        )
        if bytes(pubkey) == cosigner_pubkey
    ]
    if matches != [signing_message]:
        raise ValueError(
            "governance MINT spend does not emit the exact KoS co-signature condition"
        )
    return CanonicalKosMintExecution(
        governance_coin_id=governance_coin_id,
        proposal_hash=proposal_hash,
        cosigner_pubkey=cosigner_pubkey,
        visible_message=visible_message,
        signing_message=signing_message,
    )


def _validate_reveals_match_coins(bundle: SpendBundle) -> None:
    seen: set[bytes] = set()
    for coin_spend in bundle.coin_spends:
        coin_id = bytes(coin_spend.coin.name())
        if coin_id in seen:
            raise ValueError("bundle contains a duplicate coin spend")
        seen.add(coin_id)
        if bytes(_program(coin_spend.puzzle_reveal).get_tree_hash()) != bytes(
            coin_spend.coin.puzzle_hash
        ):
            raise ValueError("coin puzzle hash does not match puzzle_reveal")


def _parse_tracker_propose(coin_spend: Any) -> tuple[bytes32, Program, int, int]:
    outer = list(_program(coin_spend.solution).as_iter())
    if len(outer) != 3:
        raise ValueError("governance singleton solution is malformed")
    inner = list(outer[2].as_iter())
    if len(inner) != 5 or inner[3].as_int() != 1:
        raise ValueError("governance singleton spend is not TRK_PROPOSE")
    params = list(inner[4].as_iter())
    if len(params) != 5:
        raise ValueError("TRK_PROPOSE parameters are malformed")
    return (
        bytes32(params[0].as_atom()),
        params[1],
        params[3].as_int(),
        params[4].as_int(),
    )


def _single_spend_for_launcher(bundle: SpendBundle, launcher_id: bytes32) -> Any:
    matches = [
        cs for cs in bundle.coin_spends
        if _singleton_launcher_id(cs) == launcher_id
    ]
    if len(matches) != 1:
        raise ValueError(f"bundle must contain one singleton spend for 0x{launcher_id.hex()}")
    return matches[0]


def _singleton_launcher_id(coin_spend: Any) -> bytes32 | None:
    puzzle = _program(coin_spend.puzzle_reveal)
    try:
        mod, args = puzzle.uncurry()
        if bytes(mod.get_tree_hash()) != bytes(SINGLETON_MOD_HASH):
            return None
        values = list(args.as_iter())
        if len(values) != 2:
            return None
        struct_values = list(values[0].as_iter())
        launcher_pair = list(struct_values[1].as_iter())
        return bytes32(launcher_pair[0].as_atom())
    except (IndexError, TypeError, ValueError):
        return None


def _admin_member_hash(
    *,
    artifact: dict[str, Any],
    authenticated_owner: str,
    compute_leaf: Any,
    prefix: bytes,
    type_hash: bytes32,
) -> bytes32:
    from eth_keys import keys

    admin = _artifact_mapping(artifact, "adminAuthority")
    pubkeys = admin.get("compressedPubkeys")
    if not isinstance(pubkeys, list):
        raise ValueError("signed artifact admin roster is malformed")
    owner = authenticated_owner.lower()
    for raw in pubkeys:
        try:
            public_key = keys.PublicKey.from_compressed_bytes(
                bytes.fromhex(str(raw).removeprefix("0x"))
            )
        except (ValueError, TypeError):
            continue
        if public_key.to_checksum_address().lower() == owner:
            return bytes32(
                compute_leaf(
                    secp256k1_pubkey=public_key.to_compressed_bytes(),
                    prefix_and_domain_separator=prefix,
                    type_hash=type_hash,
                )
            )
    raise ValueError("authenticated administrator is absent from the signed artifact")


def _artifact_mapping(artifact: dict[str, Any], key: str) -> dict[str, Any]:
    value = artifact.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"signed artifact {key} is missing or malformed")
    return value


def _artifact_bytes32(mapping: dict[str, Any], key: str) -> bytes32:
    raw = mapping.get(key)
    if not isinstance(raw, str):
        raise ValueError(f"signed artifact coordinate {key} is missing")
    try:
        return bytes32(bytes.fromhex(raw.removeprefix("0x")))
    except (ValueError, AssertionError) as exc:
        raise ValueError(f"signed artifact coordinate {key} is not bytes32") from exc


def _artifact_bytes(mapping: dict[str, Any], key: str, size: int) -> bytes:
    raw = mapping.get(key)
    if not isinstance(raw, str):
        raise ValueError(f"signed artifact coordinate {key} is missing")
    try:
        value = bytes.fromhex(raw.removeprefix("0x"))
    except ValueError as exc:
        raise ValueError(f"signed artifact coordinate {key} is not hex") from exc
    if len(value) != size:
        raise ValueError(f"signed artifact coordinate {key} is not {size} bytes")
    return value


def _program(value: Any) -> Program:
    return Program.from_bytes(bytes(value))


__all__ = [
    "CanonicalPublish",
    "CanonicalKosMintExecution",
    "validate_publish_bundle",
    "validate_execute_bundle",
    "validate_kos_mint_execute_bundle",
]
