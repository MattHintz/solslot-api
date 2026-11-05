"""Fresh-generation identity authorization by independent private signers.

The coordinator supplies evidence identifiers and the owner's authorization.
Each signer loads its own frozen profile, reconstructs current protocol
authority and checks both chains before reading its signing credential.
"""
import hashlib
import json
import time
from starlette.concurrency import run_in_threadpool
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH, puzzle_for_singleton
from chia.wallet.util.compute_additions import compute_additions_with_cost
from chia_rs import AugSchemeMPL, Coin, G1Element, G2Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from solslot_puzzles.generation_vault import vault_inner
from solslot_puzzles.vault_driver import (
    AUTH_TYPE_BLS, AUTH_TYPE_SECP256K1, eip712_typed_data_for_vault_spend, one_leaf_merkle_root,
)
from .faucet import AGG_SIG_ME_DATA
from .evm_auth import recover_evm_signer
from .generation_customer_identity_context import read_current_identity_profile
from .generation_registry_evidence import _spend
from .vault_chain_evidence import read_vault_coin
from .validator_quorum import CurrentIdentityClaim, ValidatorSignatureResponse


def selected_current_identity_profile(settings):
    if (not settings.generation_customer_identity_enabled or settings.network != 'testnet11'
            or not settings.deployment_generation_id):
        raise ValueError('CURRENT_ID_SIGNER_DISABLED')
    profile = read_current_identity_profile(settings.generation_customer_identity_profile_path,
        settings.generation_customer_identity_profile_hash)
    addresses = {c.role: c.address for c in profile.contracts}
    if (profile.generation_id != settings.deployment_generation_id
            or list(profile.validator_public_keys) != settings.roster_pubkeys
            or profile.bridge_policy_hash != settings.bridge_policy_hash
            or profile.evm_chain_id != settings.evm_chain_id
            or addresses['forwarder'] != settings.evm_forwarder_address
            or addresses['verifierAdapter'] != settings.evm_verifier_adapter_address
            or addresses['attestationEmitter'] != settings.evm_attestation_emitter_address):
        raise ValueError('CURRENT_ID_SIGNER_PROFILE_CHANGED')
    return profile


def verified_identity_owner(claim):
    try:
        authorization = bytes.fromhex(claim.owner_authorization.removeprefix('0x'))
        if '0x' + hashlib.sha256(authorization).hexdigest() != claim.owner_authorization_hash:
            raise ValueError('authorization hash differs')
        if claim.owner_auth_type == AUTH_TYPE_SECP256K1:
            typed = eip712_typed_data_for_vault_spend(b'z', bytes32.from_hexstr(claim.identity_attest_root),
                bytes32.from_hexstr(claim.current_vault_coin_id))
            recovered = recover_evm_signer(typed, claim.owner_authorization)
            if recovered.address.lower() != claim.owner_key.lower():
                raise ValueError('owner differs')
            return recovered.compressed_pubkey
        if claim.owner_auth_type == AUTH_TYPE_BLS:
            public = G1Element.from_bytes(bytes.fromhex(claim.owner_key.removeprefix('0x')))
            message = bytes(Program.to([b'z', bytes32.from_hexstr(claim.identity_attest_root),
                bytes32.from_hexstr(claim.current_vault_coin_id)]).get_tree_hash())
            message += bytes.fromhex(claim.current_vault_coin_id[2:]) + AGG_SIG_ME_DATA['testnet11']
            signature = G2Element.from_bytes(authorization)
            if public == G1Element() or not AugSchemeMPL.verify(public, message, signature):
                raise ValueError('invalid owner signature')
            return bytes(public)
    except (ValueError, KeyError) as exc:
        raise ValueError('CURRENT_ID_OWNER_AUTHORIZATION_REJECTED') from exc
    raise ValueError('CURRENT_ID_OWNER_AUTHORIZATION_REJECTED')


async def verify_current_identity_vault(claim, *, bindings, profile, provider):
    if (claim.generation_id != profile.generation_id or claim.identity_profile_hash != profile.commitment
            or claim.network != 'testnet11' or claim.bridge_policy_hash != profile.bridge_policy_hash
            or claim.bridge_amount != 1 or not any(row.coin_id == claim.bridge_coin_id
                and row.parent_id == claim.bridge_parent_id for row in profile.bridge_coins)):
        raise ValueError('CURRENT_ID_CLAIM_PROFILE_CHANGED')
    profile.require_native(bindings)
    if (await provider.get_network_info_primary()).get('network_name') != 'testnet11':
        raise ValueError('CURRENT_ID_PRIMARY_NETWORK_CHANGED')
    owner = verified_identity_owner(claim)
    launcher = bytes32.from_hexstr(claim.vault_launcher_id)
    expected_inner = vault_inner(vault_launcher_id=launcher, owner_pubkey=owner,
        auth_type=claim.owner_auth_type, members_merkle_root=one_leaf_merkle_root(owner),
        pool_launcher_id=bindings.pool_launcher, zkpassport_bridge_policy_hash=bindings.bridge_policy)
    async def read(coin_id):
        return read_vault_coin(await provider.get_coin_record_by_name_primary('0x' + coin_id.hex()), coin_id)
    origin = await read(launcher)
    if (origin.coin.puzzle_hash != SINGLETON_LAUNCHER_HASH or origin.coin.amount != 1
            or not origin.spent_height):
        raise ValueError('CURRENT_ID_VAULT_LAUNCH_UNCONFIRMED')
    vault_coin = Coin(launcher, puzzle_for_singleton(launcher, expected_inner).get_tree_hash(), uint64(1))
    current = await read(vault_coin.name())
    if (current.coin != vault_coin or current.spent_height
            or current.confirmed_height != origin.spent_height
            or claim.current_vault_coin_id != '0x' + vault_coin.name().hex()):
        raise ValueError('CURRENT_ID_VAULT_IS_NOT_FRESH_NATIVE_CUSTODY')
    launch_spend = _spend(await provider.get_puzzle_and_solution_primary(claim.vault_launcher_id,
        origin.spent_height), origin.coin)
    additions, _ = compute_additions_with_cost(launch_spend, max_cost=5_000_000)
    if [coin for coin in additions if coin.amount % 2] != [vault_coin]:
        raise ValueError('CURRENT_ID_VAULT_LAUNCH_OUTPUT_CHANGED')
    bridge_coin = Coin(bytes32.from_hexstr(claim.bridge_parent_id), bindings.bridge_policy, uint64(1))
    bridge = await read(bridge_coin.name())
    if bridge.coin != bridge_coin or bridge.spent_height or claim.bridge_coin_id != '0x' + bridge_coin.name().hex():
        raise ValueError('CURRENT_ID_BRIDGE_UNAVAILABLE')
    return origin, current, bridge


def _verify_event(settings, profile, claim):
    from .config import Settings
    from .zkpassport_enrollments import _fetch_verified_evm_attestation
    selected = Settings(runtime_environment='test', network='testnet11',
        deployment_generation_id=profile.generation_id, alpha_writes_enabled=False,
        zkpassport_evm_rpc_url=settings.evm_rpc_url, zkpassport_evm_chain_id=profile.evm_chain_id,
        zkpassport_evm_min_confirmations=settings.evm_min_confirmations,
        zkpassport_policy_version=2,
        zkpassport_emitter_address=next(c.address for c in profile.contracts if c.role == 'attestationEmitter'))
    event = _fetch_verified_evm_attestation(selected, transaction_hash=claim.evm_transaction_hash,
        expected_vault_launcher_id=claim.vault_launcher_id, current_profile=profile)
    for field in ('vault_launcher_id', 'policy_version', 'identity_attest_root', 'attestation_leaf_hash',
            'scoped_nullifier', 'nullifier_type', 'service_scope_hash', 'service_subscope_hash',
            'proof_timestamp', 'bridge_policy_hash', 'bridge_parent_id', 'bridge_amount',
            'bridge_coin_id', 'validator_message'):
        if getattr(event, field) != getattr(claim, field):
            raise ValueError('CURRENT_ID_EVM_CLAIM_CHANGED')
    if event.transaction_hash != claim.evm_transaction_hash or event.block_number != claim.evm_block_number:
        raise ValueError('CURRENT_ID_EVM_INCLUSION_CHANGED')
    expected_sender = claim.owner_key if claim.owner_auth_type == AUTH_TYPE_SECP256K1 else profile.trusted_direct_relayer
    if event.sender.lower() != expected_sender.lower():
        raise ValueError('CURRENT_ID_EVM_SENDER_CHANGED')


async def verify_current_identity_claim(settings, claim, claim_hash, *, provider, clock=time.time):
    if not isinstance(claim, CurrentIdentityClaim) or claim.canonical_hash() != claim_hash:
        raise ValueError('CURRENT_ID_CLAIM_CHANGED')
    profile = selected_current_identity_profile(settings)
    if (claim.identity_profile_hash != profile.commitment or claim.generation_id != profile.generation_id
            or claim.policy_version != 2 or claim.network != 'testnet11'
            or claim.emitter_address != next(c.address for c in profile.contracts if c.role == 'attestationEmitter')
            or any(getattr(claim, f) == '0x' + '00' * 32 for f in
                ('identity_attest_root', 'scoped_nullifier', 'service_scope_hash', 'service_subscope_hash'))):
        raise ValueError('CURRENT_ID_CLAIM_BINDING_CHANGED')
    def require_live():
        now = int(clock())
        if (abs(now - claim.current_timestamp) > settings.claim_clock_skew_seconds
                or not 0 <= now - claim.proof_timestamp <= settings.proof_max_age_seconds):
            raise ValueError('CURRENT_ID_EVIDENCE_EXPIRED')
    require_live()
    from .generation_sols_batch_validators import generation_settings
    from .generation_preparation import read_generation_preparation
    from .generation_index import load_generation_read_anchor
    from .generation_chain_evidence import resolve_generation_chain, current_evidence_unchanged
    from .generation_customer_context import customer_bindings_from_evidence
    bound = generation_settings(settings)
    anchor = load_generation_read_anchor(bound)
    evidence = await resolve_generation_chain(anchor, provider=provider)
    bindings = customer_bindings_from_evidence(read_generation_preparation(bound), anchor, evidence)
    records = await verify_current_identity_vault(claim, bindings=bindings, profile=profile, provider=provider)
    await run_in_threadpool(_verify_event, settings, profile, claim)
    for record in records:
        fresh = read_vault_coin(await provider.get_coin_record_by_name_primary('0x' + record.coin.name().hex()), record.coin.name())
        if fresh != record:
            raise ValueError('CURRENT_ID_COIN_CHANGED_DURING_VERIFICATION')
    if not await current_evidence_unchanged(evidence, provider=provider):
        raise ValueError('CURRENT_ID_AUTHORITY_CHANGED_DURING_VERIFICATION')
    require_live()
    return profile


async def sign_current_identity(settings, ledger, claim, claim_hash, *, provider, clock=time.time):
    await verify_current_identity_claim(settings, claim, claim_hash, provider=provider, clock=clock)
    from .validator_service import load_validator_private_key
    private = load_validator_private_key(settings)
    if '0x' + bytes(private.get_g1()).hex() != settings.roster_pubkeys[settings.signer_index]:
        raise ValueError('CURRENT_ID_SIGNER_ROSTER_CHANGED')
    signature = '0x' + bytes(AugSchemeMPL.sign(private, claim.signature_message())).hex()
    signature = ledger.record_or_recover(claim_hash=claim_hash,
        canonical_claim=json.dumps(claim.model_dump(mode='json'), sort_keys=True,
            separators=(',', ':'), ensure_ascii=True), scoped_nullifier=claim.scoped_nullifier,
        bridge_coin_id=claim.bridge_coin_id,
        vault_action=f'{claim.vault_launcher_id}:{claim.current_vault_coin_id}:{claim.identity_attest_root}:update_identity',
        evm_transaction_hash=claim.evm_transaction_hash, signature=signature)
    return ValidatorSignatureResponse(claimHash=claim_hash, signerIndex=settings.signer_index,
        validatorPubkey='0x' + bytes(private.get_g1()).hex(), signature=signature)


async def recover_existing_current_identity_signature(settings,ledger,*,original_claim_hash,refreshed_claim,
        refreshed_claim_hash,provider,clock=time.time):
    """Revalidate a fresh EVM claim and return only this signer's existing signature.

    The separately gated recovery route never loads a private key and cannot
    issue a signature for a new authorization subject.
    """
    from chia_rs import AugSchemeMPL,G1Element,G2Element
    from .generation_identity_signature_recovery import require_matching_recovery_subject
    if (not isinstance(original_claim_hash,str) or len(original_claim_hash)!=66
            or not original_claim_hash.startswith('0x') or not isinstance(refreshed_claim,CurrentIdentityClaim)
            or refreshed_claim.canonical_hash()!=refreshed_claim_hash):
        raise ValueError('CURRENT_ID_RECOVERY_REQUEST_INVALID')
    saved=ledger.read_existing_identity_signature(claim_hash=original_claim_hash)
    if saved is None:raise ValueError('CURRENT_ID_RECOVERY_SIGNATURE_NOT_FOUND')
    original=CurrentIdentityClaim.model_validate_json(saved[0])
    if original.canonical_hash()!=original_claim_hash:
        raise ValueError('CURRENT_ID_RECOVERY_LEDGER_CHANGED')
    require_matching_recovery_subject(original=original,refreshed=refreshed_claim,now=int(clock()))
    await verify_current_identity_claim(settings,refreshed_claim,refreshed_claim_hash,provider=provider,clock=clock)
    require_matching_recovery_subject(original=original,refreshed=refreshed_claim,now=int(clock()))
    slot=settings.signer_index
    if type(slot)is not int or slot not in (0,1,2):raise ValueError('CURRENT_ID_RECOVERY_ROSTER_CHANGED')
    try:
        public=G1Element.from_bytes(bytes.fromhex(settings.roster_pubkeys[slot].removeprefix('0x')))
        signature=G2Element.from_bytes(bytes.fromhex(saved[1].removeprefix('0x')))
    except (ValueError,TypeError,IndexError) as exc:raise ValueError('CURRENT_ID_RECOVERY_LEDGER_INVALID') from exc
    if not AugSchemeMPL.verify(public,refreshed_claim.signature_message(),signature):
        raise ValueError('CURRENT_ID_RECOVERY_SIGNATURE_INVALID')
    return ValidatorSignatureResponse(claimHash=original_claim_hash,signerIndex=slot,
        validatorPubkey=settings.roster_pubkeys[slot],signature=saved[1])
