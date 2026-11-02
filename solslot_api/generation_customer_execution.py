"""Exact fresh-customer execution and native confirmation, not legacy admission.

No public route, owner session, fee-policy change or background broadcast is
installed here. Preparation is explicit; cached progress never signs or builds.
"""
from dataclasses import dataclass
from hashlib import sha256
import asyncio
import time

from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER, launch_conditions_and_coinsol, puzzle_for_singleton,
)
from chia_rs import Coin, G1Element
from chia_rs.sized_ints import uint64
from eth_keys import keys

from solslot_puzzles.generation_vault import vault_inner
from solslot_puzzles.vault_driver import (
    AUTH_TYPE_BLS, AUTH_TYPE_SECP256K1, one_leaf_merkle_root, vault_discovery_hint,
)
from .generation_customer_context import current_customer_launch_bindings
from .generation_customer_launch import assemble_customer_launch
from .generation_customer_store import canonical, read_consent
from .singleton_launcher import launcher_coin_for_parent
from .vault_chain_evidence import read_vault_coin


def request_key(identity):
    return 'customer:' + identity


def review_document(consent, signature, authorized_at, owner, output, fee_cap):
    message = consent.message()
    identity = '0x' + sha256(canonical(message).encode()).hexdigest()
    return {'kind':'CREATE_CUSTOMER_VAULT','generationId':message['generationId'],
        'requestKey':request_key(identity),'registrationId':identity,
        'feeCapMojos':fee_cap,'consent':message,'authorizedAt':authorized_at,
        'signatureHash':'0x'+sha256(signature.encode()).hexdigest(),
        'ownerPublicKey':'0x'+owner.hex(),'createdVaultCoinId':'0x'+output.name().hex(),
        'custodyPuzzleHash':'0x'+output.puzzle_hash.hex(),
        'identityVerified':False,'requiresFreshIdCheck':True}


def validate_customer_bundle(bundle, review):
    """Reconstruct exact public spends without keys, signing or API assertions."""
    names={'kind','generationId','requestKey','registrationId','feeCapMojos','consent',
        'authorizedAt','signatureHash','ownerPublicKey','createdVaultCoinId',
        'custodyPuzzleHash','identityVerified','requiresFreshIdCheck'}
    if not isinstance(review,dict) or set(review)!=names:
        raise ValueError('customer operation requires its complete exact creation review')
    consent=read_consent(review['consent'])
    identity='0x'+sha256(canonical(consent.message()).encode()).hexdigest()
    if (review['kind']!='CREATE_CUSTOMER_VAULT' or review['generationId']!=consent.message()['generationId']
            or review['registrationId']!=identity or review['requestKey']!=request_key(identity)
            or review['identityVerified'] is not False or review['requiresFreshIdCheck'] is not True
            or type(review['authorizedAt']) is not int or not 0<review['authorizedAt']<consent.expires_at
            or type(review['feeCapMojos']) is not int or not 0<=review['feeCapMojos']<=1_000_000_000):
        raise ValueError('customer review changes its generation, consent or admission boundary')
    owner_hex=review['ownerPublicKey']
    if not isinstance(owner_hex,str) or not owner_hex.startswith('0x'):
        raise ValueError('customer owner public key is missing')
    owner=bytes.fromhex(owner_hex[2:])
    if owner_hex!='0x'+owner.hex():raise ValueError('customer owner key is not canonical')
    if consent.auth_type=='chia_bls':
        if owner_hex!=consent.owner or G1Element.from_bytes(owner)==G1Element():
            raise ValueError('customer review changes the BLS owner')
        auth=AUTH_TYPE_BLS
    else:
        if keys.PublicKey.from_compressed_bytes(owner).to_checksum_address()!=consent.owner:
            raise ValueError('customer review changes the EVM owner')
        auth=AUTH_TYPE_SECP256K1
    if len(bundle.coin_spends)!=2:raise ValueError('customer creation must have exactly two native spends')
    parent_spend,launch_spend=bundle.coin_spends
    parent=parent_spend.coin
    launcher=launcher_coin_for_parent(parent)
    if (parent.amount<1 or parent.name()!=consent.funding_coin_id
            or launcher.name()!=consent.vault_launcher_id
            or launch_spend.coin!=launcher
            or Program.from_bytes(bytes(parent_spend.puzzle_reveal)).get_tree_hash()!=parent.puzzle_hash):
        raise ValueError('customer operation changes the reserved funding or launcher')
    inner=vault_inner(vault_launcher_id=launcher.name(),owner_pubkey=owner,auth_type=auth,
        members_merkle_root=one_leaf_merkle_root(owner),pool_launcher_id=consent.bindings.pool_launcher,
        zkpassport_bridge_policy_hash=consent.bindings.bridge_policy)
    conditions,expected_launch=launch_conditions_and_coinsol(parent,inner,[],uint64(1))
    # The existing shared launch helper adds the native discovery hint only to
    # CREATE_COIN. Its announcement still commits the exact launcher solution.
    exact=[Program.to([51,launcher.puzzle_hash,1,[vault_discovery_hint(auth,owner)]]),conditions[1]]
    if parent.amount>1:exact.append(Program.to([51,parent.puzzle_hash,int(parent.amount)-1]))
    solution=Program.to([0,Program.to((1,Program.to(exact))),0])
    if bytes(parent_spend.solution)!=bytes(solution) or bytes(launch_spend)!=bytes(expected_launch):
        raise ValueError('customer operation changes native outputs, change or launcher commitment')
    output=Coin(launcher.name(),puzzle_for_singleton(launcher.name(),inner).get_tree_hash(),uint64(1))
    if (review['createdVaultCoinId']!='0x'+output.name().hex()
            or review['custodyPuzzleHash']!='0x'+output.puzzle_hash.hex()):
        raise ValueError('customer review changes the created custody output')
    return consent,owner,output


def saved_customer_operation(store,journal,identity):
    consent,signature,authorized_at=store.authorized_material(identity)
    if store.generation_id!=journal.generation_id:
        raise ValueError('customer state and operation journal belong to different generations')
    saved=journal.request_status(request_key(identity))
    if saved is None:return None
    review=saved['review']
    bundle=journal.protocol_bundle(saved['operationId'])
    checked,owner,output=validate_customer_bundle(bundle,review)
    recovered,_=consent.verified_owner(signature,authorized_at)
    expected=review_document(consent,signature,authorized_at,recovered,output,int(saved['feeCapMojos']))
    if saved['kind']!='CREATE_CUSTOMER_VAULT' or checked!=consent or owner!=recovered or review!=expected:
        raise ValueError('saved customer operation differs from the retained signed consent')
    return saved


async def prepare_customer_operation(identity,fee_cap,*,store,journal,settings,index,provider,faucet,
        maximum_parent_amount,clock=time.time):
    """Explicit native preparation. A retry returns retained bytes before signing."""
    saved=saved_customer_operation(store,journal,identity)
    if saved is not None:
        if type(fee_cap) is not int or fee_cap!=int(saved['feeCapMojos']):
            raise ValueError('retry changes the saved customer fee cap')
        return saved
    consent,signature,authorized_at=store.authorized_material(identity)
    bindings=current_customer_launch_bindings(settings,index,now=int(clock()))
    if consent.bindings!=bindings:raise ValueError('signed customer bindings are no longer current')
    if type(maximum_parent_amount) is not int or not 1<=maximum_parent_amount<=1_000_000_000_000:
        raise ValueError('customer funding requires a separately bounded parent limit')
    async with asyncio.timeout(20):
        if (await provider.get_network_info_primary()).get('network_name')!='testnet11':
            raise ValueError('customer creation requires the primary Testnet11 node')
        before=await provider.get_coin_record_by_name_primary(consent.message()['fundingCoinId'])
        from .generation_recipient_execution import _funding_coin
        funding=_funding_coin(before,consent.message()['fundingCoinId'])
        if funding.puzzle_hash!=faucet.address_puzzle_hash or funding.amount>maximum_parent_amount:
            raise ValueError('customer funding is not the bounded owned parent')
        if consent.message()['fundingCoinId'] in journal.reserved_input_coin_ids():
            raise ValueError('customer parent is held by a different unresolved operation')
        after=await provider.get_coin_record_by_name_primary(consent.message()['fundingCoinId'])
        if before!=after:raise ValueError('customer funding changed during preparation')
        # Sign-by governs accepting consent. Retained consent is validated at
        # its durable acceptance time; delays do not silently demand a new one.
        from .generation_customer_signer import ReviewedCustomerSigner
        signer=ReviewedCustomerSigner(faucet,store,identity,funding,
            bindings=bindings,maximum_parent_amount=maximum_parent_amount)
        operation=assemble_customer_launch(bindings=bindings,consent=consent,
            signature=signature,funding_coin=funding,faucet=signer,now=authorized_at)
        owner,_=consent.verified_owner(signature,authorized_at)
        review=review_document(consent,signature,authorized_at,owner,operation.successors[0].coin,fee_cap)
        validate_customer_bundle(operation.bundle(),review)
        digest='0x'+sha256(canonical(review).encode()).hexdigest()
        journal.prepare(operation,request_key(identity),fee_cap,int(clock()),
            request_digest=digest,request_document=review)
    return saved_customer_operation(store,journal,identity)


@dataclass(frozen=True)
class CustomerCreationEvidence:
    generation_id:str
    registration_id:str
    operation_id:str
    vault_launcher_id:str
    vault_coin_id:str
    confirmed_height:int


async def verify_customer_creation(identity,*,store,journal,settings,index,provider,clock=time.time,require_unused=True):
    """Prove exact creation; only the native history reader may follow spent custody."""
    saved=saved_customer_operation(store,journal,identity)
    if saved is None or saved['stage']!='CONFIRMED':
        raise ValueError('the exact saved customer transaction is not confirmed')
    consent,_,_=store.authorized_material(identity)
    if current_customer_launch_bindings(settings,index,now=int(clock()))!=consent.bindings:
        raise ValueError('customer custody belongs to different current bindings')
    bundle=journal.protocol_bundle(saved['operationId'])
    _,_,output=validate_customer_bundle(bundle,saved['review'])
    async with asyncio.timeout(20):
        if (await provider.get_network_info_primary()).get('network_name')!='testnet11':
            raise ValueError('customer custody requires primary Testnet11 evidence')
        launcher=read_vault_coin(await provider.get_coin_record_by_name_primary(consent.message()['vaultLauncherId']),consent.vault_launcher_id)
        child=read_vault_coin(await provider.get_coin_record_by_name_primary('0x'+output.name().hex()),output.name())
        if (launcher.coin!=bundle.coin_spends[1].coin or not launcher.spent_height
                or child.coin!=output or (require_unused and child.spent_height) or child.confirmed_height!=launcher.spent_height
                or child.confirmed_height!=saved['confirmedHeight']):
            raise ValueError('current customer output differs from the confirmed native creation')
        raw=await provider.get_puzzle_and_solution_primary(consent.message()['vaultLauncherId'],launcher.spent_height)
        from .generation_recipient_evidence import _program
        if (not isinstance(raw,dict) or Coin.from_json_dict(raw['coin'])!=launcher.coin
                or bytes(make_spend(launcher.coin,_program(raw['puzzle_reveal']),_program(raw['solution'])))!=bytes(bundle.coin_spends[1])):
            raise ValueError('customer launcher spend differs from retained creation')
        for record in (launcher,child):
            if read_vault_coin(await provider.get_coin_record_by_name_primary('0x'+record.coin.name().hex()),record.coin.name())!=record:
                raise ValueError('customer creation changed during confirmation')
    return CustomerCreationEvidence(store.generation_id,identity,saved['operationId'],
        consent.message()['vaultLauncherId'],'0x'+output.name().hex(),child.confirmed_height)
