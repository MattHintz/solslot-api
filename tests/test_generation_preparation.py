from copy import deepcopy

import pytest
from chia.types.blockchain_format.coin import Coin
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_keys import keys
from solslot_puzzles.generation_vault import vault_inner, sgt_owner
from solslot_puzzles.vault_driver import one_leaf_merkle_root
from solslot_puzzles.admin_authority_v3_driver import authority_v3_launcher_ids

from solslot_api.generation_preparation import GenerationPreparation, SOURCE_KEYS, COORDINATE_KEYS


def b32(n):return '0x'+f'{n:02x}'*32


def reservation(n):
    parent=bytes32.from_hexstr(b32(n))
    return {'fundingCoinId':b32(n),'launcherId':'0x'+Coin(parent,SINGLETON_LAUNCHER_HASH,uint64(1)).name().hex()}


def manifest():
    accounts=[Account.from_key(bytes([n])*32) for n in (1,2,3)] # Synthetic fixture keys only.
    raw=dict(generationId=b32(7),sourceCommits={k:'12'*20 for k in SOURCE_KEYS},
        sgtFundingCoinId=b32(80),reserveOwnerPuzzleHash=b32(81),bridgePolicyHash=b32(82),
        coordinates={k:reservation(i+10) for i,k in enumerate(sorted(COORDINATE_KEYS))},
        administrators=[dict(slot=i+1,name=f'Test administrator {i+1}',wallet=a.address.lower(),
            identityAuthorityLauncher=b32(30+i),recoveryDrillHash=b32(40+i),custody=reservation(50+i),
            custodyAuthType=3,custodyOwnerPublicKey='0x'+keys.PrivateKey(bytes([i+1])*32).public_key.to_compressed_bytes().hex(),
            custodyInnerHash=b32(60+i),sgtOwnerPuzzleHash=b32(70+i)) for i,a in enumerate(accounts)])
    bind_identities(raw)
    bind_custody(raw)
    return GenerationPreparation.model_validate(raw), accounts


def bind_identities(raw):
    _, *identities = authority_v3_launcher_ids(bytes32.from_hexstr(raw['coordinates']['authority']['fundingCoinId']))
    for admin, identity in zip(raw['administrators'], identities):
        admin['identityAuthorityLauncher']='0x'+identity.hex()


def bind_custody(raw):
    for a in raw['administrators']:
        owner=bytes.fromhex(a['custodyOwnerPublicKey'][2:])
        inner=vault_inner(vault_launcher_id=bytes32.from_hexstr(a['custody']['launcherId']),
            owner_pubkey=owner,auth_type=a['custodyAuthType'],members_merkle_root=one_leaf_merkle_root(owner),
            pool_launcher_id=bytes32.from_hexstr(raw['coordinates']['pool']['launcherId']),
            zkpassport_bridge_policy_hash=bytes32.from_hexstr(raw['bridgePolicyHash']))
        a['custodyInnerHash']='0x'+inner.get_tree_hash().hex()
        a['sgtOwnerPuzzleHash']='0x'+sgt_owner(bytes32.from_hexstr(raw['generationId']),
            bytes32.from_hexstr(a['custody']['launcherId'])).get_tree_hash().hex()


def signatures(m,accounts):
    return {i+1: '0x'+a.sign_message(encode_typed_data(full_message=m.acknowledgement(i+1))).signature.hex()
            for i,a in enumerate(accounts)}


def test_all_three_exact_acknowledgements_and_one_canonical_review():
    m,accounts=manifest()
    m.verify_acknowledgements(signatures(m,accounts))
    review=m.review()
    assert review['initialQuorum']==15000
    assert review['holderSupply']+review['reserveSupply']==review['totalSupply']==1000000
    for row in review['recipients']:
        signed=m.acknowledgement(row['administratorSlot'])['message']
        assert row['recipientVault']==signed['recipientVault']
        assert row['recipientPuzzle']==signed['recipientPuzzle']
        assert row['amount']==signed['amount']==10000
    with pytest.raises(ValueError,match='all three'):
        m.verify_acknowledgements({k:v for k,v in signatures(m,accounts).items() if k!=3})


@pytest.mark.parametrize('change',['coordinate','authority_coordinate','source','generation','recipient','name','recovery'])
def test_every_preparation_change_invalidates_old_destination_acknowledgements(change):
    m,accounts=manifest(); old=signatures(m,accounts)
    raw=m.model_dump(mode='json',by_alias=True)
    if change=='coordinate':raw['coordinates']['pool']=reservation(90)
    if change=='authority_coordinate':
        raw['coordinates']['authority']=reservation(90)
        bind_identities(raw)
    if change=='source':raw['sourceCommits']['protocol']='34'*20
    if change=='generation':raw['generationId']=b32(8)
    if change=='recipient':raw['administrators'][0]['custody']=reservation(91)
    if change=='name':raw['administrators'][0]['name']='Different administrator label'
    if change=='recovery':raw['administrators'][0]['recoveryDrillHash']=b32(92)
    bind_custody(raw)
    new=GenerationPreparation.model_validate(raw)
    assert m.manifest_hash!=new.manifest_hash
    with pytest.raises(ValueError,match='acknowledgement'):new.verify_acknowledgements(old)


@pytest.mark.parametrize('change',['wrong_launcher','same_funding','same_wallet','same_recipient','identity_custody','mainnet','grant','source_missing','unknown_coordinate','zero','custody_hash','owner_hash','sgt_funding','custody_key'])
def test_rejects_ambiguous_preparation_before_any_signature(change):
    m,_=manifest();raw=m.model_dump(mode='json',by_alias=True)
    if change=='wrong_launcher':raw['coordinates']['pool']['launcherId']=b32(93)
    if change=='same_funding':raw['administrators'][0]['custody']=deepcopy(raw['coordinates']['pool'])
    if change=='same_wallet':raw['administrators'][1]['wallet']=raw['administrators'][0]['wallet']
    if change=='same_recipient':raw['administrators'][1]['sgtOwnerPuzzleHash']=raw['administrators'][0]['sgtOwnerPuzzleHash']
    if change=='identity_custody':raw['administrators'][0]['identityAuthorityLauncher']=raw['administrators'][0]['custody']['launcherId']
    if change=='mainnet':raw['network']='mainnet'
    if change=='grant':raw['administrators'][0]['initialSgt']=20000
    if change=='source_missing':del raw['sourceCommits']['api']
    if change=='unknown_coordinate':raw['coordinates']['bootstrapVote']=reservation(94)
    if change=='zero':raw['generationId']=b32(0)
    if change=='custody_hash':raw['administrators'][0]['custodyInnerHash']=b32(93)
    if change=='owner_hash':raw['administrators'][0]['sgtOwnerPuzzleHash']=b32(94)
    if change=='sgt_funding':raw['sgtFundingCoinId']=raw['coordinates']['pool']['fundingCoinId']
    if change=='custody_key':raw['administrators'][0]['custodyOwnerPublicKey']=raw['administrators'][1]['custodyOwnerPublicKey']
    with pytest.raises(ValueError):GenerationPreparation.model_validate(raw)


@pytest.mark.parametrize('fault', ['arbitrary_identity','swapped_slots','stale_identity_after_reservation'])
def test_identity_authorities_cannot_be_independently_substituted(fault):
    m,_=manifest();raw=m.model_dump(mode='json',by_alias=True)
    if fault=='arbitrary_identity':raw['administrators'][0]['identityAuthorityLauncher']=b32(101)
    if fault=='swapped_slots':
        a,b=raw['administrators'][:2]
        a['identityAuthorityLauncher'],b['identityAuthorityLauncher']=b['identityAuthorityLauncher'],a['identityAuthorityLauncher']
    if fault=='stale_identity_after_reservation':raw['coordinates']['authority']=reservation(102)
    with pytest.raises(ValueError,match='derive from the reserved authority'):
        GenerationPreparation.model_validate(raw)
