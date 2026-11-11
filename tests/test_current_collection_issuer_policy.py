from dataclasses import replace
from hashlib import sha256
import json
from types import SimpleNamespace

import pytest
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import MOD
from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton
from solslot_puzzles.generation_vault import vault_inner
from solslot_puzzles.vault_driver import one_leaf_merkle_root, AUTH_TYPE_BLS
from chia_rs import AugSchemeMPL, Coin
from chia_rs.sized_bytes import bytes32

from solslot_api.generation_customer_collection_policy import TestnetCollectionIssuerPolicy as CollectionPolicy, read_collection_issuer_policy
from solslot_api.generation_customer_vault import CurrentCustomerVault
from tests.test_native_purchases import _context, _b32


def make_policy():
    keys=tuple(AugSchemeMPL.key_gen(bytes([n])*32) for n in (51,52,53))
    ctx=_context(AugSchemeMPL.key_gen(b'p'*32),keys,now=2000,deed_parent_seed=22)[0]
    generation=_b32(1)
    terms=replace(ctx.terms,inventory_version=4,protocol_puzhash=Program.from_bytes(bytes(MOD)).curry(keys[2].get_g1()).get_tree_hash(),
        generation_batch_bindings=bytes(Program.to([generation,*[_b32(2)]*7])))
    policy=CollectionPolicy(generation,terms.collection_id,terms.metadata_anchor_id,terms.metadata_root,
        terms.protocol_puzhash,terms.protocol_treasury_puzzle_hash,bytes(keys[2].get_g1()),
        frozenset([terms.deed_launcher_id]),10**14)
    return policy,terms


def save(tmp_path,document):
    raw=json.dumps(document,sort_keys=True).encode();path=tmp_path/'policy.json';path.write_bytes(raw)
    return path,'0x'+sha256(raw).hexdigest()


def vault(policy,launcher,root=None):
    root=root or _b32(13)
    owner=bytes(AugSchemeMPL.key_gen(b'v'*32).get_g1())
    inner=vault_inner(vault_launcher_id=launcher,owner_pubkey=owner,auth_type=AUTH_TYPE_BLS,
        members_merkle_root=one_leaf_merkle_root(owner),pool_launcher_id=_b32(9),identity_attest_root=root,
        zkpassport_bridge_policy_hash=_b32(7))
    coin=Coin(_b32(11),puzzle_for_singleton(launcher,inner).get_tree_hash(),1)
    return CurrentCustomerVault(policy.generation,launcher,coin,inner,root,1,_b32(14),_b32(15),1,None)


def test_separate_pinned_schema_has_no_fixed_buyer_or_global_test_window_or_purchase_quota(tmp_path):
    policy,terms=make_policy();path,pin=save(tmp_path,policy.public())
    assert read_collection_issuer_policy(path,pin)==policy
    assert policy.require_terms(terms)==policy
    assert not {'buyerVaultLauncherId','maximumPurchases','issuedAt','expiresAt'} & policy.public().keys()
    for launcher in (_b32(21),_b32(22)):
        assert policy.require_verified_vault(vault(policy,launcher),launcher=launcher,auth_type='chia_bls')==policy
    with pytest.raises(ValueError,match='FILE_CHANGED'):read_collection_issuer_policy(path,'0x'+'00'*32)


@pytest.mark.parametrize('field,value',[
    ('collection_id',_b32(90)),('metadata_anchor_id',_b32(90)),('metadata_root',_b32(90)),
    ('deed_launcher_id',_b32(90)),('protocol_puzhash',_b32(90)),
    ('protocol_treasury_puzzle_hash',_b32(90)),('technology_fee_bps',101)])
def test_exact_mint_scope_is_required(field,value):
    policy,terms=make_policy()
    with pytest.raises(ValueError,match='TERMS_CHANGED'):policy.require_terms(replace(terms,**{field:value}))


def test_session_vault_identity_and_chia_ownership_cannot_be_substituted():
    policy,_=make_policy();original=vault(policy,_b32(21))
    for candidate,launcher,auth in [
        (original,_b32(22),'chia_bls'),(original,_b32(21),'evm'),
        (replace(original,stamp_coin_id=None),_b32(21),'chia_bls'),
        (replace(original,generation=_b32(77)),_b32(21),'chia_bls'),
        (SimpleNamespace(identity_verified=True),_b32(21),'chia_bls')]:
        with pytest.raises(ValueError,match='VERIFIED_CHIA_VAULT_REQUIRED'):
            policy.require_verified_vault(candidate,launcher=launcher,auth_type=auth)


@pytest.mark.parametrize('mutation',[
    lambda p:p.update(network='mainnet'),lambda p:p.update(mainnetEnabled=True),
    lambda p:p.update(masterKeyExportAuthorized=True),lambda p:p.update(maximumPurchases=3),
    lambda p:p.update(technologyFeeBps=99),lambda p:p.update(buyerVaultLauncherId='0x'+'11'*32)])
def test_schema_rejects_scope_or_legacy_field_changes(tmp_path,mutation):
    policy,_=make_policy();document=policy.public();mutation(document);path,pin=save(tmp_path,document)
    with pytest.raises(ValueError):read_collection_issuer_policy(path,pin)


def test_exact_purchase_terms_current_vault_and_quote_deadline():
    keys=tuple(AugSchemeMPL.key_gen(bytes([n])*32) for n in (51,52,53))
    ctx=_context(AugSchemeMPL.key_gen(b'p'*32),keys,now=2000,deed_parent_seed=22)[0]
    generation=_b32(1);terms=replace(ctx.terms,inventory_version=4,
        protocol_puzhash=Program.from_bytes(bytes(MOD)).curry(keys[2].get_g1()).get_tree_hash(),
        generation_batch_bindings=bytes(Program.to([generation,*[_b32(2)]*7])))
    policy=CollectionPolicy(generation,terms.collection_id,terms.metadata_anchor_id,terms.metadata_root,
        terms.protocol_puzhash,terms.protocol_treasury_puzzle_hash,bytes(keys[2].get_g1()),
        frozenset([terms.deed_launcher_id]),10**14)
    artifact=ctx.purchase;current=vault(policy,artifact.vault_launcher_id,root=artifact.zkpassport_root)
    assert policy.require_purchase(artifact,terms,current,launcher=current.launcher,auth_type='chia_bls',now=2001)==policy
    for bad,now in [(replace(artifact,zkpassport_root=_b32(60)),2001),
                    (artifact,artifact.quote_expires_at)]:
        with pytest.raises(ValueError,match='PURCHASE_SCOPE_CHANGED'):
            policy.require_purchase(bad,terms,current,launcher=current.launcher,auth_type='chia_bls',now=now)

    with pytest.raises(ValueError,match='PURCHASE_SCOPE_CHANGED'):
        replace(policy,maximum_gross_mojos=artifact.rail_amount-1).require_purchase(artifact,terms,current,launcher=current.launcher,auth_type='chia_bls',now=2001)


def test_collection_policy_preserves_approved_testnet_nominal_conversion(tmp_path):
    from types import SimpleNamespace
    from solslot_api.generation_customer_test_conversion import configured_price,claim_price
    from solslot_puzzles.payment_artifacts_v3 import build_xch_purchase_artifact
    policy,_=make_policy();policy=replace(policy,test_usd_minor_per_txch=3_000_000)
    path,pin=save(tmp_path,policy.public());assert read_collection_issuer_policy(path,pin)==policy
    settings=SimpleNamespace(network='testnet11',deployment_generation_id='0x'+policy.generation.hex())
    price,evidence=configured_price(settings,policy,now=1100,expires_at=1400)
    assert claim_price(evidence,policy)==price
    quote=build_xch_purchase_artifact(network='testnet11',collection_id=_b32(1),deed_launcher_id=_b32(2),
        metadata_root=_b32(3),metadata_anchor_id=_b32(4),share_ppm=40000,base_amount_minor=300000,
        technology_fee_bps=100,protocol_treasury_puzzle_hash=_b32(5),zkpassport_root=_b32(6),
        vault_launcher_id=_b32(7),vault_p2_puzzle_hash=_b32(8),authorization_nonce=_b32(9),
        authorization_expires_at=1400,quote_expires_at=1400,oracle_round=price.round)
    assert quote.rail_amount==101_000_000_000 and quote.technology_fee_minor==3000
    with pytest.raises(ValueError):price.verify_policy(policy,now=1400,expires_at=1400)
    with pytest.raises(ValueError):price.verify_policy(replace(policy,test_usd_minor_per_txch=4_000_000),now=1100,expires_at=1400)
    with pytest.raises(ValueError):configured_price(SimpleNamespace(network='mainnet',deployment_generation_id=settings.deployment_generation_id),policy,now=1100,expires_at=1400)
