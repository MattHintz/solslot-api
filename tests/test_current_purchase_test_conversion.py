from dataclasses import replace
from types import SimpleNamespace
import pytest
from tests.test_current_purchase_private_boundary import policy,write_policy
from solslot_api.generation_customer_purchase_policy import read_current_issuer_policy
from solslot_api.generation_customer_test_conversion import FixedTestnetConversion,claim_price,configured_price,status
from solslot_puzzles.payment_artifacts_v3 import build_xch_purchase_artifact
from chia_rs.sized_bytes import bytes32


def nominal():return replace(policy(),test_usd_minor_per_txch=3_000_000)

def test_fixed_conversion_is_exact_finite_policy_not_a_market_attestation(tmp_path):
    p=nominal();path,pin=write_policy(tmp_path,p.public())
    assert read_current_issuer_policy(path,pin)==p
    assert p.commitment!=policy().commitment
    settings=SimpleNamespace(network='testnet11',deployment_generation_id='0x'+p.generation.hex())
    price,evidence=configured_price(settings,p,now=1100,expires_at=1400)
    assert claim_price(evidence,p)==price
    assert 'signatures'not in evidence and 'observations'not in evidence
    assert price.round.source_evidence_root!=bytes32.zeros
    assert status(p,now=1100)['price']['sourceCount']==0
    assert status(p,now=1701)['price']['canQuote']is False


@pytest.mark.parametrize('patch',[{'network':'mainnet'},{'deployment_generation_id':'0x'+'ff'*32}])
def test_fixed_conversion_cannot_cross_network_or_generation(patch):
    p=nominal();s={'network':'testnet11','deployment_generation_id':'0x'+p.generation.hex(),**patch}
    with pytest.raises(ValueError):configured_price(SimpleNamespace(**s),p,now=1100,expires_at=1400)


@pytest.mark.parametrize('rate',[0,-1,True,1.2,10**15+1])
def test_fixed_conversion_rejects_invalid_rate(rate):
    with pytest.raises(ValueError):replace(policy(),test_usd_minor_per_txch=rate).validate()


def test_fixed_conversion_cannot_replace_market_policy_or_change_saved_work():
    p=nominal();price=FixedTestnetConversion(p,1400)
    for other in [policy(),replace(p,test_usd_minor_per_txch=4_000_000),replace(p,expires_at=2100)]:
        with pytest.raises(ValueError):price.verify_policy(other,now=1100,expires_at=1400)
    for now,expires in [(1400,1400),(999,1400),(1100,1401),(1800,2100)]:
        with pytest.raises(ValueError):price.verify_policy(p,now=now,expires_at=expires)
    for patch in [{'issuerPolicyHash':policy().commitment},{'signatures':[]},{'expiresAt':True}]:
        with pytest.raises(ValueError):claim_price({**price.evidence(),**patch},p)
    with pytest.raises(ValueError):claim_price(price.evidence(),policy())


def test_nominal_txch_amount_preserves_sealed_dollars_and_one_percent_fee():
    p=nominal();price=FixedTestnetConversion(p,1400)
    b=lambda n:bytes32(bytes([n])*32)
    quote=build_xch_purchase_artifact(network='testnet11',collection_id=b(1),deed_launcher_id=b(2),
        metadata_root=b(3),metadata_anchor_id=b(4),share_ppm=40000,base_amount_minor=300000,
        technology_fee_bps=100,protocol_treasury_puzzle_hash=b(5),zkpassport_root=b(6),
        vault_launcher_id=b(7),vault_p2_puzzle_hash=b(8),authorization_nonce=b(9),
        authorization_expires_at=1400,quote_expires_at=1400,oracle_round=price.round)
    assert quote.base_amount_minor==300000 and quote.technology_fee_minor==3000
    assert quote.rail_amount==101_000_000_000
    assert quote.oracle_round_hash==price.round.round_hash


def test_two_deed_sltc_price_binds_the_tail_and_preserves_native_policy(tmp_path):
    from tests.test_current_collection_issuer_policy import make_policy, save
    from solslot_api.generation_customer_collection_policy import CheckoutCat, read_collection_issuer_policy
    SLTC_ASSET = bytes32.from_hexstr("b37a1d4efc0e70e7444407f7b3241c4c6a542706d38398a8a56a0152df730059")
    from solslot_puzzles.payment_artifacts_v3 import build_cat_purchase_artifact
    base, _ = make_policy()
    prior = replace(base, test_usd_minor_per_txch=3_000_000)
    policy = replace(prior, checkout_cats=(CheckoutCat(SLTC_ASSET, "SLTC", 3, 100, 3_030_000),))
    settings = SimpleNamespace(network='testnet11', deployment_generation_id='0x'+policy.generation.hex())
    assert read_collection_issuer_policy(*save(tmp_path, prior.public())) == prior
    assert read_collection_issuer_policy(*save(tmp_path, policy.public())) == policy
    price, evidence = configured_price(settings, policy, now=1100, expires_at=1400, asset=SLTC_ASSET)
    assert claim_price(evidence, policy) == price
    assert policy.commitment == prior.commitment and policy.asset_policy_hash != prior.commitment
    revised = replace(policy, checkout_cats=(replace(policy.checkout_cats[0], usd_minor_per_unit=250),))
    with pytest.raises(ValueError):
        claim_price(evidence, revised)
    native, _ = configured_price(settings, policy, now=1100, expires_at=1400)
    old_native, old_evidence = configured_price(settings, prior, now=1100, expires_at=1400)
    assert native.round.round_hash == old_native.round.round_hash
    assert native.evidence() == old_evidence
    assert native.round.round_hash != price.round.round_hash
    for wrong in (bytes32(b'Z'*32), bytes32.from_hexstr('91bfdb4a750308c25b12d0f787309df590a4cad80e7466accdd99b1d1759d9e4')):
        with pytest.raises(ValueError):
            configured_price(settings, policy, now=1100, expires_at=1400, asset=wrong)
    with pytest.raises(ValueError):
        configured_price(settings, prior, now=1100, expires_at=1400, asset=SLTC_ASSET)
    with pytest.raises(ValueError):
        claim_price(evidence, prior)
    b=lambda n:bytes32(bytes([n])*32)
    quotes = [build_cat_purchase_artifact(network='testnet11',collection_id=b(1),deed_launcher_id=b(i),
        metadata_root=b(3),metadata_anchor_id=b(4),share_ppm=40000,base_amount_minor=300000,
        technology_fee_bps=100,protocol_treasury_puzzle_hash=b(5),zkpassport_root=b(6),
        vault_launcher_id=b(7),vault_p2_puzzle_hash=b(8),authorization_nonce=b(9),
        authorization_expires_at=1400,quote_expires_at=1400,oracle_round=price.round,
        cat_asset_id=SLTC_ASSET,cat_asset_decimals=3) for i in (10,11)]
    assert sum(q.rail_amount for q in quotes) == 6_060_000
    assert sum(q.technology_fee_minor for q in quotes) == 6_000



def test_another_configured_cat_uses_the_same_checkout_conversion():
    from tests.test_current_collection_issuer_policy import make_policy
    from solslot_api.generation_customer_collection_policy import CheckoutCat
    base, _ = make_policy()
    cat = CheckoutCat(bytes32(b'X' * 32), 'SECOND', 3, 250, 2500000)
    policy = replace(base, checkout_cats=(cat,)).validate()
    settings = SimpleNamespace(network='testnet11', deployment_generation_id='0x'+policy.generation.hex())
    price, evidence = configured_price(settings, policy, now=1100, expires_at=1400, asset=cat.asset_id)
    assert claim_price(evidence, policy) == price
    assert price.round.asset_id == cat.asset_id
    assert price.round.price_usd_minor_per_asset == 250
