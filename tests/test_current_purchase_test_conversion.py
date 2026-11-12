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
