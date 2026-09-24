"""Signed payment domain drives authority independently of identity."""
import json
import pytest
from solslot_api.authority_network import authority_chain_id, ceremony_authority_document
from solslot_api.authority_v3_evidence import load_governance_evidence, validate_governance_roster, _canonical_hash
from solslot_api.omnichain_evidence import load_omnichain_evidence, OmnichainEvidenceError
from solslot_api.config import Settings
from tests.test_authority_v3_evidence import _evidence, _settings


def test_mixed_network_authority_uses_signed_selection():
    draft = {'evmChainId':11155111}
    plan = {**draft, 'paymentChainId':8453}
    assert authority_chain_id(draft) == 84532
    assert authority_chain_id(ceremony_authority_document({'draft':draft,'plan':plan})) == 8453
    assert draft == {'evmChainId':11155111}
    assert authority_chain_id({**plan,'genesisPlan':plan}) == 8453


@pytest.mark.parametrize('value', [True, '8453', 1, 11155111, None])
def test_invalid_explicit_selection_rejected(value):
    with pytest.raises(ValueError):
        authority_chain_id({'evmChainId':11155111,'paymentChainId':value})


@pytest.mark.parametrize('nested', [{}, {'paymentChainId':84532}])
def test_nested_signed_plan_cannot_disagree(nested):
    with pytest.raises(ValueError, match='signed plan'):
        authority_chain_id({'evmChainId':11155111,'paymentChainId':8453,'genesisPlan':nested})


def test_plan_cannot_change_identity_domain():
    with pytest.raises(ValueError, match='identity chain'):
        ceremony_authority_document({'draft':{'evmChainId':11155111},
                                    'plan':{'evmChainId':84532,'paymentChainId':8453}})


def test_mainnet_evidence_accepts_sepolia_identity_only_with_payment_selection(tmp_path):
    evidence = _evidence()
    evidence.update(network='baseMainnet',chainId=8453)
    evidence['artifactHash'] = _canonical_hash(evidence)
    settings = _settings(tmp_path,evidence)
    with pytest.raises(ValueError, match='network'):
        load_governance_evidence(settings)
    settings.payment_omnichain_chain_id = 8453
    assert settings.eip712_chain_id == settings.zkpassport_evm_chain_id == 11155111
    assert load_governance_evidence(settings)['chainId'] == 8453
    evidence.update(network='baseSepolia',chainId=84532)
    evidence['artifactHash'] = _canonical_hash(evidence)
    from pathlib import Path
    Path(settings.authority_v3_governance_evidence_path).write_text(json.dumps(evidence))
    with pytest.raises(ValueError, match='network'):
        load_governance_evidence(settings)


def test_roster_checks_plan_chain_before_any_guardian_data():
    record = {'draft':{'evmChainId':11155111},'plan':{'evmChainId':11155111,'paymentChainId':8453}}
    with pytest.raises(ValueError, match='wrong EVM network'):
        validate_governance_roster(record, [], {'network':'baseSepolia','chainId':84532})
    # Matching the chain must not skip the remaining roster requirements.
    with pytest.raises(ValueError, match='three recovery drills'):
        validate_governance_roster(record, [], {'network':'baseMainnet','chainId':8453})


def test_payment_request_cannot_choose_its_own_network():
    with pytest.raises(OmnichainEvidenceError, match='configured payment chain'):
        load_omnichain_evidence(Settings(payment_omnichain_enabled=True),
            chain_id=8453,token_address='0x'+'11'*20,gateway_profile='base')
