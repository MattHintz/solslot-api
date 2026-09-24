"""The full sealed evidence graph must work on Base without age-chain relabeling."""
import json
from pathlib import Path
import pytest
from solslot_api.config import get_settings
from solslot_api.omnichain_evidence import load_omnichain_evidence, OmnichainEvidenceError, _canonical_hash
from tests.test_protocol_artifacts import _configure_external_quote
from tests.test_authority_v3_payment_evidence import evidence as v3_evidence


def base_graph(monkeypatch, tmp_path, fixture='TEST-USDC'):
    _configure_external_quote(monkeypatch,tmp_path)
    paths = {n: tmp_path / f'omnichain-{n}.json' for n in (
        'governance-evidence','samuel-evidence','warp-portal-evidence','preflight-evidence',
        'deployment-evidence','ownership-intent','activation-evidence')}
    records={n:json.loads(p.read_text()) for n,p in paths.items()}
    replacements={}
    deploy=records['deployment-evidence']
    if fixture == 'TEST-SOLS':
        from solslot_puzzles.alpha_payment_profile import alpha_payment_profile
        profile = alpha_payment_profile()
        replacements[deploy['contracts']['usdc']] = profile['tokenAddress']
        replacements[deploy['runtimeCodeHashes']['usdc']] = profile['tokenRuntimeCodeHash']
    governance=v3_evidence()
    root=deploy['configuration']['governanceRootSafe'];lock=deploy['configuration']['governanceTimelock']
    governance['safes']['root']['address']=root;governance['payoutAddress']=root
    governance['timelock'].update(address=lock,proposer=root,executor=root,canceller=root)
    governance['runtimeCodeHashes'].update(rootSafe=deploy['runtimeCodeHashes']['governanceRootSafe'],timelock=deploy['runtimeCodeHashes']['governanceTimelock'])
    governance['artifactHash']=records['governance-evidence']['artifactHash']
    records['governance-evidence']=governance
    samuel=records['samuel-evidence'];samuel['baseMainnet']=samuel.pop('baseSepolia')
    samuel['baseMainnet']['chainId']=8453
    samuel.update(schemaVersion=4,paymentChainId=8453,testOnly=True,validatorIdentityDomain='solslot-alpha-native-bridge-testnet11-base-mainnet')
    portal=records['warp-portal-evidence']
    portal.update(schemaVersion=2,kind='solslot-native-bridge-base-mainnet-portal-deployment',chiaNetwork='testnet11',testOnly=True,validatorIdentityDomain=samuel['validatorIdentityDomain'])
    asset={'schemaVersion':1,'kind':'solslot-test-asset-deployment','chainId':8453,'network':'baseMainnet',
        'chiaNetwork':'testnet11','testOnly':True,'fixture':fixture,'decimals':6,'sourceSha':'a'*40,
        'address':replacements.get(deploy['contracts']['usdc'],deploy['contracts']['usdc']),
        'runtimeCodeHash':replacements.get(deploy['runtimeCodeHashes']['usdc'],deploy['runtimeCodeHashes']['usdc']),
        'transactionHash':'0x'+'10'*32,'blockHash':'0x'+'20'*32,'blockNumber':100}
    asset['artifactHash']=_canonical_hash(asset)
    asset_path=tmp_path/'test-asset.json';asset_path.write_text(json.dumps(asset))
    records['preflight-evidence']['hubName']='baseMainnet'
    records['preflight-evidence']['inspection']['testAssetArtifactHash']=asset['artifactHash']

    def rewrite(value):
        if isinstance(value,dict):
            return {replacements.get(k,k):8453 if k=='chainId' and v==84532 else 'baseMainnet' if k=='network' and v=='baseSepolia' else rewrite(v) for k,v in value.items()}
        if isinstance(value,list):return [rewrite(v) for v in value]
        return replacements.get(value,value) if isinstance(value,str) else value

    for name in paths:  # topological order: leaves, preflight, deployment, ownership, activation
        before=records[name]['artifactHash']
        value=rewrite(records[name]);value.pop('artifactHash')
        value['artifactHash']=_canonical_hash(value)
        replacements[before]=value['artifactHash'];paths[name].write_text(json.dumps(value))
    monkeypatch.setenv('SOLSLOT_PAYMENT_OMNICHAIN_CHAIN_ID','8453')
    monkeypatch.setenv('SOLSLOT_PAYMENT_OMNICHAIN_TEST_ASSET_EVIDENCE_PATH',str(asset_path))
    get_settings.cache_clear()
    return get_settings(),asset['address']


@pytest.mark.parametrize('fixture',['TEST-USDC','TEST-SOLS'])
def test_complete_base_payment_evidence(monkeypatch,tmp_path,fixture):
    settings,token=base_graph(monkeypatch,tmp_path,fixture)
    result=load_omnichain_evidence(settings,chain_id=8453,token_address=token,gateway_profile='bse')
    assert result.chain_id == 8453
    assert settings.zkpassport_evm_chain_id == 11155111


def test_base_cannot_skip_test_asset_receipt(monkeypatch,tmp_path):
    settings,token=base_graph(monkeypatch,tmp_path)
    settings.payment_omnichain_test_asset_evidence_path=None
    with pytest.raises(OmnichainEvidenceError,match='test_asset evidence is not configured'):
        load_omnichain_evidence(settings,chain_id=8453,token_address=token,gateway_profile='bse')
