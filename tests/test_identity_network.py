"""Synthetic authority history only; these fixtures never authorize a live action."""
import copy
import hashlib
import json
from dataclasses import replace

import pytest
from solslot_puzzles import identity_network_amendment as network
from solslot_puzzles import identity_deployment_amendment as v1
from solslot_api import identity_deployment as resolver
from solslot_api.config import Settings
from solslot_api.identity_deployment_activation import identity_activation_request
from solslot_api.public_artifact import _release_source_shas, PublicArtifactError
from tests.test_identity_deployment import BASE, DEPLOYMENT, PLAN_HASH, _statement, _chain


def seal(record):
    record = {k:v for k,v in record.items() if k != 'artifactHash'}
    return {**record, 'artifactHash':'0x'+hashlib.sha256(v1.canonical_json(record)).hexdigest()}


@pytest.fixture
def records(tmp_path, monkeypatch):
    old = seal(copy.deepcopy(DEPLOYMENT))
    previous = _statement()
    previous['deploymentArtifactHash'] = old['artifactHash']
    first = _chain(previous)
    predecessor = network.ConfirmedPredecessor(previous, old, PLAN_HASH,
        v1.ConfirmedAmendmentAnchor(first.digest, BASE['launcherIds']['adminAuthority'],
            first.authority_coin_id, first.authority_version, first.spent_height,
            previous['approvalExpiresAt'], first.announcement))
    deployment = copy.deepcopy(old)
    deployment.update(chainId=8453, network='base')
    for index, name in enumerate(['forwarder','verifierAdapter','attestationEmitter']):
        deployment[name+'Address'] = '0x'+str(index+4)*40
        deployment['deploymentTransactions'][name]['hash'] = '0x'+str(index+4)*64
        deployment['deploymentTransactions'][name]['blockNumber'] = 52_000_000+index
        deployment['deploymentTransactions'][name]['blockHash'] = '0x'+str(index+7)*64
    deployment = seal(deployment)
    boundary = copy.deepcopy(previous['activationBoundary'])
    boundary.update(authorityCoinId='0x'+'bb'*32,authorityVersion=4)
    statement = network.build_statement(base_artifact=BASE,deployment_artifact=deployment,
        deployment_plan_hash='0x'+'dd'*32,activation_source_shas={'api':'3'*40,'protocol':'4'*40},
        activation_boundary=boundary,approval_expires_at=2_000_000_200,predecessor=predecessor)
    second = resolver.ChainAmendment(network.amendment_hash(statement),boundary['authorityCoinId'],
        boundary['authorityVersion'],first.spent_height+10,network.announcement_message(network.amendment_hash(statement)))
    paths = {}
    for name, record in [('previous',previous),('old',old),('candidate',statement),('deployment',deployment)]:
        path = tmp_path/(name+'.json')
        path.write_bytes(v1.canonical_json(record))
        paths[name] = str(path)
    settings = Settings(_env_file=None,identity_deployment_amendment_path=paths['previous'],
        identity_deployment_artifact_path=paths['old'],identity_deployment_plan_hash=PLAN_HASH,
        identity_network_amendment_path=paths['candidate'],identity_network_artifact_path=paths['deployment'],
        identity_network_plan_hash='0x'+'dd'*32)
    monkeypatch.setattr(resolver,'load_signed_public_artifact',lambda _settings:BASE)
    verified=[]
    async def verify(**kwargs):
        verified.append(kwargs['selected'].digest)
    monkeypatch.setattr(resolver,'_verify_activation_boundary',verify)
    async def history(**kwargs):
        return (first,second)
    monkeypatch.setattr(resolver,'discover_confirmed_identity_amendments',history)
    return settings,statement,deployment,previous,first,second,verified


@pytest.mark.asyncio
async def test_base_requires_both_confirmed_boundaries(records):
    settings,statement,deployment,previous,first,second,verified = records
    selected = await resolver.load_effective_identity_deployment(settings,provider=object())
    assert selected['revision']==2 and selected['evmChainId']==8453
    assert selected['addresses']['forwarder']==deployment['forwarderAddress']
    assert verified==[first.digest,second.digest]
    assert BASE['evmChainId']==11155111


@pytest.mark.asyncio
async def test_staging_candidate_does_not_activate(records,monkeypatch):
    settings,statement,deployment,previous,first,second,verified=records
    async def one(**kwargs):return (first,)
    monkeypatch.setattr(resolver,'discover_confirmed_identity_amendments',one)
    selected=await resolver.load_effective_identity_deployment(settings,provider=object())
    assert selected['revision']==1 and selected['evmChainId']==11155111
    assert selected['addresses']['forwarder']==previous['newDeployment']['addresses']['forwarder']
    assert identity_activation_request(settings)=={'amendmentHash':second.digest,'revision':2}


@pytest.mark.asyncio
@pytest.mark.parametrize('mutation', ['missing-candidate','partial-config','wrong-digest','wrong-domain','wrong-order','extra-revision','invalid-predecessor-spend'])
async def test_altered_or_unprovable_history_fails_closed(records,monkeypatch,mutation):
    settings,statement,deployment,previous,first,second,verified=records
    history=(first,second)
    if mutation=='missing-candidate':
        settings.identity_network_amendment_path=settings.identity_network_artifact_path=settings.identity_network_plan_hash=''
    elif mutation=='partial-config':settings.identity_network_plan_hash=''
    elif mutation=='wrong-digest':history=(first,replace(second,digest='0x'+'ee'*32))
    elif mutation=='wrong-domain':history=(first,replace(second,announcement=v1.announcement_message(second.digest)))
    elif mutation=='wrong-order':history=(first,replace(second,spent_height=first.spent_height))
    elif mutation=='extra-revision':history=(first,second,replace(second,digest='0x'+'ee'*32))
    else:
        async def reject(**kwargs):raise resolver.IdentityDeploymentError('predecessor identity spend absent')
        monkeypatch.setattr(resolver,'_verify_activation_boundary',reject)
    async def changed(**kwargs):return history
    monkeypatch.setattr(resolver,'discover_confirmed_identity_amendments',changed)
    with pytest.raises(resolver.IdentityDeploymentError):
        await resolver.load_effective_identity_deployment(settings,provider=object())


def test_sources_from_candidate_require_complete_record_binding(records):
    settings,statement,deployment,previous,first,second,verified=records
    sources=_release_source_shas(settings,BASE)
    assert sources['api']=='3'*40 and sources['protocol']=='4'*40
    settings.identity_network_plan_hash='0x'+'ee'*32
    with pytest.raises(PublicArtifactError,match='source record is invalid'):
        _release_source_shas(settings,BASE)


def test_chain_local_rpc_selection_and_enrollment_are_closed(records):
    settings,statement,deployment,previous,first,second,verified=records
    selected={'evmChainId':8453,'addresses':statement['newDeployment']['addresses'],
        'credentialPolicyVersion':2,'chiaBridgePolicyHash':statement['chiaBridgePolicyHash'],
        'revision':2,'amendmentHash':second.digest,'acceptedProofVersions':['0.20.0','0.21.0']}
    local=resolver.settings_for_identity_deployment(settings,selected)
    assert local.zkpassport_evm_chain_id==8453 and local.zkpassport_evm_rpc_url=='https://mainnet.base.org'
    assert settings.zkpassport_evm_chain_id==11155111
    binding=resolver.enrollment_identity_binding(selected)
    assert resolver.deployment_for_enrollment(base_artifact=BASE,current=selected,enrollment={'identityDeployment':binding})==selected
    binding['evmChainId']=11155111
    with pytest.raises(resolver.IdentityDeploymentError,match='different identity deployment'):
        resolver.deployment_for_enrollment(base_artifact=BASE,current=selected,enrollment={'identityDeployment':binding})
    with pytest.raises(resolver.IdentityDeploymentError,match='RPC mapping'):
        resolver.identity_rpc_url(settings,1)
