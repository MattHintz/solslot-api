"""Protected selected launch identity through the actual guided HTTP entrypoints."""
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import pytest
from chia_rs import AugSchemeMPL
from eth_account import Account
from solslot_api import launch_control as launch
from solslot_api.genesis_store import GenesisConflict
from tests.test_genesis_permit_evm import deployment_setup
from tests.test_launch_control import _client, _plan_template, _sign, ADMIN_TOKEN

@pytest.fixture
def guided(deployment_setup,tmp_path):
    s=deployment_setup
    local=tmp_path/'guided';local.mkdir()
    client,store,settings=_client(local)
    for name in ['runtime_environment','eip712_chain_id','zkpassport_evm_chain_id','zkpassport_evm_rpc_url',
        'genesis_evm_deployment_path','enrollment_deployment_review_path','enrollment_deployment_review_sha256',
        'enrollment_permit_release_identity','enrollment_permit_issuer_key_ref','enrollment_permit_identity_client_id',
        'launch_release_tag','launch_source_evidence_path','launch_source_evidence_sha256']:
        setattr(settings,name,getattr(s.settings,name))
    template=_plan_template(bytes(AugSchemeMPL.key_gen(b'new-guided-kos-key-local-only-1234').get_g1()))
    template.update(enrollmentActivation=copy.deepcopy(s.active),evmAddresses=s.plan['evmAddresses'],validatorPubkeys=s.plan['validatorSet']['pubkeys'])
    file=local/'plan.json';file.write_text(json.dumps(template));settings.launch_plan_template_path=str(file)
    return SimpleNamespace(client=client,store=store,settings=settings,template=template,file=file,active=s.active)

def claim(g):
    return g.client.post('/admin/launch/claim',json=dict(token=ADMIN_TOKEN,displayName='Synthetic owner',timezone='America/Chicago'))

def test_selected_claim_and_invitation_use_fixed_ceremony_and_chain(guided):
    g=guided;r=claim(g);assert r.status_code==200,r.text
    assert r.json()['ceremonyId']==g.active['deploymentId']
    record=g.store.get(r.json()['ceremonyId']);assert record['draft']['evmChainId']==84532
    assert record['draft']['enrollmentActivation']==g.active
    assert record['draft']['launchPlanTemplateSha256']==hashlib.sha256(g.file.read_bytes()).hexdigest()
    owner=Account.create()
    prepared=g.client.post('/admin/launch/invitations/prepare',json=dict(token=r.json()['ownerEnrollmentToken'],wallet=owner.address))
    assert prepared.status_code==200,prepared.text
    data=prepared.json();assert data['typedData']['domain']['chainId']==84532
    assert data['ceremonyBinding']==dict(ceremonyId=g.active['deploymentId'],evmChainId=84532)
    wrong=copy.deepcopy(data['typedData']);wrong['domain']['chainId']=11155111
    bad=g.client.post('/admin/launch/invitations/accept',json=dict(token=r.json()['ownerEnrollmentToken'],wallet=owner.address,signature=_sign(owner,wrong)))
    assert bad.status_code==403
    accepted=g.client.post('/admin/launch/invitations/accept',json=dict(token=r.json()['ownerEnrollmentToken'],wallet=owner.address,signature=_sign(owner,data['typedData'])))
    assert accepted.status_code==200,accepted.text
    resumed=g.client.post('/admin/launch/auth/challenge',json=dict(wallet=owner.address));assert resumed.status_code==200,resumed.text
    assert resumed.json()['typedData']['domain']['chainId']==84532
    login=g.client.post('/admin/launch/auth/login',json=dict(wallet=owner.address,nonce=resumed.json()['nonce'],signature=_sign(owner,resumed.json()['typedData'])))
    assert login.status_code==200,login.text

@pytest.mark.parametrize('failure',['null','missing','wrong_chain','wrong_environment','missing_source_pin','review_pin','issuer','source','context','alias_null'])
def test_selected_claim_fails_closed_without_creating_a_draft(guided,failure):
    g=guided
    if failure=='null':g.template['enrollmentActivation']=None
    elif failure=='missing':g.template.pop('enrollmentActivation')
    elif failure=='alias_null':g.template['enrollment_activation']=None;g.template.pop('enrollmentActivation')
    elif failure=='wrong_chain':g.settings.eip712_chain_id=11155111
    elif failure=='wrong_environment':g.template['enrollmentActivation']['environment']='production-alpha'
    elif failure=='missing_source_pin':g.settings.launch_source_evidence_sha256=None
    elif failure=='review_pin':g.settings.enrollment_deployment_review_sha256='f'*64
    elif failure=='issuer':g.settings.enrollment_permit_issuer_key_ref=''
    elif failure=='source':g.template['enrollmentActivation']['sourceShas']['customerWeb']='f'*40
    elif failure=='context':g.template['enrollmentActivation']['contextHash']='0x'+'ee'*32
    g.file.write_text(json.dumps(g.template));r=claim(g)
    assert r.status_code==409,r.text
    assert g.store.active() is None


def test_selected_claim_refuses_template_drift_and_legacy_downgrade(guided):
    g=guided;r=claim(g);assert r.status_code==200,r.text
    record=g.store.get(r.json()['ceremonyId'])
    assert launch._selected_template(g.settings,g.template,record['draft']['launchPlanTemplateSha256'],record=record)
    changed=copy.deepcopy(g.template);changed['faucetPuzzleHash']='0x'+'ef'*32
    g.file.write_text(json.dumps(changed));assert claim(g).status_code==409
    with pytest.raises(GenesisConflict,match='changed'):
        launch._plan_template_evidence(g.settings,record)
    g.settings.zkpassport_evm_chain_id=11155111;g.settings.launch_plan_template_path=str(g.file.parent/'absent.json')
    assert claim(g).status_code==409


def test_launch_action_domains_keep_legacy_default_and_selected_chain():
    kwargs=dict(ceremony_id='0x'+'11'*32,action_type='funding',action_id='0x'+'22'*32,payload_hash='0x'+'33'*32,expires_at=1900000000)
    assert launch._action_typed_data(**kwargs)['domain']['chainId']==11155111
    assert launch._action_typed_data(**kwargs,chain_id=84532)['domain']['chainId']==84532

@pytest.mark.asyncio
@pytest.mark.parametrize('failure',['','review_missing','failed_receipt','changed_template'])
async def test_guided_build_checks_selected_deployment_before_plan_builder(guided,deployment_setup,monkeypatch,failure):
    g=guided;s=deployment_setup;r=claim(g);assert r.status_code==200,r.text
    record=g.store.get(r.json()['ceremonyId']);record['state']='roster_frozen'
    store=SimpleNamespace(get=lambda key:record,funding_receipt=lambda key:dict(state='confirmed',plan=dict(fundingCoinIds=launch.PLACEHOLDER_FUNDING_IDS)))
    built=[]
    async def builder(ceremony_id,body,settings,passed_store):
        built.append(body);return {'ceremonyId':ceremony_id}
    monkeypatch.setattr(launch,'create_plan',builder)
    if failure=='review_missing':Path(g.settings.enrollment_deployment_review_path).unlink()
    if failure=='failed_receipt':next(iter(s.eth.receipts.values()))['status']=0
    if failure=='changed_template':g.template['faucetPuzzleHash']='0x'+'ff'*32;g.file.write_text(json.dumps(g.template))
    session=launch.LaunchSession(ceremony_id=record['ceremony_id'],slot=1,wallet='0x'+'aa'*20,setup=False,expires_at=1900000000)
    if failure:
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as error:await launch.build_guided_plan(g.settings,store,session)
        assert error.value.status_code==409;assert not built
    else:
        assert (await launch.build_guided_plan(g.settings,store,session))['ceremonyId']==g.active['deploymentId']
        assert built[0].enrollment_activation==g.active
