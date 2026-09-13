"""Real genesis control flow; synthetic RPC, authority review and funding only."""
import copy
import inspect
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from solslot_api import genesis as genesis
from solslot_api.genesis_store import GenesisConflict
from solslot_api.validator_quorum import ValidatorQuorumError
from tests.test_genesis_permit_evm import deployment_setup, verify
from tests.test_genesis_api import _direct_broadcast_fixture


@pytest.mark.asyncio
async def test_fresh_preparation_passes_exact_activation_and_retains_approval(deployment_setup,monkeypatch):
    s=deployment_setup
    s.record['plan_hash']=s.plan['planHash'];s.record['plan_expires_at']=int(time.time())+3600
    authority={'fileSha256':'0x'+'ab'*32}
    monkeypatch.setattr(genesis,'_authority_preflight',AsyncMock(return_value=authority))
    # Funding and signatures are tested by existing ceremony/consensus suites.
    s.record['plan_input']['faucetPuzzleHash']='0x'+'de'*32
    monkeypatch.setattr(genesis,'_faucet',lambda:SimpleNamespace(address_puzzle_hash=bytes.fromhex('de'*32),master_sk=b'synthetic'))
    monkeypatch.setattr(genesis,'_coinset',lambda:object())
    monkeypatch.setattr(genesis,'_live_funding',AsyncMock(return_value={}))
    bundle=dict(plan=s.plan,planHash=s.plan['planHash'],spendBundleId='0x'+'ef'*32)
    monkeypatch.setattr(genesis,'_run_worker',AsyncMock(return_value=bundle))
    health=AsyncMock(return_value=())
    monkeypatch.setattr(genesis,'probe_validator_health',health)
    monkeypatch.setattr(genesis,'_validate_audit_approval',lambda *_:{'approved':'synthetic-control'})
    plan,result,approval,_=await genesis._prepare_bundle(s.settings,s.record)
    assert plan==s.plan and result==bundle
    assert health.await_args.kwargs['expected_enrollment_activation']==s.active
    assert approval['enrollmentDeploymentReview']['receipt']==s.review
    assert approval['evmManifestArtifactHash']==s.deployment['artifactHash']
    assert approval['authorityV3Review']==authority


@pytest.mark.asyncio
@pytest.mark.parametrize('failure',['health','deployment','authority','review_drift'])
async def test_selected_push_preflight_does_not_rebuild_and_rejects_drift(deployment_setup,monkeypatch,failure):
    s=deployment_setup;evidence=verify(s);authority={'fileSha256':'0x'+'ab'*32}
    approval=dict(authorityV3Review=authority,enrollmentDeploymentReview=evidence['enrollmentDeploymentReview'],evmManifestArtifactHash=evidence['manifestArtifactHash'])
    monkeypatch.setattr(genesis,'_authority_preflight',AsyncMock(return_value=authority))
    monkeypatch.setattr(genesis,'probe_validator_health',AsyncMock(return_value=()))
    monkeypatch.setattr(genesis,'_run_worker',AsyncMock(side_effect=AssertionError('must not rebuild a reservation')))
    if failure=='health':monkeypatch.setattr(genesis,'probe_validator_health',AsyncMock(side_effect=ValidatorQuorumError('unhealthy')))
    elif failure=='deployment':s.eth.chain_id=1
    elif failure=='authority':approval['authorityV3Review']={'fileSha256':'different'}
    else:approval['enrollmentDeploymentReview']={}
    with pytest.raises(GenesisConflict):await genesis._selected_push_preflight(s.settings,s.record,approval)
    genesis._run_worker.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize('replay',[False,True])
@pytest.mark.parametrize('failure',[False,True])
async def test_selected_push_callback_runs_inside_submitter_and_retains_exact_reservation(tmp_path,monkeypatch,replay,failure):
    store,settings,cid,protocol_bundle,prepared_bundle,Prepared=_direct_broadcast_fixture(tmp_path,monkeypatch,'selected-boundary')
    record=store.get(cid)
    # The control-flow test sets selection in the durable plan; cryptographic
    # activation and real RPC validation are exercised in deployment_setup tests.
    record['plan']['enrollmentActivation']={'synthetic':'selected'}
    with store._transaction() as db:
        db.execute('UPDATE ceremonies SET plan_json=? WHERE ceremony_id=?',(json.dumps(record['plan']),cid))
    gate=genesis._ceremony_broadcast_gate_authorization(settings,store,cid)
    prepared=Prepared();events=[]
    if replay:
        store.reserve_broadcast(cid,expected_plan_hash=record['plan_hash'],spend_bundle_id=prepared.spend_bundle_id,
            spend_bundle=prepared_bundle,fee_coin_id=prepared.fee_coin_id,fee_mojos=prepared.fee_mojos,
            ceremony_evidence={'auditApproval':{'original':True},'authorityV3ReviewBase64':'e30K','validatorHealth':{}},gate_authorization=gate)
    before=copy.deepcopy(store.get(cid).get('broadcast'))
    async def recheck(_settings,current,approval):
        events.append('recheck')
        assert current['plan']==record['plan']
        if replay:assert approval=={'original':True}
        if failure:raise GenesisConflict('selected deployment changed')
    monkeypatch.setattr(genesis,'_selected_push_preflight',recheck)
    monkeypatch.setattr(genesis,'_materialize_broadcast_evidence',lambda **kw:events.append('materialize'))
    class Submitter:
        async def submit(self,bundle,*,before_push,selection_purpose):
            events.append('submit-entered');assert bundle==protocol_bundle
            callback=before_push(prepared);assert inspect.isawaitable(callback);await callback
            events.append('push')
            assert store.get(cid)['broadcast']['spendBundle']==prepared_bundle
            return prepared.to_json()
        async def reconcile_reserved(self,reservation,*,before_push):
            events.append('reconcile-entered');assert reservation['spendBundle']==prepared_bundle
            callback=before_push();assert inspect.isawaitable(callback);await callback
            events.append('push')
            return prepared.to_json()
    request=SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(protocol_submitter=Submitter())))
    if failure:
        with pytest.raises(GenesisConflict,match='changed'):
            await genesis._broadcast_ceremony(cid,request,settings,store,gate_authorization=gate)
        assert 'push' not in events and store.get(cid).get('broadcast')==before
    else:
        await genesis._broadcast_ceremony(cid,request,settings,store,gate_authorization=gate)
        assert events[:3]==['reconcile-entered' if replay else 'submit-entered','recheck','push']
        assert store.get(cid)['broadcast']['spendBundle']==prepared_bundle
