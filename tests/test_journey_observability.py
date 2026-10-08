import json
import logging
import uuid
import pytest
from pydantic import ValidationError
from solslot_api.alpha_observability import JourneyEvent, JourneyBatch, AlphaObservabilityStore, IntakeLimitExceeded
from solslot_api.journey_logging import JourneyRequestLogging


def event(**changes):
    return dict(event_id=str(uuid.uuid4()),flow_id=str(uuid.uuid4()),sequence=1,release_sha='a'*40,
        source='customer',actor='visitor',screen='identity',action='wallet_prompt',stage='awaiting_wallet',
        phase='waiting',wallet='sage',network='testnet11',error_code='none',**changes)

@pytest.mark.parametrize('field,value', [('address','0x'+ '1'*40),('url','https://example.test/?token=secret'),('cookie','secret'),('signature','secret'),('form','document')])
def test_sensitive_fields_rejected(field,value):
    payload=event();payload[field]=value
    with pytest.raises(ValidationError):JourneyEvent(**payload)

@pytest.mark.parametrize('field,value',[('screen','/vault/0x123'),('error_code','secret failure'),('release_sha','a'*40+'\n'),('sequence',201)])
def test_arbitrary_identifiers_and_unbounded_fields_rejected(field,value):
    payload=event();payload[field]=value
    with pytest.raises(ValidationError):JourneyEvent(**payload)

def test_lost_response_retries_are_not_counted_twice():
    store=AlphaObservabilityStore(':memory:'); payload=JourneyBatch(events=[JourneyEvent(**event())])
    store.journey(payload,'203.0.113.9');store.journey(payload,'203.0.113.9')
    assert store.aggregate_counts()['telemetry_event_count']==1
    row=store._conn.execute('SELECT * FROM alpha_telemetry_events').fetchone()
    assert '203.0.113.9' not in json.dumps(dict(row))
    assert json.loads(row['details_json'])['stage']=='awaiting_wallet'

def test_batch_capacity_failure_is_atomic(monkeypatch):
    import solslot_api.alpha_observability as module
    monkeypatch.setattr(module,'_MAX_TELEMETRY_ROWS',1)
    store=AlphaObservabilityStore(':memory:')
    with pytest.raises(IntakeLimitExceeded):store.journey(JourneyBatch(events=[JourneyEvent(**event()),JourneyEvent(**event())]),'203.0.113.9')
    assert store.aggregate_counts()['telemetry_event_count']==0

@pytest.mark.asyncio
async def test_request_log_redacts_private_route_and_correlates_error(caplog):
    async def app(scope,receive,send):
        await send({'type':'http.response.start','status':503,'headers':[]})
        await send({'type':'http.response.body','body':b'private body'})
    messages=[]
    async def send(message): messages.append(message)
    flow=str(uuid.uuid4())
    scope={'type':'http','path':'/zkpassport/enrollments/secret-vault/stamp/submit','method':'POST','headers':[(b'x-solslot-flow',flow.encode()),(b'cookie',b'secret')]}
    with caplog.at_level(logging.INFO,logger='solslot.journey'):
        await JourneyRequestLogging(app)(scope,None,send)
    assert 'operation=identity_stamp' in caplog.text and 'status=503' in caplog.text and flow in caplog.text
    assert 'secret' not in caplog.text and 'private body' not in caplog.text
    assert any(k==b'x-solslot-request-id' for k,v in messages[0]['headers'])

@pytest.mark.asyncio
async def test_expected_session_discovery_is_not_a_user_error(caplog):
    async def app(scope,receive,send):await send({'type':'http.response.start','status':401,'headers':[]})
    async def send(message):pass
    with caplog.at_level(logging.INFO,logger='solslot.journey'):
        await JourneyRequestLogging(app)({'type':'http','path':'/zkpassport/enrollments/secret/session','method':'GET'},None,send)
    assert 'journey_api' not in caplog.text

@pytest.mark.asyncio
async def test_preserved_outer_guard_and_base_middleware_issue_only_one_receipt(caplog):
    async def app(scope,receive,send): await send({'type':'http.response.start','status':503,'headers':[]})
    messages=[]
    async def send(message):messages.append(message)
    with caplog.at_level(logging.INFO,logger='solslot.journey'):
        await JourneyRequestLogging(JourneyRequestLogging(app))({'type':'http','path':'/admin/collections/private','method':'POST'},None,send)
    assert caplog.text.count('journey_api')==1
    assert sum(k==b'x-solslot-request-id' for k,v in messages[0]['headers'])==1


def test_public_intake_accepts_bounded_diagnostics_and_rejects_free_text():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from solslot_api.alpha_observability import router,get_alpha_observability_store
    from solslot_api.config import get_settings,Settings
    app=FastAPI();app.include_router(router)
    store=AlphaObservabilityStore(':memory:')
    app.dependency_overrides[get_alpha_observability_store]=lambda:store
    app.dependency_overrides[get_settings]=lambda:Settings()
    client=TestClient(app)
    payload={'events':[event()]}
    assert client.post('/alpha/journey-events',json=payload).status_code==202
    payload['events'][0]['cookie']='never store this'
    assert client.post('/alpha/journey-events',json=payload).status_code==422
    assert store.aggregate_counts()['telemetry_event_count']==1
