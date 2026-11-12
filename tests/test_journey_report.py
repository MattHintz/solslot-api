import importlib.util
from pathlib import Path
from solslot_api.alpha_observability import AlphaObservabilityStore,JourneyBatch,JourneyEvent
from tests.test_journey_observability import event

spec=importlib.util.spec_from_file_location('journey_report',Path(__file__).parents[1]/'ops/user-journey-repair-AE197/journey-report.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


def test_report_excludes_synthetic_and_private_identifiers():
    store=AlphaObservabilityStore(':memory:')
    payload=event();payload['phase']='failed';payload['latency_ms']=1234
    store.journey(JourneyBatch(events=[JourneyEvent(**payload)]),'private-ip')
    synthetic=event();synthetic['actor']='synthetic'
    store.journey(JourneyBatch(events=[JourneyEvent(**synthetic)]),'private-ip')
    import time,json
    now=int(time.time())
    report=module.summarize(store._conn,now-3600,now)
    assert report['received_events']==1 and report['people_count'] is None
    assert report['groups'][0]['p95_latency_ms']==1234
    assert payload['flow_id'] not in json.dumps(report) and 'private-ip' not in json.dumps(report)


def test_report_ignores_legacy_free_text_and_closes_wallet_wait_on_confirmation():
    import time, json
    from solslot_api.alpha_observability import AlphaTelemetryRequest
    store=AlphaObservabilityStore(':memory:')
    legacy=AlphaTelemetryRequest(event='JOURNEY_SIGN_IN',correlation_id='private-name',release_sha='a'*40,artifact_hash='0x'+'0'*64,details={'screen':'PrivateName','diagnostics_revision':'AE197'})
    store.telemetry(legacy,'private-ip')
    waiting=event();waiting.update(action='wallet_prompt',stage='awaiting_wallet',phase='waiting')
    store.journey(JourneyBatch(events=[JourneyEvent(**waiting)]),'private-ip')
    complete=event();complete.update(flow_id=waiting['flow_id'],action='verify_id',stage='stamp',phase='completed')
    store.journey(JourneyBatch(events=[JourneyEvent(**complete)]),'private-ip')
    now=int(time.time())
    store._conn.execute('UPDATE alpha_telemetry_events SET occurred_at=?',(now-120,));store._conn.commit()
    report=module.summarize(store._conn,now-3600,now)
    assert report['received_events']==2 and report['waits_without_terminal_event_over_60s']==[]
    assert 'PrivateName' not in json.dumps(report) and 'private-name' not in json.dumps(report)
