from copy import deepcopy
from solslot_puzzles.property_metadata import commit_metadata
from types import SimpleNamespace
import pytest
from solslot_api.generation_operations import canonical
from solslot_api.generation_public_catalog import confirmed_catalog_entry

GEN='0x'+'11'*32


def fixture():
    metadata={'purpose':'TEST_ONLY','network':'testnet11','generationId':GEN,'revision':14,
        'collectionId':'TEST-EXAMPLE','title':'A reviewed edition — Testnet Edition','deedAllocation':[{'deedId':'A'},{'deedId':'B'}],
        'valuation':{'marketValueMinor':'155000000'},'unknownFields':[{'path':'/capital/debtBalanceMinor','status':'UNKNOWN'}]}
    root='0x'+commit_metadata(metadata).metadata_root.hex()
    source={'packageId':'0x'+'22'*32,'generationId':GEN,'request':{'revision':14,'metadataRoot':root}}
    receipt={'operationId':'0x'+'33'*32,'transactionId':'0x'+'44'*32,'confirmedHeight':123,
        'deedCount':2,'editionHash':'0x'+'55'*32,'metadataRoot':root,'inventory':[{'coinId':'1'},{'coinId':'2'}]}
    operation={'stage':'CONFIRMED','kind':'MINT_COLLECTION','generationId':GEN,
        'review':{'sourceReviewId':source['packageId']},'transactionId':receipt['transactionId'],'confirmedHeight':123}
    reviews=SimpleNamespace(for_collection=lambda _:source,inventory_status=lambda _:{'receipt':receipt})
    collections=SimpleNamespace(sealed_test_mint_snapshot=lambda _:{'canonicalMetadata':metadata,'metadataRoot':root},
        get=lambda _:pytest.fail('Never serialize private admin workspace'))
    journal=SimpleNamespace(status=lambda _:operation)
    return metadata,source,receipt,operation,dict(collections=collections,reviews=reviews,journal=journal,generation=GEN)


def test_automatic_projection_uses_canonical_economics_and_confirmed_issuance_only():
    metadata,source,receipt,operation,kwargs=fixture()
    value=confirmed_catalog_entry('TEST-EXAMPLE',**kwargs)
    assert value['canonicalMetadata']['valuation']['marketValueMinor']=='155000000'
    assert value['canonicalMetadata']['unknownFields'][0]['status']=='UNKNOWN'
    assert value['mint']['deedCount']==2
    assert value['sale']['availableDeeds'] is None
    assert value['sale']['status']=='UNAVAILABLE'  # A mint is not permission to sell.
    assert not {'funding','signatures','pricing','auditEvents','reviews','comments'} & value.keys()
    assert not {'operationId','request','funding'} & value['mint'].keys()


def test_unconfirmed_editions_are_not_an_available_listing():
    *_,kwargs=fixture();kwargs['reviews'].inventory_status=lambda _:{'receipt':None}
    assert confirmed_catalog_entry('TEST-EXAMPLE',**kwargs) is None


@pytest.mark.parametrize('change', ['generation','operation-generation','stage','height','source','metadata','revision','purpose','count'])
def test_stale_or_inconsistent_mint_metadata_cannot_become_public_inventory(change):
    metadata,source,receipt,operation,kwargs=fixture()
    if change=='generation':source['generationId']='0x'+'99'*32
    if change=='operation-generation':operation['generationId']='0x'+'99'*32
    if change=='stage':operation['stage']='SUBMITTED'
    if change=='height':operation['confirmedHeight']=124
    if change=='source':operation['review']['sourceReviewId']='0x'+'99'*32
    if change=='metadata':metadata['valuation']['marketValueMinor']='75000000'
    if change=='revision':source['request']['revision']=15
    if change=='purpose':metadata['purpose']='PRODUCTION'
    if change=='count':receipt['deedCount']=3
    with pytest.raises(ValueError):confirmed_catalog_entry('TEST-EXAMPLE',**kwargs)


def test_public_route_is_read_only_and_unavailable_evidence_is_not_an_empty_catalog(monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    import solslot_api.generation_public_catalog as module
    from solslot_api.config import get_settings
    metadata,source,receipt,operation,kwargs=fixture()
    state={'status':'READY','generationId':GEN,'lastCheckedAt':123}
    kwargs['reviews'].generation_id=GEN
    kwargs['reviews'].confirmed_collection_ids=lambda:['TEST-EXAMPLE']
    kwargs['journal'].generation_id=GEN
    app=FastAPI();app.include_router(module.router)
    app.state.generation_mint_reviews=kwargs['reviews'];app.state.generation_operations=kwargs['journal']
    app.state.generation_index=SimpleNamespace(verified=True,store=SimpleNamespace(status=lambda *a,**kw:state))
    monkeypatch.setattr(module,'get_collection_store',lambda _:kwargs['collections'])
    app.dependency_overrides[get_settings]=lambda:SimpleNamespace(network='testnet11',deployment_generation_id=GEN)
    client=TestClient(app)
    response=client.get('/public/generation/collections')
    assert response.status_code==200
    assert response.json()['collections'][0]['mint']['deedCount']==2
    assert response.headers['cache-control']=='public, max-age=5, must-revalidate'
    assert client.post('/public/generation/collections').status_code==405
    state['status']='STALE'
    response=client.get('/public/generation/collections')
    assert response.status_code==503
    assert response.json()['detail']['code']=='PUBLIC_GENERATION_EVIDENCE_UNAVAILABLE'
