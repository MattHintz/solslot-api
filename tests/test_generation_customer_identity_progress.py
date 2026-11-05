import pytest
from solslot_api.generation_customer_identity_progress import saved_stamp_progress

PENDING={'status':'stamp_pending'}
SAVED={'bundle_hex':'synthetic-retained-bundle','dispatch_status':'not_submitted','dispatch_count':0}


def test_saved_authorization_does_not_imply_a_broadcast():
    assert saved_stamp_progress(PENDING,SAVED,None)=={
        'state':'READY_TO_RESUME','broadcastState':'NOT_SENT','resumeAvailable':True}


@pytest.mark.parametrize('status',['dispatching','uncertain','rejected','superseded','unknown'])
def test_ambiguous_funded_attempt_is_reconciled_and_never_marked_confirmed(status):
    assert saved_stamp_progress(PENDING,SAVED,{'status':status})=={
        'state':'RECONCILING','broadcastState':'UNKNOWN','resumeAvailable':False}


@pytest.mark.parametrize('status',['mempool','confirmed'])
def test_funding_observation_never_grants_verified_identity(status):
    assert saved_stamp_progress(PENDING,SAVED,{'status':status})=={
        'state':'NETWORK_CONFIRMATION','broadcastState':'SENT','resumeAvailable':False}


def test_prepared_candidate_still_requires_primary_reconciliation_on_resume():
    assert saved_stamp_progress(PENDING,SAVED,{'status':'prepared'})=={
        'state':'READY_TO_RESUME','broadcastState':'UNKNOWN','resumeAvailable':True}


@pytest.mark.parametrize('status',['reserved','evm_confirmed','chia_confirmed','receipt_syncing'])
def test_other_stages_have_no_submission_hint(status):
    assert saved_stamp_progress({'status':status},SAVED,None) is None


def test_missing_or_inconsistent_saved_attempt_does_not_offer_retry():
    for attempt in (None,{},dict(SAVED,bundle_hex=None),dict(SAVED,dispatch_count=1)):
        assert saved_stamp_progress(PENDING,attempt,None)['resumeAvailable'] is False
