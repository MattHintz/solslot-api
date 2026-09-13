import pytest
from fastapi import HTTPException
from solslot_api import zkpassport_enrollments as enroll
from solslot_api.credential_ledger import get_credential_ledger
from tests import test_zkpassport_enrollments as journeys

@pytest.mark.parametrize('journey', [journeys.test_evm_proof_builds_and_confirms_atomic_chia_vault_stamp,
    journeys.test_bls_proof_requires_wallet_signature_for_atomic_chia_vault_stamp], ids=['evm','bls'])
@pytest.mark.parametrize('change', ['event_removed','artifact_changed','emitter_changed'])
def test_retained_resume_revalidates_original_evidence(monkeypatch, tmp_path, journey, change):
    original = enroll._push_chia_stamp_and_mark_pending
    intercepted = False
    async def intercept(settings, **kwargs):
        nonlocal intercepted
        if intercepted: return await original(settings, **kwargs)
        intercepted = True
        class Timeout:
            async def push_tx(self, _): raise TimeoutError('synthetic ambiguous dispatch')
        with pytest.raises(HTTPException) as first:
            await original(settings, **{**kwargs,'coinset':Timeout()})
        assert first.value.status_code == 502
        retained = get_credential_ledger(settings).get_stamp_attempt(kwargs['key'])
        with monkeypatch.context() as changed:
            if change == 'event_removed':
                def removed(*_, **__): raise HTTPException(status_code=409,detail='synthetic removed EVM event')
                changed.setattr(enroll, '_fetch_verified_evm_attestation', removed)
            elif change == 'artifact_changed':
                changed.setattr(enroll, '_active_artifact_hash', lambda *_:'0x'+'fe'*32)
            else:
                changed.setattr(enroll, '_active_emitter_address', lambda *_:'0x'+'fe'*20)
            with pytest.raises(HTTPException) as error:
                await enroll.submit_evm_chia_stamp(kwargs['key'], enroll.SubmitChiaStampRequest(signature='0x00'),
                    journeys._request(kwargs['coinset']))
            assert error.value.status_code == 409
        after = get_credential_ledger(settings).get_stamp_attempt(kwargs['key'])
        assert after == retained
        return await enroll.submit_evm_chia_stamp(kwargs['key'], enroll.SubmitChiaStampRequest(signature='0x00'),
            journeys._request(kwargs['coinset']))
    monkeypatch.setattr(enroll, '_push_chia_stamp_and_mark_pending', intercept)
    journey(monkeypatch,tmp_path)
