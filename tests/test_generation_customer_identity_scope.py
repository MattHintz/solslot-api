"""Request isolation; no credential, RPC, enrollment write or signature."""
import asyncio
from types import SimpleNamespace
import pytest
from solslot_api.generation_customer_identity_context import CurrentCustomerIdentityProfile
from solslot_api.generation_customer_identity_scope import current_identity_request,current_identity_scope
from tests.test_generation_customer_identity_context import profile


@pytest.fixture
def scope(monkeypatch):
    document,bindings=profile();pins=CurrentCustomerIdentityProfile.model_validate(document)
    import solslot_api.generation_customer_context as context
    monkeypatch.setattr(context,'current_customer_launch_bindings',lambda *args,**kwargs:bindings)
    settings=SimpleNamespace(network='testnet11',deployment_generation_id=pins.generation_id,
        alpha_writes_enabled=False,zkpassport_base_evm_rpc_url='https://example.invalid')
    settings.model_copy=lambda *,update:SimpleNamespace(**{**vars(settings),**update})
    now=[1000];launcher='0x'+'81'*32
    snapshot={'generationId':pins.generation_id,'registrationId':'0x'+'82'*32,'owner':'0x'+'83'*20,
        'authType':'evm','checkedAt':1000,'vault':{'identityVerified':False,'identityStatus':'FRESH_ID_REQUIRED'}}
    customers=SimpleNamespace(index=object(),current_vault_snapshot=lambda _:snapshot)
    return SimpleNamespace(settings=settings,pins=pins,launcher=launcher,customers=customers,snapshot=snapshot,now=now)


def enter(s,**kwargs):
    return current_identity_request(s.settings,s.pins,s.launcher,s.customers,runtime=object(),clock=lambda:s.now[0],**kwargs)


def test_current_profile_never_changes_global_legacy_flags_or_claims_genesis(scope):
    s=scope
    assert current_identity_scope() is None
    with enter(s) as selected:
        assert current_identity_scope(s.settings,s.launcher) is selected
        assert selected.settings.alpha_writes_enabled is False
        assert selected.settings.zkpassport_evm_chain_id==8453
        assert selected.enrollment_binding['generationId']==s.pins.generation_id
        assert 'genesisArtifactHash' not in selected.enrollment_binding
    assert current_identity_scope() is None and s.settings.alpha_writes_enabled is False


def test_stale_wrong_vault_or_generation_does_not_fall_back_to_legacy(scope):
    s=scope
    with enter(s):
        with pytest.raises(ValueError):current_identity_scope(s.settings,'0x'+'91'*32)
        with pytest.raises(ValueError):current_identity_scope(SimpleNamespace(network='testnet11',deployment_generation_id='0x'+'92'*32))
        s.now[0]=1061
        with pytest.raises(ValueError):current_identity_scope(s.settings,s.launcher)


def test_existing_legacy_or_foreign_receipt_is_not_a_current_enrollment(scope):
    s=scope
    with enter(s) as selected:
        good={'vaultLauncherId':s.launcher,'network':'testnet11','identityDeployment':selected.enrollment_binding,
            'bridgePolicyHash':s.pins.bridge_policy_hash}
        assert selected.require_record(good) is good
        with pytest.raises(ValueError):selected.require_record({**good,'identityDeployment':None})
        with pytest.raises(ValueError):selected.require_record({**good,'identityDeployment':{**selected.enrollment_binding,'generationId':'0x'+'91'*32}})
        with pytest.raises(ValueError):selected.require_record({**good,'enrollmentPermit':{'old':True}})


def test_reused_identity_primitives_cannot_load_or_relabel_legacy_genesis(scope,monkeypatch):
    s=scope
    import solslot_api.public_artifact as artifacts
    import solslot_api.zkpassport_enrollments as identity
    from fastapi import HTTPException
    def forbidden(*args):raise AssertionError('the current generation must never load a legacy genesis')
    monkeypatch.setattr(artifacts,'load_signed_public_artifact',forbidden)
    with enter(s) as selected:
        assert identity._settings() is selected.settings
        assert identity._active_pool_launcher_id(selected.settings)==s.pins.pool_launcher_id
        assert identity._active_bridge_policy_hash(selected.settings)==s.pins.bridge_policy_hash
        assert identity._active_artifact_hash(selected.settings)==s.pins.commitment
        assert identity._receipt_genesis_artifact_hash(selected.settings) is None
        with pytest.raises(HTTPException):identity._active_genesis_artifact(selected.settings)
        coin=s.pins.bridge_coins[0]
        record={'vaultLauncherId':s.launcher,'network':'testnet11','identityDeployment':selected.enrollment_binding,
            'bridgePolicyHash':s.pins.bridge_policy_hash,'bridgeCoinId':coin.coin_id,'bridgeParentId':coin.parent_id,'bridgeAmount':1}
        identity._require_enrollment_bridge_policy(selected.settings,record)
        assert identity._settings_for_enrollment(selected.settings,None,record)[0] is selected.settings
        with pytest.raises(ValueError):identity._settings_for_enrollment(selected.settings,None,{**record,'identityDeployment':None})


def test_confirmation_can_be_read_but_never_starts_another_enrollment(scope):
    s=scope;s.snapshot['vault']={'identityVerified':True,'identityStatus':'VERIFIED'}
    with pytest.raises(ValueError):
        with enter(s):pass
    with enter(s,require_fresh=False):assert current_identity_scope() is not None


@pytest.mark.asyncio
async def test_scope_follows_a_worker_thread_and_is_removed_after_error(scope):
    s=scope
    with pytest.raises(RuntimeError):
        with enter(s) as selected:
            assert await asyncio.to_thread(current_identity_scope) is selected
            raise RuntimeError('synthetic worker failure')
    assert current_identity_scope() is None
