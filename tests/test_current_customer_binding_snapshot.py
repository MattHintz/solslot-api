"""A snapshot uses one validated authority reading, never a second profile read."""
import hashlib
import json
from types import SimpleNamespace

import pytest

from solslot_api import generation_customer_runtime as module


def test_snapshot_binds_the_validated_profile_when_later_profile_is_unavailable(monkeypatch):
    generation='0x'+'01'*32
    launcher='0x'+'02'*32
    identity='0x'+'03'*32
    bindings=SimpleNamespace(preparation_manifest=bytes.fromhex('04'*32),pool_launcher=bytes.fromhex('05'*32),
        bridge_policy=bytes.fromhex('06'*32),vault_module=bytes.fromhex('07'*32))
    native={'generationId':generation,'vaultLauncherId':launcher,'identityVerified':False,
        'identityStatus':'FRESH_ID_REQUIRED'}
    digest=hashlib.sha256(json.dumps(native,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    consent=SimpleNamespace(owner='0x'+'08'*20,auth_type='evm',vault_launcher_id=bytes.fromhex('02'*32))
    signed=SimpleNamespace(verified_owner=lambda signature,at:(bytes.fromhex('09'*33),None))
    store=SimpleNamespace(generation_id=generation,registered_vault=lambda _: (identity,consent),
        vault_observation=lambda _: {'checkedAt':1000,'vault':native},
        authorized_material=lambda _: (signed,'synthetic-signature',1000))
    runtime=module.GenerationCustomerRuntime.__new__(module.GenerationCustomerRuntime)
    runtime.settings=SimpleNamespace();runtime.index=object();runtime.store=store;runtime.clock=lambda:1000
    runtime.verified_observations={identity:(1000,digest)}
    runtime.profile=lambda: {'status':'UNAVAILABLE'}
    monkeypatch.setattr(module,'current_customer_launch_bindings',lambda *a,**kw:bindings)
    monkeypatch.setattr(module,'puzzle_for_p2_vault',lambda _:SimpleNamespace(get_tree_hash=lambda:bytes.fromhex('0a'*32)))
    result=runtime.current_vault_snapshot(launcher)
    assert result['profileHash']==module.customer_binding_profile(generation,bindings)[1]
    assert result['vault']['identityVerified'] is False
    runtime.verified_observations[identity]=(1000,'invalid')
    with pytest.raises(ValueError,match='CUSTODY_OBSERVATION_UNAVAILABLE'):
        runtime.current_vault_snapshot(launcher)
