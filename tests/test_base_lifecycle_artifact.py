"""Actual two-admin signed release upgrade with immutable original capability."""
from copy import deepcopy
from types import SimpleNamespace
import json

import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data
from solslot_puzzles.artifact_schema_v4 import artifact_hash, artifact_signing_typed_data, _rebuild_plan, _projection
from solslot_puzzles import load_puzzle
from solslot_api.base_lifecycle_claims import base_lifecycle_activation, digest
from solslot_api.purchase_admission import ADMISSION_POLICY
from solslot_api.public_artifact import load_signed_public_artifact, PublicArtifactError
from tests.test_public_artifact import _signed_artifact, _settings
from tests.test_base_lifecycle import activate


def resign(artifact,accounts):
    artifact['artifactHash']=artifact_hash(artifact)
    typed=artifact_signing_typed_data(artifact)
    artifact['signatures']=[dict(adminIndex=i,compressedPubkey=artifact['adminAuthority']['compressedPubkeys'][i],
        signature='0x'+bytes(accounts[i].sign_message(encode_typed_data(full_message=typed)).signature).hex()) for i in (0,2)]


def runtime_settings(tmp_path, artifact):
    path=tmp_path/('release-'+artifact['artifactHash']+'.json')
    path.write_text(json.dumps(dict(schemaVersion=2,protocolVersion='solslot-v2',
        api_commit=artifact['sourceShas']['api'],protocol_commit=artifact['sourceShas']['protocol'],
        built_at_utc='2026-09-14T00:00:00Z',package_name='solslot_api',app_module='solslot_api.app:app')))
    return _settings(tmp_path,artifact,runtime_environment='staging',release_metadata_path=str(path))


def upgraded_artifact():
    accounts=[Account.create() for _ in range(3)]
    a=_signed_artifact(accounts=accounts)
    a['inventoryActivation']=dict(schema='solslot.inventory-activation.v1',network='testnet11',environment='staging-alpha',
        deploymentId=a['ceremony']['ceremonyId'],inventoryVersion=2,adapterVersion=1,sourceShas=a['sourceShas'],reviewEvidenceSha256='ab'*32,
        availableModuleHash='0x'+load_puzzle('mint_offer_inventory_available_v2.clsp').get_tree_hash().hex(),
        reservedModuleHash='0x'+load_puzzle('mint_offer_delegate_v5.clsp').get_tree_hash().hex())
    inv=a['inventoryActivation']
    cap=dict(schema='solslot.base-inventory-hold.v1',environment='staging-alpha',network='testnet11',
        deploymentId=inv['deploymentId'],sourceShas=a['sourceShas'],inventoryVersion=2,adapterVersion=1,
        validatorLedgerVersion=14,chainId=84532,minConfirmations=3,spoke='0x'+'12'*20,token='0x'+'13'*20,sourceChainSelector=12345,
        availableModuleHash=inv['availableModuleHash'],reservedModuleHash=inv['reservedModuleHash'],paymentConfirmationEnabled=False,
        holdPolicy='base-prepayment-exclusion-v1',**ADMISSION_POLICY)
    cap['releaseIdentity']=digest(cap);cap['reviewEvidenceSha256']='bc'*32
    a['baseInventoryHold']=cap
    resign(a,accounts)
    old=deepcopy(a)
    c=SimpleNamespace(genesis=a,claim=SimpleNamespace(activation=cap))
    activate(c)
    resign(a,accounts)
    return old,a,accounts


def test_signed_upgrade_preserves_onchain_identity_and_rejects_unsigned_widening(tmp_path):
    old,new,accounts=upgraded_artifact()
    assert new['artifactHash']!=old['artifactHash'] and new['genesisPlan']==old['genesisPlan']
    assert new['launcherIds']==old['launcherIds'] and new['validatorSet']==old['validatorSet']
    # File loader verifies canonical plan and real secp256k1 committee signatures.
    loaded=load_signed_public_artifact(runtime_settings(tmp_path,new))
    assert base_lifecycle_activation(loaded,'staging-alpha')['holdOrigins'][0]['artifactHash']==old['artifactHash']
    changed=deepcopy(new);changed['baseReservationLifecycle']['historicalDirectPaymentSha256']=['ab'*32]
    with pytest.raises(PublicArtifactError):load_signed_public_artifact(runtime_settings(tmp_path,changed))
    # Even freshly signed malformed capability cannot invent changed deployment.
    changed=deepcopy(new);changed['baseReservationLifecycle']['customerPaymentEnabled']=True;resign(changed,accounts)
    with pytest.raises(ValueError):base_lifecycle_activation(changed,'staging-alpha')
    # Rebuilding a source-aware genesis under the OLD confirmation would change
    # actual authority custody outputs. Even new committee signatures cannot
    # silently import old holds into that impossible deployment projection.
    changed=deepcopy(new);changed['sourceShas']={**new['sourceShas'],'api':'dc'*20}
    changed['genesisPlan']['sourceShas']=changed['sourceShas']
    plan=_rebuild_plan(changed);changed['genesisPlan']=plan.canonical_payload()
    changed['ceremony']['planHash']=changed['genesisPlan']['planHash'];changed.update(_projection(plan))
    changed['inventoryActivation']['sourceShas']=changed['sourceShas']
    cap=changed['baseReservationLifecycle'];cap['sourceShas']=changed['sourceShas']
    cap['releaseIdentity']=digest({k:v for k,v in cap.items() if k not in ('releaseIdentity','reviewEvidenceSha256')})
    resign(changed,accounts)
    assert changed['puzzleHashes']['adminAuthorityFull']!=old['puzzleHashes']['adminAuthorityFull']
    with pytest.raises(PublicArtifactError):load_signed_public_artifact(runtime_settings(tmp_path,changed))
