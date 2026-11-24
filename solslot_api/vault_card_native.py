"""Prepare one release-authorized order from confirmed issuance and stamped native custody."""
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from typing import Annotated, Literal

from chia.wallet.util.compute_additions import compute_additions
from chia_rs.sized_bytes import bytes32
from pydantic import BaseModel, ConfigDict, Field, model_validator
from solslot_puzzles.payment_artifacts_v3 import build_purchase_batch_v1, purchase_batch_to_json
from solslot_puzzles.vault_driver import puzzle_hash_for_p2_vault

from .bootstrap_manifest import content_hash
from .generation_chain_evidence import current_evidence_unchanged
from .generation_coin_evidence import read_confirmed_coin
from .generation_customer_context import customer_bindings_from_evidence
from .generation_customer_inventory import h, resolve_current_primary_inventory
from .generation_customer_stripe_order import original_reservation, prove_receipt_shape, stripe_artifact
from .generation_customer_vault import resolve_native_identity_vault
from .generation_preparation import read_generation_preparation
from .generation_index import load_generation_read_anchor
from .generation_registry_evidence import _spend
from .generation_sols_batch_execution import unspent
from .vault_card_store import VaultCardRecord

Hash = Annotated[str, Field(pattern=r'^0x[0-9a-f]{64}$')]


class VaultCardRelease(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
    schemaVersion: Literal['solslot.vault-card-release.v2']
    network: Literal['testnet11', 'mainnet']
    mode: Literal['test', 'live']
    accountId: Annotated[str, Field(pattern=r'^acct_[A-Za-z0-9]+$')]
    generationId: Hash
    generationAnchorHash: Hash
    technologyFeePuzzleHash: Hash
    primaryProceedsPuzzleHash: Hash
    collectionId: Hash
    editionId: Hash
    metadataRoot: Hash
    vaultLauncherId: Hash
    deedLauncherIds: tuple[Hash, Hash]
    originalCoinIds: tuple[Hash, Hash]
    authorizationNonce: Hash
    batchNonce: Hash
    signerIndices: tuple[int, int]
    validFrom: int
    expiresAt: int
    credentialPolicyVersion: int = Field(ge=2)
    maximumFeePerStageMojos: int = Field(gt=0,lt=2**64,strict=True)
    maximumTotalFeeMojos: int = Field(gt=0,lt=2**64,strict=True)

    @model_validator(mode='after')
    def check(self):
        hashes = (self.generationId,self.generationAnchorHash,self.technologyFeePuzzleHash,self.primaryProceedsPuzzleHash,self.collectionId,self.editionId,self.metadataRoot,
                  self.vaultLauncherId,self.authorizationNonce,self.batchNonce,*self.originalCoinIds,*self.deedLauncherIds)
        if (any(int(v,16)==0 for v in hashes) or len(set(self.originalCoinIds)) != 2
                or tuple(sorted(set(self.deedLauncherIds))) != self.deedLauncherIds
                or self.signerIndices not in ((0,1),(0,2),(1,2))
                or ('test' if self.network=='testnet11' else 'live') != self.mode
                or self.maximumTotalFeeMojos < self.maximumFeePerStageMojos*5
                or not 0 < self.validFrom < self.expiresAt):
            raise ValueError('Invalid vault card scope')
        return self


@dataclass(frozen=True)
class VaultCardEvidence:
    order: VaultCardRecord
    items: tuple
    vault: object
    transitions: tuple
    inventory: object


class VaultCardNative:
    def __init__(self,settings,scope,release_id):
        self.settings,self.scope,self.release_id=settings,scope,release_id

    @classmethod
    def configured(cls, settings):
        with os.fdopen(os.open(settings.vault_card_release_file,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as f:
            info=os.fstat(f.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0,os.geteuid())
                    or info.st_mode & 0o022 or not 0 < info.st_size <= 16384):
                raise ValueError('Protected card release required')
            raw=f.read(16385)
        digest=h(hashlib.sha256(raw).digest())
        if digest != settings.vault_card_release_sha256:
            raise ValueError('Vault card release digest differs')
        scope=VaultCardRelease.model_validate_json(raw)
        native=cls(settings,scope,digest)
        native.check_profile()
        return native

    def check_profile(self):
        s=self.scope
        if ((s.network,s.mode,s.accountId,s.generationId,s.generationAnchorHash)
                != (self.settings.network,self.settings.stripe_mode,self.settings.stripe_account_id,
                    self.settings.deployment_generation_id,self.settings.generation_chain_anchor_hash)):
            raise ValueError('Vault card release belongs to another deployment')
        version=getattr(self.settings,'zkpassport_policy_version',getattr(self.settings,'credential_policy_version',None))
        if version!=s.credentialPolicyVersion:
            raise ValueError('Current credential policy changed')

    async def reconstruct(self,customers,snapshot):
        return await self.from_primary(customers.index.anchor,customers.provider,snapshot)

    async def from_primary(self,anchor,provider,snapshot=None):
        self.check_profile()
        s=self.scope
        if load_generation_read_anchor(self.settings)!=anchor:
            raise ValueError('Current generation launch anchor changed')
        if (await provider.get_network_info_primary()).get('network_name')!=s.network:
            raise ValueError('Primary node network differs')
        b=bytes32.from_hexstr
        inventory=await resolve_current_primary_inventory(settings=self.settings,anchor=anchor,provider=provider,
            collection=b(s.collectionId),edition_hash=b(s.editionId),metadata_root=b(s.metadataRoot))
        bindings=customer_bindings_from_evidence(read_generation_preparation(self.settings),anchor,inventory.evidence)
        vault=await resolve_native_identity_vault(bindings=bindings,launcher=b(s.vaultLauncherId),provider=provider)
        _,values=vault.inner.uncurry()
        _,owner_key,kind,*_=values.as_iter()
        owner_key,kind=h(owner_key.as_atom()),kind.as_int()
        if (not vault.identity_verified or h(vault.generation)!=s.generationId or h(vault.launcher)!=s.vaultLauncherId
                or vault.public()['network']!=s.network or kind not in (1,3)):
            raise ValueError('Confirmed vault differs')
        if snapshot is not None and (snapshot['vault']!=vault.public() or snapshot['network']!=s.network
                or snapshot['generationId']!=s.generationId or snapshot['ownerPublicKey'].lower()!=owner_key
                or {'evm':3,'chia_bls':1}.get(snapshot['authType'])!=kind
                or snapshot['p2VaultPuzzleHash']!=h(puzzle_hash_for_p2_vault(vault.launcher))):
            raise ValueError('Receiving vault registration changed')
        originals={h(item.original.terms.deed_launcher_id):item.original for item in inventory.items}
        items=tuple(originals[k] for k in s.deedLauncherIds)
        transitions=[]
        for item,original in zip(items,s.originalCoinIds,strict=True):
            t=item.terms
            if (t.network!=s.network or h(t.collection_id)!=s.collectionId or h(t.metadata_root)!=s.metadataRoot
                    or h(t.metadata_anchor_id)!=s.editionId or h(item.coin.name())!=original
                    or h(t.protocol_treasury_puzzle_hash)!=s.technologyFeePuzzleHash or h(t.protocol_puzhash)!=s.primaryProceedsPuzzleHash
                    or t.validator_pubkeys!=items[0].terms.validator_pubkeys):
                raise ValueError('Original deeds differ from release')
            artifact=stripe_artifact(t,vault.launcher,vault.root,b(s.authorizationNonce),s.expiresAt,s.expiresAt)
            transition=original_reservation(item,artifact,s.signerIndices)
            if compute_additions(transition.spend)!=[transition.reserved_coin]:
                raise ValueError('Reserved successor differs')
            transitions.append(transition)
        batch=build_purchase_batch_v1(batch_nonce=b(s.batchNonce),artifacts=tuple(t.reservation.artifact for t in transitions))
        prove_receipt_shape(batch,items[0].terms.validator_pubkeys,s.validFrom)
        if not await current_evidence_unchanged(inventory.evidence,provider=provider):
            raise ValueError('Current issuance changed during review')
        order=VaultCardRecord(purchase_id=h(batch.purchase_id),batch_hash=h(batch.batch_hash),generation_id=s.generationId,
            collection_id=s.collectionId,vault_launcher_id=s.vaultLauncherId,destination_puzzle_hash=h(batch.vault_p2_puzzle_hash),
            deed_launcher_ids=s.deedLauncherIds,reserved_coin_ids=tuple(h(t.reserved_coin.name()) for t in transitions),
            network=s.network,mode=s.mode,account_id=s.accountId,amount_minor=batch.total_rail_amount,currency='usd',
            expires_at=s.expiresAt,batch=purchase_batch_to_json(batch),release_id=self.release_id,
            original_coin_ids=s.originalCoinIds,vault_coin_id=h(vault.coin.name()),credential_root=h(vault.root),
            owner_key=owner_key,owner_auth_type=kind,policy_version=s.credentialPolicyVersion,
            bridge_policy_hash=h(bindings.bridge_policy),generation_anchor_hash=s.generationAnchorHash,
            technology_fee_puzzle_hash=s.technologyFeePuzzleHash,primary_proceeds_puzzle_hash=s.primaryProceedsPuzzleHash,
            maximum_fee_per_stage_mojos=s.maximumFeePerStageMojos,maximum_total_fee_mojos=s.maximumTotalFeeMojos).check()
        return VaultCardEvidence(order,items,vault,tuple(transitions),inventory)

    @staticmethod
    async def stage(evidence,provider):
        await unspent(provider,evidence.vault.coin)
        if await provider.primary.get_mempool_items_by_coin_name(h(evidence.vault.coin.name()))!=[]:
            raise ValueError('Vault has a pending spend')
        stages=[]
        heights=set()
        for t in evidence.transitions:
            coin=t.spend.coin
            old=read_confirmed_coin(await provider.get_coin_record_by_name_primary(h(coin.name())),coin.name())
            if old.coin!=coin:
                raise ValueError('Incorrect original coin')
            if not old.spent_height:
                pending=await provider.primary.get_mempool_items_by_coin_name(h(coin.name()))
                if not isinstance(pending,list):
                    raise ValueError('Original coin status unavailable')
                stages.append('PENDING' if pending else 'AVAILABLE')
                continue
            actual=_spend(await provider.get_puzzle_and_solution_primary(h(coin.name()),old.spent_height),coin)
            if actual != t.spend:
                raise ValueError('Original deed went to another order')
            nxt=await unspent(provider,t.reserved_coin)
            if nxt.confirmed_height!=old.spent_height or await provider.primary.get_mempool_items_by_coin_name(h(nxt.coin.name()))!=[]:
                raise ValueError('Reservation no longer available')
            heights.add(nxt.confirmed_height)
            stages.append('CONFIRMED')
        if len(set(stages))!=1 or len(heights)>1:
            raise ValueError('Both deeds must be reserved atomically')
        return stages[0],next(iter(heights),None)

    @staticmethod
    def retain(purchases,evidence,now):
        o=evidence.order
        receipt=dict(vaultLauncherId=o.vault_launcher_id,vaultP2PuzzleHash=o.destination_puzzle_hash,
            chiaVaultCoinId=o.vault_coin_id,identityAttestRoot=o.credential_root,policyVersion=o.policy_version,
            bridgePolicyHash=o.bridge_policy_hash,ownerAuthType=o.owner_auth_type,ownerKey=o.owner_key,
            stampCoinId=h(evidence.vault.stamp_coin_id),bridgeCoinId=h(evidence.vault.bridge_coin_id),
            stampHeight=evidence.vault.stamp_height)
        intent='vault-card-'+o.purchase_id[2:]
        protocol=dict(purchaseIntentId=intent,rail='stripe',quantity=len(o.deed_launcher_ids),
            vaultLauncherId=o.vault_launcher_id,zkPassportRequired=True,collectionId=o.collection_id,
            purchaseId=o.purchase_id,purchaseArtifactHash=o.batch_hash,deedLauncherIds=list(o.deed_launcher_ids))
        offer=dict(schemaVersion=4,kind='solslot_protocol_offer',protocolVersion='solslot-v2',network=o.network,
            generationAnchorHash=o.generation_anchor_hash,generationId=o.generation_id,vaultCardReleaseId=o.release_id,purchaseBatchV1=o.batch,vaultCredentialReceipt=receipt,protocol=protocol)
        return purchases.save(purchase_intent_id=intent,rail='stripe',offer_artifact_hash=content_hash(offer),
            offer_artifact=offer,purchase_artifact=o.batch,created_at=now)
