"""Current-generation enrollment orchestration and primary-only request reads.

Native and EVM evidence is fetched asynchronously before existing identity
primitives execute. Those primitives may read only this bounded request set;
they cannot silently fall back to an earlier deployment or public indexer.
"""
from __future__ import annotations
import asyncio
import copy
import time
from dataclasses import dataclass
from chia_rs.sized_bytes import bytes32
from starlette.concurrency import run_in_threadpool
from .credential_ledger import get_credential_ledger, LedgerConflict
from .generation_customer_identity_context import load_current_identity_profile
from .generation_customer_identity_scope import current_identity_request, current_identity_settings
from .generation_customer_execution import saved_customer_operation, validate_customer_bundle
from .vault_chain_evidence import read_vault_coin
from .generation_customer_identity_evm import read_current_identity_compatibility


@dataclass(frozen=True)
class CurrentIdentityReads:
    launcher: str
    initial_coin_id: str
    profile: object
    records: dict
    event: object | None
    checked_at: int
    clock: object
    fee_submitter: object | None = None
    funding_store: object | None = None
    authority: object | None = None
    primary_read_set: bool = True

    def live(self):
        if not 0 <= int(self.clock()) - self.checked_at <= 60:
            raise ValueError('CURRENT_ID_PRIMARY_READ_SET_EXPIRED')

    def coin_record(self, coin_id):
        self.live()
        if coin_id not in self.records:
            raise ValueError('CURRENT_ID_COIN_OUTSIDE_REQUEST')
        return copy.deepcopy(self.records[coin_id])

    def children(self, parents, *, include_spent=False):
        self.live()
        if parents != [self.launcher]:raise ValueError('CURRENT_ID_PARENT_OUTSIDE_REQUEST')
        record=self.coin_record(self.initial_coin_id)
        return [record] if record and (include_spent or not record.get('spent_block_index')) else []

    def bridge_records(self, policy_hash):
        self.live()
        if policy_hash != self.profile.bridge_policy_hash:raise ValueError('CURRENT_ID_BRIDGE_POLICY_CHANGED')
        return [self.coin_record(row.coin_id) for row in self.profile.bridge_coins
            if row.coin_id in self.records and self.records[row.coin_id] is not None]

    def verified_event(self, transaction_hash, launcher):
        self.live()
        if (self.event is None or launcher != self.launcher
                or self.event.transaction_hash != transaction_hash
                or self.event.vault_launcher_id != launcher):
            raise ValueError('CURRENT_ID_EVENT_OUTSIDE_REQUEST')
        return self.event

    def require_relay(self, scope):
        self.live()
        if self.authority is None:raise ValueError('CURRENT_ID_RELAY_NOT_AUTHORIZED')
        self.authority.require_live(scope.profile, int(self.clock()))

    def require_stamp(self,scope):
        self.require_relay(scope)
        if self.fee_submitter is None or self.funding_store is None:
            raise ValueError('CURRENT_ID_STAMP_FEE_AUTHORITY_UNAVAILABLE')


class CurrentCustomerIdentityRuntime:
    def __init__(self, settings, customers, *, authority=None, fee_submitter=None, funding_store=None, clock=time.time):
        self.settings,self.customers,self.clock=settings,customers,clock
        self.authority,self.fee_submitter,self.funding_store=authority,fee_submitter,funding_store
        self.ledger=get_credential_ledger(settings)
        self.relay_observations={}
        self.health={'status':'RECONCILING','lastCheckedAt':None,'pendingCount':0}
        self.compatibility={'status':'NOT_CHECKED','checkedAt':None}

    def compatibility_ready(self, profile):
        value=getattr(self,'compatibility',{})
        checked=value.get('checkedAt')
        return (value.get('status')=='READY' and value.get('profileHash')==profile.commitment
            and value.get('proofVersions')==list(profile.accepted_proof_versions)
            and type(checked)is int and 0<=int(self.clock())-checked<=60)

    async def refresh_compatibility(self):
        if not hasattr(self,'_compatibility_lock'):self._compatibility_lock=asyncio.Lock()
        async with self._compatibility_lock:
            await self._refresh_compatibility()

    async def _refresh_compatibility(self):
        profile=self.profile();value=getattr(self,'compatibility',{})
        checked=value.get('checkedAt')
        if (value.get('profileHash')==profile.commitment and type(checked)is int
                and 0<=int(self.clock())-checked<30):
            if self.compatibility_ready(profile):return
            if value.get('status')=='UNAVAILABLE':raise ValueError(value['code'])
        try:
            self.compatibility=await run_in_threadpool(read_current_identity_compatibility,
                self.settings,profile,int(self.clock()))
            if not self.compatibility_ready(profile):raise ValueError('CURRENT_ID_COMPATIBILITY_UNAVAILABLE')
        except Exception as exc:
            code=('CURRENT_ID_EVM_PROOF_VERSION_UNSUPPORTED'
                if isinstance(exc,ValueError) and str(exc)=='CURRENT_ID_EVM_PROOF_VERSION_UNSUPPORTED'
                else 'CURRENT_ID_COMPATIBILITY_UNAVAILABLE')
            self.compatibility={'status':'UNAVAILABLE','checkedAt':int(self.clock()),
                'profileHash':profile.commitment,'code':code}
            raise ValueError(code) from exc

    def profile(self):
        profile=load_current_identity_profile(self.settings,self.customers.index,now=int(self.clock()))
        if profile is None:raise ValueError('CURRENT_ID_NOT_CONFIGURED')
        return profile

    def cached(self, launcher):
        profile=self.profile()
        with current_identity_request(self.settings,profile,launcher,self.customers,runtime=object(),
                clock=self.clock,require_fresh=False) as scope:
            record=self.ledger.get_enrollment(launcher)
            if record is not None:scope.require_record(record)
            if record is not None and record['status']=='chia_confirmed':
                native=self.customers.current_vault_snapshot(launcher)['vault']
                receipt=record.get('receipt') or {}
                if (not native['identityVerified'] or receipt.get('identityAttestRoot')!=native['identityAttestRoot']
                        or receipt.get('chiaVaultCoinId')!=native['currentCoinId']):
                    record={**record,'status':'receipt_syncing'}
            return copy.deepcopy(record)

    async def request_reads(self, launcher, *, include_event=True, all_bridges=False, transaction_hash=None):
        profile=self.profile()
        registered,_=self.customers.store.registered_vault(launcher)
        native=await self.customers.observe_current_vault(registered)
        operation=saved_customer_operation(self.customers.store,self.customers.journal,registered)
        if operation is None:raise ValueError('CURRENT_ID_REGISTERED_CREATION_MISSING')
        _,_,initial=validate_customer_bundle(self.customers.journal.protocol_bundle(operation['operationId']),operation['review'])
        initial_id='0x'+initial.name().hex()
        with current_identity_request(self.settings,profile,launcher,self.customers,runtime=object(),
                clock=self.clock,require_fresh=False) as scope:
            existing=self.ledger.get_enrollment(launcher)
            if existing is not None:scope.require_record(existing)
        ids={launcher,initial_id}
        if existing is not None:ids.add(existing['bridgeCoinId'])
        if all_bridges:
            used=self.ledger.enrollment_bridge_coin_ids()
            ids.update(row.coin_id for row in profile.bridge_coins if row.coin_id not in used)
        limit=asyncio.Semaphore(4)
        async def read(coin_id):
            async with limit:
                raw=await self.customers.provider.get_coin_record_by_name_primary(coin_id)
                if raw is not None:read_vault_coin(raw,bytes32.from_hexstr(coin_id))
                return coin_id,copy.deepcopy(raw)
        records=dict(await asyncio.gather(*(read(value) for value in sorted(ids))))
        if records.get(initial_id) is None or records.get(launcher) is None:
            raise ValueError('CURRENT_ID_PRIMARY_CUSTODY_UNAVAILABLE')
        event=None
        receipt=(existing or {}).get('receipt') or {}
        event_hash=transaction_hash or receipt.get('evmTxHash')
        if include_event and event_hash:
            from .zkpassport_enrollments import _fetch_verified_evm_attestation
            # Outside the scope: a fresh independently verified EVM receipt,
            # then only the exact resulting event is available inside it.
            event=await run_in_threadpool(_fetch_verified_evm_attestation,
                current_identity_settings(self.settings,profile), transaction_hash=event_hash,
                expected_vault_launcher_id=launcher,current_profile=profile)
        return CurrentIdentityReads(launcher,initial_id,profile,records,event,int(self.clock()),self.clock,
            self.fee_submitter,self.funding_store,self.authority),native

    async def reserve(self, launcher, owner):
        from .zkpassport_enrollments import EnrollmentRecord, _public_record, _bridge_coin_candidates
        # This runs before QR/proof creation. Incompatible or stale service
        # configuration cannot ask a customer to scan a document or sign.
        await self.refresh_compatibility()
        reads,native=await self.request_reads(launcher,include_event=False,all_bridges=True)
        if native.identity_verified:raise ValueError('CURRENT_ID_ALREADY_CONFIRMED')
        with current_identity_request(self.settings,reads.profile,launcher,self.customers,runtime=reads,clock=self.clock) as scope:
            existing=self.ledger.get_enrollment(launcher)
            if existing is not None:
                scope.require_record(existing)
                return _public_record(existing)
            used=self.ledger.enrollment_bridge_coin_ids()
            candidates=_bridge_coin_candidates(scope.settings,bridge_policy_hash=reads.profile.bridge_policy_hash)
            for coin in candidates:
                if coin.coin_id in used:continue
                now=int(self.clock())
                record=EnrollmentRecord(vaultLauncherId=launcher,network='testnet11',policyVersion=2,status='reserved',
                    bridgePolicyHash=reads.profile.bridge_policy_hash,bridgeParentId=coin.parent_id,
                    bridgeAmount=1,bridgeCoinId=coin.coin_id,createdAt=now,updatedAt=now,identityDeployment=scope.enrollment_binding)
                try:
                    saved,_=self.ledger.reserve_enrollment(record=record.model_dump(),owner_key=owner.owner_key,
                        max_pending_per_owner=self.settings.zkpassport_enrollment_max_pending_per_owner)
                except LedgerConflict:continue
                scope.require_record(saved)
                return _public_record(saved)
        raise ValueError('CURRENT_ID_BRIDGE_CAPACITY_UNAVAILABLE')

    async def sync(self, launcher):
        from .zkpassport_enrollments import EnrollmentRecord
        reads,native=await self.request_reads(launcher,include_event=False)
        with current_identity_request(self.settings,reads.profile,launcher,self.customers,runtime=reads,
                clock=self.clock,require_fresh=False) as scope:
            raw=self.ledger.get_enrollment(launcher)
            if raw is None:raise ValueError('CURRENT_ID_ENROLLMENT_NOT_FOUND')
            scope.require_record(raw);record=EnrollmentRecord.model_validate(raw)
            if not native.identity_verified:return record
            if (record.receipt is None or record.status not in ('stamp_pending','receipt_syncing','chia_confirmed')
                    or record.receipt.identityAttestRoot!='0x'+native.root.hex()
                    or record.bridgeCoinId!='0x'+native.bridge_coin_id.hex()):
                raise ValueError('CURRENT_ID_NATIVE_RECEIPT_MISMATCH')
            receipt=record.receipt.model_copy(update={'chiaVaultCoinId':'0x'+native.coin.name().hex(),
                'chiaStampCoinId':'0x'+native.stamp_coin_id.hex(),'confirmedBlockIndex':native.confirmed_height,
                'genesisArtifactHash':None})
            confirmed=record.model_copy(update={'status':'chia_confirmed','receipt':receipt,'updatedAt':int(self.clock())})
            self.ledger.update_enrollment(confirmed.model_dump(),expected_statuses={'stamp_pending','receipt_syncing','chia_confirmed'})
            return confirmed

    async def sync_evm(self,launcher):
        from .zkpassport_enrollments import _fetch_verified_evm_attestation,VaultCredentialReceipt,EnrollmentRecord,AttestationProof
        profile=self.profile();record=self.cached(launcher)
        if record is None or record['status']!='reserved':return
        saved=self.ledger.get_relay_transaction(launcher)
        if saved is None:return
        identity,_=self.customers.store.registered_vault(launcher)
        await self.customers.observe_current_vault(identity)
        event=await run_in_threadpool(_fetch_verified_evm_attestation,current_identity_settings(self.settings,profile),
            transaction_hash=saved['tx_hash'],expected_vault_launcher_id=launcher,current_profile=profile)
        snapshot=self.customers.current_vault_snapshot(launcher)
        expected=snapshot['owner'] if snapshot['authType']=='evm' else profile.trusted_direct_relayer
        if (event.sender.lower()!=expected.lower() or event.bridge_coin_id!=record['bridgeCoinId']
                or event.bridge_parent_id!=record['bridgeParentId'] or event.bridge_amount!=1
                or event.bridge_policy_hash!=record['bridgePolicyHash']):
            raise ValueError('CURRENT_ID_RELAY_RECEIPT_MISMATCH')
        self.ledger.require_submitted_relay(transaction_hash=event.transaction_hash,vault_launcher_id=launcher,
            owner_key=snapshot['owner'],bridge_coin_id=event.bridge_coin_id)
        now=int(self.clock())
        receipt=VaultCredentialReceipt(generationId=profile.generation_id,identityProfileHash=profile.commitment,
            vaultLauncherId=launcher,network='testnet11',policyVersion=2,
            identityAttestRoot=event.identity_attest_root,attestationLeafHash=event.attestation_leaf_hash,
            attestationProof=AttestationProof(bitpath=0,siblings=[]),scopedNullifier=event.scoped_nullifier,
            nullifierType=event.nullifier_type,serviceScopeHash=event.service_scope_hash,
            serviceSubscopeHash=event.service_subscope_hash,proofTimestamp=event.proof_timestamp,
            bridgePolicyHash=event.bridge_policy_hash,bridgeParentId=event.bridge_parent_id,bridgeAmount=1,
            bridgeCoinId=event.bridge_coin_id,bridgeMessage=event.bridge_message,validatorMessage=event.validator_message,
            evmTxHash=event.transaction_hash,evmConfirmedBlockIndex=event.block_number,enrolledAt=now)
        updated=EnrollmentRecord.model_validate(record).model_copy(update={'status':'evm_confirmed','receipt':receipt,'updatedAt':now})
        self.ledger.record_evm_event(record=updated.model_dump(),owner_key=snapshot['owner'],
            transaction_hash=event.transaction_hash,scoped_nullifier=event.scoped_nullifier,
            bridge_coin_id=event.bridge_coin_id,block_number=event.block_number)
        self.relay_observations[launcher]={'status':'confirmed','checkedAt':now,'txHash':event.transaction_hash}

    def relay_status(self,launcher):
        record=self.cached(launcher)
        if record is None:return {'vaultLauncherId':launcher,'status':'not_started','txHash':None,'canResubmit':False,'proof':None}
        attempt=self.ledger.get_relay_attempt(launcher);saved=self.ledger.get_relay_transaction(launcher)
        if not attempt:return {'vaultLauncherId':launcher,'status':'not_started','txHash':None,'canResubmit':False,'proof':None}
        if not saved:return {'vaultLauncherId':launcher,'status':'incomplete','txHash':None,'canResubmit':False,'proof':None}
        receipt=record.get('receipt') or {}
        if receipt.get('evmTxHash')==saved['tx_hash']:
            proof={key:receipt.get(key) for key in ('vaultLauncherId','policyVersion','identityAttestRoot',
                'attestationLeafHash','attestationProof','bridgePolicyHash','bridgeParentId','bridgeAmount',
                'bridgeCoinId','bridgeMessage','validatorMessage')}
            return {'vaultLauncherId':launcher,'status':'confirmed','txHash':saved['tx_hash'],'canResubmit':False,
                'proof':{'txHash':saved['tx_hash'],**proof}}
        can_resubmit=False
        try:
            if self.authority is not None:self.authority.require_live(self.profile(),int(self.clock()))
            can_resubmit=self.authority is not None and int(self.clock())<saved['retry_until']
        except ValueError:pass
        return {'vaultLauncherId':launcher,'status':'pending','txHash':saved['tx_hash'],
            'proof':None,'canResubmit':can_resubmit,'lastCheckedAt':(self.relay_observations.get(launcher) or {}).get('checkedAt')}

    async def run_once(self):
        self.profile()
        compatibility_failed=False
        try:await self.refresh_compatibility()
        except ValueError:compatibility_failed=True
        records=self.ledger.all_enrollments()
        pending=[key for key,row in records.items() if row.get('status') in ('reserved','stamp_pending','receipt_syncing')]
        failures=int(compatibility_failed)
        start=getattr(self,'_cursor',0)%max(1,len(pending))
        batch=(pending[start:]+pending[:start])[:16]
        self._cursor=start+len(batch)
        for key in batch:
            try:
                if records[key]['status']=='reserved':await self.sync_evm(key)
                else:await self.sync(key)
            except Exception:failures+=1
        self.health={'status':'READY' if not failures else 'DEGRADED','lastCheckedAt':int(self.clock()),
            'pendingCount':len(pending),'failedChecks':failures,
            'compatibility':copy.deepcopy(getattr(self,'compatibility',{}))}

    async def run(self):
        while True:
            try:await self.run_once()
            except Exception:self.health={'status':'UNAVAILABLE','lastCheckedAt':int(self.clock()),'pendingCount':1}
            await asyncio.sleep(5 if self.health['pendingCount'] else 30)

    def close(self):
        if self.funding_store is not None:self.funding_store.close()
