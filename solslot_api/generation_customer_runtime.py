"""First-class fresh customer workflow. Reads never select, sign or submit."""
from __future__ import annotations
import asyncio,hashlib,json,re,secrets,time,logging
from dataclasses import dataclass
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.vault_driver import puzzle_for_p2_vault
from .generation_customer_context import current_customer_launch_bindings
from .generation_customer_launch import CustomerLaunchConsent
from .generation_customer_execution import prepare_customer_operation,saved_customer_operation,verify_customer_creation,validate_customer_bundle
from .generation_customer_store import CustomerRegistrationConflict
from .generation_operations import submit_saved_operation
from .singleton_launcher import launcher_coin_for_parent
from .evm_auth import normalize_evm_address

logger=logging.getLogger(__name__)

def normalized_owner(owner,auth_type):
    if auth_type=='evm':return normalize_evm_address(owner)
    if auth_type!='chia_bls' or not isinstance(owner,str):raise ValueError('unsupported customer wallet')
    from chia_rs import G1Element
    value=owner.lower()
    if re.fullmatch(r'0x[0-9a-f]{96}',value) is None:raise ValueError('a full Chia owner public key is required')
    point=G1Element.from_bytes(bytes.fromhex(value[2:]))
    if point==G1Element():raise ValueError('a nonidentity Chia owner public key is required')
    return '0x'+bytes(point).hex()

@dataclass(frozen=True)
class CustomerCreationPolicy:
    generation_id:str
    allowed_parent_ids:frozenset[str]
    maximum_parent_mojos:int
    fee_cap_mojos:int
    issued_at:int
    expires_at:int
    allowed_fee_ids:frozenset[str]=frozenset()
    maximum_fee_parent_mojos:int=1_000_000_000

    def validate(self,generation,now):
        if (self.generation_id!=generation or not isinstance(self.allowed_parent_ids,frozenset)
                or not 1<=len(self.allowed_parent_ids)<=32
                or any(re.fullmatch(r'0x[0-9a-f]{64}',v) is None for v in self.allowed_parent_ids)
                or not isinstance(self.allowed_fee_ids,frozenset) or not 1<=len(self.allowed_fee_ids)<=32
                or any(re.fullmatch(r'0x[0-9a-f]{64}',v) is None for v in self.allowed_fee_ids)
                or self.allowed_parent_ids & self.allowed_fee_ids
                or type(self.maximum_fee_parent_mojos) is not int
                or not 1<=self.maximum_fee_parent_mojos<=1_000_000_000_000
                or type(self.maximum_parent_mojos) is not int or not 1<=self.maximum_parent_mojos<=1_000_000_000_000
                or type(self.fee_cap_mojos) is not int or not 1<=self.fee_cap_mojos<=1_000_000_000
                or type(self.issued_at) is not int or type(self.expires_at) is not int
                or not self.issued_at<=now<self.expires_at<=self.issued_at+172800):
            raise ValueError('the reviewed bounded customer funding window is unavailable')
        return self

class GenerationCustomerRuntime:
    def __init__(self,*,settings,index,provider,store,journal,registry,faucet=None,policy=None,submitter=None,clock=time.time):
        self.settings,self.index,self.provider=settings,index,provider
        self.store,self.journal,self.registry=store,journal,registry
        self.faucet,self.policy,self.submitter=faucet,policy,submitter
        self.clock=clock;self.guard=asyncio.Lock()
        # A persisted projection is not admitted after restart until this process
        # independently reconstructs its native ancestry. GETs never refresh it.
        self.verified_observations={}
        self.observer_health={'lastCheckedAt':None,'status':'STARTING','pendingCount':0,'errorCount':0}
        if store.generation_id!=journal.generation_id or store.generation_id!=settings.deployment_generation_id:
            raise ValueError('customer runtime stores must share the exact generation')

    def profile(self):
        """Only the already verified background projection supplies authority."""
        generation=self.store.generation_id
        base={'schema':'solslot.current-customer-profile.v1','generationId':generation,'network':'testnet11',
            'registrationEnabled':False,'requiresFreshIdCheck':True,'earlierVaultsAdmitted':False,
            'pollAfterSeconds':30}
        try:
            b=current_customer_launch_bindings(self.settings,self.index,now=int(self.clock()))
            fields={'generationId':generation,'preparationManifest':'0x'+b.preparation_manifest.hex(),
                'poolLauncherId':'0x'+b.pool_launcher.hex(),'bridgePolicyHash':'0x'+b.bridge_policy.hex(),
                'vaultModuleHash':'0x'+b.vault_module.hex(),'network':'testnet11'}
            digest='0x'+hashlib.sha256(json.dumps(fields,sort_keys=True,separators=(',',':')).encode()).hexdigest()
            enabled=bool(getattr(self.settings,'generation_customer_enabled',False) and self.faucet is not None
                and self.policy is not None and self.submitter is not None)
            if enabled:
                try:self.policy.validate(generation,int(self.clock()))
                except ValueError:enabled=False
            return {**base,'status':'READY','registrationEnabled':enabled,'bindings':fields,'profileHash':digest,
                'feeCapMojos':str(self.policy.fee_cap_mojos) if enabled else None,
                'nextAction':'CONNECT_WALLET' if enabled else 'REGISTRATION_NOT_ENABLED'}
        except (ValueError,OSError):
            return {**base,'status':'UNAVAILABLE','code':'CURRENT_CUSTOMER_AUTHORITY_UNAVAILABLE',
                'message':'Vault registration is temporarily unavailable. Your saved progress is preserved.'}

    def _writable(self,generation):
        if generation!=self.store.generation_id or not getattr(self.settings,'generation_customer_enabled',False):
            raise ValueError('fresh customer registration is not enabled for this generation')
        if self.faucet is None or self.policy is None:raise ValueError('the separate customer signer is unavailable')
        self.policy.validate(generation,int(self.clock()))
        if getattr(self.faucet,'network',None)!='testnet11':raise ValueError('customer funding requires Testnet11')
        return current_customer_launch_bindings(self.settings,self.index,now=int(self.clock()))

    async def prepare_review(self,owner,auth_type,generation,browser_hash):
        owner=normalized_owner(owner,auth_type)
        async with self.guard:
            b=self._writable(generation);now=int(self.clock())
            self.store.expire_unsigned(now=now)
            if self.store.confirmed_owner(owner,auth_type):raise CustomerRegistrationConflict('reconnect the existing current-generation vault')
            existing=(self.registry.get_by_evm(owner) if auth_type=='evm'
                else self.registry.get_by_bls(bytes.fromhex(owner[2:])))
            if existing is not None:
                raise CustomerRegistrationConflict('prove and reconnect the existing current-generation custody before preparing another vault')
            retained=self.store.active_owner_review(owner,auth_type,browser_hash=browser_hash,now=now)
            if retained is not None:return self.status(retained['registrationId'],browser_hash)
            held=self.store.held_funding_ids()|self.journal.reserved_input_coin_ids()
            from .generation_recipient_execution import _funding_coin
            async with asyncio.timeout(20):
                if (await self.provider.get_network_info_primary()).get('network_name')!='testnet11':raise ValueError('primary Testnet11 node is required')
                for identity in sorted(self.policy.allowed_parent_ids-held):
                    raw=await self.provider.get_coin_record_by_name_primary(identity)
                    try:coin=_funding_coin(raw,identity)
                    except ValueError:continue
                    if coin.puzzle_hash!=self.faucet.address_puzzle_hash or coin.amount>self.policy.maximum_parent_mojos:continue
                    consent=CustomerLaunchConsent(b,bytes32(secrets.token_bytes(32)),owner,auth_type,coin.name(),launcher_coin_for_parent(coin).name(),now+300)
                    self.store.reserve(consent,now=now,browser_hash=browser_hash)
                    identity='0x'+hashlib.sha256(json.dumps(consent.message(),sort_keys=True,separators=(',',':')).encode()).hexdigest()
                    return self.status(identity,browser_hash)
            raise ValueError('no reviewed customer funding input is currently available')

    def status(self,identity,browser_hash):
        """Pure durable reads: no node, registry update, key, reservation or JWT."""
        self.store.require_browser(identity,browser_hash)
        row=self.store.status(identity,now=int(self.clock()))
        op=saved_customer_operation(self.store,self.journal,identity) if row['stage']=='AUTHORIZED' else None
        confirmed=self.store.confirmation(identity)
        if op is not None:
            row={**row,'stage':op['stage'],'operationId':op['operationId'],'transactionId':op['transactionId'],
                'errorCode':op.get('errorCode'),'feeCapMojos':op['feeCapMojos']}
        if confirmed is not None:
            row={**row,'stage':'VAULT_READY','registrationConfirmed':True,'transactionId':confirmed['transaction_id'],
                'confirmedHeight':confirmed['confirmed_height'],'currentVaultCoinId':confirmed['vault_coin_id']}
        consent=self.store.status(identity,now=int(self.clock()))['review']
        from .generation_customer_store import read_consent
        value=read_consent(consent)
        next_action = {
            'VAULT_READY': 'CONNECT_CONFIRMED_VAULT',
            'REVIEW_READY': 'APPROVE_CREATION_IN_WALLET',
            'CONSENT_EXPIRED': 'RENEW_UNSIGNED_REVIEW',
            'EXPIRED_UNSIGNED': 'RENEW_UNSIGNED_REVIEW',
            'AUTHORIZED': 'RESUME_PREPARATION',
            'PREPARED': 'SUBMIT_REGISTRATION',
            'DISPATCHING': 'CHECK_SAVED_TRANSACTION',
            'RECONCILING': 'CHECK_SAVED_TRANSACTION',
            'CONFIRMED': 'VERIFY_VAULT_CREATION',
        }.get(row['stage'], 'WAIT_FOR_CONFIRMATION')
        authority_available=True
        try:current_customer_launch_bindings(self.settings,self.index,now=int(self.clock()))
        except (ValueError,OSError):authority_available=False
        return {**row,'currentAuthorityAvailable':authority_available,
            'typedData':value.typed_data() if value.auth_type=='evm' else None,
            'messageHex':'0x'+value.bls_message().hex() if value.auth_type=='chia_bls' else None,
            'requiresFreshIdCheck':True,'nextAction':next_action,'pollAfterSeconds':30 if confirmed else 5}

    async def authorize(self,identity,signature,browser_hash,generation):
        async with self.guard:
            self._writable(generation);self.store.require_browser(identity,browser_hash)
            self.store.accept_signature(identity,signature,now=int(self.clock()))
            return await self._prepare_authorized(identity,browser_hash)

    async def prepare_authorized(self,identity,browser_hash,generation):
        """Resume saved consent after a lost response without another signature."""
        async with self.guard:
            self._writable(generation)
            self.store.require_browser(identity,browser_hash)
            return await self._prepare_authorized(identity,browser_hash)

    async def _prepare_authorized(self,identity,browser_hash):
        await prepare_customer_operation(identity,self.policy.fee_cap_mojos,store=self.store,journal=self.journal,
            settings=self.settings,index=self.index,provider=self.provider,faucet=self.faucet,
            maximum_parent_amount=self.policy.maximum_parent_mojos,clock=self.clock)
        return self.status(identity,browser_hash)

    async def submit(self,identity,browser_hash,generation):
        async with self.guard:
            self._writable(generation);self.store.require_browser(identity,browser_hash)
            op=saved_customer_operation(self.store,self.journal,identity)
            if op is None:raise ValueError('the exact signed customer operation is not prepared')
            if self.submitter is None:raise ValueError('the reviewed customer fee submitter is unavailable')
            await submit_saved_operation(self.journal,op['operationId'],self.submitter,clock=self.clock)
            return self.status(identity,browser_hash)

    async def reconcile_once(self):
        """Background confirmation only. Never signs, reserves or broadcasts."""
        from .state import VaultRecord
        count=0;errors=0
        pending=self.store.pending_authorized()
        for identity in pending:
            try:count+=await self._reconcile_one(identity,VaultRecord)
            except (ValueError,OSError,RuntimeError,TimeoutError) as exc:
                errors+=1
                logger.warning('customer observation unavailable (%s)',type(exc).__name__)
        for identity in self.store.confirmed_registrations():
            try:
                observed=self.verified_observations.get(identity)
                if observed is None or int(self.clock())-observed[0]>=25:
                    await self.observe_current_vault(identity)
            except (ValueError,OSError,RuntimeError,TimeoutError) as exc:
                self.verified_observations.pop(identity,None)
                errors+=1
                logger.warning('current custody observation unavailable (%s)',type(exc).__name__)
        self.observer_health={'lastCheckedAt':int(self.clock()),'status':'DEGRADED' if errors else 'READY',
            'pendingCount':len(pending)-count,'errorCount':errors}
        return count

    async def observe_current_vault(self,identity):
        from .generation_customer_vault import resolve_registered_customer_vault
        current_customer_launch_bindings(self.settings,self.index,now=int(self.clock()))
        evidence=await resolve_registered_customer_vault(identity,store=self.store,journal=self.journal,
            settings=self.settings,index=self.index,provider=self.provider,clock=self.clock)
        now=int(self.clock())
        self.store.observe_vault(identity,evidence,now=now)
        digest=hashlib.sha256(json.dumps(evidence.public(),sort_keys=True,separators=(',',':')).encode()).hexdigest()
        self.verified_observations[identity]=(now,digest)
        return evidence

    def current_vault_snapshot(self,launcher):
        """Cached native projection only; never constructs or submits a spend."""
        now=int(self.clock())
        bindings=current_customer_launch_bindings(self.settings,self.index,now=now)
        identity,consent=self.store.registered_vault(launcher)
        verified=self.verified_observations.get(identity)
        checked=verified[0] if verified is not None else None
        saved=self.store.vault_observation(identity)
        if (type(checked)is not int or not 0<=now-checked<=60 or saved is None or
                saved['checkedAt']!=checked or saved['vault']['generationId']!=self.store.generation_id or
                saved['vault']['vaultLauncherId']!=launcher or
                hashlib.sha256(json.dumps(saved['vault'],sort_keys=True,separators=(',',':')).encode()).hexdigest()!=verified[1]):
            raise ValueError('CURRENT_CUSTOMER_CUSTODY_OBSERVATION_UNAVAILABLE')
        signed_consent,signature,authorized_at=self.store.authorized_material(identity)
        owner_pubkey,_=signed_consent.verified_owner(signature,authorized_at)
        return {**saved,'schema':'solslot.current-customer-session.v1',
            'generationId':self.store.generation_id,'network':'testnet11',
            'owner':consent.owner,'authType':consent.auth_type,
            'ownerPublicKey':'0x'+owner_pubkey.hex(),
            'registrationId':identity,'profileHash':self.profile()['profileHash'],
            'p2VaultPuzzleHash':'0x'+puzzle_for_p2_vault(consent.vault_launcher_id).get_tree_hash().hex(),
            'pollAfterSeconds':30}

    async def _reconcile_one(self,identity,VaultRecord):
            op=saved_customer_operation(self.store,self.journal,identity)
            if op is None or op['stage']!='CONFIRMED':return 0
            receipt=await verify_customer_creation(identity,store=self.store,journal=self.journal,
                settings=self.settings,index=self.index,provider=self.provider,clock=self.clock)
            consent,_,_=self.store.authorized_material(identity)
            _,owner,output=validate_customer_bundle(self.journal.protocol_bundle(op['operationId']),op['review'])
            from solslot_puzzles.vault_driver import AUTH_TYPE_BLS,AUTH_TYPE_SECP256K1
            auth=AUTH_TYPE_BLS if consent.auth_type=='chia_bls' else AUTH_TYPE_SECP256K1
            old=(self.registry.get_by_bls(owner) if auth==AUTH_TYPE_BLS else self.registry.get_by_evm(consent.owner))
            if old is not None and old.launcher_id!=consent.vault_launcher_id:raise ValueError('a different current vault already owns this wallet registration')
            self.registry.record(VaultRecord(consent.vault_launcher_id,output.puzzle_hash,
                puzzle_for_p2_vault(consent.vault_launcher_id).get_tree_hash(),auth,owner,
                consent.owner if consent.auth_type=='evm' else None,op['transactionId'],int(self.clock())))
            self.store.confirm_creation(receipt,operation_id=op['operationId'],transaction_id=op['transactionId'])
            return 1

    async def run(self):
        while True:
            try:await self.reconcile_once()
            except Exception as exc:
                self.observer_health={**self.observer_health,'lastCheckedAt':int(self.clock()),'status':'UNAVAILABLE'}
                logger.error('customer observer unavailable (%s)',type(exc).__name__)
            await asyncio.sleep(5 if self.observer_health['pendingCount'] else 30)

    def close(self):
        if self.submitter is not None and self.submitter.funding_store is not None:
            self.submitter.funding_store.close()

    async def verified_registration_owner(self,identity,browser_hash):
        """Session admission is an explicit POST after exact native confirmation."""
        self.store.require_browser(identity,browser_hash)
        if self.store.confirmation(identity) is None:raise ValueError('the new customer vault is not confirmed')
        # Cookie admission is consequential even though it spends nothing.
        # Recheck creation against the primary node so a saved confirmation
        # cannot admit a coin removed by a reorganization. This initial connect
        # precedes the ID stamp; later owner login is a separate signed flow.
        await verify_customer_creation(identity,store=self.store,journal=self.journal,
            settings=self.settings,index=self.index,provider=self.provider,clock=self.clock)
        consent,_,_=self.store.authorized_material(identity)
        record=self.registry.get(consent.vault_launcher_id)
        if record is None:raise ValueError('the confirmed current vault is not admitted')
        owner,_=consent.verified_owner(self.store.authorized_material(identity)[1],self.store.authorized_material(identity)[2])
        if bytes(record.owner_pubkey)!=owner:raise ValueError('the admitted current vault owner differs')
        from .credential_auth import VerifiedOwner
        return VerifiedOwner(consent.owner.lower() if consent.auth_type=='evm' else consent.owner,consent.auth_type,record)
