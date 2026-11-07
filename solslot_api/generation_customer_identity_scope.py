"""Request-local native identity context. Never changes legacy write flags.

Only the dedicated current-customer router may enter this scope after cookie,
origin and current native custody checks. Existing identity primitives can
then reuse compatible verifier infrastructure without loading a legacy genesis
artifact or accepting one of its registrations/receipts.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import time

from .generation_customer_identity_context import CurrentCustomerIdentityProfile

_scope=ContextVar('solslot_current_customer_private_identity',default=None)


@dataclass(frozen=True)
class CurrentIdentityScope:
    settings:object
    profile:CurrentCustomerIdentityProfile
    launcher:str
    registration_id:str
    owner:str
    auth_type:str
    checked_at:int
    runtime:object
    clock:object=time.time

    @property
    def enrollment_binding(self):
        return {'schema':'solslot.current-customer-enrollment-binding.v1',
            'generationId':self.profile.generation_id,'identityProfileHash':self.profile.commitment,
            'registrationId':self.registration_id}

    def require_record(self,record):
        if (record.get('vaultLauncherId')!=self.launcher or record.get('network')!='testnet11'
                or record.get('identityDeployment')!=self.enrollment_binding
                or record.get('enrollmentPermit') is not None
                or record.get('permitIssuerSignature') is not None
                or record.get('permitIssuanceStatus') is not None
                or (record.get('receipt') or {}).get('genesisArtifactHash') is not None
                or (record.get('receipt') is not None and (
                    record['receipt'].get('generationId')!=self.profile.generation_id
                    or record['receipt'].get('identityProfileHash')!=self.profile.commitment))
                or record.get('bridgePolicyHash')!=self.profile.bridge_policy_hash):
            raise ValueError('CURRENT_ID_ENROLLMENT_GENERATION_CHANGED')
        return record


def current_identity_scope(settings=None,launcher=None):
    value=_scope.get()
    if value is None:return None
    now=int(value.clock())
    if (not 0<=now-value.checked_at<=60 or
            (settings is not None and (settings.network!='testnet11' or
                settings.deployment_generation_id!=value.profile.generation_id)) or
            (launcher is not None and launcher!=value.launcher)):
        raise ValueError('CURRENT_ID_REQUEST_CONTEXT_CHANGED')
    return value


def current_identity_settings(settings, profile, *, runtime=None):
    """Private request configuration; never changes global legacy flags."""
    addresses={row.role:row.address for row in profile.contracts}
    rpc=settings.zkpassport_base_evm_rpc_url
    if not rpc.startswith('https://'):raise ValueError('CURRENT_ID_RPC_CONFIGURATION_INVALID')
    updates={
        'zkpassport_evm_chain_id':profile.evm_chain_id,'zkpassport_evm_rpc_url':rpc,
        'zkpassport_forwarder_address':addresses['forwarder'],
        'zkpassport_verifier_adapter_address':addresses['verifierAdapter'],
        'zkpassport_emitter_address':addresses['attestationEmitter'],
        'zkpassport_bridge_policy_hash':profile.bridge_policy_hash,'zkpassport_policy_version':2,
        'zkpassport_validator_pubkeys':list(profile.validator_public_keys),'zkpassport_validator_threshold':2,
        'enrollment_permit_release_identity':'','enrollment_permit_issuer_key_ref':'',
        'enrollment_permit_identity_client_id':'',
        'protocol_fee_funding_enabled':bool(getattr(runtime,'fee_submitter',None))}
    authority=getattr(runtime,'authority',None)
    if authority is not None:
        updates.update(zkpassport_base_relay_max_fee_wei=authority.base_max_fee_wei,
            zkpassport_base_relay_daily_fee_wei=authority.base_daily_fee_wei)
    return settings.model_copy(update=updates)


@contextmanager
def current_identity_request(settings,profile,launcher,customers,*,runtime,clock=time.time,require_fresh=True):
    if (not isinstance(profile,CurrentCustomerIdentityProfile) or _scope.get() is not None
            or settings.alpha_writes_enabled is not False):
        raise ValueError('CURRENT_ID_REQUEST_CONTEXT_UNAVAILABLE')
    from .generation_customer_context import current_customer_launch_bindings
    profile.require_native(current_customer_launch_bindings(settings,customers.index,now=int(clock())))
    snapshot=customers.current_vault_snapshot(launcher)
    if (snapshot['generationId']!=profile.generation_id or
            (require_fresh and (snapshot['vault']['identityVerified'] or
                snapshot['vault']['identityStatus']!='FRESH_ID_REQUIRED'))):
        # A confirmed stamped owner uses ordinary observation and receipt
        # reconciliation; this scope cannot create a second fresh enrollment.
        raise ValueError('CURRENT_ID_FRESH_ENROLLMENT_NOT_REQUIRED')
    selected=current_identity_settings(settings,profile,runtime=runtime)
    value=CurrentIdentityScope(selected,profile,launcher,snapshot['registrationId'],snapshot['owner'],
        snapshot['authType'],snapshot['checkedAt'],runtime,clock)
    token=_scope.set(value)
    try:yield value
    finally:_scope.reset(token)
