"""Explicit installation of current ID orchestration and finite stamp fees."""
import time
from .generation_customer_identity_context import read_current_identity_profile
from .generation_customer_identity_fees import load_current_identity_authority, CurrentIdentityFeeFaucet
from .generation_customer_identity_runtime import CurrentCustomerIdentityRuntime


def configured_current_customer_identity(settings,customers,*,clock=time.time):
    if not settings.generation_customer_identity_enabled:return None
    if (customers is None or settings.network!='testnet11' or settings.alpha_writes_enabled
            or customers.store.generation_id!=settings.deployment_generation_id):
        raise ValueError('CURRENT_ID_REQUIRES_SEPARATE_CURRENT_CUSTOMER_RUNTIME')
    profile=read_current_identity_profile(settings.generation_customer_identity_profile_path,
        settings.generation_customer_identity_profile_hash)
    if profile.generation_id!=settings.deployment_generation_id:
        raise ValueError('CURRENT_ID_GENERATION_CHANGED')
    authority=load_current_identity_authority(settings,profile,now=int(clock()),allow_expired_read_context=True)
    runtime=CurrentCustomerIdentityRuntime(settings,customers,authority=authority,clock=clock)
    if not authority.issued_at<=int(clock())<authority.expires_at:return runtime
    from .generation_customer_factory import protected_customer_faucet
    from .protocol_submission import ProtocolBundleSubmitter,ProtocolFeePolicy
    from .generation_storage import generation_path
    from .stamp_funding import StampFundingStore
    faucet=protected_customer_faucet(settings.generation_customer_identity_fee_signer_key_path)
    if faucet.address_hex!=authority.funding_puzzle_hash:
        raise ValueError('CURRENT_ID_FEE_KEY_BINDING_CHANGED')
    faucet.add_coin_reservation_source(customers.store.held_funding_ids)
    faucet.add_coin_reservation_source(customers.journal.reserved_input_coin_ids)
    store=StampFundingStore(generation_path(settings.generation_customer_identity_funding_db_path,
        settings.deployment_generation_id),generation_id=settings.deployment_generation_id)
    try:
        faucet.add_coin_reservation_source(store.reserved_coin_ids)
        runtime.funding_store=store
        runtime.fee_submitter=ProtocolBundleSubmitter(provider=customers.provider,
            faucet=CurrentIdentityFeeFaucet(faucet,authority,profile,runtime.ledger,clock=clock),
            policy=ProtocolFeePolicy(enabled=True,minimum_mojos=1,
                maximum_mojos=authority.maximum_stamp_fee_mojos,
                maximum_funding_coin_mojos=authority.maximum_fee_parent_mojos,
                native_admission_enabled=True,cost_fee_tiers_enabled=settings.protocol_fee_cost_tiers_enabled))
        return runtime
    except BaseException:store.close();raise
