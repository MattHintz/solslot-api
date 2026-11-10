"""Prepare an explicitly installed current native checkout; default is closed.

Uses the existing generation-local payment and funding journals. Read-only
recovery reopens the exact fee journal without reading a key, including after
the finite authority expires. No service or public route is enabled here.
"""
from types import SimpleNamespace
import time
import sqlite3
from pathlib import Path
from contextlib import closing

from .generation_customer_factory import protected_customer_faucet
from .generation_customer_runtime import GenerationCustomerRuntime
from .generation_customer_purchase_policy import selected_purchase_policy, selected_prior_purchase_policy
from .generation_customer_collection_policy import TestnetCollectionIssuerPolicy
from .generation_customer_purchase_cutover import read_checkout_cutover
from .generation_customer_purchase_scope import policy_live_at
from .generation_customer_purchase_fees import read_purchase_fee_authority,CurrentPurchaseFeeFaucet,CurrentPurchaseBundleSubmitter
from .generation_customer_purchase_execution import CurrentNativePurchaseExecution
from .generation_customer_purchase_execution_store import CurrentPurchaseExecutionStore
from .generation_storage import generation_path
from .protocol_submission import ProtocolBundleSubmitter,ProtocolFeePolicy


def configured_current_customer_purchase(settings,*,customers,funding_store,clock=time.time):
    if not getattr(settings,'generation_customer_purchase_enabled',False):return None
    if (settings.network!='testnet11' or settings.alpha_writes_enabled
            or not isinstance(customers,GenerationCustomerRuntime)
            or customers.settings is not settings or customers.store.generation_id!=settings.deployment_generation_id
            or funding_store is None
            or generation_path(funding_store.path,settings.deployment_generation_id)!=funding_store.path):
        raise ValueError('CURRENT_PURCHASE_CONFIGURED_RUNTIME_REQUIRED')
    policy=selected_purchase_policy(settings)
    authority=read_purchase_fee_authority(settings.generation_customer_purchase_fee_authority_path,
        settings.generation_customer_purchase_fee_authority_hash,policy)
    now=int(clock())
    collection = isinstance(policy, TestnetCollectionIssuerPolicy)
    cutover = None
    if collection:
        prior = selected_prior_purchase_policy(settings, policy)
        cutover = read_checkout_cutover(settings, prior, policy)
        if (cutover.fee_authority != settings.generation_customer_purchase_fee_authority_hash
                or authority.maximum_total_fee_mojos > cutover.fee_limit_mojos - cutover.inherited_fee_mojos):
            raise ValueError('CURRENT_PURCHASE_FEE_CUTOVER_BUDGET_CHANGED')
    if collection or not authority.issued_at<=now<authority.expires_at:
        path=Path(generation_path(settings.payment_purchase_db_path,settings.deployment_generation_id))
        if not path.is_file() or path.is_symlink():
            raise ValueError('CURRENT_PURCHASE_RECOVERY_JOURNAL_REQUIRED')
        # Missing recovery state must never be materialized as an empty book.
        # Check the prior exact policy before a store constructor can migrate.
        try:
            with closing(sqlite3.connect(path.absolute().as_uri()+'?mode=ro',uri=True)) as db:
                required={'current_customer_purchase_reviews','current_customer_purchase_delivery',
                    'current_customer_purchase_signatures','current_purchase_execution_policies','current_purchase_executions'}
                tables={r[0]for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if collection:
                    row = db.execute('SELECT policy_hash,cutover_hash,fee_cap FROM current_purchase_collection_execution '
                                     'WHERE id=1').fetchone() if required <= tables else None
                    expected = (policy.commitment, settings.generation_customer_purchase_cutover_hash,
                                authority.maximum_stage_fee_mojos)
                else:
                    row=db.execute('SELECT maximum_purchases,fee_cap FROM current_purchase_execution_policies '
                        'WHERE policy_hash=?',(policy.commitment,)).fetchone() if required<=tables else None
                    expected = (policy.maximum_purchases, authority.maximum_stage_fee_mojos)
                if row != expected:
                    raise ValueError('CURRENT_PURCHASE_RECOVERY_POLICY_REQUIRED')
        except sqlite3.Error as exc:raise ValueError('CURRENT_PURCHASE_RECOVERY_JOURNAL_REQUIRED')from exc
    store=CurrentPurchaseExecutionStore(settings.payment_purchase_db_path,settings.deployment_generation_id)
    # Keep the public funding coordinates and existing journal available for
    # restart-after-broadcast recovery, even when all new spending is closed.
    sender=SimpleNamespace(funding_store=funding_store,
        faucet=SimpleNamespace(network='testnet11',address_hex=authority.funding_puzzle_hash),
        policy=ProtocolFeePolicy(enabled=False))
    if (getattr(settings,'generation_customer_purchase_funding_enabled',False)
            and authority.issued_at<=int(clock())<authority.expires_at):
        faucet=protected_customer_faucet(settings.generation_customer_purchase_fee_signer_key_path)
        faucet.add_coin_reservation_source(customers.store.held_funding_ids)
        faucet.add_coin_reservation_source(customers.journal.reserved_input_coin_ids)
        faucet.add_coin_reservation_source(funding_store.reserved_coin_ids)
        guarded=CurrentPurchaseFeeFaucet(faucet,authority,policy,store,clock=clock,
            funding_store=funding_store,cutover=cutover)
        sender=CurrentPurchaseBundleSubmitter(execution_store=store,clock=clock,provider=customers.provider,faucet=guarded,funding_store=funding_store,
            policy=ProtocolFeePolicy(enabled=True,minimum_mojos=1,
                maximum_mojos=authority.maximum_stage_fee_mojos,
                maximum_funding_coin_mojos=authority.maximum_fee_parent_mojos,native_admission_enabled=True,
                cost_fee_tiers_enabled=bool(getattr(settings,'protocol_fee_cost_tiers_enabled',False))))
    return CurrentNativePurchaseExecution(settings=settings,anchor=customers.index.anchor,
        provider=customers.provider,policy=policy,store=store,fee_cap=authority.maximum_stage_fee_mojos,
        submitter=sender,clock=clock,cutover=cutover)


def configured_current_purchase_worker(settings,service):
    if not getattr(settings,'generation_customer_purchase_worker_enabled',False):return None
    if not isinstance(service,CurrentNativePurchaseExecution) or service.settings is not settings:
        raise ValueError('CURRENT_PURCHASE_WORKER_CONFIGURED_SERVICE_REQUIRED')
    if not policy_live_at(service.policy, int(service.clock())):
        return None
    if isinstance(service.policy, TestnetCollectionIssuerPolicy) and not service.submitter.policy.enabled:
        return None
    service._funding_context()
    from .generation_customer_purchase_worker import CurrentPurchaseWorker
    from .generation_customer_purchase_issuer_client import PrivateCurrentIssuerClient
    worker = CurrentPurchaseWorker(service,issuer_sign=PrivateCurrentIssuerClient(settings))
    if isinstance(service.policy, TestnetCollectionIssuerPolicy):
        service.purchase_worker = worker
    return worker
