"""Independent batch proceeds checks using the original finite issuer journal."""
from contextlib import nullcontext
from chia.consensus.condition_tools import conditions_dict_for_solution,pkm_pairs_for_conditions_dict
from chia_rs import AugSchemeMPL,G2Element,SpendBundle
from solslot_puzzles.generation_revenue import CompanyRevenue,PrimaryFeeSplitter
from solslot_puzzles.generation_statutes import GenerationStatutes
from solslot_puzzles.testnet_primary_forwarding import build_testnet_primary_forwarding
from .generation_customer_purchase_batch import verify_current_batch_delivery,fresh_children,h
from .generation_customer_issuer import TestnetIssuerJournal
from .generation_sols_batch_execution import unspent
from .faucet import AGG_SIG_ME_DATA


async def sign_batch_issuer(request,*,settings,anchor,provider,journal,load_key,clock,journal_lock):
    if (not isinstance(journal,TestnetIssuerJournal)or not callable(load_key)or settings.network!='testnet11'
            or not settings.generation_customer_purchase_enabled or request.generation_id!=settings.deployment_generation_id
            or request.policy_hash!=journal.policy.commitment or request.claim.digest()!=request.claim_hash):
        raise ValueError('CURRENT_ISSUER_FIXED_CONTEXT_REQUIRED')
    evidence=await verify_current_batch_delivery(request.claim,settings=settings,anchor=anchor,provider=provider,
        issuer_policy=journal.policy,expected_issuer_policy_hash=request.policy_hash,clock=clock)
    raw=request.purchase_bundle
    if set(raw)!={'coin_spends','aggregated_signature'}or not isinstance(raw['coin_spends'],list)or not 1<=len(raw['coin_spends'])<=256:
        raise ValueError('CURRENT_ISSUER_BUNDLE_BOUND_REQUIRED')
    bundle=SpendBundle.from_json_dict(raw)
    if len(bytes(bundle))>4*1024*1024 or [bytes(s)for s in bundle.coin_spends]!=[bytes(s)for s in evidence.bundle.coin_spends]:
        raise ValueError('CURRENT_ISSUER_NATIVE_BUNDLE_CHANGED')
    pairs=[pair for spend in bundle.coin_spends for pair in pkm_pairs_for_conditions_dict(
        conditions_dict_for_solution(spend.puzzle_reveal,spend.solution,100_000_000),spend.coin,AGG_SIG_ME_DATA['testnet11'])]
    if not pairs or not AugSchemeMPL.aggregate_verify([p[0]for p in pairs],[p[1]for p in pairs],bundle.aggregated_signature):
        raise ValueError('CURRENT_ISSUER_BUYER_AND_QUORUM_SIGNATURES_REQUIRED')
    chain=evidence.inventory.evidence
    statutes=[c.state for c in chain.economic_components.values()if isinstance(c.state,GenerationStatutes)]
    if len(statutes)!=1:raise ValueError('CURRENT_ISSUER_NATIVE_FEES_REQUIRED')
    fees=PrimaryFeeSplitter(chain.governance.state.sgt,statutes[0].launcher_id,
        CompanyRevenue(journal.policy.generation,chain.registry.state.administrator_id))
    terms=[c.item.original.terms for c in evidence.children]
    companions=[build_testnet_primary_forwarding(bundle=bundle,artifact=a,terms=t,
        issuer_public_key=journal.policy.issuer_public_key,fees=fees)for a,t in zip(evidence.batch.artifacts,terms,strict=True)]
    expected=[]
    for companion in companions:
        spend=companion.issuer_signature_spend
        current=pkm_pairs_for_conditions_dict(conditions_dict_for_solution(spend.puzzle_reveal,spend.solution,100_000_000),spend.coin,AGG_SIG_ME_DATA['testnet11'])
        if len(current)!=1:raise ValueError('CURRENT_ISSUER_SIGNATURE_SCOPE_CHANGED')
        expected.extend(current)
    if (any(h(p[0])!=request.issuer_public_key for p in expected)
            or request.message!=[h(p[1])for p in expected]
            or request.issuer_coin_spend!=[c.issuer_signature_spend.to_json_dict()for c in companions]):
        raise ValueError('CURRENT_ISSUER_COORDINATOR_REVIEW_CHANGED')
    await fresh_children(evidence.children,provider);await unspent(provider,evidence.payment_coin)
    allowed={bytes(p[1])for p in expected};private=None
    def fixed_sign(message):
        nonlocal private
        if message not in allowed or int(clock())>=min(evidence.batch.artifacts[0].quote_expires_at,journal.policy.expires_at):
            raise ValueError('CURRENT_ISSUER_MESSAGE_OR_DEADLINE_CHANGED')
        if private is None:
            private=load_key()
            if bytes(private.get_g1())!=journal.policy.issuer_public_key:raise ValueError('CURRENT_ISSUER_FIXED_KEY_CHANGED')
        return AugSchemeMPL.sign(private,message)
    with journal_lock if journal_lock is not None else nullcontext():
        journal.authorize_batch(bundle=bundle,artifacts=evidence.batch.artifacts,terms=terms,fees=fees,now=int(clock()),sign_message=fixed_sign)
        signatures=[G2Element.from_bytes(bytes.fromhex(journal.db.execute(
            'SELECT signature FROM issuer_forwarding WHERE artifact_hash=?',(h(a.artifact_hash),)).fetchone()[0][2:]))for a in evidence.batch.artifacts]
    signature=AugSchemeMPL.aggregate(signatures)
    if not AugSchemeMPL.aggregate_verify([p[0]for p in expected],[p[1]for p in expected],signature):
        raise ValueError('CURRENT_ISSUER_SAVED_SIGNATURE_INVALID')
    return signature
