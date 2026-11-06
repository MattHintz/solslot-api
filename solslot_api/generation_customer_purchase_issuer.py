"""Independently reconstruct a finite Testnet issuer-forwarding request.

The caller installs a protected, fixed key loader. Requests cannot choose a key,
treasury, message, fee or spend. The existing issuer journal bounds the number
of purchases and preserves the first signature before it can be returned.
"""
import time
from pydantic import Field
from chia.consensus.condition_tools import conditions_dict_for_solution,pkm_pairs_for_conditions_dict
from chia_rs import AugSchemeMPL,SpendBundle
from solslot_puzzles.payment_artifacts_v3 import purchase_artifact_v3_from_json
from solslot_puzzles.generation_revenue import CompanyRevenue,PrimaryFeeSplitter
from solslot_puzzles.generation_statutes import GenerationStatutes
from .generation_execution import Model,Hash
from .generation_customer_issuer import TestnetIssuerJournal
from .generation_customer_purchase_delivery import CurrentDeliveryClaim,verify_current_delivery
from .generation_chain_evidence import current_evidence_unchanged
from .generation_sols_batch_execution import unspent
from .faucet import AGG_SIG_ME_DATA


class CurrentIssuerRequest(Model):
    generation_id:Hash=Field(alias='generationId')
    policy_hash:Hash=Field(alias='policyHash')
    claim:CurrentDeliveryClaim
    claim_hash:Hash=Field(alias='claimHash')
    purchase_bundle:dict=Field(alias='purchaseBundle')
    issuer_coin_spend:dict=Field(alias='issuerCoinSpend')
    issuer_public_key:str=Field(alias='issuerPublicKey',pattern=r'^0x[0-9a-f]{96}$')
    message:str=Field(pattern=r'^0x[0-9a-f]{1,2048}$')


async def sign_current_issuer(request,*,settings,anchor,provider,journal,load_key,clock=time.time,journal_lock=None):
    if (not isinstance(request,CurrentIssuerRequest) or not isinstance(journal,TestnetIssuerJournal)
            or not callable(load_key) or settings.network!='testnet11'
            or getattr(settings,'generation_customer_purchase_enabled',False)is not True
            or request.generation_id!=settings.deployment_generation_id
            or request.policy_hash!=journal.policy.commitment
            or request.claim.digest()!=request.claim_hash):
        raise ValueError('CURRENT_ISSUER_FIXED_CONTEXT_REQUIRED')
    evidence=await verify_current_delivery(request.claim,settings=settings,anchor=anchor,provider=provider,
        issuer_policy=journal.policy,expected_issuer_policy_hash=request.policy_hash,clock=clock)
    if (set(request.purchase_bundle)!={'coin_spends','aggregated_signature'}
            or not isinstance(request.purchase_bundle.get('coin_spends'),list)
            or not 1<=len(request.purchase_bundle['coin_spends'])<=32):
        raise ValueError('CURRENT_ISSUER_BUNDLE_BOUND_REQUIRED')
    bundle=SpendBundle.from_json_dict(request.purchase_bundle)
    if (len(bytes(bundle))>512000
            or [bytes(s)for s in bundle.coin_spends]!=[bytes(s)for s in evidence.bundle.coin_spends]):
        raise ValueError('CURRENT_ISSUER_NATIVE_BUNDLE_CHANGED')
    pairs=[p for spend in bundle.coin_spends for p in pkm_pairs_for_conditions_dict(
        conditions_dict_for_solution(spend.puzzle_reveal,spend.solution,100_000_000),
        spend.coin,AGG_SIG_ME_DATA['testnet11'])]
    if not pairs or not AugSchemeMPL.aggregate_verify([p[0]for p in pairs],[p[1]for p in pairs],bundle.aggregated_signature):
        raise ValueError('CURRENT_ISSUER_BUYER_AND_QUORUM_SIGNATURES_REQUIRED')
    chain=evidence.inventory.evidence
    statutes=[item.state for item in chain.economic_components.values()if isinstance(item.state,GenerationStatutes)]
    if len(statutes)!=1:raise ValueError('CURRENT_ISSUER_NATIVE_FEES_REQUIRED')
    fees=PrimaryFeeSplitter(chain.governance.state.sgt,statutes[0].launcher_id,
        CompanyRevenue(journal.policy.generation,chain.registry.state.administrator_id))
    from solslot_puzzles.testnet_primary_forwarding import build_testnet_primary_forwarding
    artifact=purchase_artifact_v3_from_json(request.claim.reservation.purchase_artifact)
    forwarding=build_testnet_primary_forwarding(bundle=bundle,artifact=artifact,
        terms=evidence.item.original.terms,issuer_public_key=journal.policy.issuer_public_key,fees=fees)
    spend=forwarding.issuer_signature_spend
    expected=pkm_pairs_for_conditions_dict(conditions_dict_for_solution(spend.puzzle_reveal,spend.solution,100_000_000),
        spend.coin,AGG_SIG_ME_DATA['testnet11'])
    if (len(expected)!=1 or request.issuer_public_key!='0x'+bytes(expected[0][0]).hex()
            or request.message!='0x'+bytes(expected[0][1]).hex()
            or request.issuer_coin_spend!=spend.to_json_dict()):
        raise ValueError('CURRENT_ISSUER_COORDINATOR_REVIEW_CHANGED')
    # All network checks precede the only credential callback. The journal
    # returns its retained signature without loading the key on a retry.
    if not await current_evidence_unchanged(chain,provider=provider):
        raise ValueError('CURRENT_ISSUER_AUTHORITY_CHANGED')
    await unspent(provider,evidence.payment_coin)
    await unspent(provider,evidence.reservation_transition.reserved_coin)
    await unspent(provider,evidence.vault.coin)
    def fixed_sign(message):
        if message!=bytes(expected[0][1]) or int(clock())>=min(artifact.quote_expires_at,journal.policy.expires_at):
            raise ValueError('CURRENT_ISSUER_MESSAGE_OR_DEADLINE_CHANGED')
        private=load_key()
        if bytes(private.get_g1())!=journal.policy.issuer_public_key:
            raise ValueError('CURRENT_ISSUER_FIXED_KEY_CHANGED')
        return AugSchemeMPL.sign(private,message)
    from contextlib import nullcontext
    with journal_lock if journal_lock is not None else nullcontext():
        journal.authorize(bundle=bundle,artifact=artifact,terms=evidence.item.original.terms,
            fees=fees,now=int(clock()),sign_message=fixed_sign)
        row=journal.db.execute('SELECT signature FROM issuer_forwarding WHERE artifact_hash=?',
            ('0x'+artifact.artifact_hash.hex(),)).fetchone()
    from chia_rs import G2Element
    signature=G2Element.from_bytes(bytes.fromhex(row['signature'][2:]))
    if not AugSchemeMPL.verify(expected[0][0],expected[0][1],signature):
        raise ValueError('CURRENT_ISSUER_SAVED_SIGNATURE_INVALID')
    return signature


def load_fixed_issuer_key(settings):
    """Installed path only; no request can select or return a private key."""
    import os,stat
    from pathlib import Path
    from chia_rs import PrivateKey
    p=Path(settings.generation_customer_purchase_issuer_key_path)
    info=p.lstat()
    if (not p.is_absolute() or p.is_symlink() or not stat.S_ISREG(info.st_mode)
            or info.st_uid not in (0,os.geteuid()) or info.st_mode&0o077 or not 64<=info.st_size<=66):
        raise ValueError('CURRENT_ISSUER_PROTECTED_FIXED_KEY_REQUIRED')
    raw=p.read_text().strip()
    if len(raw)!=64 or any(c not in '0123456789abcdef'for c in raw):
        raise ValueError('CURRENT_ISSUER_FIXED_KEY_INVALID')
    return PrivateKey.from_bytes(bytes.fromhex(raw))
