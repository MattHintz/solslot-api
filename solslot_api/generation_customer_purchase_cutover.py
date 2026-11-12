"""Read the pinned evidence from retiring the previous Testnet checkout."""
from contextlib import closing
from hashlib import sha256
from pathlib import Path
import sqlite3
from typing import Literal

from pydantic import Field, StrictInt, model_validator

from .generation_execution import Hash
from .generation_index import _bounded_file
from .generation_preparation import PreparationModel


class RetiredCheckout(PreparationModel):
    intent_id: Hash = Field(alias='intentId')
    claim_hash: Hash = Field(alias='claimHash')
    outcome: Literal['UNSTARTED', 'UNSUBMITTED_EXPIRED', 'RELEASED', 'COMPLETE']


class CheckoutCutover(PreparationModel):
    schema_version: Literal['solslot.testnet-checkout-cutover.v1'] = Field(alias='schema')
    generation_id: Hash = Field(alias='generationId')
    anchor_hash: Hash = Field(alias='anchorHash')
    prior_policy: Hash = Field(alias='priorPolicy')
    collection_policy: Hash = Field(alias='collectionPolicy')
    fee_authority: Hash = Field(alias='feeAuthority')
    prior_issuer_rows: Hash = Field(alias='priorIssuerRows')
    purchase_journal_snapshot: Hash = Field(alias='purchaseJournalSnapshot')
    funding_journal_snapshot: Hash = Field(alias='fundingJournalSnapshot')
    fee_limit_mojos: StrictInt = Field(alias='feeLimitMojos', gt=0, le=50_000_000_000)
    inherited_fee_mojos: StrictInt = Field(alias='inheritedFeeMojos', ge=0)
    peak_hash: Hash = Field(alias='peakHash')
    peak_height: StrictInt = Field(alias='peakHeight', gt=0)
    transaction_time: StrictInt = Field(alias='transactionTime', gt=0)
    retired_orders: tuple[RetiredCheckout, ...] = Field(alias='retiredOrders', max_length=512)

    @model_validator(mode='after')
    def exact_bindings(self):
        if (self.prior_policy == self.collection_policy
                or self.inherited_fee_mojos > self.fee_limit_mojos
                or len({item.intent_id for item in self.retired_orders}) != len(self.retired_orders)):
            raise ValueError('CURRENT_CHECKOUT_CUTOVER_INVALID')
        return self


def read_checkout_cutover(settings, prior, policy):
    raw = _bounded_file(settings.generation_customer_purchase_cutover_path, 256 * 1024)
    if '0x' + sha256(raw).hexdigest() != settings.generation_customer_purchase_cutover_hash:
        raise ValueError('CURRENT_CHECKOUT_CUTOVER_FILE_CHANGED')
    value = CheckoutCutover.model_validate_json(raw)
    if (value.generation_id != settings.deployment_generation_id
            or value.anchor_hash != settings.generation_chain_anchor_hash
            or value.prior_policy != prior.commitment
            or value.collection_policy != policy.commitment):
        raise ValueError('CURRENT_CHECKOUT_CUTOVER_SCOPE_CHANGED')
    return value


def activate_checkout_journal(purchase_path, funding_path, *, settings, prior, policy):
    """Bind a verified cutover to the existing coordinator journal.

    Run offline while all legacy checkout roles are fenced. Both existing
    databases must match the collected closure at the first activation.
    """
    from .generation_customer_purchase_cutover_evidence import checkout_journal_snapshots
    from .generation_customer_purchase_fees import read_purchase_fee_authority
    from .generation_customer_purchase_policy import validate_collection_policy_successor

    validate_collection_policy_successor(prior, policy)
    cutover = read_checkout_cutover(settings, prior, policy)
    authority = read_purchase_fee_authority(settings.generation_customer_purchase_fee_authority_path,
        settings.generation_customer_purchase_fee_authority_hash, policy)
    if (cutover.fee_authority != settings.generation_customer_purchase_fee_authority_hash
            or authority.maximum_total_fee_mojos > cutover.fee_limit_mojos - cutover.inherited_fee_mojos):
        raise ValueError('CURRENT_CHECKOUT_CUTOVER_BUDGET_CHANGED')
    purchase_path, funding_path = Path(purchase_path), Path(funding_path)
    if any(not path.is_file() or path.is_symlink() for path in (purchase_path, funding_path)):
        raise ValueError('CURRENT_CHECKOUT_CUTOVER_JOURNALS_REQUIRED')
    expected = (policy.commitment, settings.generation_customer_purchase_cutover_hash,
        authority.maximum_stage_fee_mojos)
    with closing(sqlite3.connect(purchase_path.absolute().as_uri() + '?mode=rw', uri=True)) as purchase, \
            closing(sqlite3.connect(funding_path.absolute().as_uri() + '?mode=rw', uri=True)) as funding:
        with purchase, funding:
            purchase.execute('BEGIN IMMEDIATE')
            funding.execute('BEGIN IMMEDIATE')
            for database in (purchase, funding):
                bindings = database.execute('SELECT generation_id, network FROM deployment_generation_binding').fetchall()
                if bindings != [(cutover.generation_id, 'testnet11')]:
                    raise ValueError('CURRENT_CHECKOUT_CUTOVER_JOURNAL_SCOPE_CHANGED')
            existing = purchase.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='current_purchase_collection_execution'"
            ).fetchone()
            if existing is not None:
                binding = purchase.execute(
                    'SELECT policy_hash, cutover_hash, fee_cap FROM current_purchase_collection_execution WHERE id=1'
                ).fetchone()
                if binding != expected:
                    raise ValueError('CURRENT_CHECKOUT_CUTOVER_ALREADY_BOUND')
                return cutover
            if checkout_journal_snapshots(purchase, funding) != (
                    cutover.purchase_journal_snapshot, cutover.funding_journal_snapshot):
                raise ValueError('CURRENT_CHECKOUT_CUTOVER_JOURNAL_CHANGED')
            purchase.execute('''CREATE TABLE current_purchase_collection_execution (
                id INTEGER PRIMARY KEY CHECK(id=1), policy_hash TEXT NOT NULL,
                cutover_hash TEXT NOT NULL, fee_cap INTEGER NOT NULL)''')
            purchase.execute('INSERT INTO current_purchase_collection_execution VALUES (1,?,?,?)', expected)
    return cutover
