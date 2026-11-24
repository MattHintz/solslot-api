"""Private, read-only current-generation proof for one retained two-deed Stripe test order."""
from dataclasses import dataclass
from hashlib import sha256
import re
import time

from chia.types.blockchain_format.program import Program
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD_HASH
from chia_rs import Coin
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.payment_artifacts_v3 import (
    PurchaseBatchV1, STRIPE_PAYMENT_PROVIDER_ID, build_purchase_batch_settlement_receipt_v1,
    build_stripe_purchase_artifact_v3, purchase_batch_from_json, purchase_batch_to_json,
)
from solslot_puzzles.stripe_settlement_v1_driver import (
    InventoryReservationV1, PurchaseBatchSettlementTermsV1, build_inventory_reservation_spend,
    build_purchase_batch_receipt_spend, curry_purchase_batch_settlement_receipt,
)
from solslot_puzzles.vault_driver import puzzle_hash_for_p2_vault

from .bootstrap_manifest import content_hash
from .generation_chain_evidence import current_evidence_unchanged
from .generation_coin_evidence import read_confirmed_coin
from .generation_customer_context import customer_bindings_from_evidence
from .generation_customer_inventory import h, resolve_current_primary_inventory
from .generation_customer_vault import resolve_native_identity_vault
from .generation_preparation import read_generation_preparation
from .generation_registry_evidence import _spend
from .generation_sols_batch_execution import unspent


@dataclass(frozen=True)
class StripeOrderScope:
    release_id: bytes32
    generation: bytes32
    anchor_hash: bytes32
    collection: bytes32
    edition: bytes32
    metadata_root: bytes32
    vault: bytes32
    purchase_id: bytes32
    launchers: tuple[bytes32, bytes32]
    originals: tuple[bytes32, bytes32]
    issued_at: int
    expires_at: int
    purchase_intent_id: str
    offer_artifact_hash: str

    def __post_init__(self):
        hashes = (self.release_id, self.generation, self.anchor_hash, self.collection, self.edition,
                  self.metadata_root, self.vault, self.purchase_id, *self.launchers, *self.originals)
        if (not isinstance(self.purchase_intent_id, str) or not 0 < len(self.purchase_intent_id) <= 256
                or not isinstance(self.offer_artifact_hash,str) or not re.fullmatch(r'sha256:[0-9a-f]{64}',self.offer_artifact_hash)
                or any(not isinstance(value, bytes32) or value == bytes32.zeros for value in hashes)
                or len(self.launchers) != 2 or tuple(sorted(set(self.launchers))) != self.launchers
                or len(self.originals) != 2 or len(set(self.originals)) != 2
                or type(self.issued_at) is not int or type(self.expires_at) is not int
                or not 0 < self.issued_at < self.expires_at):
            raise ValueError("Invalid two-deed Stripe release scope")


@dataclass(frozen=True)
class StripeNativeEvidence:
    release_id: str
    generation_id: str
    collection_id: str
    vault_launcher_id: str
    vault_coin_id: str
    owner_key: str
    owner_auth_type: int
    owner_account: str
    credential_root: str
    destination_puzzle_hash: str
    purchase_id: str
    batch_hash: str
    purchase_intent_id: str
    offer_artifact_hash: str
    genesis_artifact_hash: str
    deed_launcher_ids: tuple[str, ...]
    original_coin_ids: tuple[str, ...]
    reserved_coin_ids: tuple[str, ...]
    confirmation_height: int
    expires_at: int
    batch: PurchaseBatchV1


@dataclass(frozen=True)
class StripeOrderReview:
    document: dict
    native: StripeNativeEvidence | None = None


def prove_receipt_shape(batch, keys, observed_at):
    """Check the actual compiled receipt before taking money. The probe authorizes nothing."""
    placeholder = bytes32(sha256(b'Sols Lot unsigned Stripe receipt shape '+batch.batch_hash).digest())
    receipt = build_purchase_batch_settlement_receipt_v1(
        batch=batch, provider_id=STRIPE_PAYMENT_PROVIDER_ID, external_reference_hash=placeholder,
        evidence_hash=placeholder, observed_at=observed_at, validator_pubkeys=keys,
        collected_amount_minor=batch.total_rail_amount,
    )
    terms = PurchaseBatchSettlementTermsV1(receipt, keys)
    puzzle = curry_purchase_batch_settlement_receipt(terms)
    coin = Coin(placeholder, puzzle.get_tree_hash(), batch.quantity)
    spend = build_purchase_batch_receipt_spend(receipt_coin=coin, terms=terms, signer_indices=(0, 1))
    puzzle.run_with_cost(100_000_000, Program.from_bytes(bytes(spend.solution)))


def stripe_artifact(terms, vault, root, nonce, authorization_expires_at, quote_expires_at):
    return build_stripe_purchase_artifact_v3(network=terms.network, collection_id=terms.collection_id,
        deed_launcher_id=terms.deed_launcher_id, metadata_root=terms.metadata_root, metadata_anchor_id=terms.metadata_anchor_id,
        share_ppm=terms.share_ppm, base_usd_amount_minor=terms.base_amount_minor, technology_fee_bps=terms.technology_fee_bps,
        protocol_treasury_puzzle_hash=terms.protocol_treasury_puzzle_hash, zkpassport_root=root,
        vault_launcher_id=vault, vault_p2_puzzle_hash=puzzle_hash_for_p2_vault(vault),
        authorization_nonce=nonce, authorization_expires_at=authorization_expires_at,
        quote_expires_at=quote_expires_at)


def original_reservation(item, artifact, indices):
    t = item.terms
    parent = item.launcher_spend.coin
    expected = build_inventory_reservation_spend(
        available_coin=item.coin,
        deed_singleton_struct=Program.to((SINGLETON_MOD_HASH,(t.deed_launcher_id,t.deed_launcher_puzzle_hash))),
        lineage_proof=LineageProof(parent.parent_coin_info,amount=parent.amount), terms=t,
        reservation=InventoryReservationV1(artifact,artifact.quote_expires_at), signer_indices=indices,
    )
    return expected


def check_offer(scope, batch, offer):
    embedded = offer.get('protocol') or {}
    expected = {'purchaseIntentId':scope.purchase_intent_id,'rail':'stripe','quantity':2,
                'vaultLauncherId':h(scope.vault),'zkPassportRequired':True,'collectionId':h(scope.collection),
                'purchaseId':h(batch.purchase_id),'purchaseArtifactHash':h(batch.batch_hash),
                'deedLauncherIds':[h(a.deed_launcher_id) for a in batch.artifacts]}
    if (content_hash(offer) != scope.offer_artifact_hash or offer.get('schemaVersion') != 4
            or offer.get('network') != 'testnet11' or offer.get('kind') != 'solslot_protocol_offer'
            or offer.get('protocolVersion') != 'solslot-v2' or not offer.get('genesisArtifactHash')
            or offer.get('purchaseBatchV1') != purchase_batch_to_json(batch)
            or any(embedded.get(key) != value or type(embedded.get(key)) is not type(value)
                   for key,value in expected.items())):
        raise ValueError('Original Stripe offer envelope differs from its purchase')


def checked_batch(scope, record, rows):
    batch = purchase_batch_from_json(record.purchase_artifact)
    if (purchase_batch_to_json(batch) != record.purchase_artifact or batch.purchase_id != scope.purchase_id
            or record.rail != 'stripe' or record.purchase_id != h(batch.purchase_id)
            or record.artifact_hash != h(batch.batch_hash) or record.purchase_intent_id != scope.purchase_intent_id
            or record.offer_artifact_hash != scope.offer_artifact_hash
            or batch.network != 'testnet11' or batch.quantity != 2 or batch.rail.name != 'STRIPE'
            or batch.artifacts[0].collection_id != scope.collection or batch.vault_launcher_id != scope.vault
            or batch.vault_p2_puzzle_hash != puzzle_hash_for_p2_vault(scope.vault)
            or tuple(a.deed_launcher_id for a in batch.artifacts) != scope.launchers
            or record.deed_launcher_ids != tuple(map(h, scope.launchers)) or len(rows) != 2
            or record.quote_expires_at != batch.quote_expires_at or batch.quote_expires_at > scope.expires_at):
        raise ValueError('Stripe order differs from its original release')
    check_offer(scope, batch, record.offer_artifact)
    for index, (a, row) in enumerate(zip(batch.artifacts, rows, strict=True)):
        if (row.ordinal != index or row.deed_launcher_id != h(a.deed_launcher_id)
                or row.child_artifact_hash != h(a.artifact_hash) or row.child_purchase_id != h(a.purchase_id)
                or a.metadata_root != scope.metadata_root or a.metadata_anchor_id != scope.edition
                or a.quote_expires_at > a.authorization_expires_at or a.purchase_kind.name != 'DIRECT' or a.delivery_kind.name != 'SMARTDEED'
                or (a.base_amount_minor, a.technology_fee_bps, a.technology_fee_minor, a.rail_amount)
                != (300000, 100, 3000, 303000)):
            raise ValueError('Stripe deed or minted USD terms changed')
    return batch


def public_review(scope, batch, state):
    return dict(schema='solslot.current-stripe-order.v1', generationId=h(scope.generation),
        collectionId=h(scope.collection), vaultLauncherId=h(scope.vault),
        destinationPuzzleHash=h(batch.vault_p2_puzzle_hash), purchaseId=h(batch.purchase_id),
        purchaseBatch=purchase_batch_to_json(batch), quoteExpiresAt=batch.quote_expires_at,
        baseAmountMinor=batch.total_base_amount_minor, technologyFeeMinor=batch.total_technology_fee_minor,
        totalAmountMinor=batch.total_rail_amount, currency='usd', quantity=batch.quantity,
        deedLauncherIds=[h(a.deed_launcher_id) for a in batch.artifacts], state=state, validUntil=None)


class CurrentStripeOrder:
    """Installed privately with one immutable order and its local payment journal."""
    def __init__(self, *, settings, scope, store, clock=time.time):
        self.settings = settings
        self.scope = scope
        self.store = store
        self.clock = clock

    def recovering_payment(self, purchase_id):
        existing_hold = self.store.checkout_hold(purchase_id)
        return bool(self.store.checkout_terminal(purchase_id)
                    or self.store.inventory_timeout_operations(purchase_id)
                    or self.store.inventory_extension_operations(purchase_id)
                    or existing_hold and existing_hold['state'] != 'ARMED')

    async def current_custody(self, customers, snapshot):
        scope = self.scope
        anchor, provider = customers.index.anchor, customers.provider
        inventory = await resolve_current_primary_inventory(settings=self.settings, anchor=anchor, provider=provider,
            collection=scope.collection, edition_hash=scope.edition, metadata_root=scope.metadata_root)
        bindings = customer_bindings_from_evidence(read_generation_preparation(self.settings), anchor, inventory.evidence)
        vault = await resolve_native_identity_vault(bindings=bindings, launcher=scope.vault, provider=provider)
        if (vault.public() != snapshot['vault'] or vault.generation != scope.generation
                or not vault.identity_verified or vault.launcher != scope.vault):
            raise ValueError('Confirmed Stripe recipient changed')
        _, args = vault.inner.uncurry()
        _, owner_key, owner_kind, *_ = args.as_iter()
        if (h(owner_key.as_atom()) != snapshot['ownerPublicKey'].lower()
                or {'chia_bls':1, 'evm':3}.get(snapshot['authType']) != owner_kind.as_int()):
            raise ValueError('Confirmed receiving vault owner changed')
        return inventory, vault

    async def prepare_originals(self, customers, snapshot, *, authorization_nonce, batch_nonce,
                                authorization_expires_at, quote_expires_at, signer_indices):
        """Prepare immutable quote and unsigned reservation messages for separate release/signers."""
        from solslot_puzzles.payment_artifacts_v3 import build_purchase_batch_v1
        from chia.wallet.util.compute_additions import compute_additions
        scope = self.scope
        now = int(self.clock())
        if (self.settings.network != 'testnet11' or h(scope.generation) != self.settings.deployment_generation_id
                or h(scope.anchor_hash) != self.settings.generation_chain_anchor_hash
                or not scope.issued_at <= now < quote_expires_at <= authorization_expires_at <= scope.expires_at):
            raise ValueError('Original Stripe quote is outside its release')
        inventory,vault = await self.current_custody(customers,snapshot)
        transitions = []
        keys = None
        for launcher, original_id in zip(scope.launchers,scope.originals,strict=True):
            item = inventory.require_available(launcher)
            if item.original.coin != item.current.coin or item.original.coin.name() != original_id:
                raise ValueError('Stripe original has already moved')
            terms = item.original.terms
            if ((terms.base_amount_minor,terms.technology_fee_bps,terms.technology_fee_minor) != (300000,100,3000)
                    or (keys is not None and keys != terms.validator_pubkeys)):
                raise ValueError('Stripe original minted terms changed')
            keys = terms.validator_pubkeys
            artifact = stripe_artifact(terms,scope.vault,vault.root,authorization_nonce,authorization_expires_at,quote_expires_at)
            transition = original_reservation(item.original,artifact,signer_indices)
            if compute_additions(transition.spend) != [transition.reserved_coin]:
                raise ValueError('Original Stripe reservation output changed')
            transitions.append(transition)
        batch = build_purchase_batch_v1(batch_nonce=batch_nonce,artifacts=tuple(t.reservation.artifact for t in transitions))
        if batch.purchase_id != scope.purchase_id:
            raise ValueError('Original Stripe batch differs from the one-order release')
        prove_receipt_shape(batch,keys,now)
        provider = customers.provider
        if not await current_evidence_unchanged(inventory.evidence,provider=provider):
            raise ValueError('Stripe generation changed during preparation')
        for coin in (vault.coin, *(transition.spend.coin for transition in transitions)):
            await unspent(provider,coin)
            if await provider.primary.get_mempool_items_by_coin_name(h(coin.name())) != []:
                raise ValueError('Original Stripe custody is busy')
        if not now <= int(self.clock()) < quote_expires_at:
            raise ValueError('Original Stripe preparation expired')
        return batch, tuple(transitions)

    async def retain_original_offer(self, customers, snapshot, offer, *, signer_indices):
        """Provision the existing service-authorized offer into its ordinary durable journal."""
        scope = self.scope
        if content_hash(offer) != scope.offer_artifact_hash:
            raise ValueError('Unrecognized original Stripe offer')
        batch = purchase_batch_from_json(offer['purchaseBatchV1'])
        first = batch.artifacts[0]
        prepared, transitions = await self.prepare_originals(customers,snapshot,
            authorization_nonce=first.authorization_nonce, batch_nonce=batch.batch_nonce,
            authorization_expires_at=first.authorization_expires_at, quote_expires_at=first.quote_expires_at,
            signer_indices=signer_indices)
        credential = offer.get('vaultCredentialReceipt') or {}
        if (prepared != batch or purchase_batch_to_json(batch) != offer['purchaseBatchV1']
                or offer['protocol'].get('purchaseIntentId') != scope.purchase_intent_id
                or credential.get('vaultLauncherId') != h(scope.vault)
                or credential.get('chiaVaultCoinId') != snapshot['vault']['currentCoinId']
                or credential.get('identityAttestRoot') != h(batch.zkpassport_root)):
            raise ValueError('Original Stripe offer and current custody differ')
        check_offer(scope, batch, offer)
        self.store.save(purchase_intent_id=scope.purchase_intent_id,rail='stripe',
            offer_artifact_hash=scope.offer_artifact_hash,offer_artifact=offer,
            purchase_artifact=purchase_batch_to_json(batch),created_at=int(self.clock()))
        return batch,transitions

    async def review(self, customers, snapshot):
        scope = self.scope
        settings = self.settings
        now = int(self.clock())
        custody = snapshot['vault']
        if (settings.network != 'testnet11' or snapshot['network'] != 'testnet11'
                or settings.deployment_generation_id != h(scope.generation)
                or settings.generation_chain_anchor_hash != h(scope.anchor_hash)
                or snapshot['generationId'] != h(scope.generation)
                or custody['vaultLauncherId'] != h(scope.vault) or custody['identityVerified'] is not True
                or snapshot['p2VaultPuzzleHash'] != h(puzzle_hash_for_p2_vault(scope.vault))):
            raise ValueError('Current authorized Stripe vault unavailable')
        saved = self.store.inventory_status_snapshot(h(scope.purchase_id))
        record, rows, expiry_evidence, release_evidence = saved
        batch = checked_batch(scope, record, rows)
        credential = record.offer_artifact.get('vaultCredentialReceipt') or {}
        if (h(batch.zkpassport_root) != custody['identityAttestRoot']
                or credential.get('vaultLauncherId') != h(scope.vault)
                or credential.get('chiaVaultCoinId') != custody['currentCoinId']
                or credential.get('identityAttestRoot') != custody['identityAttestRoot']):
            raise ValueError('Current vault identity differs from the order')
        doc = public_review(scope, batch, 'PAYMENT_UNAVAILABLE')
        if (expiry_evidence or release_evidence or record.external_message is not None
                or record.inventory_extension_receipts or self.recovering_payment(record.purchase_id)
                or not scope.issued_at <= now < batch.quote_expires_at):
            return StripeOrderReview(doc)
        if record.inventory_state in ('UNRESERVED','PREPARED','SUBMITTED'):
            doc['state'] = 'AWAITING_RESERVATION'
            return StripeOrderReview(doc)
        if record.inventory_state != 'CONFIRMED':
            return StripeOrderReview(doc)
        provider = customers.provider
        inventory, vault = await self.current_custody(customers,snapshot)
        if vault.root != batch.zkpassport_root:
            raise ValueError('Confirmed vault credential differs from the original batch')
        if (record.inventory_expires_at != batch.quote_expires_at or not record.inventory_confirmation_height
                or any(row.state != 'CONFIRMED' for row in rows)):
            raise ValueError('Both confirmed current reservations are required')
        originals = {item.original.terms.deed_launcher_id:item.original for item in inventory.items}
        held = []
        common_keys = None
        for a, row, original_id in zip(batch.artifacts, rows, scope.originals, strict=True):
            item = originals[a.deed_launcher_id]
            t = item.terms
            if item.coin.name() != original_id or row.available_coin_id != h(original_id):
                raise ValueError('Stripe reservation original changed')
            rebuilt = stripe_artifact(t, scope.vault, vault.root, a.authorization_nonce,
                                     a.authorization_expires_at, a.quote_expires_at)
            if rebuilt != a or (common_keys is not None and common_keys != t.validator_pubkeys):
                raise ValueError('Stripe quote differs from the confirmed mint')
            common_keys = t.validator_pubkeys
            transition = original_reservation(item, a, row.signer_indices)
            original = read_confirmed_coin(await provider.get_coin_record_by_name_primary(h(original_id)), original_id)
            if original.coin != item.coin or original.spent_height != record.inventory_confirmation_height:
                raise ValueError('Confirmed original Stripe spend missing')
            actual = _spend(await provider.get_puzzle_and_solution_primary(h(original_id),original.spent_height), item.coin)
            successor = transition.reserved_coin
            if (actual != transition.spend or row.reserved_coin_id != h(successor.name())
                    or row.reserved_puzzle_hash != h(successor.puzzle_hash)):
                raise ValueError('Confirmed Stripe reservation differs from the approved order')
            held.append(successor)
        prove_receipt_shape(batch, common_keys, now)
        if not await current_evidence_unchanged(inventory.evidence,provider=provider):
            raise ValueError('Stripe generation changed during review')
        for coin in (*held, vault.coin):
            current = await unspent(provider, coin)
            if coin in held and current.confirmed_height != record.inventory_confirmation_height:
                raise ValueError('Stripe reserved coin did not confirm with its parent')
            pending = await provider.primary.get_mempool_items_by_coin_name(h(coin.name()))
            if pending != []:
                raise ValueError('Stripe reservation or credential has a pending spend')
        if (self.store.inventory_status_snapshot(record.purchase_id) != saved
                or self.recovering_payment(record.purchase_id)):
            raise ValueError('Stripe order changed during proof')
        if not now <= int(self.clock()) < batch.quote_expires_at:
            return StripeOrderReview(doc)
        native = StripeNativeEvidence(h(scope.release_id), h(scope.generation), h(scope.collection), h(scope.vault),
            h(vault.coin.name()), snapshot['ownerPublicKey'].lower(), {'chia_bls':1,'evm':3}[snapshot['authType']],
            snapshot['owner'].lower(), h(vault.root), h(batch.vault_p2_puzzle_hash), h(batch.purchase_id), h(batch.batch_hash),
            record.purchase_intent_id, record.offer_artifact_hash, record.offer_artifact['genesisArtifactHash'], tuple(map(h, scope.launchers)), tuple(map(h,scope.originals)),
            tuple(h(c.name()) for c in held), record.inventory_confirmation_height, batch.quote_expires_at, batch)
        return StripeOrderReview(doc, native)
