"""Current native checkout lifecycle using the existing native validators.

No public route or standing financial authority is created by this module.
The caller authenticates the current receiving vault before each operation.
Only explicit dispatch can select fees or broadcast; recovery only observes
the original saved bundle. The existing funding journal owns coin holds.
"""
import asyncio
import time
import secrets

from chia.consensus.condition_tools import conditions_dict_for_solution, pkm_pairs_for_conditions_dict
from chia_rs import AugSchemeMPL, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia.wallet.util.compute_additions import compute_additions_with_cost

from solslot_puzzles.generation_revenue import CompanyRevenue, PrimaryFeeSplitter
from solslot_puzzles.generation_statutes import GenerationStatutes
from solslot_puzzles.testnet_primary_forwarding import build_testnet_primary_forwarding
from solslot_puzzles.payment_artifacts_v3 import purchase_artifact_v3_from_json
from solslot_puzzles.payment_artifacts_v3 import purchase_artifact_v3_to_json
from solslot_puzzles.generation_primary_price import SignedPrimaryPrice

from .faucet import AGG_SIG_ME_DATA
from .generation_customer_issuer import TestnetIssuerPolicy
from .generation_customer_purchase_execution_store import CurrentPurchaseExecutionStore
from .generation_customer_purchase_reservation import CurrentReservationClaim, verify_current_reservation
from .generation_customer_purchase_delivery import verify_current_delivery
from .generation_customer_purchase_timeout import verify_current_timeout
from .generation_customer_purchase_quorum import collect_current_purchase_quorum
from .generation_customer_purchase_wallet import prepare_current_native_payment
from .generation_operations import bundle_id
from .generation_storage import generation_path
from .protocol_submission import PreparedProtocolBundle, ProtocolSubmissionError
from .generation_customer_inventory import resolve_current_primary_inventory
from .generation_customer_quote import current_customer_xch_quote
from .generation_customer_context import customer_bindings_from_evidence
from .generation_customer_vault import resolve_native_identity_vault
from .generation_preparation import read_generation_preparation
from .payment_quotes import load_authorized_oracle_round
from .generation_customer_test_conversion import configured_price
from .generation_customer_purchase_batch import CurrentReservationBatch,CurrentDeliveryBatch,CurrentBatchPaymentRequest,artifacts
from . import generation_customer_purchase_batch_execution as batch_execution


def h(value):
    return '0x'+bytes(value).hex()


class CurrentNativePurchaseExecution:
    def __init__(self, *, settings, anchor, provider, policy, store, fee_cap,
                 submitter=None, clock=time.time):
        if (not isinstance(policy, TestnetIssuerPolicy)
                or not isinstance(store, CurrentPurchaseExecutionStore)
                or settings.network != 'testnet11'
                or getattr(settings, 'generation_customer_purchase_enabled', False) is not True
                or settings.deployment_generation_id != store.generation_id
                or '0x'+policy.generation.hex() != store.generation_id
                or policy.generation != anchor.issuance.generation
                or type(fee_cap) is not int or not 0 <= fee_cap <= 1_000_000_000):
            raise ValueError('CURRENT_EXECUTION_EXACT_CONTEXT_REQUIRED')
        policy.validate()
        self.settings, self.anchor, self.provider = settings, anchor, provider
        self.policy, self.store, self.fee_cap = policy, store, fee_cap
        self.submitter, self.clock = submitter, clock
        store.bind_execution_policy(policy.commitment, policy.maximum_purchases, fee_cap)

    async def quote(self, request_key, deed_launcher_id, *, browser_hash):
        if isinstance(deed_launcher_id,(list,tuple)):
            if len(deed_launcher_id)==1:deed_launcher_id=deed_launcher_id[0]
            else:return await batch_execution.quote_batch(self,request_key,deed_launcher_id,browser_hash)
        deed = bytes32.from_hexstr(deed_launcher_id)
        prior = self.store.review_for_request(request_key, browser_hash=browser_hash)
        if prior is not None:
            return self._same_quote(prior['intentId'], deed, browser_hash)
        now = int(self.clock())
        if not self.policy.issued_at <= now < self.policy.expires_at:
            raise ValueError('CURRENT_EXECUTION_PURCHASE_WINDOW_CLOSED')
        if now+300>self.policy.expires_at:
            raise ValueError('CURRENT_EXECUTION_PURCHASE_WINDOW_ENDING')
        if deed not in self.policy.deed_launchers:
            raise ValueError('CURRENT_EXECUTION_DEED_OUTSIDE_REVIEWED_POLICY')
        inventory = await resolve_current_primary_inventory(settings=self.settings,
            anchor=self.anchor, provider=self.provider, collection=self.policy.collection,
            edition_hash=self.policy.edition, metadata_root=self.policy.metadata_root)
        bindings = customer_bindings_from_evidence(read_generation_preparation(self.settings),
            self.anchor, inventory.evidence)
        vault = await resolve_native_identity_vault(bindings=bindings,
            launcher=self.policy.buyer_vault, provider=self.provider)
        # Reservation confirmation, wallet review and delivery are separate
        # native steps. Admit their full existing five-minute review window;
        # never send a customer into a nearly expired price or authorization.
        expires = now+300
        price,price_evidence=configured_price(self.settings,self.policy,now=now,expires_at=expires)
        if expires>price.round.valid_until:
            raise ValueError('CURRENT_PURCHASE_FRESH_PRICE_WINDOW_REQUIRED')
        quote = current_customer_xch_quote(inventory=inventory, vault=vault, deed_launcher=deed,
            price=price, nonce=bytes32(secrets.token_bytes(32)), now=now, expires_at=expires,
            forwarding_policy=self.policy)
        claim = CurrentReservationClaim(generationId=self.store.generation_id,
            anchorHash=self.settings.generation_chain_anchor_hash, issuerPolicyHash=self.policy.commitment,
            purchaseArtifact=purchase_artifact_v3_to_json(quote), signedPrice=price_evidence,
            availableCoinId=h(inventory.require_available(deed).current.coin.name()),
            currentVaultCoinId=h(vault.coin.name()), signerIndices=(0,1))
        await verify_current_reservation(claim, **self._arguments())
        try:
            identity = self.store.save_review(claim, browser_hash=browser_hash,
                request_key=request_key, now=int(self.clock()))
        except ValueError as exc:
            if str(exc) != 'CURRENT_CHECKOUT_RETRY_CHANGES_REVIEW':
                raise
            # Simultaneous clicks may construct different nonces. The first
            # committed review wins; a retry cannot replace its sealed price.
            prior = self.store.review_for_request(request_key, browser_hash=browser_hash)
            if prior is None:
                raise
            return self._same_quote(prior['intentId'], deed, browser_hash)
        return self.review(identity, browser_hash=browser_hash)

    def _same_quote(self, identity, deed, browser_hash):
        saved = self._review_saved(identity, browser_hash)
        if isinstance(saved['reservationClaim'],CurrentReservationBatch):
            raise ValueError('CURRENT_EXECUTION_REQUEST_KEY_DEED_CHANGED')
        artifact = purchase_artifact_v3_from_json(saved['reservationClaim'].purchase_artifact)
        if artifact.deed_launcher_id != deed:
            raise ValueError('CURRENT_EXECUTION_REQUEST_KEY_DEED_CHANGED')
        return self.review(identity, browser_hash=browser_hash)

    async def inventory(self):
        """Current custody and public terms only; never quote or reserve."""
        inventory = await resolve_current_primary_inventory(settings=self.settings,
            anchor=self.anchor, provider=self.provider, collection=self.policy.collection,
            edition_hash=self.policy.edition, metadata_root=self.policy.metadata_root)
        value = inventory.public()
        for item, row in zip(inventory.items, value['items']):
            terms = item.original.terms
            row.update(deedLauncherPuzzleHash=h(terms.deed_launcher_puzzle_hash),
                smartDeedInnerHash=h(terms.smart_deed_inner_hash),
                withinTestPolicy=terms.deed_launcher_id in self.policy.deed_launchers)
        now = int(self.clock())
        return {**value, 'receivingVaultLauncherId':h(self.policy.buyer_vault),
            'lastCheckedAt':now, 'purchaseWindowOpen':self.policy.issued_at <= now < self.policy.expires_at-300,
            'policyExpiresAt':self.policy.expires_at}

    async def payer_coins(self, identity, public_keys, *, browser_hash, public_key_kind="raw"):
        """Find confirmed standard payer coins using public keys, no wallet RPC.

        Coin discovery is bounded and does not consolidate, sign, fund, reserve
        or submit. Payment preparation rechecks the selected coin independently.
        """
        from chia_rs import G1Element, Coin
        from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import puzzle_for_pk, puzzle_for_synthetic_public_key
        from .generation_coin_evidence import read_confirmed_coin
        saved = self._saved(identity, browser_hash)
        reservation=saved['reservationClaim']
        selected=(artifacts(reservation)if isinstance(reservation,CurrentReservationBatch)
            else (purchase_artifact_v3_from_json(reservation.purchase_artifact),))
        artifact=selected[0]
        amount=sum(a.rail_amount for a in selected)
        now = int(self.clock())
        if not self.policy.issued_at <= now < min(self.policy.expires_at, artifact.quote_expires_at):
            raise ValueError('CURRENT_EXECUTION_PURCHASE_WINDOW_CLOSED')
        if not isinstance(public_keys, (list, tuple)) or not 1 <= len(public_keys) <= 32 or len(set(public_keys)) != len(public_keys):
            raise ValueError('CURRENT_PAYMENT_PUBLIC_KEY_LIST_INVALID')
        if public_key_kind not in ("raw", "synthetic"):
            raise ValueError("CURRENT_PAYMENT_PUBLIC_KEY_KIND_INVALID")
        keys = []
        for value in public_keys:
            if not isinstance(value,str) or len(value)!=98 or not value.startswith('0x') or value!=value.lower():
                raise ValueError('CURRENT_PAYMENT_PUBLIC_KEY_LIST_INVALID')
            key = G1Element.from_bytes(bytes.fromhex(value[2:]))
            if key == G1Element():raise ValueError('CURRENT_PAYMENT_NONIDENTITY_KEY_REQUIRED')
            keys.append((value,(puzzle_for_pk(key) if public_key_kind == "raw" else puzzle_for_synthetic_public_key(key)).get_tree_hash()))
        if (await self.provider.get_network_info_primary()).get('network_name') != 'testnet11':
            raise ValueError('CURRENT_PAYMENT_PRIMARY_NETWORK_CHANGED')
        limit = asyncio.Semaphore(4)
        async def read_key(public,puzzle):
            async with limit:
                records = await self.provider.get_coin_records_by_puzzle_hash_primary(h(puzzle),include_spent=False)
            if not isinstance(records,list) or len(records)>256:
                raise ValueError('CURRENT_PAYMENT_COIN_READ_BOUND_EXCEEDED')
            candidates = []
            for raw in records:
                coin = Coin.from_json_dict(raw['coin'])
                record = read_confirmed_coin(raw,coin.name())
                if record.coin.puzzle_hash != puzzle:
                    raise ValueError('CURRENT_PAYMENT_COIN_OWNER_CHANGED')
                if not record.spent_height and amount <= record.coin.amount <= 2**53-1:
                    candidates.append({'paymentCoinId':h(record.coin.name()),'paymentPublicKey':public,
                        'paymentPublicKeyKind':public_key_kind,'amountMojos':str(record.coin.amount),'confirmedHeight':record.confirmed_height})
            return candidates
        async with asyncio.timeout(15):
            groups = await asyncio.gather(*(read_key(public,puzzle)for public,puzzle in keys))
        candidates = [row for group in groups for row in group]
        if int(self.clock()) >= min(self.policy.expires_at,artifact.quote_expires_at):
            raise ValueError('CURRENT_PAYMENT_REVIEW_EXPIRED_DURING_READ')
        unique = {r['paymentCoinId']:r for r in candidates}
        return {'schema':'solslot.current-payer-coins.v1','generationId':self.store.generation_id,
            'network':'testnet11','intentId':identity,'receivingVaultLauncherId':h(self.policy.buyer_vault),
            'amountMojos':str(amount),'lastCheckedAt':int(self.clock()),
            'candidates':sorted(unique.values(),key=lambda r:(int(r['amountMojos']),r['paymentCoinId']))[:32]}

    def review(self, identity, *, browser_hash):
        saved = self._review_saved(identity, browser_hash)
        claim = saved['reservationClaim']
        if isinstance(claim,CurrentReservationBatch):return batch_execution.review_batch(self,identity,saved,browser_hash)
        artifact = purchase_artifact_v3_from_json(claim.purchase_artifact)
        return {'intentId':identity, 'generationId':self.store.generation_id, 'network':'testnet11',
            'receivingVaultLauncherId':h(artifact.vault_launcher_id), 'deedLauncherId':h(artifact.deed_launcher_id),
            'purchaseId':h(artifact.purchase_id), 'purchaseArtifactHash':h(artifact.artifact_hash),
            'rail':'CHIA_XCH', 'amountMojos':str(artifact.rail_amount),
            'baseAmountUsdMinor':str(artifact.base_amount_minor),
            'technologyFeeUsdMinor':str(artifact.technology_fee_minor),
            'totalAmountUsdMinor':str(artifact.subtotal_minor),
            'quoteExpiresAt':artifact.quote_expires_at, 'feeCapMojosPerStage':str(self.fee_cap),
            'maximumNetworkFeeMojos':str(2*self.fee_cap),
            'quoteExpired':int(self.clock())>=artifact.quote_expires_at,
            'reservationRequested':self.store.reservation_request(identity,browser_hash=browser_hash)is not None,
            'reservationClaimHash':claim.digest(), 'payerAuthorizationSaved':saved['deliveryClaim'] is not None}

    def request_reservation(self, identity, *, browser_hash):
        """Save explicit intent for the existing worker, without signing or funding."""
        claim = self._saved(identity, browser_hash)['reservationClaim']
        selected = artifacts(claim)
        now = int(self.clock())
        prior = self.store.reservation_request(identity, browser_hash=browser_hash)
        if prior is None and not self.policy.issued_at <= now < min(
                self.policy.expires_at, selected[0].quote_expires_at):
            raise ValueError('CURRENT_EXECUTION_PURCHASE_WINDOW_CLOSED')
        requested = self.store.request_reservation(identity, browser_hash=browser_hash, now=now)
        return {'schema':'solslot.current-reservation-request.v1', 'intentId':identity,
            'generationId':self.store.generation_id, 'receivingVaultLauncherId':h(self.policy.buyer_vault),
            'reservationClaimHash':claim.digest(), 'quantity':len(selected), 'requestedAt':requested}

    def reserved_coin_id(self, identity, *, browser_hash):
        if isinstance(self._saved(identity,browser_hash)['reservationClaim'],CurrentReservationBatch):
            return batch_execution.reserved_coins(self,identity,browser_hash)
        bundle = self.store.execution_bundle(identity, 'RESERVATION', browser_hash=browser_hash)
        if len(bundle.coin_spends) != 1:
            raise ValueError('CURRENT_EXECUTION_EXACT_RESERVATION_SPEND_REQUIRED')
        outputs, _ = compute_additions_with_cost(bundle.coin_spends[0], max_cost=100_000_000)
        successors = [c for c in outputs if c.amount % 2]
        if len(successors) != 1 or successors[0].amount != 1:
            raise ValueError('CURRENT_EXECUTION_RESERVATION_OUTPUT_CHANGED')
        return h(successors[0].name())

    def _arguments(self):
        return dict(settings=self.settings, anchor=self.anchor, provider=self.provider,
                    issuer_policy=self.policy, expected_issuer_policy_hash=self.policy.commitment,
                    clock=self.clock)

    def _saved(self, identity, browser_hash):
        saved = self.store.saved(identity, browser_hash=browser_hash)
        claim = saved['reservationClaim']
        if (claim.generation_id != self.store.generation_id
                or claim.issuer_policy_hash != self.policy.commitment):
            raise ValueError('CURRENT_EXECUTION_SAVED_POLICY_CHANGED')
        return saved

    def _review_saved(self,identity,browser_hash):
        """Recover only an expired, unstarted predecessor for terminal display.

        This path cannot authorize a financial step. Every mutation continues
        to use _saved and rejects the prior policy, including its signatures.
        """
        try:return self._saved(identity,browser_hash)
        except ValueError as exc:
            if str(exc)!='CURRENT_EXECUTION_SAVED_POLICY_CHANGED':raise
        saved=self.store.unstarted_review(identity,browser_hash=browser_hash)
        claim=saved['reservationClaim'];selected=artifacts(claim);now=int(self.clock())
        first=claim.children[0]if isinstance(claim,CurrentReservationBatch)else claim
        from .generation_customer_purchase_policy import selected_prior_purchase_policy
        from solslot_puzzles.payment_artifacts_v2 import PaymentRail
        prior=selected_prior_purchase_policy(self.settings,self.policy)
        if (prior is None or claim.issuer_policy_hash!=prior.commitment
                or claim.generation_id!=self.store.generation_id
                or self.settings.deployment_generation_id!=self.store.generation_id
                or first.anchor_hash!=self.settings.generation_chain_anchor_hash
                or now<prior.expires_at or len(selected)>prior.maximum_purchases
                or any(a.network!='testnet11' or a.vault_launcher_id!=prior.buyer_vault
                    or a.rail!=PaymentRail.CHIA_XCH or a.rail_chain_id!=0
                    or a.rail_asset_id!=bytes32.zeros or a.rail_asset_decimals!=12
                    or a.collection_id!=prior.collection or a.metadata_anchor_id!=prior.edition
                    or a.metadata_root!=prior.metadata_root or a.deed_launcher_id not in prior.deed_launchers
                    or a.protocol_treasury_puzzle_hash!=prior.fee_puzzle
                    or not 0<int(a.rail_amount)<=prior.maximum_gross_mojos
                    or not prior.issued_at<a.quote_expires_at<=a.authorization_expires_at<=prior.expires_at
                    or now<a.quote_expires_at for a in selected)):
            raise ValueError('CURRENT_EXECUTION_SAVED_POLICY_CHANGED')
        return saved

    def _existing(self, identity, phase, browser_hash):
        try:
            return self.store.execution_status(identity, phase, browser_hash=browser_hash)
        except ValueError as exc:
            if str(exc) != 'CURRENT_EXECUTION_UNAVAILABLE':
                raise
        return None

    async def prepare_reservation(self, identity, *, browser_hash):
        saved = self._saved(identity, browser_hash)
        if isinstance(saved['reservationClaim'],CurrentReservationBatch):
            return await batch_execution.prepare_reservation(self,identity,browser_hash)
        existing = self._existing(identity, 'RESERVATION', browser_hash)
        if existing is not None:
            return existing
        checked = await verify_current_reservation(saved['reservationClaim'], **self._arguments())
        def retain(index, reply):
            self.store.save_signature(identity, 'reservation', index, reply, browser_hash=browser_hash)
        signature = await collect_current_purchase_quorum(self.settings, checked,
            retained=saved['retainedSignatures']['reservation'], on_signature=retain)
        # Reconstruct after the network calls. A response received just before
        # an expiry or custody change cannot authorize an outdated spend.
        fresh = await verify_current_reservation(saved['reservationClaim'], **self._arguments())
        if bytes(fresh.transition.spend) != bytes(checked.transition.spend):
            raise ValueError('CURRENT_EXECUTION_RESERVATION_CHANGED_DURING_QUORUM')
        bundle = SpendBundle([fresh.transition.spend], signature)
        return self.store.prepare_execution(identity, 'RESERVATION', bundle,
            browser_hash=browser_hash, claim_hash=saved['reservationClaim'].digest(),
            fee_cap=self.fee_cap, expires_at=min(self.policy.expires_at,
                purchase_artifact_v3_from_json(saved['reservationClaim'].purchase_artifact).quote_expires_at),
            now=int(self.clock()))

    async def prepare_wallet(self, identity, request, *, browser_hash):
        saved = self._saved(identity, browser_hash)
        if request.reservation.canonical() != saved['reservationClaim'].canonical():
            raise ValueError('CURRENT_EXECUTION_WALLET_REVIEW_CHANGED')
        status = self.store.execution_status(identity, 'RESERVATION', browser_hash=browser_hash)
        if status['stage'] != 'CONFIRMED':
            raise ValueError('CURRENT_EXECUTION_RESERVATION_NOT_CONFIRMED')
        if isinstance(request,CurrentBatchPaymentRequest):
            from .generation_customer_purchase_batch import prepare_current_batch_payment
            return await prepare_current_batch_payment(request,**self._arguments())
        return await prepare_current_native_payment(request, **self._arguments())

    def _fees(self, evidence):
        chain = evidence.inventory.evidence
        statutes = [h.state for h in chain.economic_components.values()
                    if isinstance(h.state, GenerationStatutes)]
        if len(statutes) != 1 or statutes[0].generation != self.policy.generation:
            raise ValueError('CURRENT_EXECUTION_NATIVE_FEE_AUTHORITY_REQUIRED')
        return PrimaryFeeSplitter(chain.governance.state.sgt, statutes[0].launcher_id,
            CompanyRevenue(self.policy.generation, chain.registry.state.administrator_id))

    async def accept_payer(self, identity, claim, *, browser_hash):
        """Durably retain a valid signed payer offer before any private call.

        An invalid first offer cannot poison a saved checkout. Identical retries
        recover the original authorization; replacements are rejected by the
        journal. This step cannot fund, submit or request issuer signatures.
        """
        saved = self._saved(identity, browser_hash)
        if claim.reservation.canonical() != saved['reservationClaim'].canonical():
            raise ValueError('CURRENT_EXECUTION_DELIVERY_REVIEW_CHANGED')
        status = self.store.execution_status(identity, 'RESERVATION', browser_hash=browser_hash)
        if status['stage'] != 'CONFIRMED':
            raise ValueError('CURRENT_EXECUTION_RESERVATION_NOT_CONFIRMED')
        # Successful retries after submission must not revalidate spent inputs.
        if saved['deliveryClaim'] is not None:
            if saved['deliveryClaim'].canonical() != claim.canonical():
                raise ValueError('CURRENT_EXECUTION_SAVED_DELIVERY_CHANGED')
            return self.review(identity, browser_hash=browser_hash)
        await verify_current_delivery(claim, **self._arguments())
        self.store.save_delivery(identity, claim, browser_hash=browser_hash, now=int(self.clock()))
        return self.review(identity, browser_hash=browser_hash)

    async def delivery_issuer_review(self, identity, claim, *, browser_hash):
        if isinstance(claim,CurrentDeliveryBatch):return await batch_execution.issuer_review(self,identity,claim,browser_hash)
        await self.accept_payer(identity, claim, browser_hash=browser_hash)
        saved = self._saved(identity, browser_hash)
        checked = await verify_current_delivery(claim, **self._arguments())
        def retain(index, reply):
            self.store.save_signature(identity, 'delivery', index, reply, browser_hash=browser_hash)
        signature = await collect_current_purchase_quorum(self.settings, checked,
            retained=saved['retainedSignatures']['delivery'], on_signature=retain)
        fresh = await verify_current_delivery(claim, **self._arguments())
        if bytes(fresh.bundle) != bytes(checked.bundle):
            raise ValueError('CURRENT_EXECUTION_DELIVERY_CHANGED_DURING_QUORUM')
        signed = SpendBundle(fresh.bundle.coin_spends,
            AugSchemeMPL.aggregate([fresh.bundle.aggregated_signature, signature]))
        companion = build_testnet_primary_forwarding(bundle=signed,
            artifact=purchase_artifact_v3_from_json(claim.reservation.purchase_artifact),
            terms=fresh.item.original.terms, issuer_public_key=self.policy.issuer_public_key,
            fees=self._fees(fresh))
        pairs = pkm_pairs_for_conditions_dict(conditions_dict_for_solution(
            companion.issuer_signature_spend.puzzle_reveal,
            companion.issuer_signature_spend.solution, 100_000_000),
            companion.issuer_signature_spend.coin, AGG_SIG_ME_DATA['testnet11'])
        if len(pairs) != 1:
            raise ValueError('CURRENT_EXECUTION_ONE_EXACT_ISSUER_SIGNATURE_REQUIRED')
        return fresh, signed, companion, pairs[0]

    async def prepare_delivery(self, identity, claim, issuer_signature, *, browser_hash):
        if isinstance(claim,CurrentDeliveryBatch):return await batch_execution.prepare_delivery(self,identity,claim,issuer_signature,browser_hash)
        existing = self._existing(identity, 'DELIVERY', browser_hash)
        if existing is not None:
            saved = self._saved(identity, browser_hash)
            if saved['deliveryClaim'] is None or saved['deliveryClaim'].canonical() != claim.canonical():
                raise ValueError('CURRENT_EXECUTION_SAVED_DELIVERY_CHANGED')
            return existing
        if not isinstance(issuer_signature, G2Element):
            raise ValueError('CURRENT_EXECUTION_TYPED_ISSUER_SIGNATURE_REQUIRED')
        evidence, signed, companion, pair = await self.delivery_issuer_review(identity, claim, browser_hash=browser_hash)
        if not AugSchemeMPL.verify(pair[0], pair[1], issuer_signature):
            raise ValueError('CURRENT_EXECUTION_ISSUER_SIGNATURE_INVALID')
        bundle = SpendBundle([*signed.coin_spends, *companion.operation.spends],
            AugSchemeMPL.aggregate([signed.aggregated_signature, issuer_signature]))
        return self.store.prepare_execution(identity, 'DELIVERY', bundle, browser_hash=browser_hash,
            claim_hash=claim.digest(), fee_cap=self.fee_cap,
            expires_at=min(self.policy.expires_at,
                purchase_artifact_v3_from_json(evidence.claim.reservation.purchase_artifact).quote_expires_at),
            now=int(self.clock()))

    async def _revalidate_prepared(self, saved, phase, bundle):
        if isinstance(saved['reservationClaim'],CurrentReservationBatch):
            expected=await batch_execution.expected_spends(self,saved,phase)
        elif phase == 'RESERVATION':
            evidence = await verify_current_reservation(saved['reservationClaim'], **self._arguments())
            expected = [evidence.transition.spend]
        elif phase == 'RELEASE':
            checked=await verify_current_timeout(saved['reservationClaim'],None,**self._arguments())
            expected=list(checked.coin_spends)
        else:
            if saved['deliveryClaim'] is None:
                raise ValueError('CURRENT_EXECUTION_SAVED_PAYER_REQUIRED')
            evidence = await verify_current_delivery(saved['deliveryClaim'], **self._arguments())
            companion = build_testnet_primary_forwarding(bundle=evidence.bundle,
                artifact=purchase_artifact_v3_from_json(saved['reservationClaim'].purchase_artifact),
                terms=evidence.item.original.terms, issuer_public_key=self.policy.issuer_public_key,
                fees=self._fees(evidence))
            expected = [*evidence.bundle.coin_spends, *companion.operation.spends]
        if [bytes(s) for s in expected] != [bytes(s) for s in bundle.coin_spends]:
            raise ValueError('CURRENT_EXECUTION_NATIVE_PREPARATION_CHANGED')
        pairs = []
        for spend in expected:
            pairs.extend(pkm_pairs_for_conditions_dict(conditions_dict_for_solution(
                spend.puzzle_reveal, spend.solution, 100_000_000), spend.coin,
                AGG_SIG_ME_DATA['testnet11']))
        if not AugSchemeMPL.aggregate_verify([p[0] for p in pairs], [p[1] for p in pairs],
                                            bundle.aggregated_signature):
            raise ValueError('CURRENT_EXECUTION_NATIVE_SIGNATURE_INVALID')

    async def prepare_timeout(self,identity,*,browser_hash):
        saved=self._saved(identity,browser_hash)
        existing=self._existing(identity,'RELEASE',browser_hash)
        if existing is not None:return existing
        reserved=self.store.execution_status(identity,'RESERVATION',browser_hash=browser_hash)
        delivered=self._existing(identity,'DELIVERY',browser_hash)
        if reserved['stage']!='CONFIRMED' or delivered is not None and delivered['stage']=='CONFIRMED':
            raise ValueError('CURRENT_TIMEOUT_UNDELIVERED_RESERVATION_REQUIRED')
        if isinstance(saved['reservationClaim'],CurrentReservationBatch):
            spends=await batch_execution.expected_spends(self,saved,'RELEASE')
            bundle=SpendBundle(spends,G2Element())
        else:bundle=await verify_current_timeout(saved['reservationClaim'],self.reserved_coin_id(identity,browser_hash=browser_hash),**self._arguments())
        return self.store.prepare_execution(identity,'RELEASE',bundle,browser_hash=browser_hash,
            claim_hash=saved['reservationClaim'].digest(),fee_cap=self.fee_cap,
            expires_at=self.policy.expires_at,now=int(self.clock()))

    def _funding_context(self):
        submitter = self.submitter
        if (submitter is None or submitter.funding_store is None
                or not submitter.policy.enabled or not submitter.policy.native_admission_enabled
                or submitter.policy.maximum_mojos > self.fee_cap
                or submitter.faucet.network != 'testnet11'
                or generation_path(submitter.funding_store.path, self.store.generation_id) != submitter.funding_store.path):
            raise ValueError('CURRENT_EXECUTION_BOUNDED_NATIVE_FUNDING_REQUIRED')
        return {'feeTill': submitter.faucet.address_hex, 'purpose': None, 'backingMojos': 0}

    async def dispatch(self, identity, phase, *, browser_hash):
        saved = self._saved(identity, browser_hash)
        status = self.store.execution_status(identity, phase, browser_hash=browser_hash)
        if status['stage'] == 'CONFIRMED':
            return status
        recovered = await self.reconcile(identity, phase, browser_hash=browser_hash)
        if recovered['stage'] in ('CONFIRMED', 'MEMPOOL'):
            return recovered
        context = self._funding_context()
        bundle = self.store.execution_bundle(identity, phase, browser_hash=browser_hash)
        funded = self.store.execution_funding(identity, phase, browser_hash=browser_hash)
        if funded is not None:
            retained = self.submitter.funding_store.lookup('testnet11', bundle_id(bundle), context)
            if retained is None or any(retained.get(k) != v for k, v in funded.items()):
                raise ValueError('CURRENT_EXECUTION_ORIGINAL_FUNDING_REQUIRED')
        now = int(self.clock())
        if not self.policy.issued_at <= now < min(self.policy.expires_at, status['expiresAt']):
            raise ValueError('CURRENT_EXECUTION_DISPATCH_WINDOW_CLOSED')
        await self._revalidate_prepared(saved, phase, bundle)
        async def before_push(prepared):
            self.store.save_execution_funding(identity, phase, prepared, browser_hash=browser_hash, now=int(self.clock()))
            if int(self.clock()) >= min(self.policy.expires_at, status['expiresAt']):
                raise ProtocolSubmissionError('Saved payment window ended before submission.', code='CHAIN_WINDOW_EXPIRED')
        receipt = await self.submitter.submit(bundle.to_json_dict(), before_push=before_push)
        status = receipt['status'].upper()
        if status == 'MEMPOOL_RECONCILED':
            status = 'MEMPOOL'
        return self.store.observe_execution(identity, phase, browser_hash=browser_hash,
            transaction_id=receipt['spendBundleId'], status=status,
            confirmed_height=receipt.get('confirmedHeight'), now=int(self.clock()))

    async def reconcile(self, identity, phase, *, browser_hash):
        self._saved(identity, browser_hash)
        if self.submitter is not None and self.submitter.funding_store is not None:
            if (self.submitter.faucet.network != 'testnet11'
                    or generation_path(self.submitter.funding_store.path, self.store.generation_id)
                        != self.submitter.funding_store.path):
                raise ValueError('CURRENT_EXECUTION_READ_FUNDING_CONTEXT_CHANGED')
        funded = self.store.execution_funding(identity, phase, browser_hash=browser_hash)
        if funded is None:
            # The funding journal commits before the UI checkpoint callback.
            # Recover that exact durable entry after a process interruption,
            # including after expiry, without selecting or submitting anything.
            if self.submitter is not None and self.submitter.funding_store is not None:
                original = self.store.execution_bundle(identity, phase, browser_hash=browser_hash)
                context = {'feeTill': self.submitter.faucet.address_hex, 'purpose': None, 'backingMojos': 0}
                retained = self.submitter.funding_store.lookup('testnet11', bundle_id(original), context)
                if retained is not None:
                    if retained.get('protocolSpendBundle') != original.to_json_dict():
                        raise ValueError('CURRENT_EXECUTION_ORIGINAL_FUNDING_CHANGED')
                    recovered = PreparedProtocolBundle(SpendBundle.from_json_dict(retained['spendBundle']),
                        int(retained['feeMojos']), retained['feeCoinId'], int(retained['backingMojos']))
                    self.store.save_execution_funding(identity, phase, recovered,
                        browser_hash=browser_hash, now=int(self.clock()))
                    funded = self.store.execution_funding(identity, phase, browser_hash=browser_hash)
            if funded is None:
                return self.store.execution_status(identity, phase, browser_hash=browser_hash)
        if (await self.provider.get_network_info_primary()).get('network_name') != 'testnet11':
            raise ValueError('CURRENT_EXECUTION_PRIMARY_TESTNET_REQUIRED')
        async with asyncio.timeout(20):
            receipt = await self.provider.observe_exact_protocol_bundle(funded['spendBundle'])
        if receipt is None:
            return self.store.execution_status(identity, phase, browser_hash=browser_hash)
        if self.submitter is not None and self.submitter.funding_store is not None:
            original = self.store.execution_bundle(identity, phase, browser_hash=browser_hash)
            context = {'feeTill': self.submitter.faucet.address_hex, 'purpose': None, 'backingMojos': 0}
            retained = self.submitter.funding_store.lookup('testnet11', bundle_id(original), context)
            if retained is None or any(retained.get(k) != v for k, v in funded.items()):
                raise ValueError('CURRENT_EXECUTION_FUNDING_RECONCILIATION_CHANGED')
            self.submitter.funding_store.event('testnet11', bundle_id(original), receipt['status'].lower())
        return self.store.observe_execution(identity, phase, browser_hash=browser_hash,
            transaction_id=funded['spendBundleId'], status=receipt['status'].upper(),
            confirmed_height=receipt.get('confirmed_height'), now=int(self.clock()))
