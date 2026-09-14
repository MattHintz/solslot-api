"""Opt-in automatic observation and renewal of the existing checkout journal."""
import asyncio
import hashlib
import re
import time
import uuid

from fastapi import HTTPException

from .inventory_extension_claims import extension_activation, ACH_REVIEW_SECONDS
from .inventory_extension_store import canonical, conflict
from .inventory_payment_hold_claims import payment_hold_activation
from .inventory_payment_holds import checkout_status
from .payment_start import PaymentStartClaim, adopt_payment_start, verify_start_receipt


def lifecycle_activation(artifact, environment):
    hold = payment_hold_activation(artifact, environment)
    extension = extension_activation(artifact, environment)
    expected = dict(schema='solslot.checkout-lifecycle.v1', environment=environment, network='testnet11',
        deploymentId=hold['deploymentId'], sourceShas=hold['sourceShas'], adapterVersion=1,
        paymentHoldReleaseIdentity=hold['releaseIdentity'], extensionReleaseIdentity=extension['releaseIdentity'],
        stripeAccountId=hold['stripeAccountId'], stripeMode='test', workerLeaseSeconds=60,
        advanceDeadlineSeconds=45, recoveryLane='independent', achReviewSeconds=ACH_REVIEW_SECONDS)
    expected['releaseIdentity'] = hashlib.sha256(canonical(expected).encode()).hexdigest()
    value = artifact.get('checkoutLifecycle')
    if (hold['adapterVersion'] != 2 or hold['stripeAccountId'] != extension['stripeAccountId']
            or hold['sourceShas'] != extension['sourceShas'] or hold['deploymentId'] != extension['deploymentId']
            or not isinstance(value, dict) or set(value) != set(expected) | {'reviewEvidenceSha256'}
            or any(value[k] != v or type(value[k]) is not type(v) for k,v in expected.items())
            or not re.fullmatch(r'[0-9a-f]{64}', str(value.get('reviewEvidenceSha256')))
            or value['reviewEvidenceSha256'] == '0'*64):
        raise conflict('automatic checkout lifecycle requires its reviewed exact deployment capability')
    return dict(value)


def enqueue_candidate(*, store, settings, purchase_id, payment, load_artifact):
    if not settings.checkout_lifecycle_worker_enabled or settings.network != 'testnet11':
        raise HTTPException(status_code=503, detail='Automatic payment recovery is not enabled for this release.')
    artifact = load_artifact()
    binding = lifecycle_activation(artifact, settings.runtime_environment + '-alpha')
    hold = store.checkout_hold(purchase_id)
    if hold is None:
        raise conflict('payment observation needs an existing checkout')
    checkout_status(hold, artifact, now=int(time.time()))
    # A terminal replay acknowledges the already-retained same payment; it never
    # reopens a completed job or changes its anchor.
    if hold['state'] in ('DELIVERED', 'RETURNED'):
        if any(hold['claim'][k] != payment[k] for k in ('payment_intent_id', 'payment_method')):
            raise conflict('terminal callback changes payment identity')
        return
    store.retain_payment_candidate(purchase_id, candidate=payment, binding=binding, expected_hold=hold)


class CheckoutLifecycleWorker:
    def __init__(self, *, store, presales, settings, node, submitter, load_artifact, authorize):
        self.store, self.presales, self.settings = store, presales, settings
        self.node, self.submitter = node, submitter
        self.load_artifact, self.authorize = load_artifact, authorize
        self.owner = uuid.uuid4().hex
        self.tasks = []

    async def start(self):
        if not self.settings.checkout_lifecycle_worker_enabled or self.tasks:
            return
        lifecycle_activation(self.load_artifact(), self.settings.runtime_environment + '-alpha')
        if self.settings.network != 'testnet11':
            raise conflict('lifecycle worker requires isolated testnet11')
        self.tasks = [asyncio.create_task(self.run(lane), name='checkout-' + lane) for lane in ('renewal', 'terminal')]

    async def stop(self):
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        self.tasks = []

    async def run(self, lane):
        while True:
            try:
                worked = await self.reconcile_once(lane)
            except asyncio.CancelledError:
                raise
            except Exception:
                # Invalid deployment evidence cannot advance any job. Publish a
                # failure receipt without claiming the current binding is healthy.
                self.store.lifecycle_health(lane, now=int(time.time()), binding={}, status='UNAVAILABLE')
                worked = False
            await asyncio.sleep(0.1 if worked else 5)

    async def reconcile_once(self, lane):
        if not self.settings.checkout_lifecycle_worker_enabled or self.settings.network != 'testnet11':
            return False
        binding = lifecycle_activation(self.load_artifact(), self.settings.runtime_environment + '-alpha')
        self.store.seed_checkout_jobs()
        owner = self.owner + ':' + uuid.uuid4().hex
        job = self.store.claim_checkout_job(lane, owner=owner, now=int(time.time()))
        if job is None:
            self.store.lifecycle_health(lane, now=int(time.time()), binding=binding, status='IDLE')
            return False
        if job.get('busy'):
            return False
        status, done = 'INTERRUPTED', False
        try:
            async with asyncio.timeout(binding['advanceDeadlineSeconds']):
                status, done = await self.advance(job['purchase_id'], lane, binding)
        except TimeoutError:
            status = 'TIMED_OUT'
        except HTTPException as exc:
            status = 'PAUSED' if exc.status_code in (403, 503) else 'REVIEW_REQUIRED'
        except (ValueError, KeyError, TypeError):
            status = 'REVIEW_REQUIRED'
        except asyncio.CancelledError:
            raise
        except Exception:
            status = 'UNAVAILABLE'
        finally:
            now = int(time.time())
            self.store.finish_checkout_job(job['purchase_id'], lane, owner=owner, now=now, status=status, done=done)
            self.store.lifecycle_health(lane, now=now, binding=binding, status=status)
        return True

    async def advance(self, purchase_id, lane, binding):
        from .checkout_terminals import (reconcile_paid_checkout, reconcile_checkout_return,
            terminal_status, active_context, observe_return)
        from .inventory_payment_holds import abort_checkout
        from .inventory_extensions import advance_extension
        from .inventory_extension_chain import current_position
        artifact = self.load_artifact()
        if lifecycle_activation(artifact, self.settings.runtime_environment + '-alpha') != binding:
            raise conflict('worker deployment changed')
        hold = self.store.checkout_hold(purchase_id)
        checkout_status(hold, artifact, now=int(time.time()))
        if self.store.checkout_terminal(purchase_id):
            terminal_status(self.store, purchase_id, artifact)
            return 'COMPLETE', True
        args = dict(store=self.store, settings=self.settings, purchase_id=purchase_id, load_artifact=self.load_artifact)
        if lane == 'terminal':
            voucher = self.presales.voucher_for_purchase(purchase_id)
            if voucher and voucher.get('state') == 'REDEEMED':
                await reconcile_paid_checkout(**args, node=self.node, presales=self.presales)
                return 'COMPLETE', True
            from .inventory_extension_chain import inspect_position
            from .inventory_recovery import release_peak
            _, _, _, position = active_context(self.store, self.settings, purchase_id, artifact)
            peak = await release_peak(self.node, 'testnet11')
            spent = await inspect_position(self.node, position, peak, require_unspent=False)
            if not spent or peak[0]-spent+1 < 3:
                return 'WAITING_FOR_CHAIN', False
            if hold['state'] in ('ARMING', 'ABORTING'):
                # Do not pin abort intent while inventory is live. Only a mature
                # exact timeout permits automatic canceled/unfunded observation.
                _, _, _, position = active_context(self.store, self.settings, purchase_id, artifact)
                await observe_return(self.node, position)
                await abort_checkout(**args)
            await reconcile_checkout_return(**args, node=self.node)
            return 'COMPLETE', True
        if hold['state'] != 'ARMED':
            return 'REVIEW_REQUIRED', False
        retained = self.store.payment_start(purchase_id)
        operations = self.store.inventory_extension_operations(purchase_id)
        if retained:
            claim = PaymentStartClaim.model_validate(retained['claim'])
            verify_start_receipt(claim, retained['receipt'], artifact)
            payment = claim.payment()
        elif operations:
            # Previously retained transaction claims are immutable. The existing
            # extension validator must verify/recover its original private anchor.
            payment = {k: operations[0]['claim'][k] for k in ('payment_intent_id','payment_event_id','payment_started_at','payment_method')}
        else:
            candidate = self.store.payment_candidate(purchase_id)
            if candidate is None:
                return 'WAITING_FOR_PAYMENT', False
            if candidate['binding'] != binding:
                raise conflict('candidate came from a different release')
            payment = await adopt_payment_start(**args, payment=candidate['payment'])
        def authorize_dispatch():
            if (not self.settings.checkout_lifecycle_worker_enabled or not self.settings.protocol_fee_funding_enabled
                    or self.submitter is None):
                raise HTTPException(status_code=503, detail='Reservation renewal is paused; payment observation is retained.')
            if lifecycle_activation(self.load_artifact(), self.settings.runtime_environment + '-alpha') != binding:
                raise conflict('lifecycle deployment changed before dispatch')
            self.authorize()
        extension_args = dict(**args, node=self.node, submitter=self.submitter, presales=self.presales,
            payment=payment, authorize=authorize_dispatch)
        await advance_extension(**extension_args, observe_only=True)
        if payment['payment_method'] == 'us_bank_account' and int(time.time())-payment['payment_started_at'] >= ACH_REVIEW_SECONDS:
            return 'REVIEW_REQUIRED', False
        stored = self.store.get(purchase_id)
        position = current_position(stored, self.store.inventory_items(purchase_id), artifact)
        if position.reservation.expires_at <= int(time.time()):
            return 'EXPIRED_REVIEW', False
        # Runtime write gates are checked here and again by extension preflight
        # immediately before funding/broadcast. Observation above stays available.
        authorize_dispatch()
        await advance_extension(**extension_args)
        return 'PAYMENT_HELD', False
