"""Bounded recovery of already signed Testnet11 identity stamps.

Never creates an enrollment, collects an authorization, or requests validator
signatures. The saved authorization must still match the canonical EVM event,
release and current owner before the funded transaction may be continued.
"""
import asyncio
import contextlib
import json
import logging
import time

from chia_rs import Coin, SpendBundle
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.vault_driver import AUTH_TYPE_SECP256K1, AUTH_TYPE_BLS

from .credential_ledger import get_credential_ledger
from . import zkpassport_enrollments as enrollment

logger = logging.getLogger(__name__)


async def recover_saved_stamp(settings, submitter, store, key, record, attempt):
    enrollment._require_enrollment_bridge_policy(settings, record, execution=True)
    parsed = enrollment.EnrollmentRecord.model_validate(record)
    claim = json.loads(attempt['claim_json'])
    vault_record = enrollment.get_registry().get(bytes32.fromhex(key.removeprefix('0x')))
    if vault_record is None:
        raise ValueError('Saved stamp owner is unavailable')
    if vault_record.auth_type == AUTH_TYPE_SECP256K1 and vault_record.owner_evm_address:
        owner = vault_record.owner_evm_address.lower()
    elif vault_record.auth_type == AUTH_TYPE_BLS:
        owner = '0x' + bytes(vault_record.owner_pubkey).hex()
    else:
        raise ValueError('Saved stamp owner type is unsupported')
    if owner != claim['owner_key']:
        raise ValueError('Saved stamp owner changed')
    event = enrollment._fetch_verified_evm_attestation(settings,
        transaction_hash=parsed.receipt.evmTxHash, expected_vault_launcher_id=key)
    vault_coin = enrollment._find_initial_vault_coin(settings, key)
    enrollment._verify_reserved_bridge_coin(settings, parsed)
    fresh = enrollment._validator_claim(settings, key=key, record=parsed, event=event,
        vault_coin=vault_coin, vault_record=vault_record, owner_key=owner,
        owner_authorization=claim['owner_authorization'], current_timestamp=claim['current_timestamp'])
    if (fresh.model_dump(mode='json') != claim or fresh.canonical_hash() != attempt['claim_hash']
            or (vault_record.owner_evm_address and event.sender.lower() != vault_record.owner_evm_address.lower())):
        raise ValueError('Saved stamp differs from the canonical proof or release')
    return await enrollment._push_chia_stamp_and_mark_pending(settings,
        coinset=submitter.provider, key=key, fee_submitter=submitter, fee_store=store,
        spend_bundle=SpendBundle.from_bytes(bytes.fromhex(attempt['bundle_hex'])),
        expected_vault_coin=Coin.from_json_dict(json.loads(attempt['expected_coin_json'])))


class StampRecoveryWorker:
    def __init__(self, settings, submitter, store):
        if settings.network != 'testnet11' or not settings.protocol_fee_funding_enabled:
            raise ValueError('Automatic stamp funding is limited to Testnet11')
        self.settings, self.submitter, self.store = settings, submitter, store
        self.ledger = get_credential_ledger(settings)
        self.task = None
        self.next_check = {}
        self.failures = {}

    async def tick(self):
        for key, record in self.ledger.all_enrollments().items():
            if record.get('status') != 'stamp_pending' or time.monotonic() < self.next_check.get(key, 0):
                continue
            attempt = self.ledger.get_stamp_attempt(key)
            if not attempt or not attempt.get('bundle_hex'):
                continue
            try:
                synced = enrollment._sync_chia_stamp(self.settings, key)
                if synced.status == 'chia_confirmed':
                    latest = self.store.latest(key)
                    if latest:
                        self.store.event(latest['bundle_id'], 'confirmed')
                    logger.info('stamp_recovery vault=%s status=confirmed', key)
                    continue
                # Always reconcile receipts, even after exhausting the three
                # separately journaled submission windows. Never spend forever.
                if self.store.attempt_count(key) >= 3:
                    self.next_check[key] = time.monotonic() + 60
                    continue
                await recover_saved_stamp(self.settings, self.submitter, self.store, key, record, attempt)
                self.failures.pop(key, None)
                self.next_check[key] = time.monotonic() + 10
            except Exception as exc:
                count = self.failures.get(key, 0) + 1
                self.failures[key] = min(count, 5)
                delay = min(60, 5 * 2 ** min(count - 1, 4))
                self.next_check[key] = time.monotonic() + delay
                # Exception bodies can contain proof metadata. Log only a
                # classified code; exact node errors live in the private journal.
                from .submission_errors import error_code
                logger.warning('stamp_recovery vault=%s error_type=%s error_code=%s retry_seconds=%d',
                    key, type(exc).__name__, error_code(exc), delay)

    async def _run(self):
        while True:
            try:
                await self.tick()
            except Exception as exc:
                logger.error('stamp_recovery_scan error_type=%s', type(exc).__name__)
            await asyncio.sleep(5)

    async def start(self):
        self.task = asyncio.create_task(self._run())

    async def stop(self):
        if self.task:
            self.task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.task
