from __future__ import annotations

import pytest

from solslot_api.validator_ledger import (
    SCHEMA_VERSION,
    ValidatorLedger,
    ValidatorLedgerConflict,
)


def _record(ledger: ValidatorLedger, *, claim: str = "01", nullifier: str = "02") -> str:
    return ledger.record_or_recover(
        claim_hash="0x" + claim * 32,
        canonical_claim='{"claim":"' + claim + '"}',
        scoped_nullifier="0x" + nullifier * 32,
        bridge_coin_id="0x" + "03" * 32,
        vault_action="0xvault:0xcoin:0xroot:update_identity",
        evm_transaction_hash="0x" + "04" * 32,
        signature="0x" + "05" * 96,
    )


def test_exact_claim_retry_recovers_the_original_signature() -> None:
    ledger = ValidatorLedger(":memory:")
    try:
        first = _record(ledger)
        second = _record(ledger)
    finally:
        ledger.close()
    assert first == second


def test_reused_nullifier_bridge_event_or_vault_action_fails_closed() -> None:
    ledger = ValidatorLedger(":memory:")
    try:
        _record(ledger)
        with pytest.raises(ValidatorLedgerConflict, match="already signed"):
            _record(ledger, claim="06", nullifier="07")
    finally:
        ledger.close()


def test_validator_ledger_uses_wal_and_passes_integrity_check(tmp_path) -> None:
    ledger = ValidatorLedger(tmp_path / "signatures.db")
    try:
        assert ledger.healthcheck() is True
        journal_mode = ledger._conn.execute("PRAGMA journal_mode").fetchone()[0]
    finally:
        ledger.close()
    assert journal_mode.lower() == "wal"


def test_validator_ledger_migrates_voucher_redemption_schema() -> None:
    ledger = ValidatorLedger(":memory:")
    try:
        version = ledger._conn.execute("PRAGMA user_version").fetchone()[0]
        table = ledger._conn.execute(
            "SELECT name FROM sqlite_master WHERE name = 'voucher_series_phase_signatures'"
        ).fetchone()
        stripe_table = ledger._conn.execute(
            "SELECT name FROM sqlite_master WHERE name = 'stripe_settlement_signatures'"
        ).fetchone()
        columns = {
            row[1]
            for row in ledger._conn.execute(
                "PRAGMA table_info(voucher_transition_signatures)"
            ).fetchall()
        }
    finally:
        ledger.close()
    assert version == SCHEMA_VERSION == 15
    assert table is not None
    assert stripe_table is not None
    assert "deed_coin_id" in columns


def test_inventory_reservation_retry_is_exact_and_rebinding_fails_closed() -> None:
    ledger = ValidatorLedger(":memory:")
    kwargs = {
        "claim_hash": "0x" + "15" * 32,
        "canonical_claim": '{"reservation":"one"}',
        "purchase_id": "0x" + "16" * 32,
        "available_coin_id": "0x" + "17" * 32,
        "signature": "0x" + "18" * 96,
    }
    try:
        first = ledger.record_inventory_reservation_or_recover(**kwargs)
        assert ledger.record_inventory_reservation_or_recover(**kwargs) == first
        with pytest.raises(ValidatorLedgerConflict, match="already reserved"):
            ledger.record_inventory_reservation_or_recover(
                **{
                    **kwargs,
                    "claim_hash": "0x" + "19" * 32,
                    "canonical_claim": '{"reservation":"changed"}',
                    "purchase_id": "0x" + "1a" * 32,
                }
            )
    finally:
        ledger.close()


def test_primary_purchase_retry_recovers_the_original_signature() -> None:
    ledger = ValidatorLedger(":memory:")
    kwargs = {
        "claim_hash": "0x" + "11" * 32,
        "canonical_claim": '{"purchase":"one"}',
        "purchase_id": "0x" + "12" * 32,
        "deed_coin_id": "0x" + "13" * 32,
        "signature": "0x" + "14" * 96,
    }
    try:
        first = ledger.record_primary_purchase_or_recover(**kwargs)
        second = ledger.record_primary_purchase_or_recover(**kwargs)
    finally:
        ledger.close()
    assert first == second


def test_validator_will_not_sign_one_deed_for_two_primary_purchases() -> None:
    ledger = ValidatorLedger(":memory:")
    try:
        ledger.record_primary_purchase_or_recover(
            claim_hash="0x" + "21" * 32,
            canonical_claim='{"purchase":"one"}',
            purchase_id="0x" + "22" * 32,
            deed_coin_id="0x" + "23" * 32,
            signature="0x" + "24" * 96,
        )
        with pytest.raises(ValidatorLedgerConflict, match="already authorized"):
            ledger.record_primary_purchase_or_recover(
                claim_hash="0x" + "25" * 32,
                canonical_claim='{"purchase":"two"}',
                purchase_id="0x" + "26" * 32,
                deed_coin_id="0x" + "23" * 32,
                signature="0x" + "27" * 96,
            )
    finally:
        ledger.close()


def test_primary_purchase_batch_is_recorded_atomically() -> None:
    ledger = ValidatorLedger(":memory:")
    values = {
        "claim_hashes": ("0x" + "41" * 32, "0x" + "42" * 32),
        "canonical_claims": (
            '{"batch":"one","item":0}',
            '{"batch":"one","item":1}',
        ),
        "purchase_ids": ("0x" + "43" * 32, "0x" + "44" * 32),
        "deed_coin_ids": ("0x" + "45" * 32, "0x" + "46" * 32),
        "signatures": ("0x" + "47" * 96, "0x" + "48" * 96),
    }
    try:
        first = ledger.record_primary_purchase_batch_or_recover(**values)
        assert ledger.record_primary_purchase_batch_or_recover(**values) == first
        count = ledger._conn.execute(
            "SELECT COUNT(*) FROM primary_purchase_signatures"
        ).fetchone()[0]
        with pytest.raises(ValidatorLedgerConflict, match="already authorized"):
            ledger.record_primary_purchase_batch_or_recover(
                **{
                    **values,
                    "claim_hashes": (
                        "0x" + "49" * 32,
                        "0x" + "4a" * 32,
                    ),
                    "canonical_claims": (
                        '{"batch":"two","item":0}',
                        '{"batch":"two","item":1}',
                    ),
                    "purchase_ids": (
                        "0x" + "4b" * 32,
                        "0x" + "4c" * 32,
                    ),
                }
            )
        assert ledger._conn.execute(
            "SELECT COUNT(*) FROM primary_purchase_signatures"
        ).fetchone()[0] == count
    finally:
        ledger.close()


def test_stripe_settlement_retry_is_exact_and_rebinding_fails_closed() -> None:
    ledger = ValidatorLedger(":memory:")
    kwargs = {
        "claim_hash": "0x" + "28" * 32,
        "canonical_claim": '{"stripe":"one"}',
        "purchase_id": "0x" + "29" * 32,
        "payment_intent_id": "pi_test_one",
        "receipt_coin_id": "0x" + "2a" * 32,
        "deed_coin_id": "0x" + "2b" * 32,
        "signature": "0x" + "2c" * 96,
    }
    try:
        first = ledger.record_stripe_settlement_or_recover(**kwargs)
        assert ledger.record_stripe_settlement_or_recover(**kwargs) == first
        with pytest.raises(ValidatorLedgerConflict, match="already authorized"):
            ledger.record_stripe_settlement_or_recover(
                **{
                    **kwargs,
                    "claim_hash": "0x" + "2d" * 32,
                    "canonical_claim": '{"stripe":"changed"}',
                    "receipt_coin_id": "0x" + "2e" * 32,
                }
            )
    finally:
        ledger.close()


def test_stripe_batch_settlement_is_atomic_and_idempotent() -> None:
    ledger = ValidatorLedger(":memory:")
    kwargs = {
        "claim_hash": "0x" + "51" * 32,
        "canonical_claim": '{"stripeBatch":"one"}',
        "purchase_id": "0x" + "52" * 32,
        "payment_intent_id": "pi_test_batch_one",
        "receipt_coin_id": "0x" + "53" * 32,
        "delivery_coin_ids": (
            "0x" + "54" * 32,
            "0x" + "55" * 32,
        ),
        "signature": "0x" + "56" * 96,
    }
    try:
        first = ledger.record_stripe_settlement_batch_or_recover(**kwargs)
        assert ledger.record_stripe_settlement_batch_or_recover(**kwargs) == first
        rows = ledger._conn.execute(
            """
            SELECT delivery_coin_id
            FROM stripe_settlement_delivery_locks
            ORDER BY rowid
            """
        ).fetchall()
        assert tuple(str(row[0]) for row in rows) == kwargs["delivery_coin_ids"]
        with pytest.raises(ValidatorLedgerConflict, match="already authorized"):
            ledger.record_stripe_settlement_batch_or_recover(
                **{
                    **kwargs,
                    "claim_hash": "0x" + "57" * 32,
                    "canonical_claim": '{"stripeBatch":"changed"}',
                    "purchase_id": "0x" + "58" * 32,
                    "payment_intent_id": "pi_test_batch_two",
                    "receipt_coin_id": "0x" + "59" * 32,
                }
            )
        assert ledger._conn.execute(
            "SELECT COUNT(*) FROM stripe_settlement_signatures"
        ).fetchone()[0] == 1
    finally:
        ledger.close()


def _voucher_transition_record(
    ledger: ValidatorLedger,
    *,
    claim: str = "31",
    payment_id: str = "32",
    series_coin: str = "33",
    voucher_coin: str = "34",
    payment_coin: str = "35",
    deed_coin: str | None = None,
) -> str:
    return ledger.record_voucher_transition_or_recover(
        claim_hash="0x" + claim * 32,
        canonical_claim='{"transition":"' + claim + '"}',
        global_payment_id="0x" + payment_id * 32,
        series_coin_id="0x" + series_coin * 32,
        voucher_coin_id="0x" + voucher_coin * 32,
        payment_coin_id="0x" + payment_coin * 32,
        deed_coin_id=("0x" + deed_coin * 32 if deed_coin else None),
        signature="0x" + "36" * 96,
    )


def test_voucher_transition_retry_recovers_original_signature() -> None:
    ledger = ValidatorLedger(":memory:")
    try:
        first = _voucher_transition_record(ledger)
        second = _voucher_transition_record(ledger)
    finally:
        ledger.close()
    assert first == second


def test_voucher_transition_rejects_reused_governed_deed() -> None:
    ledger = ValidatorLedger(":memory:")
    try:
        _voucher_transition_record(ledger, deed_coin="37")
        with pytest.raises(ValidatorLedgerConflict, match="already settled"):
            _voucher_transition_record(
                ledger,
                claim="38",
                payment_id="39",
                series_coin="3a",
                voucher_coin="3b",
                payment_coin="3c",
                deed_coin="37",
            )
    finally:
        ledger.close()


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("payment_id", "41"),
        ("series_coin", "42"),
        ("voucher_coin", "43"),
        ("payment_coin", "44"),
    ],
)
def test_voucher_transition_rejects_reused_terminal_evidence(
    field: str,
    replacement: str,
) -> None:
    ledger = ValidatorLedger(":memory:")
    try:
        _voucher_transition_record(ledger)
        kwargs = {
            "claim": "45",
            "payment_id": "32",
            "series_coin": "33",
            "voucher_coin": "34",
            "payment_coin": "35",
            field: replacement,
        }
        with pytest.raises(ValidatorLedgerConflict, match="already settled"):
            _voucher_transition_record(ledger, **kwargs)
    finally:
        ledger.close()


def test_series_phase_retry_recovers_and_reused_coin_fails_closed() -> None:
    ledger = ValidatorLedger(":memory:")
    kwargs = {
        "claim_hash": "0x" + "51" * 32,
        "canonical_claim": '{"phase":"launch"}',
        "series_coin_id": "0x" + "52" * 32,
        "transition": 2,
        "signature": "0x" + "53" * 96,
    }
    try:
        first = ledger.record_voucher_series_phase_or_recover(**kwargs)
        second = ledger.record_voucher_series_phase_or_recover(**kwargs)
        assert first == second
        with pytest.raises(ValidatorLedgerConflict, match="already authorized"):
            ledger.record_voucher_series_phase_or_recover(
                **{
                    **kwargs,
                    "claim_hash": "0x" + "54" * 32,
                    "canonical_claim": '{"phase":"cancel"}',
                    "transition": 3,
                }
            )
    finally:
        ledger.close()
