"""Native payer scope and signed-offer decoding; synthetic inputs only."""
import pytest
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import G2Element
from pydantic import ValidationError
from solslot_api.generation_customer_purchase_wallet import CurrentNativePaymentRequest
from solslot_api.wallet_offer_validation import decode_offer, validate_standard_payment
from tests.test_generation_customer_purchase_reservation_claim import body
from tests.test_wallet_offer_cost_security import prepared_payment, encode_bundle, extra_input_bundle


def request():
    return dict(reservation=body(), reservedCoinId='0x'+'07'*32,
        paymentCoinId='0x'+'08'*32, paymentPublicKey='0x'+'09'*48)


@pytest.mark.parametrize('change', [
    {'paymentPublicKey':'0x'+'AA'*48}, {'paymentPublicKey':'0x'+'09'*32},
    {'paymentCoinId':'0x'+'GG'*32}, {'reservedCoinId':True},
    {'vaultLauncherId':'0x'+'10'*32}, {'network':'mainnet'},
    {'coinSpends':[{'opaque':'server input'}]}, {'proceedsPuzzleHash':'0x'+'11'*32},
])
def test_payer_request_cannot_replace_receiver_terms_network_or_spends(change):
    with pytest.raises(ValidationError):
        CurrentNativePaymentRequest.model_validate({**request(),**change})


def test_payer_request_preserves_separate_reservation_recipient():
    r=CurrentNativePaymentRequest.model_validate(request())
    assert r.reservation.current_vault_coin_id==body()['currentVaultCoinId']
    assert r.payment_coin_id!=r.reservation.current_vault_coin_id


def test_signed_decoder_is_explicit_and_keeps_original_default_closed():
    unsigned,_,signature=prepared_payment()
    signed=WalletSpendBundle(unsigned.coin_spends(),G2Element.from_bytes(bytes.fromhex(signature[2:])))
    wire=encode_bundle(signed)
    with pytest.raises(ValueError,match='must be unsigned'):
        decode_offer(wire,real_spends=1,dummy_spends=0)
    decoded=decode_offer(wire,real_spends=1,dummy_spends=0,allow_signed=True)
    validate_standard_payment(decoded,asset_id=None)
    assert bytes(decoded.bundle)==bytes(signed)


def test_signed_mode_does_not_allow_an_extra_payment_input():
    with pytest.raises(ValueError,match='input count'):
        decode_offer(encode_bundle(extra_input_bundle()),real_spends=1,dummy_spends=0,allow_signed=True)
