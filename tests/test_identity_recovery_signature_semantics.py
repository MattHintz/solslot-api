"""Evidence for recovery design only; these tests do not authorize recovery."""
from chia_rs import AugSchemeMPL
from chia_rs.sized_bytes import bytes32
from solslot_api.validator_quorum import CurrentIdentityClaim
from solslot_puzzles.vault_driver import eip712_typed_data_for_vault_spend
from tests.test_validator_quorum import _claim


def test_validator_signature_message_is_unchanged_but_claim_hash_changes_with_timestamp():
    keys=[AugSchemeMPL.key_gen(bytes([i])*32) for i in (1,2,3)]
    data=_claim(keys).model_dump();data.pop('artifact_hash')
    data.update(claim_version='solslot.current-customer-identity-claim.v1',
        generation_id='0x'+'91'*32,identity_profile_hash='0x'+'92'*32)
    old=CurrentIdentityClaim.model_validate(data)
    fresh=CurrentIdentityClaim.model_validate({**data,'current_timestamp':old.current_timestamp+300})
    assert old.canonical_hash()!=fresh.canonical_hash()
    assert old.signature_message()==fresh.signature_message()
    signature=AugSchemeMPL.sign(keys[1],old.signature_message())
    assert AugSchemeMPL.verify(keys[1].get_g1(),fresh.signature_message(),signature)
    assert not AugSchemeMPL.verify(keys[0].get_g1(),fresh.signature_message(),signature)


def test_evm_vault_stamp_authorization_binds_root_and_vault_coin():
    root=bytes32.from_hexstr('0x'+'01'*32)
    coin=bytes32.from_hexstr('0x'+'02'*32)
    other=bytes32.from_hexstr('0x'+'03'*32)
    typed=eip712_typed_data_for_vault_spend(b'z',root,coin)
    assert typed==eip712_typed_data_for_vault_spend(b'z',root,coin)
    assert typed!=eip712_typed_data_for_vault_spend(b'z',other,coin)
    assert typed!=eip712_typed_data_for_vault_spend(b'z',root,other)
