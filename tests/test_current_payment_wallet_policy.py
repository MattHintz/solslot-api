import pytest
from solslot_api.current_payment_wallet_policy import permits_payment_rail


@pytest.mark.parametrize('auth,rail,allowed',[
    ('evm','CHIA_XCH',False),('evm','CHIA_CAT',False),
    ('chia_bls','CHIA_XCH',True),('chia_bls','CHIA_CAT',True),
    ('evm','BASE_USDC',True),('chia_bls','BASE_USDC',True),
    ('evm','STRIPE',True),('chia_bls','STRIPE',True),
    (None,'CHIA_XCH',False),('unknown','BASE_USDC',False),('chia_bls','unknown',False),
])
def test_authenticated_vault_matrix_does_not_enable_a_payment_runtime(auth,rail,allowed):
    assert permits_payment_rail(auth,rail)is allowed
