"""Wallet eligibility, separate from a rail's installed financial authority."""

CHIA_PAYMENT_VAULT_MESSAGE = (
    'Chia payments require a Chia-wallet vault. '
    'Use Base or card payment with this vault when available.'
)


def permits_payment_rail(auth_type, rail):
    if auth_type not in ('evm', 'chia_bls'):
        return False
    if rail in ('CHIA_XCH', 'CHIA_CAT'):
        return auth_type == 'chia_bls'
    return rail in ('BASE_USDC', 'STRIPE')
