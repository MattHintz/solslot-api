"""A one-purchase Testnet window shared by the coordinator and issuer."""
from dataclasses import dataclass
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.payment_artifacts_v2 import PaymentRail


@dataclass(frozen=True)
class CatTestWindow:
    vault: bytes32
    asset: bytes32
    amount_per_deed: int
    starts_at: int
    ends_at: int

    def validate(self):
        if (any(not isinstance(v, bytes32) or v == bytes32.zeros for v in (self.vault, self.asset))
                or type(self.amount_per_deed) is not int or not 1 < self.amount_per_deed < 2**63
                or type(self.starts_at) is not int or type(self.ends_at) is not int
                or not 0 < self.starts_at < self.ends_at <= self.starts_at + 3600):
            raise ValueError('Invalid single-purchase Testnet window')
        return self

    def public(self):
        return {'vaultLauncherId': '0x' + self.vault.hex(), 'assetId': '0x' + self.asset.hex(),
                'amountPerDeedAtomic': str(self.amount_per_deed), 'startsAt': self.starts_at,
                'endsAt': self.ends_at, 'quantity': 2}

    @classmethod
    def parse(cls, row):
        window = cls(bytes32.from_hexstr(row['vaultLauncherId']), bytes32.from_hexstr(row['assetId']),
                     int(row['amountPerDeedAtomic']), row['startsAt'], row['endsAt']).validate()
        if row != window.public() or type(row['quantity']) is not int:
            raise ValueError('Invalid single-purchase Testnet window')
        return window

    def require_order(self, vault, asset, quantity, buyer_paid, now):
        if not (self.starts_at <= now < self.ends_at and buyer_paid is True and vault == self.vault
                and asset == self.asset and quantity == 2):
            raise ValueError('CURRENT_CHECKOUT_OUTSIDE_TEST_WINDOW')

    def require_artifacts(self, items, *, buyer_paid, now):
        if not items:
            raise ValueError('CURRENT_CHECKOUT_OUTSIDE_TEST_WINDOW')
        self.require_order(items[0].vault_launcher_id, items[0].rail_asset_id, len(items), buyer_paid, now)
        if (len({a.deed_launcher_id for a in items}) != 2 or any(
                a.network != 'testnet11' or a.rail != PaymentRail.CHIA_CAT or a.vault_launcher_id != self.vault
                or a.rail_asset_id != self.asset or a.rail_amount != self.amount_per_deed
                or not now < a.quote_expires_at <= self.ends_at for a in items)):
            raise ValueError('CURRENT_CHECKOUT_OUTSIDE_TEST_WINDOW')
