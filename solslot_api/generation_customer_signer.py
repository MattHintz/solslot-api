"""A saved registration may sign its own hold, never another execution's.

This adapter exposes only the public puzzle and one exact delegated spend.
The ordinary faucet's reservation checks remain intact for all other callers.
"""
from types import SimpleNamespace

from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import launch_conditions_and_coinsol
from chia_rs.sized_ints import uint64
from solslot_puzzles.generation_vault import vault_inner
from solslot_puzzles.vault_driver import one_leaf_merkle_root, vault_discovery_hint


class ReviewedCustomerSigner:
    def __init__(self, faucet, store, identity, funding_coin, *, bindings, maximum_parent_amount):
        self._faucet, self._store, self._identity = faucet, store, identity
        self._funding = funding_coin
        self._bindings = bindings
        self._maximum = maximum_parent_amount
        self.network = faucet.network
        self.address_puzzle_hash = faucet.address_puzzle_hash
        self.key = SimpleNamespace(puzzle=faucet.key.puzzle)

    def sign_delegated_spend(self, coin, conditions, *, purpose=None):
        self._faucet.require_spend_purpose(None)
        consent, signature, authorized_at = self._store.authorized_material(self._identity)
        owner, auth = consent.verified_owner(signature, authorized_at)
        if (purpose is not None or self.network != 'testnet11'
                or consent.bindings != self._bindings
                or consent.message()['generationId'] != self._store.generation_id
                or coin != self._funding or coin.name() != consent.funding_coin_id
                or coin.puzzle_hash != self.address_puzzle_hash
                or type(self._maximum) is not int or not 1 <= coin.amount <= self._maximum
                or consent.message()['fundingCoinId'] not in self._store.held_funding_ids()):
            raise ValueError('customer signer requires its exact saved authorized funding hold')
        for source in self._faucet._coin_reservation_sources:
            if source == self._store.held_funding_ids:
                continue
            from .faucet import _hex_to_bytes32
            if consent.funding_coin_id in {_hex_to_bytes32(value) for value in source()}:
                raise ValueError('customer funding belongs to another retained execution')
        inner = vault_inner(vault_launcher_id=consent.vault_launcher_id, owner_pubkey=owner,
            auth_type=auth, members_merkle_root=one_leaf_merkle_root(owner),
            pool_launcher_id=self._bindings.pool_launcher,
            zkpassport_bridge_policy_hash=self._bindings.bridge_policy)
        native, launch = launch_conditions_and_coinsol(coin, inner, [], uint64(1))
        exact = [Program.to([51, launch.coin.puzzle_hash, 1, [vault_discovery_hint(auth, owner)]]), native[1]]
        if coin.amount > 1:
            exact.append(Program.to([51, coin.puzzle_hash, int(coin.amount)-1]))
        if bytes(conditions) != bytes(Program.to(exact)):
            raise ValueError('customer signer rejects changed output, fee or launcher commitment')
        return self._faucet._delegated_signature(coin, conditions)


class CustomerFeeFaucet:
    """Only fingerprinted fee parents, one bounded fee and unchanged change.

    No creation parent or returned fee change becomes a new spending budget.
    The submitter is private to registration and retains every funded bundle.
    """
    def __init__(self, faucet, policy, clock, store, journal):
        self._faucet, self._policy, self._clock = faucet, policy, clock
        self._store,self._journal=store,journal
        self.network = faucet.network
        self.address_puzzle_hash = faucet.address_puzzle_hash
        self.address_hex = faucet.address_hex
        self.key = SimpleNamespace(puzzle=faucet.key.puzzle)

    def add_coin_reservation_source(self, source):
        self._faucet.add_coin_reservation_source(source)

    def select_coin(self, records, **kwargs):
        self._policy.validate(self._policy.generation_id, int(self._clock()))
        from chia_rs import Coin
        selected = []
        for record in records:
            coin = Coin.from_json_dict(record.get('coin') or record)
            if '0x'+coin.name().hex() in self._policy.allowed_fee_ids:
                selected.append(record)
        return self._faucet.select_coin(selected, **kwargs)

    def sign_delegated_spend(self, coin, conditions, *, purpose=None):
        self._policy.validate(self._policy.generation_id, int(self._clock()))
        if (purpose is not None or self.network != 'testnet11'
                or '0x'+coin.name().hex() not in self._policy.allowed_fee_ids
                or coin.puzzle_hash != self.address_puzzle_hash
                or coin.amount > self._policy.maximum_fee_parent_mojos):
            raise ValueError('customer fee signer rejects an unreviewed parent')
        values = list(conditions.as_iter())
        fees = [v for v in values if v.first().as_int() == 52]
        if len(fees) != 1:
            raise ValueError('customer fee signer requires one explicit bounded network fee')
        fee = fees[0].rest().first().as_int()
        if not 0 <= fee <= min(self._policy.fee_cap_mojos, int(coin.amount)):
            raise ValueError('customer network fee exceeds its reviewed cap')
        exact = []
        if coin.amount > fee:
            exact.append(Program.to([51, self.address_puzzle_hash, int(coin.amount)-fee]))
        exact.append(Program.to([52, fee]))
        from .generation_customer_execution import saved_customer_operation
        from .protocol_submission import ProtocolBundleSubmitter
        matched=False
        for identity in self._store.pending_authorized():
            operation=saved_customer_operation(self._store,self._journal,identity)
            if operation is None:continue
            protocol=self._journal.protocol_bundle(operation['operationId'])
            binding=ProtocolBundleSubmitter._backing_conditions(protocol,require_announcements=True)
            if bytes(conditions)==bytes(Program.to([*exact,*binding])):
                matched=True
                break
        if not matched:
            raise ValueError('customer fee signer requires an exact retained registration and native subsidy binding')
        return self._faucet.sign_delegated_spend(coin, conditions)
