"""XCH launcher-payer (faucet).

The faucet is a single BLS key controlled by the backend that funds every
new vault's launcher coin.  Users never pay — they only sign an EIP-712
(or BLS) message to prove ownership of their public key.

On testnet11 the faucet can be topped up for free from the Chia testnet
faucet (https://testnet11-faucet.chia.net).  On mainnet (Phase 2) this
faucet is replaced by user-paid launchers or a dedicated onboarding
service.

Key derivation follows the standard Chia wallet path
  m / 12381' / 8444' / 2' / 0'
which is the first wallet address (address index 0).
"""
from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Optional

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.derive_keys import master_sk_to_wallet_sk_unhardened
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
    DEFAULT_HIDDEN_PUZZLE_HASH,
    MOD as _P2_DELEGATED_MOD,
    calculate_synthetic_secret_key,
)
from chia_rs import AugSchemeMPL, G1Element, G2Element, PrivateKey
from chia_rs.sized_bytes import bytes32

logger = logging.getLogger(__name__)


class FaucetSelectionRestricted(RuntimeError):
    """Coin selection is intentionally unavailable to this caller."""


# Cache the p2_delegated_or_hidden MOD as bytes at this module's import
# time.  chia_rs's `LazyNode` (the SEXP backing every chia ``Program``)
# is *not* thread-safe — the underlying PyO3 binding panics with
# "LazyNode is unsendable, but sent to another thread" when a
# Program created on thread A is deserialised / curried on thread B.
#
# This bites us specifically under pytest's ``TestClient(app)``, which
# runs the FastAPI lifespan on an anyio portal thread distinct from the
# import thread.  The lifespan's faucet construction calls
# ``puzzle_for_pk(wallet_pk)`` → ``MOD.curry(...)`` and then
# ``get_tree_hash()`` walks the LazyNode → panic.
#
# The fix: capture MOD as bytes once at import time, then on every call
# deserialise a *thread-local* copy via ``Program.from_bytes(...)``.
# Each call thus operates on a Program whose LazyNode is owned by the
# caller's thread.  Per-call deserialisation is cheap (the puzzle is
# tiny), and we only do it once per faucet, not per request.
_P2_DELEGATED_MOD_BYTES: bytes = bytes(_P2_DELEGATED_MOD)


def _puzzle_for_pk_threadsafe(public_key: G1Element) -> Program:
    """Thread-safe replacement for ``chia...puzzle_for_pk``.

    Reconstructs the p2_delegated_or_hidden MOD from cached bytes on
    the calling thread, then curries the public key in.  The returned
    ``Program``'s LazyNode is owned by the calling thread, so all
    subsequent operations (``bytes(...)``, ``get_tree_hash()``,
    ``run(...)``) are safe.
    """
    mod_local = Program.from_bytes(_P2_DELEGATED_MOD_BYTES)
    return mod_local.curry(public_key)

# Network-specific AGG_SIG_ME additional data.
# Pulled from chia.consensus.default_constants.DEFAULT_CONSTANTS / testnet11 overrides.
AGG_SIG_ME_DATA = {
    "mainnet": bytes.fromhex(
        "ccd5bb71183532bff220ba46c268991a00000000000000000000000000000000"
    ),
    "testnet11": bytes.fromhex(
        "37a90eb5185a9c4439a91ddc98bbadce7b4feba060d50116a067de66bf236615"
    ),
}


@dataclass
class FaucetKey:
    """A derived wallet key + puzzle."""

    wallet_sk: PrivateKey
    wallet_pk: G1Element
    synthetic_sk: PrivateKey
    synthetic_pk: G1Element
    puzzle: Program
    puzzle_hash: bytes32


class Faucet:
    """Single-address XCH faucet for funding vault launchers."""

    def __init__(self, master_sk: PrivateKey, network: str) -> None:
        if network not in AGG_SIG_ME_DATA:
            raise ValueError(f"Unknown network for faucet: {network}")
        self.network = network
        self.master_sk = master_sk
        self.agg_sig_me_data = AGG_SIG_ME_DATA[network]
        self.key = self._derive_wallet_key(0)
        self._exclusive_selection_purpose: str | None = None
        self._coin_reservation_sources: list[Callable[[], Iterable[str]]] = []

    def add_coin_reservation_source(self, source: Callable[[], Iterable[str]]) -> None:
        if source not in self._coin_reservation_sources:
            self._coin_reservation_sources.append(source)

    def reserved_coin_ids(self) -> set[bytes32]:
        try:
            return {_hex_to_bytes32(value) for source in self._coin_reservation_sources for value in source()}
        except Exception as exc:
            raise FaucetSelectionRestricted("durable faucet reservations are unavailable") from exc

    def require_unreserved_coin(self, coin: Coin) -> None:
        if coin.name() in self.reserved_coin_ids():
            raise FaucetSelectionRestricted("faucet coin is reserved by an unresolved exact execution")

    def restrict_coin_selection_to(self, purpose: str) -> None:
        """Fail closed for unrelated faucet spenders during one-shot work."""

        normalized = purpose.strip()
        if not normalized:
            raise ValueError("exclusive faucet selection purpose is required")
        self._exclusive_selection_purpose = normalized

    def require_spend_purpose(self, purpose: str | None) -> None:
        """Enforce the one-shot purpose at the shared signing boundary."""

        if (
            self._exclusive_selection_purpose is not None
            and purpose != self._exclusive_selection_purpose
        ):
            raise FaucetSelectionRestricted(
                "faucet coin selection is reserved for "
                + self._exclusive_selection_purpose
            )

    @classmethod
    def from_seed_hex(cls, seed_hex: str, network: str) -> Faucet:
        """Build a faucet from a 32-byte hex seed.

        `AugSchemeMPL.key_gen(seed)` is called with the bytes — this is the
        canonical way to generate a master BLS key from an entropy seed.
        """
        seed = bytes.fromhex(seed_hex[2:] if seed_hex.startswith("0x") else seed_hex)
        if len(seed) != 32:
            raise ValueError(
                f"faucet seed must be 32 bytes (64 hex chars), got {len(seed)} bytes"
            )
        master_sk = AugSchemeMPL.key_gen(seed)
        return cls(master_sk, network)

    @classmethod
    def from_mnemonic(cls, mnemonic: str, network: str) -> Faucet:
        """Build a faucet from a 12/24-word BIP-39 mnemonic."""
        from chia.util.keychain import mnemonic_to_seed

        seed = mnemonic_to_seed(mnemonic)
        master_sk = AugSchemeMPL.key_gen(seed)
        return cls(master_sk, network)

    @classmethod
    def from_master_private_key_hex(cls, sk_hex: str, network: str) -> Faucet:
        """Build a faucet from a raw 32-byte BLS private key hex string.

        Use this when you already have a master ``PrivateKey`` (e.g. pulled
        from the chia keychain by fingerprint) and don't have the original
        mnemonic/seed handy.  The 32 bytes are the serialised master sk,
        ``bytes(PrivateKey)``.
        """
        raw = bytes.fromhex(sk_hex[2:] if sk_hex.startswith("0x") else sk_hex)
        if len(raw) != 32:
            raise ValueError(
                f"master private key must be 32 bytes (64 hex chars), got {len(raw)}"
            )
        master_sk = PrivateKey.from_bytes(raw)
        return cls(master_sk, network)

    def _derive_wallet_key(self, index: int) -> FaucetKey:
        wallet_sk = master_sk_to_wallet_sk_unhardened(self.master_sk, index)
        wallet_pk = wallet_sk.get_g1()
        synth_sk = calculate_synthetic_secret_key(wallet_sk, DEFAULT_HIDDEN_PUZZLE_HASH)
        synth_pk = synth_sk.get_g1()
        # Thread-safe puzzle construction (see the module-level note on
        # ``_P2_DELEGATED_MOD_BYTES``).  This is what lets the faucet be
        # constructed on the lifespan thread and used from request
        # handlers on the asyncio thread without a LazyNode panic.
        puzzle = _puzzle_for_pk_threadsafe(wallet_pk)
        puzzle_hash = bytes32(puzzle.get_tree_hash())
        return FaucetKey(
            wallet_sk=wallet_sk,
            wallet_pk=wallet_pk,
            synthetic_sk=synth_sk,
            synthetic_pk=synth_pk,
            puzzle=puzzle,
            puzzle_hash=puzzle_hash,
        )

    @property
    def address_puzzle_hash(self) -> bytes32:
        return self.key.puzzle_hash

    @property
    def address_hex(self) -> str:
        return "0x" + self.key.puzzle_hash.hex()

    def bech32_address(self) -> str:
        """Return the faucet's XCH bech32m address for the configured network."""
        from chia.util.bech32m import encode_puzzle_hash

        prefix = "txch" if self.network == "testnet11" else "xch"
        return encode_puzzle_hash(self.key.puzzle_hash, prefix)

    def select_coin(
        self,
        candidate_coins: list[dict],
        min_amount: int,
        *,
        max_amount: Optional[int] = None,
        purpose: str | None = None,
    ) -> Optional[Coin]:
        """Pick the smallest coin that meets the launcher budget.

        Prefers tight matches to minimise change outputs and keep the mempool
        small. Rejects coins already spent per coinset's `spent_block_index`.

        Args:
            candidate_coins: raw coin records from coinset.org.
            min_amount: smallest acceptable coin amount (inclusive).
            max_amount: optional ceiling (inclusive).  POP-CANON-009 fix:
                enforces ``settings.faucet_max_spend_mojos``.  Mirrors the
                ``max_coin_amount`` field of Chia's
                ``chia.wallet.util.tx_config.CoinSelectionConfig``: the
                operator's configured ceiling on per-spend faucet usage.
        """
        self.require_spend_purpose(purpose)
        reserved = self.reserved_coin_ids()
        usable: list[Coin] = []
        for rec in candidate_coins:
            if rec.get("spent_block_index") not in (0, None):
                continue
            coin_json = rec.get("coin") or rec
            amount = int(coin_json["amount"])
            if amount < min_amount:
                continue
            if max_amount is not None and amount > max_amount:
                continue
            usable.append(
                Coin(
                    parent_coin_info=_hex_to_bytes32(coin_json["parent_coin_info"]),
                    puzzle_hash=_hex_to_bytes32(coin_json["puzzle_hash"]),
                    amount=amount,
                )
            )
        if not usable:
            return None
        usable = [coin for coin in usable if coin.name() not in reserved]
        if not usable:
            return None
        usable.sort(key=lambda c: c.amount)
        return usable[0]

    def sign_delegated_spend(
        self,
        coin: Coin,
        conditions: Program,
        *,
        purpose: str | None = None,
    ) -> bytes:
        """Sign the faucet's standard p2_delegated spend with AGG_SIG_ME.

        For `p2_delegated_puzzle_or_hidden_puzzle`, the AGG_SIG_ME message is:
            sha256tree(delegated_puzzle) + coin.name() + AGG_SIG_ME_ADDITIONAL_DATA
        and the signer is the wallet secret key.
        """
        self.require_spend_purpose(purpose)
        self.require_unreserved_coin(coin)
        return self._delegated_signature(coin,conditions)

    def sign_refund_fee_deadline(self, retained_bundle, protocol_signature, fee_coin_id, conditions, current_timestamp):
        """Renew ONLY a previously signed refund sponsor deadline, keeping its hold.

        No general reserved-coin signing bypass: the old aggregate proves this
        key signed the exact prior sponsor, and every non-time condition stays.
        The refund coordinator separately proves current inputs and effects.
        """
        from .stripe_refund_continuation import fee_deadline
        from chia.types.coin_spend import make_spend
        self.require_spend_purpose(None)
        spends=[s for s in retained_bundle.coin_spends if '0x'+s.coin.name().hex()==fee_coin_id]
        if len(retained_bundle.coin_spends)!=5 or len(spends)!=1:
            raise FaucetSelectionRestricted('Retained refund sponsor is missing')
        previous=spends[0]
        if previous.coin.puzzle_hash!=self.address_puzzle_hash or bytes(previous.puzzle_reveal)!=bytes(self.key.puzzle):
            raise FaucetSelectionRestricted('Retained refund sponsor key changed')
        before,old_mask=fee_deadline(previous)
        candidate=make_spend(previous.coin,self.key.puzzle,Program.to([0,Program.to((1,conditions)),0]))
        after,new_mask=fee_deadline(candidate)
        if (before is None or after is None or old_mask!=new_mask or type(current_timestamp) is not int
                or not before<=current_timestamp<after<=current_timestamp+120):
            raise FaucetSelectionRestricted('Refund sponsor may renew only its expired deadline')
        previous_conditions=list(Program.from_bytes(bytes(previous.solution)).as_iter())[1].rest()
        previous_signature=G2Element.from_bytes(self._delegated_signature(previous.coin,previous_conditions))
        if AugSchemeMPL.aggregate([protocol_signature,previous_signature])!=retained_bundle.aggregated_signature:
            raise FaucetSelectionRestricted('Retained refund sponsor authorization changed')
        return self._delegated_signature(previous.coin,conditions)

    def _delegated_signature(self,coin:Coin,conditions:Program)->bytes:
        delegated_puzzle = Program.to((1, conditions))  # (q . conditions)
        message = (
            bytes(delegated_puzzle.get_tree_hash())
            + bytes(coin.name())
            + self.agg_sig_me_data
        )
        sig = AugSchemeMPL.sign(self.key.wallet_sk, message)
        return bytes(sig)


def _hex_to_bytes32(h: str) -> bytes32:
    clean = h[2:] if h.startswith("0x") else h
    return bytes32.fromhex(clean)
