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
        self._generation_preparation_json: str | None = None
        self._generation_launch_store = None
        self._generation_mint_reviews = None
        self._generation_mint_parent_limit = None

    def bind_generation_preparation(self, preparation, *, trusted_preparation_hash: str) -> None:
        """Reserve frozen launch parents before any ordinary selection starts.

        This does not authorize issuance, broadcasting or arbitrary signing.
        The only scoped exception is the exact one-mojo recipient launch below.
        """
        from .generation_preparation import GenerationPreparation
        frozen = GenerationPreparation.model_validate_json(preparation.model_dump_json(by_alias=True))
        if self.network != 'testnet11' or frozen.manifest_hash != trusted_preparation_hash:
            raise FaucetSelectionRestricted('generation preparation does not match the reviewed Testnet11 binding')
        encoded = frozen.model_dump_json(by_alias=True)
        if self._generation_preparation_json is not None:
            if self._generation_preparation_json != encoded:
                raise FaucetSelectionRestricted('reserved generation preparation cannot change in this runtime')
            return
        reserved = frozenset([frozen.sgt_funding_coin_id,
            *(c.funding_coin_id for c in frozen.coordinates.values()),
            *(a.custody.funding_coin_id for a in frozen.administrators)])
        self._generation_preparation_json = encoded
        # Keep this source separate from durable executions. The scoped signer
        # must still reject a parent reserved by any other execution journal.
        self._generation_preparation_reservations = lambda: reserved
        self.add_coin_reservation_source(self._generation_preparation_reservations)

    def sign_generation_recipient(self, coin: Coin, slot: int, *, preparation_manifest: str):
        """Sign only the frozen recipient launch and unchanged-owner change."""
        from .generation_preparation import GenerationPreparation
        from .generation_recipient_launch import build_recipient_launch
        from chia.types.coin_spend import make_spend
        from chia.wallet.puzzles.singleton_top_layer_v1_1 import launch_conditions_and_coinsol
        from chia_rs.sized_ints import uint64
        self.require_spend_purpose('genesis')
        if self.network != 'testnet11' or self._generation_preparation_json is None:
            raise FaucetSelectionRestricted('reviewed generation preparation is not bound')
        frozen = GenerationPreparation.model_validate_json(self._generation_preparation_json)
        if (frozen.manifest_hash != preparation_manifest or type(slot) is not int or slot not in (1, 2, 3)
                or '0x' + coin.name().hex() != frozen.administrators[slot-1].custody.funding_coin_id
                or coin.puzzle_hash != self.address_puzzle_hash or coin.amount < 1):
            raise FaucetSelectionRestricted('recipient funding is not the frozen owned parent')
        for source in self._coin_reservation_sources:
            if source is self._generation_preparation_reservations:
                continue
            try:
                if coin.name() in {_hex_to_bytes32(value) for value in source()}:
                    raise FaucetSelectionRestricted('recipient parent belongs to another retained execution')
            except FaucetSelectionRestricted:
                raise
            except Exception as exc:
                raise FaucetSelectionRestricted('recipient reservations are unavailable') from exc
        conditions, _ = launch_conditions_and_coinsol(coin, frozen.custody_inner(frozen.administrators[slot-1]), [], uint64(1))
        if coin.amount > 1:
            conditions.append(Program.to([51, coin.puzzle_hash, int(coin.amount)-1]))
        conditions = Program.to(conditions)
        spend = make_spend(coin, self.key.puzzle, Program.to([0, Program.to((1, conditions)), 0]))
        operation = build_recipient_launch(frozen, slot, spend, trusted_preparation_hash=preparation_manifest)
        return operation.with_aggregated_signature(G2Element.from_bytes(self._delegated_signature(coin, conditions)))

    def bind_generation_launch(self, store):
        from .generation_launch import GenerationLaunchStore
        if (not isinstance(store, GenerationLaunchStore) or self.network != 'testnet11'
                or self._generation_preparation_json is None
                or store.preparation.model_dump_json(by_alias=True) != self._generation_preparation_json):
            raise FaucetSelectionRestricted('final launch differs from the reserved preparation')
        if self._generation_launch_store is not None and self._generation_launch_store is not store:
            raise FaucetSelectionRestricted('final launch cannot be rebound in this runtime')
        self._generation_launch_store = store

    def sign_generation_launch(self, identity, *, evidence, funding_coins, now):
        """Only the installed release and two verified exact launch consents."""
        from .generation_genesis_core import genesis_launch_funding_requests, assemble_genesis_launch
        from chia.types.coin_spend import make_spend
        from chia_rs import AugSchemeMPL
        self.require_spend_purpose('genesis')
        store=self._generation_launch_store
        if store is None:raise FaucetSelectionRestricted('final launch is not bound')
        store.require_ready(now);review=store.require_consent(identity,now)
        args=dict(preparation=store.preparation,artifact=store.artifact,evidence=evidence,
            trusted_preparation_hash=store.preparation.manifest_hash,trusted_artifact_hash=store.artifact.artifact_hash,
            consent_issued_at=review['issuedAt'])
        requests=genesis_launch_funding_requests(**args,funding_coins=dict(funding_coins))
        for item in requests:
            if item.coin.puzzle_hash!=self.address_puzzle_hash:
                raise FaucetSelectionRestricted('final launch parent is not owned by the approved funder')
            for source in self._coin_reservation_sources:
                if source is self._generation_preparation_reservations:continue
                try:
                    if item.coin.name() in {_hex_to_bytes32(v) for v in source()}:
                        raise FaucetSelectionRestricted('launch parent is retained by another operation')
                except FaucetSelectionRestricted:raise
                except Exception as exc:raise FaucetSelectionRestricted('launch reservations are unavailable') from exc
        spends={r.name:make_spend(r.coin,self.key.puzzle,Program.to([0,Program.to((1,r.conditions)),0])) for r in requests}
        unsigned=assemble_genesis_launch(**args,funding_spends=spends)
        if '0x'+unsigned.operation.commitment.hex()!=review['assemblyHash']:
            raise FaucetSelectionRestricted('native launch differs from signed release consent')
        signatures=[G2Element.from_bytes(self._delegated_signature(r.coin,r.conditions)) for r in requests]
        return unsigned.operation.with_aggregated_signature(AugSchemeMPL.aggregate(signatures))

    def add_coin_reservation_source(self, source: Callable[[], Iterable[str]]) -> None:
        if source not in self._coin_reservation_sources:
            self._coin_reservation_sources.append(source)

    def bind_generation_mint_reviews(self, store, *, generation_id, maximum_parent_mojos):
        """Bind one reviewed local namespace, never a browser-supplied store."""
        from .generation_mint_reviews import GenerationMintReviewStore
        if (self.network!='testnet11' or not isinstance(store,GenerationMintReviewStore)
                or store.generation_id!=generation_id or type(maximum_parent_mojos) is not int
                or not 0<maximum_parent_mojos<=1_000_000_000):
            raise FaucetSelectionRestricted('test mint source or parent ceiling is not configured')
        if self._generation_mint_reviews is not None and (
                self._generation_mint_reviews.path!=store.path or self._generation_mint_parent_limit!=maximum_parent_mojos):
            raise FaucetSelectionRestricted('test mint source cannot be rebound in this runtime')
        self._generation_mint_reviews=store;self._generation_mint_parent_limit=maximum_parent_mojos
        self._generation_mint_reservations=store.reserved_input_coin_ids
        self.add_coin_reservation_source(self._generation_mint_reservations)

    def sign_generation_mint(self, identity, *, chain, proposal):
        """Build/sign only the voted source's fixed one-mojo launcher funding.

        There is no reserved-coin bypass or arbitrary condition argument. The
        known native assembler fixes all three authorities, every launcher,
        every inventory output and unchanged-puzzle change before signing.
        The caller must separately recheck fresh primary evidence and save the
        returned bytes durably before dispatch. Generic spend signing stays
        unable to use these retained parents.
        """
        from .generation_mint_reviews import reviewed_mint_edition, h
        from solslot_puzzles.generation_mint import GenerationMint
        from solslot_puzzles.generation_transactions import mint_collection
        from chia.types.coin_spend import make_spend
        from chia_rs.sized_ints import uint64
        self.require_spend_purpose(None)
        if self.network!='testnet11' or self._generation_mint_reviews is None:
            raise FaucetSelectionRestricted('reviewed Testnet11 mint source is not bound')
        review=self._generation_mint_reviews.status(identity);edition=reviewed_mint_edition(review)
        gov,reg=chain.governance.state,chain.registry.state
        history=chain.economic_components.get(bytes32.from_hexstr(review['mintAuthority']['componentId']))
        if (history is None or not isinstance(history.state,GenerationMint) or reg.pause_mask&2 or reg.pending
                or gov.active or gov.upgrade_reserved or gov.sgt.generation!=edition.generation):
            raise FaucetSelectionRestricted('the exact approved mint authority is not available')
        mint=history.state
        if review['mintAuthority']!={'componentId':h(mint.component_id),'launcherId':h(mint.launcher_id),
                'coinId':h(history.current.coin.name()),'moduleHash':h(mint.logic_hash()),'version':mint.version}:
            raise FaucetSelectionRestricted('mint authority differs from its saved source')
        other_holds=set()
        for source in self._coin_reservation_sources:
            if source==self._generation_mint_reservations:continue
            try:other_holds.update(_hex_to_bytes32(v) for v in source())
            except Exception as exc:raise FaucetSelectionRestricted('other retained reservations are unavailable') from exc
        funding=[];conditions=[]
        for row,inventory in zip(review['funding'],mint.inventories(edition),strict=True):
            coin=Coin.from_json_dict(row['coin'])
            if (coin.puzzle_hash!=self.address_puzzle_hash or not 0<coin.amount<=self._generation_mint_parent_limit
                    or h(coin.name())!=row['coinId'] or h(inventory.launcher_spend.coin.name())!=row['launcherId']
                    or h(inventory.coin.name())!=row['inventoryCoinId']):
                raise FaucetSelectionRestricted('mint parent or output differs from its reviewed scope')
            if coin.name() in other_holds:raise FaucetSelectionRestricted('mint parent belongs to another retained execution')
            outputs=[[51,inventory.launcher_spend.coin.puzzle_hash,1]]
            if coin.amount>1:outputs.append([51,coin.puzzle_hash,int(coin.amount)-1])
            exact=Program.to(outputs);conditions.append((coin,exact))
            funding.append(make_spend(coin,self.key.puzzle,Program.to([0,Program.to((1,exact)),0])))
        operation,_,_,_=mint_collection(gov,chain.governance.verified_tip(reg.governance_id,gov.inner()),
            reg,chain.registry.verified_tip(reg.launcher_id,reg.inner()),mint,
            history.verified_tip(mint.launcher_id,mint.inner()),proposal,edition,tuple(funding))
        signature=AugSchemeMPL.aggregate([G2Element.from_bytes(self._delegated_signature(coin,exact))
            for coin,exact in conditions])
        return operation.with_aggregated_signature(signature)

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
