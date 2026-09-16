from __future__ import annotations

from dataclasses import dataclass, replace
from types import SimpleNamespace

import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_keys import keys as eth_keys
from chia.consensus.condition_tools import (
    conditions_dict_for_solution,
    pkm_pairs_for_conditions_dict,
)
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import INFINITE_COST, Program
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, construct_cat_puzzle
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
    DEFAULT_HIDDEN_PUZZLE_HASH,
    calculate_synthetic_secret_key,
    puzzle_for_pk,
)
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD,
    SINGLETON_MOD_HASH,
    puzzle_for_singleton,
)
from chia.wallet.trading.offer import OFFER_MOD_HASH, Offer
from chia_rs import AugSchemeMPL
from chia_rs.sized_bytes import bytes32
from fastapi import HTTPException

from solslot_api.config import Settings
from solslot_api.faucet import AGG_SIG_ME_DATA, Faucet
from solslot_api.protocol_submission import ProtocolBundleSubmitter
from solslot_api.sols_market import StatutesSnapshot
from solslot_api.sols_swap_store import SolsSwapStore
from solslot_api.sols_swaps import (
    CompleteSolsSwapRequest,
    PrepareSolsSwapRequest,
    ReverseSolsSwapContext,
    SolsSwapContext,
    VaultHeldDeed,
    _authorize_swap,
    _build_protocol_offer,
    _build_reverse_protocol_offer,
    complete_sols_swap,
    prepare_sols_swap,
)
from solslot_api.state import VaultRecord
from solslot_api.vault_eligibility import ApprovedVault
from solslot_puzzles import load_puzzle
from solslot_puzzles.mint_publish_driver import make_smart_deed_inner
from solslot_puzzles.pool_v4_driver import (
    PoolV4Config,
    make_pool_v4_full,
    p2_pool_v2_inner_hash,
)
from solslot_puzzles.protocol_deployment import pool_token_tail_hash
from solslot_puzzles.protocol_statutes_driver import (
    make_inner_puzzle as make_statutes_inner,
    protocol_statutes_inner_mod_hash,
)
from solslot_puzzles.protocol_statutes_v1 import (
    CollectionStatute,
    PermanentRules,
    ProtocolParameters,
    StatutesState,
    keyed_root,
)
from solslot_puzzles.sols_economics_v3 import SolsEconomicState
from solslot_puzzles.sols_pool_v4 import (
    SolsPoolStateV4,
    inventory_root,
    prepare_deed_to_sols,
    prepare_sols_to_deed,
)
from solslot_puzzles.sols_swap_v4_driver import (
    aggregate_sols_to_deed_swap,
)
from solslot_puzzles.vault_driver import (
    AUTH_TYPE_BLS,
    AUTH_TYPE_SECP256K1,
    one_leaf_merkle_root,
    puzzle_hash_for_p2_vault,
)
from solslot_puzzles.vault_v2_driver import (
    puzzle_for_vault_v2_full,
    vault_v2_inner_mod_hash,
)
from solslot_puzzles.vault_sols_v1 import puzzle_for_vault_sols_inner


def _b32(seed: int) -> bytes32:
    return bytes32(bytes([seed]) * 32)


def _hex32(value: bytes | bytes32) -> str:
    return "0x" + bytes(value).hex()


def _singleton_struct(launcher_id: bytes32) -> Program:
    return Program.to(
        (SINGLETON_MOD_HASH, (launcher_id, SINGLETON_LAUNCHER_HASH))
    )


POOL_LAUNCHER = _b32(1)
STATUTES_LAUNCHER = _b32(2)
GOVERNANCE_LAUNCHER = _b32(3)
DEED_LAUNCHER = _b32(4)
VAULT_LAUNCHER = _b32(6)
IDENTITY_ROOT = _b32(7)
PROPERTY_ID = _b32(9)
QUOTE_EXPIRES = 2_000_080_000
PAR_VALUE = 100_000_000
SHARE_PPM = 100_000
OWNER_SK = AugSchemeMPL.key_gen(bytes([42]) * 32)
OWNER_PK = bytes(OWNER_SK.get_g1())
MEMBERS_ROOT = one_leaf_merkle_root(OWNER_PK)
EVM_PRIVATE_KEY = bytes.fromhex("11" * 32)
EVM_ACCOUNT = Account.from_key(EVM_PRIVATE_KEY)
EVM_OWNER_KEY = eth_keys.PrivateKey(
    EVM_PRIVATE_KEY
).public_key.to_compressed_bytes()

PARAMETERS = ProtocolParameters()
RULES = PermanentRules(
    sgt_tail_hash=_b32(20),
    sgt_total_supply=1_000_000,
    sols_tail_hash=pool_token_tail_hash(POOL_LAUNCHER),
    zkpassport_policy_hash=_b32(22),
    protocol_treasury_puzzle_hash=_b32(23),
    network_id=_b32(24),
)
COLLECTION = CollectionStatute(
    collection_id=_b32(25),
    nav_micro_usd=999_000_000,
    allocation_ceiling_micro_usd=999_000_000,
    nav_version=1,
    valid_after=2_000_000_000,
    valid_until=2_000_086_400,
    status=1,
)
EMPTY_ROOT = bytes32(Program.to([]).get_tree_hash())
STATUTES_STATE = StatutesState(
    parameters_root=bytes32(
        Program.to(list(PARAMETERS.as_tuple())).get_tree_hash()
    ),
    collections_root=keyed_root([COLLECTION]),
    oracle_root=EMPTY_ROOT,
    routes_root=EMPTY_ROOT,
    liquidity_root=EMPTY_ROOT,
    pauses_root=EMPTY_ROOT,
    registry_version=3,
    permanent_rules_hash=RULES.commitment_hash,
)
EMPTY_POOL = SolsPoolStateV4(
    inventory_root=inventory_root(()),
    economics=SolsEconomicState(
        bootstrap_complete=False,
        inventory_nav_micro_usd=0,
        treasury_assets_micro_usd=0,
        proven_liabilities_micro_usd=0,
        deed_count=0,
        total_sols_mojos=1,
        reserve_sols_mojos=1,
    ),
    state_version=1,
)
CONFIG = PoolV4Config(
    pool_launcher_id=POOL_LAUNCHER,
    statutes_inner_mod_hash=protocol_statutes_inner_mod_hash(),
    statutes_singleton_struct=_singleton_struct(STATUTES_LAUNCHER),
    governance_singleton_struct=_singleton_struct(GOVERNANCE_LAUNCHER),
    permanent_rules=RULES,
    cat_mod_hash=bytes32(CAT_MOD.get_tree_hash()),
    offer_mod_hash=OFFER_MOD_HASH,
    p2_vault_mod_hash=bytes32(load_puzzle("p2_vault.clsp").get_tree_hash()),
    vault_v2_mod_hash=vault_v2_inner_mod_hash(),
    p2_pool_v2_mod_hash=bytes32(
        load_puzzle("p2_pool_v2.clsp").get_tree_hash()
    ),
    deed_launcher_puzzle_hash=_b32(29),
    reserve_puzzle_hash=_b32(30),
    sgt_rewards_puzzle_hash=_b32(31),
)
DEED_COMMITMENT = bytes32(
    Program.to(
        [
            DEED_LAUNCHER,
            PAR_VALUE,
            1,
            PROPERTY_ID,
            COLLECTION.collection_id,
            SHARE_PPM,
        ]
    ).get_tree_hash()
)


@dataclass(frozen=True)
class SwapFixture:
    context: SolsSwapContext


def _singleton_child(
    *,
    launcher_id: bytes32,
    parent_inner: Program,
    current_inner: Program,
    seed: int,
) -> tuple[Coin, LineageProof, Coin]:
    parent_coin = Coin(
        _b32(seed),
        bytes32(puzzle_for_singleton(launcher_id, parent_inner).get_tree_hash()),
        1,
    )
    child = Coin(
        parent_coin.name(),
        bytes32(puzzle_for_singleton(launcher_id, current_inner).get_tree_hash()),
        1,
    )
    return (
        child,
        LineageProof(
            parent_name=parent_coin.parent_coin_info,
            inner_puzzle_hash=bytes32(parent_inner.get_tree_hash()),
            amount=parent_coin.amount,
        ),
        parent_coin,
    )


def _deed_singleton_child(
    *,
    parent_inner: Program,
    current_inner: Program,
    seed: int,
) -> tuple[Coin, LineageProof, Coin]:
    deed_struct = Program.to(
        (
            SINGLETON_MOD_HASH,
            (DEED_LAUNCHER, CONFIG.deed_launcher_puzzle_hash),
        )
    )
    parent_coin = Coin(
        _b32(seed),
        bytes32(
            SINGLETON_MOD.curry(deed_struct, parent_inner).get_tree_hash()
        ),
        1,
    )
    child = Coin(
        parent_coin.name(),
        bytes32(
            SINGLETON_MOD.curry(deed_struct, current_inner).get_tree_hash()
        ),
        1,
    )
    return (
        child,
        LineageProof(
            parent_name=parent_coin.parent_coin_info,
            inner_puzzle_hash=bytes32(parent_inner.get_tree_hash()),
            amount=parent_coin.amount,
        ),
        parent_coin,
    )


def _fixture(*, evm: bool = False) -> SwapFixture:
    owner_key = EVM_OWNER_KEY if evm else OWNER_PK
    auth_type = AUTH_TYPE_SECP256K1 if evm else AUTH_TYPE_BLS
    members_root = one_leaf_merkle_root(owner_key)
    empty_pool_full = make_pool_v4_full(CONFIG, EMPTY_POOL)
    empty_pool_uncurried = empty_pool_full.uncurry()
    assert empty_pool_uncurried is not None
    _, empty_pool_args = empty_pool_uncurried
    empty_pool_inner = list(empty_pool_args.as_iter())[1]
    empty_pool_coin = Coin(_b32(40), empty_pool_full.get_tree_hash(), 1)

    custody_inner = load_puzzle("p2_pool_v2.clsp").curry(
        CONFIG.p2_pool_v2_mod_hash,
        SINGLETON_MOD_HASH,
        POOL_LAUNCHER,
        SINGLETON_LAUNCHER_HASH,
        DEED_COMMITMENT,
    )
    assert bytes32(custody_inner.get_tree_hash()) == p2_pool_v2_inner_hash(
        config=CONFIG,
        deed_commitment=DEED_COMMITMENT,
    )
    custody_coin, custody_lineage, deed_parent = _deed_singleton_child(
        parent_inner=Program.to(1),
        current_inner=custody_inner,
        seed=41,
    )
    deposit = prepare_deed_to_sols(
        pool_coin_id=empty_pool_coin.name(),
        state=EMPTY_POOL,
        inventory=(),
        deed_launcher_id=DEED_LAUNCHER,
        custody_coin_id=custody_coin.name(),
        deed_commitment=DEED_COMMITMENT,
        collection=COLLECTION,
        share_ppm=SHARE_PPM,
        parameters=PARAMETERS,
        statutes_state=STATUTES_STATE,
        pause=None,
        vault_launcher_id=VAULT_LAUNCHER,
        vault_coin_id=_b32(41),
        seller_sols_puzzle_hash=_b32(42),
        quote_expires_at=QUOTE_EXPIRES,
    )
    current_pool_full = make_pool_v4_full(CONFIG, deposit.next_state)
    current_pool_uncurried = current_pool_full.uncurry()
    assert current_pool_uncurried is not None
    _, current_pool_args = current_pool_uncurried
    current_pool_inner = list(current_pool_args.as_iter())[1]
    pool_coin, pool_lineage, parent_pool = _singleton_child(
        launcher_id=POOL_LAUNCHER,
        parent_inner=empty_pool_inner,
        current_inner=current_pool_inner,
        seed=40,
    )
    assert parent_pool == empty_pool_coin

    vault_full = puzzle_for_vault_v2_full(
        vault_launcher_id=VAULT_LAUNCHER,
        owner_pubkey=owner_key,
        auth_type=auth_type,
        members_merkle_root=members_root,
        pool_launcher_id=POOL_LAUNCHER,
        identity_attest_root=IDENTITY_ROOT,
        zkpassport_bridge_policy_hash=RULES.zkpassport_policy_hash,
    )
    vault_uncurried = vault_full.uncurry()
    assert vault_uncurried is not None
    _, vault_args = vault_uncurried
    vault_inner = list(vault_args.as_iter())[1]
    vault_coin, vault_lineage, _ = _singleton_child(
        launcher_id=VAULT_LAUNCHER,
        parent_inner=vault_inner,
        current_inner=vault_inner,
        seed=43,
    )
    payment_puzzle = puzzle_for_vault_sols_inner(
        config=CONFIG,
        vault_launcher_id=VAULT_LAUNCHER,
    )
    payment_parent = Coin(
        _b32(45),
        construct_cat_puzzle(
            CAT_MOD,
            RULES.sols_tail_hash,
            payment_puzzle,
        ).get_tree_hash(),
        1_000_000,
    )
    payment_coin = Coin(
        payment_parent.name(),
        payment_parent.puzzle_hash,
        payment_parent.amount,
    )
    payment_lineage = LineageProof(
        parent_name=payment_parent.parent_coin_info,
        inner_puzzle_hash=bytes32(payment_puzzle.get_tree_hash()),
        amount=payment_parent.amount,
    )
    receipt = prepare_sols_to_deed(
        pool_coin_id=pool_coin.name(),
        state=deposit.next_state,
        inventory=deposit.next_inventory,
        deed_launcher_id=DEED_LAUNCHER,
        collection=COLLECTION,
        parameters=PARAMETERS,
        statutes_state=STATUTES_STATE,
        pause=None,
        vault_launcher_id=VAULT_LAUNCHER,
        vault_coin_id=vault_coin.name(),
        sols_payment_coin_id=payment_coin.name(),
        destination_p2_vault_hash=puzzle_hash_for_p2_vault(VAULT_LAUNCHER),
        quote_expires_at=QUOTE_EXPIRES,
    )
    statutes_inner = make_statutes_inner(
        singleton_struct=CONFIG.statutes_singleton_struct,
        governance_singleton_struct=CONFIG.governance_singleton_struct,
        permanent_rules=RULES,
        state=STATUTES_STATE,
    )
    statutes_coin, statutes_lineage, _ = _singleton_child(
        launcher_id=STATUTES_LAUNCHER,
        parent_inner=statutes_inner,
        current_inner=statutes_inner,
        seed=44,
    )
    quote = receipt.sols_to_deed_quote
    assert quote is not None
    assert int(payment_coin.amount) > quote.buyer_total_sols_mojos
    assert custody_coin.parent_coin_info == deed_parent.name()

    approved = ApprovedVault(
        launcher_id=_hex32(VAULT_LAUNCHER),
        p2_puzzle_hash=_hex32(puzzle_hash_for_p2_vault(VAULT_LAUNCHER)),
        current_coin_id=_hex32(vault_coin.name()),
        identity_attest_root=_hex32(IDENTITY_ROOT),
        confirmed_block_index=123,
        enrollment=SimpleNamespace(),
    )
    vault_record = VaultRecord(
        launcher_id=VAULT_LAUNCHER,
        full_puzhash=bytes32(vault_full.get_tree_hash()),
        p2_vault_puzhash=puzzle_hash_for_p2_vault(VAULT_LAUNCHER),
        auth_type=auth_type,
        owner_pubkey=owner_key,
        owner_evm_address=EVM_ACCOUNT.address if evm else None,
        spend_bundle_id="0x" + "46" * 32,
        pushed_at=1.0,
    )
    statutes = StatutesSnapshot(
        live_coin_id=_hex32(statutes_coin.name()),
        live_puzzle_hash=_hex32(statutes_coin.puzzle_hash),
        state=STATUTES_STATE,
        parameters=PARAMETERS,
        collections=(COLLECTION,),
        oracle_rounds=(),
        bridge_routes=(),
        liquidity_venues=(),
        pauses=(),
        registry_version=STATUTES_STATE.registry_version,
        confirmed_height=123,
        lineage_depth=2,
    )
    context = SolsSwapContext(
        artifact={"launcherIds": {"statutes": _hex32(STATUTES_LAUNCHER)}},
        config=CONFIG,
        pool_state=deposit.next_state,
        pool_inventory=deposit.next_inventory,
        pool_coin=pool_coin,
        pool_lineage=pool_lineage,
        statutes=statutes,
        statutes_coin=statutes_coin,
        statutes_lineage=statutes_lineage,
        collection=COLLECTION,
        pause=None,
        approved_vault=approved,
        vault_record=vault_record,
        vault_coin=vault_coin,
        vault_lineage=vault_lineage,
        custody_coin=custody_coin,
        custody_lineage=custody_lineage,
        payment_coin=payment_coin,
        payment_lineage=payment_lineage,
        receipt=receipt,
    )
    return SwapFixture(context=context)


def _reverse_fixture(
    faucet: Faucet,
    *,
    evm: bool = False,
) -> ReverseSolsSwapContext:
    owner_key = EVM_OWNER_KEY if evm else OWNER_PK
    auth_type = AUTH_TYPE_SECP256K1 if evm else AUTH_TYPE_BLS
    members_root = one_leaf_merkle_root(owner_key)
    config = replace(CONFIG, reserve_puzzle_hash=faucet.key.puzzle_hash)
    pool_full = make_pool_v4_full(config, EMPTY_POOL)
    pool_uncurried = pool_full.uncurry()
    assert pool_uncurried is not None
    _, pool_args = pool_uncurried
    pool_inner = list(pool_args.as_iter())[1]
    pool_coin, pool_lineage, _ = _singleton_child(
        launcher_id=POOL_LAUNCHER,
        parent_inner=pool_inner,
        current_inner=pool_inner,
        seed=120,
    )

    vault_full = puzzle_for_vault_v2_full(
        vault_launcher_id=VAULT_LAUNCHER,
        owner_pubkey=owner_key,
        auth_type=auth_type,
        members_merkle_root=members_root,
        pool_launcher_id=POOL_LAUNCHER,
        identity_attest_root=IDENTITY_ROOT,
        zkpassport_bridge_policy_hash=RULES.zkpassport_policy_hash,
    )
    vault_uncurried = vault_full.uncurry()
    assert vault_uncurried is not None
    _, vault_args = vault_uncurried
    vault_inner = list(vault_args.as_iter())[1]
    vault_coin, vault_lineage, _ = _singleton_child(
        launcher_id=VAULT_LAUNCHER,
        parent_inner=vault_inner,
        current_inner=vault_inner,
        seed=121,
    )

    deed_struct = Program.to(
        (
            SINGLETON_MOD_HASH,
            (DEED_LAUNCHER, config.deed_launcher_puzzle_hash),
        )
    )
    smart_deed_inner = make_smart_deed_inner(
        deed_singleton_struct_program=deed_struct,
        protocol_did_puzhash=_b32(122),
        par_value_mojos=PAR_VALUE,
        asset_class=1,
        property_id_canon=PROPERTY_ID,
        collection_id_canon=COLLECTION.collection_id,
        share_ppm=SHARE_PPM,
        jurisdiction=b"US-MI",
        royalty_puzhash=_b32(123),
        royalty_bps=0,
        pool_singleton_launcher_id=POOL_LAUNCHER,
        pool_singleton_launcher_puzzle_hash=SINGLETON_LAUNCHER_HASH,
        p2_pool_mod_hash=config.p2_pool_v2_mod_hash,
        p2_vault_mod_hash=config.p2_vault_mod_hash,
    )
    p2_vault_inner = load_puzzle("p2_vault.clsp").curry(
        SINGLETON_MOD_HASH,
        VAULT_LAUNCHER,
        SINGLETON_LAUNCHER_HASH,
    )
    held_coin, held_lineage, _ = _deed_singleton_child(
        parent_inner=Program.to(1),
        current_inner=p2_vault_inner,
        seed=124,
    )
    ephemeral = Coin(
        held_coin.name(),
        bytes32(SINGLETON_MOD.curry(deed_struct, smart_deed_inner).get_tree_hash()),
        1,
    )
    custody_inner = load_puzzle("p2_pool_v2.clsp").curry(
        config.p2_pool_v2_mod_hash,
        SINGLETON_MOD_HASH,
        POOL_LAUNCHER,
        SINGLETON_LAUNCHER_HASH,
        DEED_COMMITMENT,
    )
    custody_coin = Coin(
        ephemeral.name(),
        bytes32(SINGLETON_MOD.curry(deed_struct, custody_inner).get_tree_hash()),
        1,
    )
    payout_hash = bytes32(
        puzzle_for_vault_sols_inner(
            config=config,
            vault_launcher_id=VAULT_LAUNCHER,
        ).get_tree_hash()
    )
    receipt = prepare_deed_to_sols(
        pool_coin_id=pool_coin.name(),
        state=EMPTY_POOL,
        inventory=(),
        deed_launcher_id=DEED_LAUNCHER,
        custody_coin_id=custody_coin.name(),
        deed_commitment=DEED_COMMITMENT,
        collection=COLLECTION,
        share_ppm=SHARE_PPM,
        parameters=PARAMETERS,
        statutes_state=STATUTES_STATE,
        pause=None,
        vault_launcher_id=VAULT_LAUNCHER,
        vault_coin_id=vault_coin.name(),
        seller_sols_puzzle_hash=payout_hash,
        quote_expires_at=QUOTE_EXPIRES,
    )
    statutes_inner = make_statutes_inner(
        singleton_struct=CONFIG.statutes_singleton_struct,
        governance_singleton_struct=CONFIG.governance_singleton_struct,
        permanent_rules=RULES,
        state=STATUTES_STATE,
    )
    statutes_coin, statutes_lineage, _ = _singleton_child(
        launcher_id=STATUTES_LAUNCHER,
        parent_inner=statutes_inner,
        current_inner=statutes_inner,
        seed=126,
    )
    reserve_coin = Coin(
        _b32(127),
        bytes32(
            construct_cat_puzzle(
                CAT_MOD,
                RULES.sols_tail_hash,
                faucet.key.puzzle,
            ).get_tree_hash()
        ),
        1,
    )
    approved = ApprovedVault(
        launcher_id=_hex32(VAULT_LAUNCHER),
        p2_puzzle_hash=_hex32(puzzle_hash_for_p2_vault(VAULT_LAUNCHER)),
        current_coin_id=_hex32(vault_coin.name()),
        identity_attest_root=_hex32(IDENTITY_ROOT),
        confirmed_block_index=123,
        enrollment=SimpleNamespace(),
    )
    vault_record = VaultRecord(
        launcher_id=VAULT_LAUNCHER,
        full_puzhash=bytes32(vault_full.get_tree_hash()),
        p2_vault_puzhash=puzzle_hash_for_p2_vault(VAULT_LAUNCHER),
        auth_type=auth_type,
        owner_pubkey=owner_key,
        owner_evm_address=EVM_ACCOUNT.address if evm else None,
        spend_bundle_id="0x" + "46" * 32,
        pushed_at=1.0,
    )
    statutes = StatutesSnapshot(
        live_coin_id=_hex32(statutes_coin.name()),
        live_puzzle_hash=_hex32(statutes_coin.puzzle_hash),
        state=STATUTES_STATE,
        parameters=PARAMETERS,
        collections=(COLLECTION,),
        oracle_rounds=(),
        bridge_routes=(),
        liquidity_venues=(),
        pauses=(),
        registry_version=STATUTES_STATE.registry_version,
        confirmed_height=123,
        lineage_depth=2,
    )
    return ReverseSolsSwapContext(
        artifact={"launcherIds": {"statutes": _hex32(STATUTES_LAUNCHER)}},
        config=config,
        pool_state=EMPTY_POOL,
        pool_inventory=(),
        pool_coin=pool_coin,
        pool_lineage=pool_lineage,
        statutes=statutes,
        statutes_coin=statutes_coin,
        statutes_lineage=statutes_lineage,
        collection=COLLECTION,
        pause=None,
        approved_vault=approved,
        vault_record=vault_record,
        vault_coin=vault_coin,
        vault_lineage=vault_lineage,
        deed=VaultHeldDeed(
            coin=held_coin,
            lineage=held_lineage,
            smart_deed_inner=smart_deed_inner,
            par_value=PAR_VALUE,
            asset_class=1,
            property_id=PROPERTY_ID,
            collection_id=COLLECTION.collection_id,
            share_ppm=SHARE_PPM,
            deed_commitment=DEED_COMMITMENT,
        ),
        reserve_coin=reserve_coin,
        reserve_lineage=LineageProof(),
        reserve_inner_puzzle=faucet.key.puzzle,
        receipt=receipt,
    )


class FakeNode:
    def __init__(self) -> None:
        self.pending = False

    async def get_mempool_items_by_coin_name(self, _coin_id):
        return [{"pending": True}] if self.pending else []


class FakeProtocolSubmitter(ProtocolBundleSubmitter):
    def __init__(self) -> None:
        self.submitted = None

    async def submit(self, bundle):
        self.submitted = bundle
        return {
            "status": "MEMPOOL",
            "spendBundleId": "0x" + "99" * 32,
            "feeMojos": "420",
            "feeTargetSeconds": 300,
            "submissionProvider": "primary",
            "mempoolObservedAt": "2026-07-27T14:30:00Z",
        }


def _settings() -> Settings:
    return Settings(
        _env_file=None,
        runtime_environment="test",
        network="testnet11",
        alpha_writes_enabled=True,
    )


def _request(
    node: FakeNode,
    submitter: FakeProtocolSubmitter,
    faucet: Faucet | None = None,
) -> SimpleNamespace:
    state = SimpleNamespace(
        coinset=node,
        protocol_submitter=submitter,
        sols_swap_store=SolsSwapStore(":memory:"),
    )
    if faucet is not None:
        state.faucet = faucet
    return SimpleNamespace(app=SimpleNamespace(state=state))


async def _prepare(monkeypatch, fixture, request):
    async def load_context(**_kwargs):
        return fixture.context

    monkeypatch.setattr("solslot_api.sols_swaps._authorize_swap", lambda *_: None)
    monkeypatch.setattr(
        "solslot_api.sols_swaps._load_swap_context",
        load_context,
    )
    return await prepare_sols_swap(
        _hex32(VAULT_LAUNCHER),
        PrepareSolsSwapRequest(
            deedLauncherId=_hex32(DEED_LAUNCHER),
        ),
        request,
        _settings(),
    )


def _wallet_signature(context: SolsSwapContext, buyer_offer: str) -> bytes:
    unsigned = Offer.from_bech32(buyer_offer)
    protocol = _build_protocol_offer(context, signature_data=None)
    atomic = aggregate_sols_to_deed_swap(
        buyer_offer=unsigned,
        protocol_offer=protocol,
        receipt=context.receipt,
        config=context.config,
        vault_launcher_id=context.vault_record.launcher_id,
    )
    bundle = atomic.aggregate_offer.to_valid_spend()
    pairs = []
    for spend in bundle.coin_spends:
        conditions = conditions_dict_for_solution(
            spend.puzzle_reveal,
            spend.solution,
            INFINITE_COST,
        )
        pairs.extend(
            pkm_pairs_for_conditions_dict(
                conditions,
                spend.coin,
                AGG_SIG_ME_DATA["testnet11"],
            )
        )
    synthetic = calculate_synthetic_secret_key(
        OWNER_SK,
        DEFAULT_HIDDEN_PUZZLE_HASH,
    )
    signatures = []
    for public_key, message in pairs:
        if public_key == synthetic.get_g1():
            signatures.append(AugSchemeMPL.sign(synthetic, message))
        elif public_key == OWNER_SK.get_g1():
            signatures.append(AugSchemeMPL.sign(OWNER_SK, message))
        else:
            raise AssertionError("unexpected swap signing key")
    assert signatures
    return bytes(AugSchemeMPL.aggregate(signatures))


def _reverse_wallet_signature(context: ReverseSolsSwapContext) -> bytes:
    bundle = _build_reverse_protocol_offer(
        context,
        signature_data=None,
    ).offer.to_valid_spend()
    pairs = []
    for spend in bundle.coin_spends:
        conditions = conditions_dict_for_solution(
            spend.puzzle_reveal,
            spend.solution,
            INFINITE_COST,
        )
        pairs.extend(
            pkm_pairs_for_conditions_dict(
                conditions,
                spend.coin,
                AGG_SIG_ME_DATA["testnet11"],
            )
        )
    synthetic = calculate_synthetic_secret_key(
        OWNER_SK,
        DEFAULT_HIDDEN_PUZZLE_HASH,
    )
    signatures = []
    for public_key, message in pairs:
        if public_key == synthetic.get_g1():
            signatures.append(AugSchemeMPL.sign(synthetic, message))
        elif public_key == OWNER_SK.get_g1():
            signatures.append(AugSchemeMPL.sign(OWNER_SK, message))
    assert signatures
    return bytes(AugSchemeMPL.aggregate(signatures))


def test_swap_routes_are_registered_in_public_api_contract() -> None:
    from solslot_api.app import app

    paths = app.openapi()["paths"]
    base = "/sols/vaults/{vault_launcher_id}/swaps"
    assert f"{base}/prepare" in paths
    assert f"{base}/complete" in paths
    assert "/sols/swaps/{operation_hash}" in paths
    assert "/sols/vaults/{vault_launcher_id}/journey" in paths
    assert "/sols/bridge-intents" in paths
    assert "/sols/liquidity-intents" in paths


def test_swap_authorization_keeps_alpha_and_network_ceiling(
    monkeypatch,
) -> None:
    request = SimpleNamespace()
    with pytest.raises(HTTPException, match="locked"):
        _authorize_swap(
            Settings(
                _env_file=None,
                runtime_environment="test",
                network="testnet11",
                alpha_writes_enabled=False,
            ),
            request,
            _hex32(VAULT_LAUNCHER),
        )

    monkeypatch.setattr(
        "solslot_api.sols_swaps.require_alpha_writes",
        lambda _settings: None,
    )
    with pytest.raises(HTTPException, match="Testnet Alpha"):
        _authorize_swap(
            Settings(
                _env_file=None,
                runtime_environment="test",
                network="mainnet",
                alpha_writes_enabled=True,
            ),
            request,
            _hex32(VAULT_LAUNCHER),
        )


@pytest.mark.asyncio
async def test_prepare_and_complete_sols_swap_is_atomic_and_fee_funded(
    monkeypatch,
) -> None:
    fixture = _fixture()
    node = FakeNode()
    submitter = FakeProtocolSubmitter()
    request = _request(node, submitter)
    prepared = await _prepare(monkeypatch, fixture, request)

    quote = fixture.context.receipt.sols_to_deed_quote
    assert quote is not None
    assert prepared.operation_hash == _hex32(fixture.context.receipt.operation_hash)
    assert prepared.schema_version == 3
    assert prepared.direction == "SOLS_TO_DEED"
    assert prepared.deed_launcher_id == _hex32(DEED_LAUNCHER)
    assert prepared.vault_auth_type == "chia_bls"
    assert prepared.total_sols_mojos == str(quote.buyer_total_sols_mojos)
    assert prepared.destination_p2_vault_hash == _hex32(
        puzzle_hash_for_p2_vault(VAULT_LAUNCHER)
    )
    assert len(prepared.signing_coin_spends) == 1

    signature = _wallet_signature(fixture.context, prepared.buyer_offer)
    completed = await complete_sols_swap(
        _hex32(VAULT_LAUNCHER),
        CompleteSolsSwapRequest(
            deedLauncherId=_hex32(DEED_LAUNCHER),
            operationHash=prepared.operation_hash,
            quoteExpiresAt=prepared.quote_expires_at,
            buyerOffer=prepared.buyer_offer,
            aggregatedSignature="0x" + signature.hex(),
        ),
        request,
        _settings(),
    )

    assert completed.status == "MEMPOOL"
    assert completed.schema_version == 3
    assert completed.direction == "SOLS_TO_DEED"
    assert completed.transaction_id == "0x" + "99" * 32
    assert completed.fee_mojos == "420"
    assert completed.fee_target_seconds == 300
    assert completed.submission_provider == "primary"
    assert submitter.submitted is not None
    assert len(submitter.submitted["coin_spends"]) == 6


@pytest.mark.asyncio
async def test_evm_vault_can_swap_sols_to_deed_with_one_typed_signature(
    monkeypatch,
) -> None:
    fixture = _fixture(evm=True)
    node = FakeNode()
    submitter = FakeProtocolSubmitter()
    request = _request(node, submitter)
    prepared = await _prepare(monkeypatch, fixture, request)

    assert prepared.vault_auth_type == "evm"
    assert prepared.signing_coin_spends == []
    assert prepared.vault_typed_data is not None
    signature = EVM_ACCOUNT.sign_message(
        encode_typed_data(full_message=prepared.vault_typed_data)
    ).signature
    completed = await complete_sols_swap(
        _hex32(VAULT_LAUNCHER),
        CompleteSolsSwapRequest(
            deedLauncherId=_hex32(DEED_LAUNCHER),
            operationHash=prepared.operation_hash,
            quoteExpiresAt=prepared.quote_expires_at,
            buyerOffer=prepared.buyer_offer,
            vaultOwnerAuthorization="0x" + signature.hex(),
        ),
        request,
        _settings(),
    )

    assert completed.status == "MEMPOOL"
    assert submitter.submitted is not None


@pytest.mark.asyncio
async def test_evm_sols_swap_rejects_a_different_wallet(
    monkeypatch,
) -> None:
    fixture = _fixture(evm=True)
    node = FakeNode()
    submitter = FakeProtocolSubmitter()
    request = _request(node, submitter)
    prepared = await _prepare(monkeypatch, fixture, request)
    assert prepared.vault_typed_data is not None
    attacker = Account.from_key(bytes.fromhex("12" * 32))
    signature = attacker.sign_message(
        encode_typed_data(full_message=prepared.vault_typed_data)
    ).signature

    with pytest.raises(HTTPException, match="vault owner"):
        await complete_sols_swap(
            _hex32(VAULT_LAUNCHER),
            CompleteSolsSwapRequest(
                deedLauncherId=_hex32(DEED_LAUNCHER),
                operationHash=prepared.operation_hash,
                quoteExpiresAt=prepared.quote_expires_at,
                buyerOffer=prepared.buyer_offer,
                vaultOwnerAuthorization="0x" + signature.hex(),
            ),
            request,
            _settings(),
        )
    assert submitter.submitted is None


@pytest.mark.asyncio
async def test_reverse_swap_requires_protocol_fountain_before_chain_loading(
    monkeypatch,
) -> None:
    node = FakeNode()
    submitter = FakeProtocolSubmitter()
    request = _request(node, submitter)
    monkeypatch.setattr(
        "solslot_api.sols_swaps._authorize_swap",
        lambda *_: None,
    )

    with pytest.raises(HTTPException, match="protocol fountain") as exc:
        await prepare_sols_swap(
            _hex32(VAULT_LAUNCHER),
            PrepareSolsSwapRequest(
                direction="DEED_TO_SOLS",
                deedLauncherId=_hex32(DEED_LAUNCHER),
            ),
            request,
            _settings(),
        )

    assert exc.value.status_code == 503
    assert submitter.submitted is None


@pytest.mark.asyncio
async def test_prepare_and_complete_deed_to_sols_is_atomic_and_fee_funded(
    monkeypatch,
) -> None:
    faucet = Faucet.from_seed_hex("77" * 32, "testnet11")
    fixture = _reverse_fixture(faucet)
    node = FakeNode()
    submitter = FakeProtocolSubmitter()
    request = _request(node, submitter, faucet)

    async def load_context(**_kwargs):
        return fixture

    monkeypatch.setattr("solslot_api.sols_swaps._authorize_swap", lambda *_: None)
    monkeypatch.setattr(
        "solslot_api.sols_swaps._load_reverse_swap_context",
        load_context,
    )
    prepared = await prepare_sols_swap(
        _hex32(VAULT_LAUNCHER),
        PrepareSolsSwapRequest(
            direction="DEED_TO_SOLS",
            deedLauncherId=_hex32(DEED_LAUNCHER),
        ),
        request,
        _settings(),
    )

    quote = fixture.receipt.deed_to_sols_quote
    assert quote is not None
    assert prepared.schema_version == 3
    assert prepared.direction == "DEED_TO_SOLS"
    assert prepared.destination_p2_vault_hash is None
    assert prepared.destination_puzzle_hash == _hex32(
        puzzle_for_vault_sols_inner(
            config=fixture.config,
            vault_launcher_id=VAULT_LAUNCHER,
        ).get_tree_hash()
    )
    assert prepared.total_sols_mojos == str(quote.seller_sols_mojos)
    assert prepared.fresh_sols_mojos_minted == str(
        quote.fresh_sols_mojos_minted
    )
    assert len(prepared.signing_coin_spends) == 1

    signature = _reverse_wallet_signature(fixture)
    completed = await complete_sols_swap(
        _hex32(VAULT_LAUNCHER),
        CompleteSolsSwapRequest(
            direction="DEED_TO_SOLS",
            deedLauncherId=_hex32(DEED_LAUNCHER),
            operationHash=prepared.operation_hash,
            quoteExpiresAt=prepared.quote_expires_at,
            buyerOffer=prepared.buyer_offer,
            aggregatedSignature="0x" + signature.hex(),
        ),
        request,
        _settings(),
    )

    assert completed.schema_version == 3
    assert completed.direction == "DEED_TO_SOLS"
    assert completed.status == "MEMPOOL"
    assert completed.destination_puzzle_hash == prepared.destination_puzzle_hash
    assert completed.fee_mojos == "420"
    assert submitter.submitted is not None
    assert len(submitter.submitted["coin_spends"]) == 7


@pytest.mark.asyncio
async def test_evm_vault_can_swap_deed_to_vault_bound_sols(
    monkeypatch,
) -> None:
    faucet = Faucet.from_seed_hex("77" * 32, "testnet11")
    fixture = _reverse_fixture(faucet, evm=True)
    node = FakeNode()
    submitter = FakeProtocolSubmitter()
    request = _request(node, submitter, faucet)

    async def load_context(**_kwargs):
        return fixture

    monkeypatch.setattr("solslot_api.sols_swaps._authorize_swap", lambda *_: None)
    monkeypatch.setattr(
        "solslot_api.sols_swaps._load_reverse_swap_context",
        load_context,
    )
    prepared = await prepare_sols_swap(
        _hex32(VAULT_LAUNCHER),
        PrepareSolsSwapRequest(
            direction="DEED_TO_SOLS",
            deedLauncherId=_hex32(DEED_LAUNCHER),
        ),
        request,
        _settings(),
    )

    assert prepared.vault_auth_type == "evm"
    assert prepared.signing_coin_spends == []
    assert prepared.vault_typed_data is not None
    signature = EVM_ACCOUNT.sign_message(
        encode_typed_data(full_message=prepared.vault_typed_data)
    ).signature
    completed = await complete_sols_swap(
        _hex32(VAULT_LAUNCHER),
        CompleteSolsSwapRequest(
            direction="DEED_TO_SOLS",
            deedLauncherId=_hex32(DEED_LAUNCHER),
            operationHash=prepared.operation_hash,
            quoteExpiresAt=prepared.quote_expires_at,
            buyerOffer=prepared.buyer_offer,
            vaultOwnerAuthorization="0x" + signature.hex(),
        ),
        request,
        _settings(),
    )

    assert completed.status == "MEMPOOL"
    assert completed.destination_puzzle_hash == prepared.destination_puzzle_hash
    assert submitter.submitted is not None


@pytest.mark.asyncio
async def test_complete_rejects_stale_operation_before_submission(
    monkeypatch,
) -> None:
    fixture = _fixture()
    node = FakeNode()
    submitter = FakeProtocolSubmitter()
    request = _request(node, submitter)
    prepared = await _prepare(monkeypatch, fixture, request)

    with pytest.raises(HTTPException, match="Prepare this exact"):
        await complete_sols_swap(
            _hex32(VAULT_LAUNCHER),
            CompleteSolsSwapRequest(
                deedLauncherId=_hex32(DEED_LAUNCHER),
                operationHash="0x" + "ff" * 32,
                quoteExpiresAt=prepared.quote_expires_at,
                buyerOffer=prepared.buyer_offer,
                aggregatedSignature="0x" + "00" * 96,
            ),
            request,
            _settings(),
        )
    assert submitter.submitted is None


@pytest.mark.asyncio
async def test_complete_is_idempotent_after_mempool_submission(
    monkeypatch,
) -> None:
    fixture = _fixture()
    node = FakeNode()
    submitter = FakeProtocolSubmitter()
    request = _request(node, submitter)
    prepared = await _prepare(monkeypatch, fixture, request)
    signature = _wallet_signature(fixture.context, prepared.buyer_offer)
    body = CompleteSolsSwapRequest(
        deedLauncherId=_hex32(DEED_LAUNCHER),
        operationHash=prepared.operation_hash,
        quoteExpiresAt=prepared.quote_expires_at,
        buyerOffer=prepared.buyer_offer,
        aggregatedSignature="0x" + signature.hex(),
    )

    first = await complete_sols_swap(
        _hex32(VAULT_LAUNCHER),
        body,
        request,
        _settings(),
    )
    submitted = submitter.submitted
    second = await complete_sols_swap(
        _hex32(VAULT_LAUNCHER),
        body,
        request,
        _settings(),
    )

    assert first == second
    assert submitter.submitted is submitted


@pytest.mark.asyncio
async def test_complete_rejects_invalid_wallet_signature(
    monkeypatch,
) -> None:
    fixture = _fixture()
    node = FakeNode()
    submitter = FakeProtocolSubmitter()
    request = _request(node, submitter)
    prepared = await _prepare(monkeypatch, fixture, request)
    wrong_key = AugSchemeMPL.key_gen(b"wrong-sols-swap-wallet-signature")
    wrong_signature = AugSchemeMPL.sign(wrong_key, b"wrong-message")

    with pytest.raises(HTTPException, match="does not authorize"):
        await complete_sols_swap(
            _hex32(VAULT_LAUNCHER),
            CompleteSolsSwapRequest(
                deedLauncherId=_hex32(DEED_LAUNCHER),
                operationHash=prepared.operation_hash,
                quoteExpiresAt=prepared.quote_expires_at,
                buyerOffer=prepared.buyer_offer,
                aggregatedSignature="0x" + bytes(wrong_signature).hex(),
            ),
            request,
            _settings(),
        )
    assert submitter.submitted is None


@pytest.mark.asyncio
async def test_complete_rejects_pending_input_without_double_submission(
    monkeypatch,
) -> None:
    fixture = _fixture()
    node = FakeNode()
    submitter = FakeProtocolSubmitter()
    request = _request(node, submitter)
    prepared = await _prepare(monkeypatch, fixture, request)
    signature = _wallet_signature(fixture.context, prepared.buyer_offer)
    node.pending = True

    with pytest.raises(HTTPException, match="already pending"):
        await complete_sols_swap(
            _hex32(VAULT_LAUNCHER),
            CompleteSolsSwapRequest(
                deedLauncherId=_hex32(DEED_LAUNCHER),
                operationHash=prepared.operation_hash,
                quoteExpiresAt=prepared.quote_expires_at,
                buyerOffer=prepared.buyer_offer,
                aggregatedSignature="0x" + signature.hex(),
            ),
            request,
            _settings(),
        )
    assert submitter.submitted is None


@pytest.mark.parametrize("reverse", [False, True])
def test_evm_swap_signature_rejects_changed_context_with_same_operation(reverse) -> None:
    from solslot_api.sols_swaps import _vault_swap_typed_data, _vault_signature_data
    from solslot_puzzles.sols_swap_v4_driver import SolsSwapOfferError

    context = (_reverse_fixture(Faucet.from_seed_hex("77" * 32, "testnet11"), evm=True)
               if reverse else _fixture(evm=True).context)
    signature = EVM_ACCOUNT.sign_message(
        encode_typed_data(full_message=_vault_swap_typed_data(context))
    ).signature
    body = SimpleNamespace(vault_owner_authorization="0x" + signature.hex())
    assert len(_vault_signature_data(context, body)) == 64
    changed = [
        replace(context, pool_coin=Coin(_b32(200), context.pool_coin.puzzle_hash, context.pool_coin.amount)),
        replace(context, receipt=replace(context.receipt, quote_expires_at=context.receipt.quote_expires_at + 1)),
    ]
    if reverse:
        changed.extend([
            replace(context, deed=replace(context.deed, coin=Coin(_b32(201), context.deed.coin.puzzle_hash, context.deed.coin.amount))),
            replace(context, deed=replace(context.deed, smart_deed_inner=Program.to(1))),
        ])
    for mutation in changed:
        assert mutation.receipt.operation_hash == context.receipt.operation_hash
        with pytest.raises(SolsSwapOfferError, match="signature does not belong"):
            _vault_signature_data(mutation, body)
