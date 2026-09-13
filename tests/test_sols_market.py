from __future__ import annotations

from chia.types.blockchain_format.program import Program
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD,
    SINGLETON_MOD_HASH,
    puzzle_for_singleton,
    solution_for_singleton,
)
from chia_rs import G1Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
import pytest

from solslot_puzzles import load_puzzle
from solslot_puzzles.pool_economics_v2 import deed_metadata_commitment
from solslot_puzzles.pool_v4_driver import (
    PoolV4Config,
    deed_to_sols_inner_solution,
    deterministic_custody_coin_id,
    make_pool_v4_full,
    make_pool_v4_inner,
)
from solslot_puzzles.protocol_statutes_driver import (
    build_update_spend,
    make_inner_puzzle as make_statutes_inner,
    protocol_statutes_inner_mod_hash,
)
from solslot_puzzles.protocol_statutes_v1 import (
    BridgeRoute,
    CollectionStatute,
    LiquidityVenue,
    MutationKind,
    OracleRound,
    PermanentRules,
    ProtocolParameters,
    build_record_mutation,
    initial_state,
)
from solslot_puzzles.sols_economics_v3 import SolsEconomicState
from solslot_puzzles.sols_pool_v4 import (
    SolsPoolStateV4,
    inventory_root,
    prepare_deed_to_sols,
)
from solslot_puzzles.vault_driver import AUTH_TYPE_BLS, puzzle_for_p2_vault
from solslot_puzzles.vault_v2_driver import vault_v2_inner_mod_hash

from solslot_api.public_artifact import PublicArtifactMissing
from solslot_api.config import Settings
from solslot_api.sols_capability_evidence import SolsCapabilityEvidence
from solslot_api.sols_market import (
    LIQUIDITY_INSTALLED_ADAPTERS,
    LiveCoin,
    SingletonTip,
    SolsMarketReader,
    StatutesSnapshot,
    _activation_state,
    _active_adapter_coverage,
    _decode_pool_state,
    _decode_statutes_state,
    _liquidity_venue,
    _resolve_statutes_witnesses,
    _singleton_child,
    _statutes_payload,
    _statutes_witnesses,
    bridge_routes,
    governance_summary,
    liquidity_venues,
    sols_market,
)


def _b32(seed: int) -> bytes32:
    return bytes32(bytes([seed]) * 32)


def _hex(value: bytes32) -> str:
    return "0x" + bytes(value).hex()


def _singleton_struct(launcher_id: bytes32) -> Program:
    return Program.to(
        (SINGLETON_MOD_HASH, (launcher_id, SINGLETON_LAUNCHER_HASH))
    )


POOL_LAUNCHER = _b32(1)
STATUTES_LAUNCHER = _b32(2)
GOVERNANCE_LAUNCHER = _b32(3)
DEED_LAUNCHER = _b32(4)
DEED_PARENT = _b32(5)
POOL_COIN_ID = _b32(6)
VAULT_LAUNCHER = _b32(7)
VAULT_COIN_ID = _b32(8)
PROPERTY_ID = _b32(9)
QUOTE_EXPIRES = 1_900_000_000
PAR_VALUE = 100_000_000
SHARE_PPM = 100_000
PARAMETERS = ProtocolParameters()
RULES = PermanentRules(
    sgt_tail_hash=_b32(20),
    sgt_total_supply=1_000_000,
    sols_tail_hash=_b32(21),
    zkpassport_policy_hash=_b32(22),
    protocol_treasury_puzzle_hash=_b32(23),
    network_id=_b32(24),
)
COLLECTION = CollectionStatute(
    collection_id=_b32(25),
    nav_micro_usd=999_000_000,
    allocation_ceiling_micro_usd=999_000_000,
    nav_version=1,
    valid_after=1_899_930_000,
    valid_until=1_900_010_000,
    status=1,
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
    cat_mod_hash=_b32(30),
    offer_mod_hash=_b32(31),
    p2_vault_mod_hash=bytes32(
        load_puzzle("p2_vault.clsp").get_tree_hash()
    ),
    vault_v2_mod_hash=vault_v2_inner_mod_hash(),
    p2_pool_v2_mod_hash=bytes32(
        load_puzzle("p2_pool_v2.clsp").get_tree_hash()
    ),
    deed_launcher_puzzle_hash=_b32(34),
    reserve_puzzle_hash=_b32(32),
    sgt_rewards_puzzle_hash=_b32(33),
)


def _live(
    *,
    coin_id: bytes32,
    puzzle_hash: bytes32,
    spent_height: int | None = None,
) -> LiveCoin:
    return LiveCoin(
        coin_id=_hex(coin_id),
        parent_coin_id=_hex(_b32(90)),
        puzzle_hash=_hex(puzzle_hash),
        amount=1,
        confirmed_height=100,
        spent_height=spent_height,
    )


def _pool_transition_fixture() -> tuple[dict, SingletonTip]:
    deed_commitment = deed_metadata_commitment(
        DEED_LAUNCHER,
        PAR_VALUE,
        1,
        PROPERTY_ID,
        COLLECTION.collection_id,
        SHARE_PPM,
    )
    custody_coin_id = deterministic_custody_coin_id(
        config=CONFIG,
        deed_parent_coin_id=DEED_PARENT,
        deed_launcher_id=DEED_LAUNCHER,
        deed_commitment=deed_commitment,
    )
    statutes_state = initial_state(
        parameters=PARAMETERS,
        permanent_rules=RULES,
    )
    statutes_state = build_record_mutation(
        state=statutes_state,
        kind=MutationKind.COLLECTION,
        current=(),
        replacement=COLLECTION,
    )[2]
    receipt = prepare_deed_to_sols(
        pool_coin_id=POOL_COIN_ID,
        state=EMPTY_POOL,
        inventory=(),
        deed_launcher_id=DEED_LAUNCHER,
        custody_coin_id=custody_coin_id,
        deed_commitment=deed_commitment,
        collection=COLLECTION,
        share_ppm=SHARE_PPM,
        parameters=PARAMETERS,
        statutes_state=statutes_state,
        pause=None,
        vault_launcher_id=VAULT_LAUNCHER,
        vault_coin_id=VAULT_COIN_ID,
        seller_sols_puzzle_hash=_b32(34),
        quote_expires_at=QUOTE_EXPIRES,
    )
    old_inner = make_pool_v4_inner(CONFIG, EMPTY_POOL)
    inner_solution = deed_to_sols_inner_solution(
        config=CONFIG,
        pool_coin_id=POOL_COIN_ID,
        pool_inner_puzzle_hash=bytes32(old_inner.get_tree_hash()),
        pool_amount=1,
        receipt=receipt,
        parameters=PARAMETERS,
        collection=COLLECTION,
        pause=None,
        statutes_state=statutes_state,
        deed_parent_coin_id=DEED_PARENT,
        par_value=PAR_VALUE,
        asset_class=1,
        property_id=PROPERTY_ID,
        seller_sols_puzzle_hash=_b32(34),
        mint_token_coin_id=_b32(35),
        vault_launcher_id=VAULT_LAUNCHER,
        vault_coin_id=VAULT_COIN_ID,
        owner_pubkey=bytes(G1Element.generator()),
        auth_type=AUTH_TYPE_BLS,
        members_root=_b32(36),
        identity_root=_b32(37),
        bridge_policy=RULES.zkpassport_policy_hash,
        quote_expires_at=QUOTE_EXPIRES,
    )
    outer_solution = solution_for_singleton(
        LineageProof(
            parent_name=_b32(38),
            inner_puzzle_hash=_b32(39),
            amount=uint64(1),
        ),
        uint64(1),
        inner_solution,
    )
    next_full = make_pool_v4_full(CONFIG, receipt.next_state)
    spent = _live(
        coin_id=POOL_COIN_ID,
        puzzle_hash=bytes32(
            make_pool_v4_full(CONFIG, EMPTY_POOL).get_tree_hash()
        ),
        spent_height=101,
    )
    live = _live(
        coin_id=_b32(40),
        puzzle_hash=bytes32(next_full.get_tree_hash()),
    )
    return (
        {
            "puzzle_reveal": bytes(
                make_pool_v4_full(CONFIG, EMPTY_POOL)
            ).hex(),
            "solution": bytes(outer_solution).hex(),
        },
        SingletonTip(
            launcher_id=_hex(POOL_LAUNCHER),
            live=live,
            latest_spent=spent,
            depth=2,
            lineage=(spent, live),
        ),
    )


def test_pool_v4_reader_reconstructs_inventory_and_economics() -> None:
    puzzle_solution, tip = _pool_transition_fixture()
    pool = _decode_pool_state(puzzle_solution, tip)

    assert pool.bootstrap_complete is True
    assert pool.deed_count == 1
    assert pool.inventory_nav_micro_usd == 99_900_000
    assert pool.total_sols_mojos == 30_001
    assert pool.reserve_sols_mojos == 1
    assert len(pool.inventory) == 1
    assert pool.inventory[0].deed_launcher_id == DEED_LAUNCHER


def test_pool_v4_reader_rejects_tampered_next_commitment() -> None:
    puzzle_solution, tip = _pool_transition_fixture()
    outer = Program.from_bytes(bytes.fromhex(puzzle_solution["solution"]))
    values = outer.as_python()
    values[2][4][36] = bytes(_b32(99))
    puzzle_solution["solution"] = bytes(Program.to(values)).hex()

    with pytest.raises(ValueError, match="next state commitment"):
        _decode_pool_state(puzzle_solution, tip)


@pytest.mark.asyncio
async def test_statutes_reader_applies_collection_update_and_exposes_witness() -> None:
    old_state = initial_state(
        parameters=PARAMETERS,
        permanent_rules=RULES,
    )
    mutation, _, next_state = build_record_mutation(
        state=old_state,
        kind=MutationKind.COLLECTION,
        current=(),
        replacement=COLLECTION,
    )
    update = build_update_spend(
        my_id=_b32(50),
        my_inner_puzzle_hash=_b32(51),
        my_amount=1,
        singleton_struct=_singleton_struct(STATUTES_LAUNCHER),
        governance_singleton_struct=_singleton_struct(GOVERNANCE_LAUNCHER),
        permanent_rules=RULES,
        current_state=old_state,
        next_state=next_state,
        mutation=mutation,
        current_entries=(),
        governance_inner_puzzle_hash=_b32(52),
    )
    old_inner = make_statutes_inner(
        singleton_struct=_singleton_struct(STATUTES_LAUNCHER),
        governance_singleton_struct=_singleton_struct(GOVERNANCE_LAUNCHER),
        permanent_rules=RULES,
        state=old_state,
    )
    old_full = puzzle_for_singleton(STATUTES_LAUNCHER, old_inner)
    next_inner = make_statutes_inner(
        singleton_struct=_singleton_struct(STATUTES_LAUNCHER),
        governance_singleton_struct=_singleton_struct(GOVERNANCE_LAUNCHER),
        permanent_rules=RULES,
        state=next_state,
    )
    solution = solution_for_singleton(
        LineageProof(
            parent_name=_b32(53),
            inner_puzzle_hash=_b32(54),
            amount=uint64(1),
        ),
        uint64(1),
        update.inner_solution,
    )
    spent = _live(
        coin_id=_b32(50),
        puzzle_hash=bytes32(old_full.get_tree_hash()),
        spent_height=102,
    )
    live = _live(
        coin_id=_b32(55),
        puzzle_hash=bytes32(
            puzzle_for_singleton(
                STATUTES_LAUNCHER,
                next_inner,
            ).get_tree_hash()
        ),
    )
    tip = SingletonTip(
        launcher_id=_hex(STATUTES_LAUNCHER),
        live=live,
        latest_spent=spent,
        depth=2,
        lineage=(spent, live),
    )
    puzzle_solution = {
        "puzzle_reveal": bytes(old_full).hex(),
        "solution": bytes(solution).hex(),
    }

    decoded = _decode_statutes_state(
        puzzle_solution,
        tip,
        expected_permanent_rules=RULES,
        expected_governance_launcher_id=_hex(GOVERNANCE_LAUNCHER),
    )
    (
        _,
        collections,
        oracle_rounds,
        bridge_routes,
        liquidity_venues,
        _,
    ) = _statutes_witnesses(puzzle_solution)
    provider = type(
        "Provider",
        (),
        {
            "get_puzzle_and_solution": staticmethod(
                lambda *_args: _async_value(puzzle_solution)
            )
        },
    )()
    (
        resolved_parameters,
        resolved_collections,
        resolved_oracle_rounds,
        resolved_bridge_routes,
        resolved_liquidity_venues,
        resolved_pauses,
    ) = (
        await _resolve_statutes_witnesses(
            provider,
            tip,
            next_state,
            PARAMETERS,
        )
    )

    assert decoded == next_state
    assert collections == (COLLECTION,)
    assert liquidity_venues is None
    assert resolved_parameters == PARAMETERS
    assert resolved_collections == (COLLECTION,)
    assert resolved_oracle_rounds == ()
    assert resolved_bridge_routes == ()
    assert resolved_liquidity_venues == ()
    assert resolved_pauses == ()


def test_statutes_payload_exposes_only_typed_chain_liquidity_venues() -> None:
    initial = initial_state(
        parameters=PARAMETERS,
        permanent_rules=RULES,
    )
    venue = LiquidityVenue(
        venue_id=_b32(0x70),
        chain_id=_b32(0x71),
        protocol_id=_b32(0x72),
        factory_id=_b32(0x73),
        pool_id=_b32(0x74),
        base_asset_id=RULES.sols_tail_hash,
        quote_asset_id=_b32(0x75),
        pool_code_hash=_b32(0x76),
        active=1,
    )
    _, venues, state = build_record_mutation(
        state=initial,
        kind=MutationKind.LIQUIDITY,
        current=(),
        replacement=venue,
    )
    decoded = _liquidity_venue(Program.to(venue.as_program_value()))
    snapshot = StatutesSnapshot(
        live_coin_id=_hex(_b32(0x77)),
        live_puzzle_hash=_hex(_b32(0x78)),
        state=state,
        parameters=PARAMETERS,
        collections=(),
        oracle_rounds=(),
        bridge_routes=(),
        liquidity_venues=venues,
        pauses=(),
        registry_version=state.registry_version,
        confirmed_height=123,
        lineage_depth=2,
    )
    payload = _statutes_payload(snapshot)

    assert decoded == venue
    assert payload is not None
    assert payload["liquidityRoot"] == _hex(state.liquidity_root)
    assert payload["liquidityVenues"] == [
        {
            "venueId": _hex(venue.venue_id),
            "chainId": _hex(venue.chain_id),
            "protocolId": _hex(venue.protocol_id),
            "factoryId": _hex(venue.factory_id),
            "poolId": _hex(venue.pool_id),
            "baseAssetId": _hex(venue.base_asset_id),
            "quoteAssetId": _hex(venue.quote_asset_id),
            "poolCodeHash": _hex(venue.pool_code_hash),
            "active": True,
        }
    ]


def test_statutes_payload_exposes_only_typed_chain_bridge_and_oracle_records() -> None:
    initial = initial_state(
        parameters=PARAMETERS,
        permanent_rules=RULES,
    )
    oracle = OracleRound(
        asset_id=_b32(0x60),
        price_micro_usd=1_000_000,
        observed_at=1_899_999_000,
        valid_until=1_900_000_000,
        round_id=1,
        source_root=_b32(0x61),
        source_count=3,
        haircut_bps=0,
        stable_min_bps=9_900,
        stable_max_bps=10_100,
    )
    _, oracles, oracle_state = build_record_mutation(
        state=initial,
        kind=MutationKind.ORACLE,
        current=(),
        replacement=oracle,
    )
    route = BridgeRoute(
        route_id=_b32(0x62),
        source_chain_id=_b32(0x63),
        destination_chain_id=_b32(0x64),
        asset_id=RULES.sols_tail_hash,
        remote_asset_id=_b32(0x65),
        decimals=3,
        active=1,
    )
    _, routes, state = build_record_mutation(
        state=oracle_state,
        kind=MutationKind.ROUTE,
        current=(),
        replacement=route,
    )
    snapshot = StatutesSnapshot(
        live_coin_id=_hex(_b32(0x66)),
        live_puzzle_hash=_hex(_b32(0x67)),
        state=state,
        parameters=PARAMETERS,
        collections=(),
        oracle_rounds=oracles,
        bridge_routes=routes,
        liquidity_venues=(),
        pauses=(),
        registry_version=state.registry_version,
        confirmed_height=124,
        lineage_depth=3,
    )

    payload = _statutes_payload(snapshot)

    assert payload is not None
    assert payload["oracleRoot"] == _hex(state.oracle_root)
    assert payload["routesRoot"] == _hex(state.routes_root)
    assert payload["oracleRounds"][0]["priceMicroUsd"] == "1000000"
    assert payload["oracleRounds"][0]["sourceCount"] == 3
    assert payload["bridgeRoutes"] == [
        {
            "routeId": _hex(route.route_id),
            "sourceChainId": _hex(route.source_chain_id),
            "destinationChainId": _hex(route.destination_chain_id),
            "assetId": _hex(route.asset_id),
            "remoteAssetId": _hex(route.remote_asset_id),
            "decimals": 3,
            "active": True,
        }
    ]


async def _async_value(value):
    return value


class _Reader:
    def __init__(self, snapshot: dict | Exception) -> None:
        self._snapshot = snapshot

    async def snapshot(self) -> dict:
        if isinstance(self._snapshot, Exception):
            raise self._snapshot
        return self._snapshot


@pytest.mark.asyncio
async def test_bridge_and_liquidity_views_require_isolated_evidence_on_testnet() -> None:
    chain_snapshot = {
        "statutes": {
            "registryVersion": 4,
            "contentHash": _hex(_b32(0x80)),
            "routesRoot": _hex(_b32(0x81)),
            "liquidityRoot": _hex(_b32(0x82)),
            "bridgeRoutes": [
                {
                    "routeId": _hex(_b32(0x83)),
                    "active": True,
                }
            ],
            "liquidityVenues": [
                {
                    "venueId": _hex(_b32(0x84)),
                    "active": True,
                }
            ],
            "parameters": {
                "votingWindowSeconds": 300,
                "quorumBps": 5_000,
                "minimumProposalStake": "10000",
            },
            "confirmedHeight": 123,
        }
    }
    settings = Settings(
        network="testnet11",
        alpha_writes_enabled=False,
        sols_bridge_enabled=True,
        sols_liquidity_enabled=True,
    )
    reader = _Reader(chain_snapshot)

    bridge = await bridge_routes(settings, reader)
    liquidity = await liquidity_venues(settings, reader)
    governance = await governance_summary(settings, reader)

    assert bridge["mode"] == "PREVIEW"
    assert bridge["activationState"] == "AWAITING_RELEASE_EVIDENCE"
    assert bridge["routes"][0]["governedActive"] is True
    assert bridge["routes"][0]["executable"] is False
    assert {
        item["id"]: item["status"] for item in bridge["readiness"]
    } == {
        "governance": "READY",
        "network": "WAITING",
        "releaseEvidence": "WAITING",
        "adapter": "READY",
        "confirmationObserver": "WAITING",
        "operatorGate": "WAITING",
    }
    assert liquidity["mode"] == "PREVIEW"
    assert liquidity["activationState"] == "AWAITING_RELEASE_EVIDENCE"
    assert liquidity["venues"][0]["executable"] is False
    assert governance["statutesVersion"] == 4
    assert governance["minimumProposalStake"] == "10000"


@pytest.mark.asyncio
async def test_feature_flags_cannot_bypass_missing_beta_adapter_evidence() -> None:
    chain_snapshot = {
        "statutes": {
            "registryVersion": 4,
            "contentHash": _hex(_b32(0x80)),
            "routesRoot": _hex(_b32(0x81)),
            "liquidityRoot": _hex(_b32(0x82)),
            "bridgeRoutes": [{"routeId": _hex(_b32(0x83)), "active": True}],
            "liquidityVenues": [
                {"venueId": _hex(_b32(0x84)), "active": True}
            ],
            "parameters": {
                "votingWindowSeconds": 300,
                "quorumBps": 5_000,
                "minimumProposalStake": "10000",
            },
            "confirmedHeight": 123,
        }
    }
    settings = Settings(
        network="mainnet",
        sols_bridge_enabled=True,
        sols_liquidity_enabled=True,
    )
    reader = _Reader(chain_snapshot)

    bridge = await bridge_routes(settings, reader)
    liquidity = await liquidity_venues(settings, reader)

    assert bridge["mode"] == "PREVIEW"
    assert bridge["executable"] is False
    assert bridge["routes"][0]["executable"] is False
    assert bridge["activationState"] == "AWAITING_RELEASE_EVIDENCE"
    assert "deployment" in bridge["reason"]
    assert liquidity["mode"] == "PREVIEW"
    assert liquidity["executable"] is False
    assert liquidity["venues"][0]["executable"] is False
    assert liquidity["activationState"] == "AWAITING_RELEASE_EVIDENCE"
    assert "deployment" in liquidity["reason"]


def test_active_adapter_coverage_rejects_uninstalled_tibet_wallet_execution() -> None:
    venue_id = _hex(_b32(0x84))
    evidence = SolsCapabilityEvidence(
        capability="governed-liquidity",
        release_tag="solslot-v2-beta-rc1",
        source_sha="ab" * 20,
        governed_root=_hex(_b32(0x82)),
        adapter_ids=("tibet-v2",),
        adapter_descriptors=(
            {
                "adapterId": "tibet-v2",
                "recordId": venue_id,
                "kind": "TIBETSWAP_V2",
            },
        ),
        records=({"venueId": venue_id, "active": True},),
        runtime_evidence_root=_hex(_b32(0x85)),
        sha256="cd" * 32,
    )

    ready, detail = _active_adapter_coverage(
        governed_records=[{"venueId": venue_id, "active": True}],
        evidence=evidence,
        installed_adapter_kinds=LIQUIDITY_INSTALLED_ADAPTERS,
    )

    assert ready is False
    assert "TIBETSWAP_V2" in detail


def test_bridge_activation_waits_for_reviewed_confirmation_observer() -> None:
    checks = [
        {"id": "governance", "status": "READY"},
        {"id": "network", "status": "READY"},
        {"id": "releaseEvidence", "status": "READY"},
        {"id": "adapter", "status": "READY"},
        {"id": "confirmationObserver", "status": "WAITING"},
        {"id": "operatorGate", "status": "READY"},
    ]

    assert (
        _activation_state("mainnet", False, checks)
        == "AWAITING_CONFIRMATION_OBSERVER"
    )


def test_singleton_continuation_ignores_other_created_coins() -> None:
    child = _singleton_child(
        [
            _coin_record(2, 3, 90_000),
            _coin_record(2, 4, 1),
            _coin_record(2, 5, 900),
        ],
        expected_amount=1,
    )

    assert child.amount == 1
    assert child.puzzle_hash == "0x" + "04" * 32


def test_singleton_continuation_fails_closed_on_ambiguity() -> None:
    with pytest.raises(ValueError, match="missing or ambiguous"):
        _singleton_child(
            [_coin_record(2, 4, 1), _coin_record(2, 5, 1)],
            expected_amount=1,
        )


def _coin_record(parent: int, puzzle: int, amount: int) -> dict:
    return {
        "coin": {
            "parent_coin_info": "0x" + f"{parent:02x}" * 32,
            "puzzle_hash": "0x" + f"{puzzle:02x}" * 32,
            "amount": amount,
        },
        "confirmed_block_index": 100,
        "spent_block_index": 0,
    }


@pytest.mark.asyncio
async def test_public_market_returns_only_reader_verified_inventory() -> None:
    payload = {
        "schemaVersion": 2,
        "network": "testnet11",
        "outcome": "READY",
        "title": "1 SmartDeed swap available",
        "body": "Chain verified.",
        "opportunities": [
            {
                "deedId": "EASTMORELAND-001",
                "totalSolsMojos": "101000",
                "chainVerified": True,
            }
        ],
        "verifiedOpportunityCount": 1,
        "rejectedCandidateCount": 2,
    }
    response = await sols_market(_Reader(payload))

    assert response == payload


@pytest.mark.asyncio
async def test_missing_genesis_artifact_locks_market_without_inventory() -> None:
    response = await sols_market(_Reader(PublicArtifactMissing("missing")))

    assert response["schemaVersion"] == 2
    assert response["outcome"] == "LOCKED"
    assert response["statutes"] is None
    assert response["opportunities"] == []
    assert response["verifiedOpportunityCount"] == 0


class _HoldingStore:
    def sols_market_candidates(self) -> list[dict]:
        return [
            {
                "deedId": "EASTMORELAND-001",
                "deedLauncherId": _hex(DEED_LAUNCHER),
                "outputCoinId": _hex(DEED_PARENT),
                "collectionId": "eastmoreland",
                "collectionSlug": "127-eastmoreland",
                "collectionTitle": "127 Eastmoreland",
                "collectionSummary": "Testnet alpha property.",
                "metadataRoot": _hex(_b32(0x91)),
                "sharePpm": 40_000,
                "parValueMojos": 100_000_000,
            }
        ]

    def public_collection(self, _identifier: str) -> dict:
        return {
            "dossier": {
                "classification": {"assetClass": "RWA-RE-RES"}
            },
            "verification": {"chainReconstructed": True},
        }


@pytest.mark.asyncio
async def test_vault_holdings_require_exact_live_p2_vault_and_mint_lineage(
    monkeypatch,
) -> None:
    deed_launcher_hash = _b32(0x95)
    live_hash = SINGLETON_MOD.curry(
        Program.to(
            (
                SINGLETON_MOD_HASH,
                (DEED_LAUNCHER, deed_launcher_hash),
            )
        ),
        puzzle_for_p2_vault(VAULT_LAUNCHER),
    ).get_tree_hash()
    tip = SingletonTip(
        launcher_id=_hex(DEED_LAUNCHER),
        live=LiveCoin(
            coin_id=_hex(_b32(0x92)),
            parent_coin_id=_hex(DEED_PARENT),
            puzzle_hash=_hex(bytes32(live_hash)),
            amount=1,
            confirmed_height=130,
            spent_height=None,
        ),
        latest_spent=None,
        depth=2,
        lineage=(
            LiveCoin(
                coin_id=_hex(DEED_PARENT),
                parent_coin_id=_hex(_b32(0x93)),
                puzzle_hash=_hex(_b32(0x94)),
                amount=1,
                confirmed_height=120,
                spent_height=130,
            ),
        ),
    )

    async def singleton_tip(_provider, _launcher_id):
        return tip

    monkeypatch.setattr(
        "solslot_api.sols_market.load_signed_public_artifact",
        lambda _settings: {
            "launcherIds": {"pool": _hex(POOL_LAUNCHER)},
            "puzzleHashes": {
                "deedLauncherPuzzleHash": _hex(deed_launcher_hash)
            },
        },
    )
    monkeypatch.setattr(
        "solslot_api.sols_market._singleton_tip",
        singleton_tip,
    )
    reader = SolsMarketReader(
        object(),
        _HoldingStore(),
        Settings(_env_file=None, network="testnet11"),
    )

    result = await reader.vault_holdings(_hex(VAULT_LAUNCHER))

    assert result["verifiedHoldingCount"] == 1
    assert result["rejectedHoldingCandidateCount"] == 0
    assert result["holdings"][0]["custody"] == "P2_VAULT"
    assert result["holdings"][0]["assetClass"] == 1
