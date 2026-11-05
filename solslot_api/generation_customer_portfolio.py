"""Owner-private current-generation holdings from primary-node evidence.

This reader has no funding, signing, reservation or submission interface. An
empty result requires a complete read; missing authority is never a zero. Mint
history supplies the deed universe and immutable terms, not legacy account rows.
"""
from __future__ import annotations

import asyncio
import time

from chia.types.blockchain_format.program import Program
from chia.wallet.cat_wallet.cat_utils import CAT_MOD
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD, SINGLETON_MOD_HASH
from chia.wallet.util.compute_additions import compute_additions_with_cost
from chia_rs import Coin
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.generation_mint import GenerationMint
from solslot_puzzles.generation_pool import GenerationPool
from solslot_puzzles.generation_sgt import SGTOutput
from solslot_puzzles.generation_vault import sgt_owner
from solslot_puzzles.holdings import HoldingKind
from solslot_puzzles.vault_driver import puzzle_for_p2_vault
from solslot_puzzles.vault_sols_v1 import puzzle_for_vault_sols_cat

from .generation_chain_evidence import current_evidence_unchanged
from .generation_coin_evidence import read_confirmed_coin
from .generation_registry_evidence import _spend
from .sols_market import _singleton_tip

MAX_COINS = 512
MAX_DEEDS = 1000


def h(value):
    return '0x' + value.hex()


class PrimarySingletonReader:
    """Adapt the generic executed-singleton reader without advisory fallback."""
    def __init__(self, provider):
        self.provider = provider

    async def get_coin_record_by_name(self, identity):
        return await self.provider.get_coin_record_by_name_primary(identity)

    async def get_puzzle_and_solution(self, identity, height):
        return await self.provider.get_puzzle_and_solution_primary(identity, height)

    async def get_coin_records_by_parent_ids(self, identities, *, include_spent=False):
        return await self.provider.get_coin_records_by_parent_ids_primary(
            identities, include_spent=include_spent)


async def _unspent(provider, puzzle_hash):
    raw = await provider.get_coin_records_by_puzzle_hash_primary(h(puzzle_hash), include_spent=False)
    if not isinstance(raw, list) or len(raw) > MAX_COINS:
        raise ValueError('portfolio coin evidence exceeds its bound')
    records = []
    for value in raw:
        coin = Coin.from_json_dict(value['coin'])
        record = read_confirmed_coin(value, coin.name(), allow_zero=True)
        if record.spent_height or coin.puzzle_hash != puzzle_hash:
            raise ValueError('portfolio query returned inconsistent custody')
        records.append(record)
    if len({record.coin.name() for record in records}) != len(records):
        raise ValueError('portfolio query returned duplicate coins')
    return records


async def _sols_balance(provider, config, launcher, observed):
    puzzle = puzzle_for_vault_sols_cat(config=config, vault_launcher_id=launcher)
    records = await _unspent(provider, puzzle.get_tree_hash())
    total, rejected = 0, 0
    for record in records:
        if record.coin.amount == 0:
            # Zero-value coins cannot add a balance. They can be sent to a
            # public puzzle hash without owning its CAT and must not break it.
            rejected += 1
            continue
        parent = read_confirmed_coin(await provider.get_coin_record_by_name_primary(
            h(record.coin.parent_coin_info)), record.coin.parent_coin_info, allow_zero=True)
        if parent.spent_height != record.confirmed_height:
            raise ValueError('Sols parent is not the confirmed atomic source')
        spend = _spend(await provider.get_puzzle_and_solution_primary(
            h(parent.coin.name()), parent.spent_height), parent.coin)
        mod, args = Program.from_bytes(bytes(spend.puzzle_reveal)).uncurry()
        fields = list(args.as_iter())
        # Anyone can send dust to a CAT puzzle hash. A confirmed spend of a
        # parent using this exact CAT tail proves native CAT lineage admission.
        if (mod != CAT_MOD or len(fields) != 3 or fields[0].as_atom() != CAT_MOD.get_tree_hash()
                or fields[1].as_atom() != config.permanent_rules.sols_tail_hash):
            rejected += 1
            continue
        additions, cost = compute_additions_with_cost(spend, max_cost=250_000_000)
        if cost > 250_000_000:
            raise ValueError('Sols ancestry exceeds the portfolio read budget')
        if record.coin not in additions:
            raise ValueError('Sols custody coin is absent from its executed parent')
        total += record.coin.amount
        observed.extend((parent, record))
    return total, rejected


async def read_current_portfolio(*, snapshot, evidence, sgt_bindings, provider,
                                 metadata_for_edition, checked_at=None):
    generation = bytes32.from_hexstr(snapshot['generationId'])
    launcher = bytes32.from_hexstr(snapshot['vault']['vaultLauncherId'])
    if (snapshot['network'] != 'testnet11' or sgt_bindings.generation != generation
            or evidence.registry.state.generation != generation
            or (await provider.get_network_info_primary()).get('network_name') != 'testnet11'):
        raise ValueError('portfolio generation or primary network changed')
    pools = [history.state for history in evidence.economic_components.values()
             if isinstance(history.state, GenerationPool)]
    mints = [history for history in evidence.economic_components.values()
             if isinstance(history.state, GenerationMint)]
    if len(pools) != 1 or len(mints) != 1:
        raise ValueError('portfolio native authorities are incomplete')
    pool, mint = pools[0], mints[0]
    if (pool.generation != generation or mint.state.generation != generation
            or mint.state.pool_id != pool.launcher_id):
        raise ValueError('portfolio economic authorities differ')
    vault_record = read_confirmed_coin(await provider.get_coin_record_by_name_primary(
        snapshot['vault']['currentCoinId']), bytes32.from_hexstr(snapshot['vault']['currentCoinId']))
    if (vault_record.spent_height or h(vault_record.coin.puzzle_hash) != snapshot['vault']['currentPuzzleHash']
            or vault_record.confirmed_height != snapshot['vault']['confirmedHeight']):
        raise ValueError('portfolio vault changed since its native observation')
    observed = [vault_record]
    sols, rejected = await _sols_balance(provider, pool.config(), launcher, observed)
    tree, _ = evidence.holdings.state
    owner = sgt_owner(generation, launcher).get_tree_hash()
    sgt = locked = 0
    for identity, holding in tree.holdings.items():
        if holding.owner_hash != owner or holding.kind not in (HoldingKind.HOLDER, HoldingKind.LOCKED_HOLDER):
            continue
        record = read_confirmed_coin(await provider.get_coin_record_by_name_primary(h(identity)), identity)
        expected = SGTOutput(holding.kind, owner, holding.amount, holding.lock_id).full(sgt_bindings)
        if (record.spent_height or record.coin.puzzle_hash != expected.get_tree_hash()
                or record.coin.puzzle_hash != holding.puzzle_hash or record.coin.amount != holding.amount):
            raise ValueError('SGT holding differs from authenticated native ledger')
        observed.append(record)
        if holding.kind == HoldingKind.HOLDER:
            sgt += holding.amount
        else:
            locked += holding.amount

    originals = []
    for transition in mint.transitions:
        if transition.edition is not None:
            edition = transition.edition
            if edition.generation != generation:
                raise ValueError('portfolio edition belongs to another generation')
            originals.extend((edition, offset, item) for offset, item in enumerate(
                transition.before.inventories(edition)))
    if (len(originals) != mint.state.issued_count or len(originals) > MAX_DEEDS
            or len({item.terms.deed_launcher_id for _, _, item in originals}) != len(originals)):
        raise ValueError('portfolio minted universe exceeds its bound or duplicates a deed')
    limit = asyncio.Semaphore(4)
    primary = PrimarySingletonReader(provider)

    async def held(edition, offset, original):
        async with limit:
            terms = original.terms
            structure = Program.to((SINGLETON_MOD_HASH,
                (terms.deed_launcher_id, terms.deed_launcher_puzzle_hash)))
            expected = SINGLETON_MOD.curry(structure, puzzle_for_p2_vault(launcher)).get_tree_hash()
            candidates = await _unspent(provider, expected)
            if not candidates:
                return None
            tip = await _singleton_tip(primary, h(terms.deed_launcher_id))
            if tip is None or h(original.coin.name()) not in {node.coin_id for node in tip.lineage}:
                raise ValueError('portfolio deed lacks its confirmed generation mint ancestry')
            matching = [record for record in candidates if h(record.coin.name()) == tip.live.coin_id]
            if not matching:
                # Unrelated dust is not a minted SmartDeed.
                return None
            if len(matching) != 1 or tip.live.puzzle_hash != h(expected) or matching[0].coin.amount != 1:
                raise ValueError('portfolio singleton custody differs')
            observed.append(matching[0])
            metadata = metadata_for_edition(edition)
            allocation = metadata['deedAllocation'][offset]
            if (allocation['sharePpm'] != terms.share_ppm
                    or int(allocation['parValueMojos']) != edition.rows[offset].sealed_par_mojos):
                raise ValueError('portfolio public metadata differs from minted allocation')
            return {'deedId': allocation['deedId'], 'deedLauncherId': h(terms.deed_launcher_id),
                'deedCoinId': tip.live.coin_id, 'collectionId': metadata['collectionId'],
                'collectionSlug': metadata['collectionId'], 'collectionTitle': metadata['title'],
                'collectionSummary': metadata.get('summary'), 'metadataRoot': h(edition.metadata_root),
                'sharePpm': terms.share_ppm, 'parValueMojos': str(edition.rows[offset].sealed_par_mojos),
                'assetClass': edition.asset_class, 'chainVerified': True,
                'confirmedHeight': tip.live.confirmed_height, 'custody': 'P2_VAULT'}

    holdings = [item for item in await asyncio.gather(*(held(*item) for item in originals)) if item is not None]
    for record in observed:
        again = read_confirmed_coin(await provider.get_coin_record_by_name_primary(
            h(record.coin.name())), record.coin.name(), allow_zero=True)
        if again != record:
            raise ValueError('portfolio changed during observation')
    if not await current_evidence_unchanged(evidence, provider=provider):
        raise ValueError('portfolio generation authority changed during observation')
    closed = {'available': False, 'state': 'NOT_YET_AVAILABLE',
        'reason': 'This action is not enabled for the current Testnet release.', 'path': '/'}
    verified = snapshot['vault']['identityVerified']
    return {'schemaVersion': 1, 'network': 'testnet11',
        'vault': {'launcherId': h(launcher), 'authType': snapshot['authType'],
            'identityConfirmed': verified, 'eligibilityReason': None if verified else 'FRESH_ID_REQUIRED'},
        'balances': {'solsMojos': str(sols), 'solsCoverage': 'CURRENT_GENERATION_VAULT',
            'sgtMojos': str(sgt), 'sgtLockedMojos': str(locked), 'sgtCoverage': 'CURRENT_GENERATION_LEDGER'},
        'holdings': holdings, 'vouchers': [], 'pendingOperations': [], 'recentActivity': [],
        'opportunities': [], 'capabilities': {name: dict(closed) for name in
            ('primaryPurchase', 'solsToDeed', 'deedToSols', 'bridge', 'liquidity')},
        'recommendedAction': {'kind': 'EXPLORE' if verified else 'VERIFY_IDENTITY',
            'label': 'Explore properties' if verified else 'Continue private ID check',
            'path': '/' if verified else '/verify-identity'},
        'verification': {'holdingsSource': 'CURRENT_GENERATION_PRIMARY_NODE',
            'generationId': h(generation), 'checkedAt': int(time.time()) if checked_at is None else checked_at,
            'verifiedHoldingCount': len(holdings), 'rejectedHoldingCandidateCount': rejected,
            'marketOutcome': 'PAUSED', 'mintedDeedsChecked': len(originals)}}
