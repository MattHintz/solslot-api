"""Explicit sealed batch reviews; no signatures, dispatch or status-side builds.

The first explicit preparation fixes launcher parents and persists conservative
holds. Cached retries recover the same edition even offline. A review is not
publication consent and cannot be submitted as a mint operation.
"""
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
import asyncio
import json
import logging
import os
import sqlite3
import time

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32
from pydantic import Field
from solslot_puzzles.generation_mint import GenerationMint, MintRow, TestMintEdition
from solslot_puzzles.property_metadata import commit_metadata
from solslot_puzzles.property_registry_driver import canonicalise_property_id
from .collection_generation_mint import build_sealed_test_mint
from .generation_chain_evidence import resolve_generation_chain, current_evidence_unchanged
from .generation_mint_checks import checked_mint_chain_cache, primary_mint_coin_records
from .generation_coin_evidence import read_confirmed_coin
from .generation_context import generation_bytes
from .generation_execution import Hash, Model
from .generation_operations import canonical
from .generation_storage import connect_generation_sqlite, generation_path, admit_retained_bytes
from .test_collection_metadata import TestPropertyDossierV1


def h(value): return '0x'+value.hex()


logger = logging.getLogger(__name__)


class MintReviewTimeout(TimeoutError):
    def __init__(self, stage):
        super().__init__('mint review preparation timed out')
        self.stage = stage


class MintReviewRequest(Model):
    generation_id: Hash = Field(alias='generationId')
    collection_id: str = Field(alias='collectionId', pattern=r'^[A-Za-z0-9_-]{1,128}$')
    revision: int = Field(strict=True, ge=1, le=2**53-1)
    metadata_root: Hash = Field(alias='metadataRoot')
    preview_hash: Hash = Field(alias='previewHash')

    @property
    def digest(self):
        return h(sha256(canonical(self.model_dump(mode='json', by_alias=True)).encode()).digest())


class GenerationMintReviewStore:
    MAX_RETAINED_BYTES = 128 * 1024 * 1024
    COMPLETION_BYTES = 65536

    def __init__(self, path, generation_id):
        generation_bytes(generation_id)
        self.generation_id = generation_id
        self.path = generation_path(path, generation_id)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.fchmod(fd, 0o600); os.close(fd)
        with self._db() as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.executescript('''
                CREATE TABLE IF NOT EXISTS generation_mint_reviews (
                    package_id TEXT PRIMARY KEY, collection_id TEXT UNIQUE NOT NULL,
                    request_digest TEXT NOT NULL, document TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS generation_mint_parent_holds (
                    coin_id TEXT PRIMARY KEY, package_id TEXT NOT NULL);
                CREATE UNIQUE INDEX IF NOT EXISTS generation_mint_collection_commitments
                    ON generation_mint_reviews(json_extract(document, '$.collectionCommitment'));
                CREATE TABLE IF NOT EXISTS generation_mint_execution_links (
                    package_id TEXT PRIMARY KEY, operation_id TEXT UNIQUE NOT NULL,
                    last_checked INTEGER, error_code TEXT);
                CREATE TABLE IF NOT EXISTS generation_mint_inventory_receipts (
                    package_id TEXT PRIMARY KEY, receipt_hash TEXT NOT NULL, document TEXT NOT NULL);
            ''')

    @contextmanager
    def _db(self, write=False):
        db = connect_generation_sqlite(self.path, timeout=5, isolation_level=None, generation_id=self.generation_id)
        db.row_factory = sqlite3.Row
        try:
            db.execute('PRAGMA synchronous=FULL')
            if write: db.execute('BEGIN IMMEDIATE')
            yield db
            if write: db.execute('COMMIT')
        except BaseException:
            if db.in_transaction: db.execute('ROLLBACK')
            raise
        finally: db.close()

    def for_collection(self, collection_id):
        with self._db() as db:
            row = db.execute('SELECT package_id FROM generation_mint_reviews WHERE collection_id=?', (collection_id,)).fetchone()
        return self.status(row[0]) if row else None

    def reviewed_request(self, request):
        if request.generation_id != self.generation_id: raise ValueError('mint review belongs to another generation')
        saved = self.for_collection(request.collection_id)
        if saved and saved['requestDigest'] != request.digest:
            raise ValueError('retry changes the saved sealed mint edition; retained holds require operator reconciliation')
        return saved

    def reserved_input_coin_ids(self):
        # Read the immutable source documents too: missing/altered hold rows
        # must fail closed instead of making those funds available to fees.
        with self._db() as db:
            ids = [r[0] for r in db.execute('SELECT package_id FROM generation_mint_reviews')]
        return {c['coinId'] for identity in ids for c in self.status(identity)['funding']}

    def status(self, identity):
        generation_bytes(identity)
        with self._db() as db:
            row = db.execute('SELECT * FROM generation_mint_reviews WHERE package_id=?', (identity,)).fetchone()
            holds = {r[0] for r in db.execute('SELECT coin_id FROM generation_mint_parent_holds WHERE package_id=?', (identity,))}
        if row is None or h(sha256(row['document'].encode()).digest()) != identity:
            raise ValueError('saved mint review is unavailable or changed')
        document = json.loads(row['document'])
        request = MintReviewRequest.model_validate(document['request'])
        if (request.generation_id != self.generation_id or document['generationId'] != self.generation_id
                or request.digest != row['request_digest'] or document['requestDigest'] != request.digest
                or request.collection_id != row['collection_id']
                or holds != {c['coinId'] for c in document['funding']}):
            raise ValueError('saved mint review or its durable funding holds changed')
        return {**document, 'packageId': identity}

    def save(self, request, document):
        # Match the browser's existing JCS metadata profile, including Unicode
        # titles and UTF-16 key order. Receipt hashing must not use ASCII JSON
        # escaping while the client hashes the visible UTF-8 source.
        raw = commit_metadata(document, enforce_size=False).canonical_json.decode()
        if len(raw.encode()) > 1_000_000 or document['request'] != request.model_dump(mode='json', by_alias=True):
            raise ValueError('mint source review exceeds its bound or differs from the request')
        if request.generation_id != self.generation_id: raise ValueError('mint review belongs to another generation')
        identity = h(sha256(raw.encode()).digest())
        with self._db(write=True) as db:
            prior = db.execute('SELECT package_id,request_digest FROM generation_mint_reviews WHERE collection_id=?', (request.collection_id,)).fetchone()
            if prior:
                if prior['request_digest'] != request.digest: raise ValueError('the original mint edition cannot be replaced')
                identity = prior['package_id']
            else:
                if db.execute('SELECT count(*) FROM generation_mint_reviews').fetchone()[0] >= 5000:
                    raise ValueError('mint review journal needs archive capacity review')
                retained = db.execute('SELECT coalesce(sum(length(CAST(document AS BLOB))+?),0) FROM generation_mint_reviews', (self.COMPLETION_BYTES,)).fetchone()[0]
                admit_retained_bytes(db, retained, len(raw.encode())+self.COMPLETION_BYTES, self.MAX_RETAINED_BYTES)
                parents = [c['coinId'] for c in document['funding']]
                if not parents or len(parents)>100 or len(set(parents)) != len(parents): raise ValueError('distinct funding holds are required')
                try:
                    db.execute('INSERT INTO generation_mint_reviews VALUES (?,?,?,?)', (identity, request.collection_id, request.digest, raw))
                    db.executemany('INSERT INTO generation_mint_parent_holds VALUES (?,?)', [(parent,identity) for parent in parents])
                except sqlite3.IntegrityError as exc:
                    raise ValueError('this canonical collection or a launcher parent is already retained by another mint review') from exc
        return self.status(identity)

    def record_execution(self,identity,operation_id):
        self.status(identity);generation_bytes(operation_id)
        with self._db(write=True) as db:
            prior=db.execute('SELECT operation_id FROM generation_mint_execution_links WHERE package_id=?',(identity,)).fetchone()
            if prior and prior[0]!=operation_id:raise ValueError('mint execution cannot be replaced')
            db.execute('INSERT OR IGNORE INTO generation_mint_execution_links VALUES (?,?,NULL,NULL)',(identity,operation_id))

    def pending_inventory_checks(self):
        with self._db() as db:
            return [tuple(row) for row in db.execute('SELECT e.package_id,e.operation_id FROM generation_mint_execution_links e '
                'LEFT JOIN generation_mint_inventory_receipts r ON e.package_id=r.package_id WHERE r.package_id IS NULL '
                'ORDER BY coalesce(e.last_checked,0),e.package_id LIMIT 4')]

    def inventory_check(self,identity,now,error):
        if type(now) is not int or now<=0 or error not in (None,'MINT_INVENTORY_NOT_CONFIRMED','PRIMARY_NODE_UNAVAILABLE'):
            raise ValueError('invalid inventory observation')
        with self._db(write=True) as db:
            db.execute('UPDATE generation_mint_execution_links SET last_checked=?,error_code=? WHERE package_id=? '
                'AND package_id NOT IN (SELECT package_id FROM generation_mint_inventory_receipts)',(now,error,identity))

    def record_inventory_confirmation(self,identity,receipt):
        source=self.status(identity);self._validate_inventory(source,receipt)
        raw=canonical(receipt)
        if len(raw.encode())>self.COMPLETION_BYTES-1024:raise ValueError('inventory evidence exceeds its reserved completion space')
        with self._db(write=True) as db:
            link=db.execute('SELECT operation_id FROM generation_mint_execution_links WHERE package_id=?',(identity,)).fetchone()
            if link is None or link[0]!=receipt['operationId']:raise ValueError('inventory belongs to another execution')
            prior=db.execute('SELECT document FROM generation_mint_inventory_receipts WHERE package_id=?',(identity,)).fetchone()
            if prior:
                old=json.loads(prior[0]);new=dict(receipt);old.pop('observedAt');new.pop('observedAt')
                if old!=new:raise ValueError('confirmed inventory cannot be replaced')
                return
            db.execute('INSERT INTO generation_mint_inventory_receipts VALUES (?,?,?)',(identity,h(sha256(raw.encode()).digest()),raw))
            db.execute('UPDATE generation_mint_execution_links SET last_checked=?,error_code=NULL WHERE package_id=?',(receipt['observedAt'],identity))

    def _validate_inventory(self,source,receipt):
        if (receipt.get('schemaVersion')!=1 or receipt.get('generationId')!=self.generation_id
                or receipt.get('network')!='testnet11' or receipt.get('purpose')!='TEST_ONLY'
                or receipt.get('sourceReviewId')!=source['packageId'] or receipt.get('metadataRoot')!=source['request']['metadataRoot']
                or receipt.get('editionHash')!=source['editionHash'] or receipt.get('deedCount')!=len(source['funding'])
                or type(receipt.get('confirmedHeight')) is not int or receipt['confirmedHeight']<=0
                or type(receipt.get('observedAt')) is not int or receipt['observedAt']<=0
                or len(receipt.get('inventory',[]))!=len(source['funding'])):raise ValueError('inventory receipt differs from its source')
        for key in ('operationId','transactionId'):generation_bytes(receipt[key])
        for expected,actual in zip(source['funding'],receipt['inventory'],strict=True):
            coin=Coin.from_json_dict(actual['coin'])
            if (actual['launcherId']!=expected['launcherId'] or actual['coinId']!=expected['inventoryCoinId']
                    or h(coin.name())!=actual['coinId'] or h(coin.parent_coin_info)!=actual['launcherId'] or coin.amount!=1):
                raise ValueError('inventory coin differs from its exact predicted output')

    def inventory_status(self,identity):
        source=self.status(identity)
        with self._db() as db:
            row=db.execute('SELECT receipt_hash,document FROM generation_mint_inventory_receipts WHERE package_id=?',(identity,)).fetchone()
            link=db.execute('SELECT operation_id,last_checked,error_code FROM generation_mint_execution_links WHERE package_id=?',(identity,)).fetchone()
        receipt=None
        if row:
            if h(sha256(row['document'].encode()).digest())!=row['receipt_hash']:raise ValueError('inventory receipt changed')
            receipt=json.loads(row['document']);self._validate_inventory(source,receipt)
            if link is None or link['operation_id']!=receipt['operationId']:raise ValueError('inventory execution link changed')
        return {'receipt':receipt,'lastCheckedAt':link['last_checked'] if link else None,'errorCode':link['error_code'] if link else None}


async def prepare_mint_review(request, *, settings, collections, anchor, provider, faucet, store, funding_guard, clock=time.time, index=None):
    request = MintReviewRequest.model_validate_json(request.model_dump_json(by_alias=True))
    if (settings.network != 'testnet11' or settings.deployment_generation_id != request.generation_id
            or h(anchor.issuance.generation) != request.generation_id):
        raise ValueError('mint review requires the exact Testnet11 generation')
    saved = store.reviewed_request(request)
    if saved: return saved  # Lost response/restart must not choose new parents.
    stage = 'WAITING_FOR_FUNDING_GUARD'
    logger.info('mint_review stage=%s request=%s', stage, request.digest)
    try:
        async with asyncio.timeout(50), funding_guard:
            saved = store.reviewed_request(request)
            if saved: return saved
            stage = 'VERIFYING_AUTHORITY'
            logger.info('mint_review stage=%s request=%s', stage, request.digest)
            chain = await checked_mint_chain_cache(anchor, provider=provider, index=index)
            if chain is None:
                chain = await resolve_generation_chain(anchor, provider=provider)
            gov, registry = chain.governance.state, chain.registry.state
            if registry.pause_mask & 3 or registry.pending:
                raise ValueError('new mint preparation is paused or an upgrade is pending')
            history = next((v for v in chain.economic_components.values()
                            if isinstance(v.state, GenerationMint) and v.state.launcher_id == gov.mint_id), None)
            if history is None or history.state.component() not in registry.components:
                raise ValueError('the supported current mint authority is unavailable')
            mint = history.state
            stage = 'CHECKING_SEALED_SOURCE'
            logger.info('mint_review stage=%s request=%s', stage, request.digest)
            snapshot = collections.sealed_test_mint_snapshot(request.collection_id)
            dossier = TestPropertyDossierV1.model_validate(snapshot['canonicalMetadata'])
            if (dossier.revision != request.revision or snapshot['metadataRoot'] != request.metadata_root
                    or snapshot['previewHash'] != request.preview_hash):
                raise ValueError('the sealed revision or approved preview changed')
            # Selection occurs only here, on an explicit action. Primary reads may
            # not silently fall back to an advisory provider for funding authority.
            stage = 'READING_FUNDING'
            logger.info('mint_review stage=%s request=%s', stage, request.digest)
            records = await provider.get_coin_records_by_puzzle_hash_primary(faucet.address_hex, include_spent=False)
            if not isinstance(records, list) or len(records)>4096: raise ValueError('funding catalog exceeds its review bound')
            reserved = faucet.reserved_coin_ids() | {bytes32.from_hexstr(v) for v in store.reserved_input_coin_ids()}
            candidates = {}
            for raw in records:
                try: coin = Coin.from_json_dict(raw['coin'])
                except (KeyError, TypeError, AttributeError, ValueError) as exc:
                    raise ValueError('primary launcher funding evidence is malformed') from exc
                rec = read_confirmed_coin(raw, coin.name())
                if (not rec.spent_height and coin.puzzle_hash == faucet.address_puzzle_hash
                        and coin.name() not in reserved and 1<=coin.amount<=settings.faucet_max_spend_mojos):
                    if coin.name() in candidates: raise ValueError('duplicate funding record')
                    candidates[coin.name()] = rec
            selected = sorted(candidates.values(), key=lambda v:(v.coin.amount,v.coin.name()))[:len(dossier.deed_allocation)]
            if len(selected) != len(dossier.deed_allocation): raise ValueError('not enough distinct confirmed launcher parents; operator funding preparation is required')
            edition = build_sealed_test_mint(collections, settings, mint, request.collection_id, tuple(v.coin.name() for v in selected))
            inventories = mint.inventories(edition)
            stage = 'VERIFYING_FUNDING'
            logger.info('mint_review stage=%s request=%s', stage, request.digest)
            observed = await primary_mint_coin_records((h(rec.coin.name()) for rec in selected), provider=provider)
            for rec, raw in zip(selected, observed, strict=True):
                current = read_confirmed_coin(raw, rec.coin.name())
                if current != rec: raise ValueError('launcher funding changed during review')
            stage = 'RECHECKING_AUTHORITY'
            logger.info('mint_review stage=%s request=%s', stage, request.digest)
            if not await current_evidence_unchanged(chain, provider=provider): raise ValueError('mint authority changed during review')
            # Recheck public source and all shared holds after external awaits.
            if collections.sealed_test_mint_snapshot(request.collection_id) != snapshot:
                raise ValueError('sealed source changed during review')
            if any(v.coin.name() in faucet.reserved_coin_ids() for v in selected): raise ValueError('launcher funding was retained by another operation')
            document = {'generationId': request.generation_id, 'network':'testnet11', 'purpose':'TEST_ONLY',
                'stage':'SOURCE_REVIEWED', 'publicationReady':False, 'createdAt':int(clock()),
                'request':request.model_dump(mode='json',by_alias=True), 'requestDigest':request.digest,
                'canonicalMetadata':snapshot['canonicalMetadata'], 'editionProgram':h(bytes(Program.to(edition.program()))),
                'editionHash':h(edition.commitment), 'billHash':h(edition.bill().get_tree_hash()),
                'collectionCommitment':h(edition.collection), 'mintAuthority':{'componentId':h(mint.component_id),
                    'launcherId':h(mint.launcher_id), 'coinId':h(history.current.coin.name()), 'moduleHash':h(mint.logic_hash()),
                    'version':mint.version},
                'funding':[{'coinId':h(rec.coin.name()), 'coin':rec.coin.to_json_dict(), 'confirmedHeight':rec.confirmed_height,
                    'launcherId':h(item.launcher_spend.coin.name()), 'inventoryCoinId':h(item.coin.name())}
                    for rec,item in zip(selected,inventories,strict=True)],
                'nextAction':'Your sealed edition and its fixed launcher funding are saved. Review publication separately.'}
            stage = 'SAVING_REVIEW'
            logger.info('mint_review stage=%s request=%s', stage, request.digest)
            result = store.save(request, document)
            logger.info('mint_review stage=SOURCE_REVIEWED request=%s', request.digest)
            return result
    except TimeoutError as exc:
        logger.warning('mint_review timeout stage=%s request=%s', stage, request.digest)
        raise MintReviewTimeout(stage) from exc


def reviewed_mint_edition(review):
    """Reconstruct the immutable native edition, never an arbitrary bill body."""
    identity = review.get('packageId')
    generation_bytes(identity)
    document = {k:v for k,v in review.items() if k != 'packageId'}
    if h(commit_metadata(document, enforce_size=False).metadata_root) != identity:
        raise ValueError('mint source package changed')
    request = MintReviewRequest.model_validate(review['request'])
    dossier = TestPropertyDossierV1.model_validate(review['canonicalMetadata'])
    if (review['generationId'] != request.generation_id or review['purpose'] != 'TEST_ONLY'
            or review['network'] != 'testnet11' or review['stage'] != 'SOURCE_REVIEWED'
            or review['publicationReady'] is not False or review['requestDigest'] != request.digest
            or dossier.generation_id != request.generation_id or dossier.collection_id != request.collection_id
            or dossier.revision != request.revision
            or h(commit_metadata(review['canonicalMetadata']).metadata_root) != request.metadata_root):
        raise ValueError('mint source differs from its sealed request')
    try:
        program = Program.from_bytes(bytes.fromhex(review['editionProgram'][2:]))
        fields = list(program.as_iter())
        if len(fields) != 11 or fields[0].as_atom() != b'TEST_ONLY':
            raise ValueError('invalid test edition')
        rows = []
        for raw in fields[10].as_iter():
            row = list(raw.as_iter())
            if len(row) != 4: raise ValueError('invalid inventory row')
            rows.append(MintRow(bytes32(row[0].as_atom()), *(v.as_int() for v in row[1:])))
        edition = TestMintEdition(*(bytes32(v.as_atom()) for v in fields[1:7]),
            fields[7].as_int(), fields[8].as_int(), fields[9].as_atom(), tuple(rows))
        if (Program.to(edition.program()) != program or edition.generation != bytes32.from_hexstr(request.generation_id)
                or edition.collection != canonicalise_property_id(request.collection_id)
                or edition.metadata_root != bytes32.from_hexstr(request.metadata_root)
                or edition.preview_hash != bytes32.from_hexstr(request.preview_hash)
                or h(edition.commitment) != review['editionHash'] or h(edition.bill().get_tree_hash()) != review['billHash']
                or h(edition.collection) != review['collectionCommitment']
                or len(rows) != len(review['funding']) or len(rows) != len(dossier.deed_allocation)
                or [h(r.launcher_parent) for r in rows] != [f['coinId'] for f in review['funding']]):
            raise ValueError('native edition differs from its saved source')
    except (TypeError, KeyError, ValueError, AttributeError) as exc:
        raise ValueError('saved test edition is invalid') from exc
    return edition


async def revalidate_mint_review(identity, *, settings, collections, store, chain, provider, publication=True):
    """Explicit publication preparation rechecks source, authority and holds.

    Status reads never call this method. No new parent is selected, reserved,
    signed or dispatched. Spent funding invalidates this source; it is not
    silently replaced underneath administrator consent.
    """
    if (store is None or collections is None or settings is None
            or store.generation_id != settings.deployment_generation_id or settings.network != 'testnet11'):
        raise ValueError('sealed generation mint source is not configured')
    review = store.status(identity)
    original = reviewed_mint_edition(review)
    gov, registry = chain.governance.state, chain.registry.state
    if registry.pause_mask & (3 if publication else 2) or registry.pending or gov.upgrade_reserved:
        raise ValueError('mint publication is paused or an upgrade is pending')
    history = chain.economic_components.get(bytes32.from_hexstr(review['mintAuthority']['componentId']))
    if (history is None or not isinstance(history.state, GenerationMint)
            or history.state.launcher_id != gov.mint_id or history.state.component() not in registry.components):
        raise ValueError('supported mint authority differs from the reviewed source')
    mint = history.state
    if review['mintAuthority'] != {'componentId':h(mint.component_id), 'launcherId':h(mint.launcher_id),
            'coinId':h(history.current.coin.name()), 'moduleHash':h(mint.logic_hash()), 'version':mint.version}:
        raise ValueError('reviewed mint authority changed')
    snapshot = collections.sealed_test_mint_snapshot(review['request']['collectionId'])
    if snapshot['canonicalMetadata'] != review['canonicalMetadata'] or snapshot['previewHash'] != review['request']['previewHash']:
        raise ValueError('sealed mint source changed')
    edition = build_sealed_test_mint(collections, settings, mint, review['request']['collectionId'],
        tuple(r.launcher_parent for r in original.rows))
    if edition != original: raise ValueError('native edition differs from current sealed source')
    records = []
    observed = await primary_mint_coin_records((row['coinId'] for row in review['funding']), provider=provider)
    for row, inventory, raw in zip(review['funding'], mint.inventories(edition), observed, strict=True):
        coin = Coin.from_json_dict(row['coin'])
        actual = read_confirmed_coin(raw, coin.name())
        if (actual.coin != coin or h(coin.name()) != row['coinId'] or actual.confirmed_height != row['confirmedHeight']
                or actual.spent_height or h(inventory.launcher_spend.coin.name()) != row['launcherId']
                or h(inventory.coin.name()) != row['inventoryCoinId']):
            raise ValueError('reviewed mint funding or predicted inventory changed')
        records.append(actual)
    # Detect concurrent source/hold changes after primary-node awaits.
    if store.status(identity) != review or collections.sealed_test_mint_snapshot(review['request']['collectionId']) != snapshot:
        raise ValueError('saved source changed during publication preparation')
    return review, edition, tuple(records)
