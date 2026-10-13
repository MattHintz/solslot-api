"""Provision real empty journal schemas before release/recovery certification.

No launch certificate, chain anchor, approval, order, key or transaction is
created here. Later constructors retain their complete authority validation.
"""
from contextlib import closing
import os
import json
from hashlib import sha256
from pathlib import Path

from .generation_context import generation_bytes
from .generation_storage import connect_generation_sqlite


FIELDS={
    'genesis_db_path':'genesis_ceremony_v2.db',
    'zkpassport_ledger_db_path':'zkpassport_v2.db',
    'payment_purchase_db_path':'payment_purchases_v2.db',
    'stripe_delivery_db_path':'stripe_deliveries_v1.db',
    'admin_db_path':'admin_desk_v2.db',
    'vault_registry_path':'vault_registry_v2.db',
    'sols_capability_operations_path':'sols_capability_operations.db',
    'challenge_store_path':'challenges_v2.db',
    'generation_preparation_db_path':'generation-preparation.sqlite3',
    'generation_launch_db_path':'generation-launch.sqlite3',
    'generation_index_db_path':'generation-index.sqlite3',
    'generation_operations_db_path':'generation-operations.sqlite3',
    'generation_consents_db_path':'generation-consents.sqlite3',
    'generation_ballots_db_path':'generation-ballots.sqlite3',
    'generation_mint_reviews_db_path':'generation-mint-reviews.sqlite3',
    'generation_sols_orders_db_path':'generation-sols-orders.sqlite3',
}
DERIVED={'zkpassport_v2.db.protocol-funding.sqlite3',
    'zkpassport_v2.db.stamp-funding.sqlite3','protocol-submissions.sqlite3',
    'admin_desk_v2.db.alpha-observability.db','collections.sqlite'}
DATABASES=frozenset(FIELDS.values())|DERIVED
INVENTORY_HASH=sha256(json.dumps(sorted(DATABASES),separators=(',',':')).encode()).hexdigest()


def _marker(db):
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='generation_recovery_inventory'").fetchone():
        return None
    rows=db.execute('SELECT singleton,inventory_hash,stage FROM generation_recovery_inventory').fetchall()
    if len(rows)!=1 or rows[0][0]!=1 or rows[0][1]!=INVENTORY_HASH or rows[0][2] not in ('INITIALIZING','READY'):
        raise ValueError('recovery initialization marker differs')
    return rows[0][2]


def _mark(path,generation,stage):
    with closing(connect_generation_sqlite(path,generation_id=generation)) as db,db:
        db.execute('CREATE TABLE IF NOT EXISTS generation_recovery_inventory('
            'singleton INTEGER PRIMARY KEY CHECK(singleton=1),inventory_hash TEXT NOT NULL,stage TEXT NOT NULL)')
        db.execute('INSERT OR IGNORE INTO generation_recovery_inventory VALUES(1,?,?)',(INVENTORY_HASH,stage))
        current=_marker(db)
        if stage=='READY' and current!='READY':
            db.execute("UPDATE generation_recovery_inventory SET stage='READY' WHERE singleton=1")


def _guard(root,generation):
    # Separate from the journals so losing all21 files still fails closed.
    # Isolated restore can reconstruct this metadata from all21 READY markers.
    path=root.parent.parent/'generation-recovery-initialization'/(generation_bytes(generation).hex()+'.json')
    expected={'schema':'solslot.generation-recovery-initialization.v1','generationId':generation,
        'inventoryHash':INVENTORY_HASH}
    for parent in (path,*path.parents):
        if parent.is_symlink():raise ValueError('recovery initialization guard symlink')
    if path.parent.exists() and path.parent.stat().st_mode&0o022:
        raise ValueError('recovery initialization guard directory is not protected')
    exists=path.exists()
    if exists:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            import stat
            info=os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_mode&0o022 or info.st_size>4096:
                raise ValueError('recovery initialization guard is not protected')
            if json.loads(stream.read(4097))!=expected:raise ValueError('recovery initialization guard differs')
    return path,expected,exists


def prepare_recovery_journals(settings,preparation_store):
    """Explicit startup-only opt-in for the separately installed AE222 lane."""
    generation=settings.deployment_generation_id
    if (not generation or settings.network!='testnet11' or preparation_store is None
            or preparation_store.preparation.generation_id!=generation
            or preparation_store.preparation.manifest_hash!=settings.generation_preparation_hash):
        raise ValueError('recovery storage requires the exact installed Testnet preparation')
    root=Path(settings.generation_preparation_db_path).parent
    if (not root.is_absolute() or root.name!=generation_bytes(generation).hex()
            or root.parent.name!='generations'):
        raise ValueError('recovery storage requires one canonical absolute namespace')
    for parent in (root,*root.parents):
        if parent.is_symlink():raise ValueError('recovery storage rejects symlink namespaces')
    for field,name in FIELDS.items():
        if Path(getattr(settings,field))!=root/name:
            raise ValueError('recovery storage path differs: '+field)
    if root.exists():
        if root.stat().st_mode&0o022:raise ValueError('recovery namespace is writable by another identity')
        allowed=DATABASES|{name+suffix for name in DATABASES for suffix in ('-wal','-shm','-journal')}
        for entry in root.iterdir():
            if entry.name not in allowed:raise ValueError('unexpected recovery namespace entry')
            info=entry.lstat()
            if entry.is_symlink() or not entry.is_file() or info.st_nlink!=1 or info.st_mode&0o022:
                raise ValueError('recovery journal is not protected: '+entry.name)
    guard,guard_value,initialized=_guard(root,generation)
    # Preflight every existing binding and phase before creating any schema.
    phases={}
    for name in sorted(DATABASES):
        path=root/name
        if path.exists() or path.is_symlink():
            with closing(connect_generation_sqlite(path,generation_id=generation)) as db:
                phases[name]=_marker(db)
    if initialized or 'READY' in phases.values():
        if set(phases)!=DATABASES or any(stage is None for stage in phases.values()):
            raise ValueError('initialized recovery journal missing; restore retained state before startup')
    else:
        # A new schema inventory is admitted only before user/chain writes.
        # An interrupted first initialization may resume while these gates
        # remain closed; it cannot reset a previously completed inventory.
        if (settings.alpha_writes_enabled or settings.generation_execution_enabled or settings.generation_launch_enabled
                or settings.generation_sols_batch_enabled or settings.generation_launch_artifact_path
                or settings.generation_launch_certificate_path or settings.generation_chain_anchor_path):
            raise ValueError('initial recovery schema setup requires paused prelaunch write gates')
        if (phases.get('generation-preparation.sqlite3')!='INITIALIZING'
                and set(phases)-{'generation-preparation.sqlite3','genesis_ceremony_v2.db','challenges_v2.db'}):
            raise ValueError('existing generation journals require explicit recovery review')
        with closing(connect_generation_sqlite(root/'generation-preparation.sqlite3',generation_id=generation)) as db:
            if db.execute('SELECT COUNT(*) FROM generation_recipient_evidence').fetchone()[0]:
                raise ValueError('recipient activity requires recovery review before initialization')
        _mark(root/'generation-preparation.sqlite3',generation,'INITIALIZING')
    root.mkdir(parents=True,exist_ok=True,mode=0o700)
    if root.stat().st_mode&0o022:raise ValueError('recovery namespace is writable by another identity')
    for name in sorted(DATABASES):
        fd=os.open(root/name,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        os.close(fd)

    from .genesis_store import GenesisStore
    from .credential_ledger import CredentialLedger
    from .payment_purchase_store import PaymentPurchaseStore
    from .stripe_delivery_store import StripeDeliveryStore
    from .sols_swap_store import SolsSwapStore
    from .vault_db import VaultStore
    from .sols_capability_operations import CapabilityOperationStore
    from .challenges import ChallengeStore,RequestRateLimiter
    from .protocol_funding_store import ProtocolFundingStore
    from .stamp_funding import StampFundingStore
    from .submission_errors import open_submission_journal
    from .alpha_observability import AlphaObservabilityStore
    from .collection_store import CollectionStore
    from .generation_operations import GenerationOperationJournal
    from .generation_consents import GenerationConsentStore
    from .generation_holder_ballots import GenerationBallotStore
    from .generation_mint_reviews import GenerationMintReviewStore
    from .generation_launch import GenerationLaunchStore
    from .generation_index import GenerationIndexStore
    from .generation_sols_batches import GenerationSolsOrderBook

    GenesisStore(settings.genesis_db_path,generation_id=generation,network='testnet11')
    with closing(CredentialLedger(settings.zkpassport_ledger_db_path,generation_id=generation)):pass
    PaymentPurchaseStore(settings.payment_purchase_db_path)
    StripeDeliveryStore(settings.stripe_delivery_db_path)
    SolsSwapStore(settings.admin_db_path)
    with closing(VaultStore(settings.vault_registry_path)):pass
    with closing(CapabilityOperationStore(settings.sols_capability_operations_path)):pass
    ChallengeStore(settings.challenge_ttl_seconds,db_path=settings.challenge_store_path)
    RequestRateLimiter(settings.challenge_per_ip_per_minute,db_path=settings.challenge_store_path)
    with closing(ProtocolFundingStore(str(root/'zkpassport_v2.db.protocol-funding.sqlite3'))):pass
    StampFundingStore(str(root/'zkpassport_v2.db.stamp-funding.sqlite3')).db.close()
    with closing(open_submission_journal(str(root/'protocol-submissions.sqlite3'))):pass
    AlphaObservabilityStore(str(root/'admin_desk_v2.db.alpha-observability.db'))._conn.close()
    with closing(CollectionStore(str(root/'collections.sqlite'),generation_id=generation)):pass
    GenerationOperationJournal(settings.generation_operations_db_path,generation)
    GenerationConsentStore(settings.generation_consents_db_path,generation)
    GenerationBallotStore(settings.generation_ballots_db_path,generation)
    GenerationMintReviewStore(settings.generation_mint_reviews_db_path,generation)
    GenerationLaunchStore.initialize_storage(settings.generation_launch_db_path,generation)
    GenerationIndexStore.initialize_storage(settings.generation_index_db_path,generation)
    GenerationSolsOrderBook.initialize_storage(settings.generation_sols_orders_db_path,generation)
    # Publish a complete phase in every journal before setting any READY bit.
    # A crash during READY publication can resume only with all21 marked files.
    for name in sorted(DATABASES):_mark(root/name,generation,'INITIALIZING')
    for name in sorted(DATABASES):_mark(root/name,generation,'READY')
    if not initialized:
        guard.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        fd=os.open(guard,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(json.dumps(guard_value,sort_keys=True,separators=(',',':')).encode())
            stream.flush();os.fsync(stream.fileno())
        fd=os.open(guard.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    return root
