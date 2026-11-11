"""Cold API reopen of actually retained offer/operation/funding records."""
from copy import deepcopy
from contextlib import closing
import base64
from pathlib import Path
import sqlite3

from generation_snapshot import snapshot, verify_isolated_restore
from solslot_api.generation_operations import GenerationOperationJournal, bundle_id
from solslot_api.generation_sols_batches import GenerationSolsOrderBook
from solslot_api.generation_storage import generation_path
from solslot_api.protocol_funding_store import ProtocolFundingStore
from tests.test_generation_batch_recovery import saved_batch
from tests.test_generation_sols_orders import GEN, SOLS


def test_restored_offer_fee_holds_exact_bundle_and_recovery_link_remain_idempotent(tmp_path):
    source=tmp_path/'source';source.mkdir(mode=0o700)
    book,journal,identity,node,sender,receipt_key=saved_batch(source,funded=True)
    before=journal.status(identity);original=journal.protocol_bundle(identity)
    order=before['review']['orderIds'][0];original_offer=bytes(book.original(order))
    old_order=book.status(order)
    sender.funding_store.close()
    root=Path(journal.path).parent
    # Only synthetic fixture names change; production uses these frozen names.
    aliases={Path(journal.path).name:'generation-operations.sqlite3',Path(book.path).name:'generation-sols-orders.sqlite3',
        'funding.db':'zkpassport_v2.db.protocol-funding.sqlite3'}
    for old,new in aliases.items():
        (root/old).rename(root/new)
        for suffix in ('-wal','-shm'):
            p=root/(old+suffix)
            if p.exists():p.rename(root/(new+suffix))
    package=snapshot(root,GEN)
    assert verify_isolated_restore(package,GEN,parent=tmp_path)['databaseCount']==3
    # Reconstruct from the exported bytes into another deployment-local root;
    # source stores are unavailable to every cold-open API below.
    restore=tmp_path/'isolated'/'generations'/GEN[2:];restore.mkdir(parents=True,mode=0o700)
    for name,record in package['manifest']['files'].items():
        (restore/name).write_bytes(base64.b64decode(package['payloads'][record['sha256']]))
    reopened=GenerationOperationJournal(str(restore/'generation-operations.sqlite3'),GEN)
    orders=GenerationSolsOrderBook(str(restore/'generation-sols-orders.sqlite3'),GEN,SOLS)
    funding=ProtocolFundingStore(str(restore/'zkpassport_v2.db.protocol-funding.sqlite3'))
    try:
        assert reopened.status(identity)==before
        assert bytes(reopened.protocol_bundle(identity))==bytes(original)
        assert bytes(orders.original(order))==original_offer
        assert orders.status(order)==old_order
        assert funding.reserved_coin_ids()
        retained=reopened.reserved_input_coin_ids()
        assert retained
        # Lost funding callback and duplicated UI recovery never rebuild offers
        # or release held inputs; both exact journals survive independently.
        for _ in range(3):orders.repair_saved_links(reopened)
        assert orders.status(order)==old_order
        assert reopened.reserved_input_coin_ids()==retained
        record=funding.lookup('testnet11',bundle_id(original),{'feeTill':sender.faucet.address_hex,'purpose':None,'backingMojos':123})
        assert record['spendBundleId']==bundle_id(original)
        assert before['transactionId'] is None  # Never fabricate chain confirmation.
    finally:funding.close()
