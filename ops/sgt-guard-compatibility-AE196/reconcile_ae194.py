"""Approved, exact AE194 expiry reconciliation. No signing, push or renewal."""
import argparse,asyncio,json,os,sqlite3,ssl,subprocess,sys,time
from pathlib import Path
from types import SimpleNamespace
import httpx

AE='AE-SOLSLOT-SGT-GUARD-COMPATIBILITY-20261007-196'
OP=Path('/opt/solslot/genesis-rc28/operations/AE196')
ORIGINAL='0xe2dd220b921d0946f7d77c763589601a0a8269a4d1f124ffdeb7ff75f891c369'
FUNDED='0x24c510bb3088824cfdf65bdb70ba5496efee246275aa71a3fbdc0fc67778c39a'
PROPOSAL='GOV-76725DF152C71D7A'
HASH='0x92e8088fd76e2dd0a041e635f54c11ec43c8f9c46eed98da9680c80840b988be'
DEADLINE=1791349008
QUEUE='/opt/solslot/genesis-rc28/state/admin_desk_v2.db'
JOURNAL='/opt/solslot/genesis-rc28/state/zkpassport_v2.db.protocol-funding.sqlite3'
sys.dont_write_bytecode=True

class ReadOnlyPrimary:
    """Only expose the full-node reads needed for expiry verification."""
    def __init__(self,client): self.client=client
    async def read(self,path,body):
        if path not in ('/get_network_info','/get_blockchain_state','/get_fee_estimate',
                        '/get_coin_record_by_name','/get_mempool_items_by_coin_name'):
            raise ValueError('Unapproved native operation')
        result=await self.client.post(path,json=body)
        result.raise_for_status()
        data=result.json()
        if data.get('success') is not True: raise ValueError('Primary read did not succeed')
        return data
    async def get_fee_estimate(self,*,target_times,spend_bundle=None,cost=None,require_primary=False):
        from chia_rs import SpendBundle
        from solslot_api.protocol_admission import admission_conditions
        assert require_primary is True
        network=await self.read('/get_network_info',{})
        if network.get('network_name')!='testnet11': raise ValueError('Primary network differs')
        state=(await self.read('/get_blockchain_state',{}))['blockchain_state']
        if state['sync'].get('synced') is not True: raise ValueError('Primary is not synced')
        if cost is None:
            conditions=admission_conditions(SpendBundle.from_json_dict(spend_bundle),state['peak']['height'],'testnet11')
            if conditions.before_seconds_absolute!=DEADLINE: raise ValueError('Native expiry differs from the exact failed attempt')
            cost=int(conditions.cost)
        return await self.read('/get_fee_estimate',{'cost':cost,'target_times':target_times})
    async def _primary_inputs_clear(self,bundle):
        from chia_rs import Coin,SpendBundle
        parsed=SpendBundle.from_json_dict(bundle)
        ephemeral={coin.name() for coin in parsed.additions()}
        for coin in parsed.removals():
            if coin.name() in ephemeral: continue
            name='0x'+coin.name().hex()
            record=(await self.read('/get_coin_record_by_name',{'name':name})).get('coin_record')
            if (not record or Coin.from_json_dict(record['coin'])!=coin
                    or not record.get('confirmed_block_index') or record.get('spent_block_index')): return False
            if (await self.read('/get_mempool_items_by_coin_name',{'coin_name':name})).get('mempool_items'): return False
        return True

async def apply():
    import hashlib
    pid=subprocess.check_output(['systemctl','show','solslot-genesis-rc28.service','-p','MainPID','--value'],text=True).strip()
    env=dict(item.split('=',1) for item in Path('/proc',pid,'environ').read_bytes().decode().split('\0') if '=' in item)
    if (env.get('SOLSLOT_NETWORK')!='testnet11' or env.get('SOLSLOT_CHIA_PRIMARY_URL','').rstrip('/')!='https://127.0.0.1:18555'
            or str(OP/'release/api') not in env.get('PYTHONPATH','')): raise ValueError('Active approved runtime differs')
    if Path(__file__).resolve()!=OP/'recovery/reconcile_ae194.py': raise ValueError('Approved operation location required')
    pins=json.loads((OP/'runtime-source-pins.json').read_text())
    if pins.get('actionEnvelopeId')!=AE: raise ValueError('Approved runtime commitment differs')
    for name,digest in pins['releaseFiles'].items():
        path=OP/'release'/name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest: raise ValueError('Pinned runtime differs')
    sys.path[:0]=[str(OP/'recovery'),str(OP/'release/api'),'/opt/solslot/genesis-rc28/operations/AE161/release/protocol']
    from recovery_health import read_receipt
    from solslot_api.protocol_funding_store import ProtocolFundingStore
    from solslot_api.protocol_submission import ProtocolBundleSubmitter,ProtocolFeePolicy
    from solslot_api.governance_queue import GovernanceQueueStore
    read_receipt()
    with sqlite3.connect('file:'+JOURNAL+'?mode=ro',uri=True) as db:
        row=db.execute('SELECT context,document FROM funded_protocol_bundles WHERE network=? AND original_id=?',('testnet11',ORIGINAL)).fetchone()
    if not row: raise ValueError('Exact saved transaction unavailable')
    context,document=map(json.loads,row)
    from chia_rs import SpendBundle
    if (document['spendBundleId']!=FUNDED or context['purpose'] is not None or context['backingMojos']!=0
            or int(document['feeMojos'])!=140865968
            or '0x'+SpendBundle.from_json_dict(document['protocolSpendBundle']).name().hex()!=ORIGINAL): raise ValueError('Exact saved funding differs')
    tls=ssl.create_default_context(cafile=env['SOLSLOT_CHIA_PRIMARY_CA_CERT_PATH'])
    tls.load_cert_chain(env['SOLSLOT_CHIA_PRIMARY_CLIENT_CERT_PATH'],env['SOLSLOT_CHIA_PRIMARY_CLIENT_KEY_PATH'])
    tls.check_hostname=False  # Existing CA-authenticated, mTLS loopback policy.
    queue=GovernanceQueueStore(QUEUE)
    store=ProtocolFundingStore(JOURNAL)
    async with httpx.AsyncClient(base_url=env['SOLSLOT_CHIA_PRIMARY_URL'],verify=tls,timeout=12) as client:
        faucet=SimpleNamespace(network='testnet11',address_hex=context['feeTill'],add_coin_reservation_source=lambda _:None)
        service=ProtocolBundleSubmitter(provider=ReadOnlyPrimary(client),faucet=faucet,policy=ProtocolFeePolicy(),funding_store=store)
        with queue._txn() as cursor:
            record=queue.get(PROPOSAL)
            if (record.state!='READY' or record.revision!=4 or record.proposal_hash!=HASH
                    or record.publication_voting_deadline!=DEADLINE or record.publication_approval_expires_at is not None
                    or record.activation_bundle_id or record.proposal_coin_id): raise ValueError('Failed proposal lineage changed; reconcile explicitly')
            if store.is_released('testnet11',ORIGINAL):
                print(json.dumps({'actionEnvelopeId':AE,'status':'already_reconciled','transactions':0})); return
            proof=await service.release_expired_saved(ORIGINAL)
            if proof['absoluteExpiry']!=DEADLINE: raise ValueError('Native expiry differs from the reviewed failed attempt')
            queue._audit(cursor,PROPOSAL,'approved-operations:'+AE,'LEGACY_PUBLICATION_EXPIRED_INPUTS_RELEASED',record.revision,
                {'originalBundleId':ORIGINAL,'bundleId':FUNDED,'absoluteExpiry':DEADLINE,'peakHeight':proof['peakHeight'],
                 'originalEvidenceRetained':True,'approvalsRenewed':False},int(time.time()))
    queue.close();store.db.close()
    print(json.dumps({'actionEnvelopeId':AE,'status':'expired_inputs_reconciled','originalEvidenceRetained':True,'transactions':0,'approvalsRenewed':False}))

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--approval',required=True)
    parser.add_argument('--apply',action='store_true',required=True)
    args=parser.parse_args()
    if os.geteuid()!=0 or args.approval!=AE: raise ValueError('Exact approved root operation required')
    asyncio.run(apply())

if __name__=='__main__':
    try: main()
    except Exception:
        print('AE196 reconciliation stopped; saved transaction and approvals retained. Inspect metadata without secret values.',file=sys.stderr)
        raise SystemExit(1)
