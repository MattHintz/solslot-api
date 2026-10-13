"""Private, generation-bound custody confirmations and destination consent.

Stores evidence, never a substitute for fresh final genesis admission. GET
status uses only these cached records. It cannot reserve inputs or sign.
"""
from __future__ import annotations

from .generation_storage import connect_generation_sqlite

import sqlite3
from contextlib import closing
from pathlib import Path
from chia.types.blockchain_format.coin import Coin
from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from .generation_preparation import GenerationPreparation
from .generation_recipient_evidence import ConfirmedRecipient
from .generation_storage import bind_generation, generation_path

CONFIRMATION_FRESH_SECONDS = 60


class GenerationPreparationStore:
    def __init__(self, path: str, preparation: GenerationPreparation):
        # Detach maps from callers. Persisted consent belongs to exactly this
        # manifest; source/roster/coordinate changes have separate records.
        self.preparation=GenerationPreparation.model_validate_json(preparation.model_dump_json(by_alias=True))
        self.path=generation_path(path,self.preparation.generation_id)
        Path(self.path).parent.mkdir(parents=True,exist_ok=True)
        with closing(self._connect()) as con,con:
            bind_generation(con,self.preparation.generation_id)
            con.execute('CREATE TABLE IF NOT EXISTS generation_recipient_evidence ('
                'manifest TEXT NOT NULL, slot INTEGER NOT NULL CHECK(slot BETWEEN 1 AND 3), '
                'coin_id TEXT, confirmed_height INTEGER, checked_at INTEGER NOT NULL, '
                'error_code TEXT, acknowledgement TEXT, acknowledged_at INTEGER, '
                'PRIMARY KEY(manifest,slot))')

    def _connect(self):
        con=connect_generation_sqlite(self.path,timeout=5)
        con.row_factory=sqlite3.Row
        return con

    def _row(self, con, slot):
        return con.execute('SELECT * FROM generation_recipient_evidence WHERE manifest=? AND slot=?',
            (self.preparation.manifest_hash,slot)).fetchone()

    def record_confirmation(self, receipt: ConfirmedRecipient, now: int):
        if type(receipt.slot) is not int or receipt.slot not in (1,2,3):
            raise ValueError('invalid confirmed recipient slot')
        admin=self.preparation.administrators[receipt.slot-1]
        expected=Coin(bytes32.from_hexstr(admin.custody.launcher_id),
            puzzle_for_singleton(bytes32.from_hexstr(admin.custody.launcher_id),
                self.preparation.custody_inner(admin)).get_tree_hash(),uint64(1))
        if ('0x'+receipt.launcher_id.hex()!=admin.custody.launcher_id
                or '0x'+receipt.owner_puzzle_hash.hex()!=admin.sgt_owner_puzzle_hash
                or receipt.coin_id!=expected.name()
                or receipt.confirmed_height<=0):
            raise ValueError('confirmation does not match frozen recipient')
        with closing(self._connect()) as con,con:
            con.execute('INSERT INTO generation_recipient_evidence '
                '(manifest,slot,coin_id,confirmed_height,checked_at) VALUES (?,?,?,?,?) '
                'ON CONFLICT(manifest,slot) DO UPDATE SET coin_id=excluded.coin_id, '
                'confirmed_height=excluded.confirmed_height,checked_at=excluded.checked_at,error_code=NULL '
                'WHERE excluded.checked_at>=generation_recipient_evidence.checked_at',
                (self.preparation.manifest_hash,receipt.slot,'0x'+receipt.coin_id.hex(),receipt.confirmed_height,now))

    def record_error(self, slot: int, code: str, now: int):
        if slot not in (1,2,3) or code not in ('RECIPIENT_NOT_CONFIRMED','NODE_UNAVAILABLE'):
            raise ValueError('invalid recipient status error')
        with closing(self._connect()) as con,con:
            con.execute('INSERT INTO generation_recipient_evidence (manifest,slot,checked_at,error_code) '
                'VALUES (?,?,?,?) ON CONFLICT(manifest,slot) DO UPDATE SET '
                'checked_at=excluded.checked_at,error_code=excluded.error_code '
                'WHERE excluded.checked_at>=generation_recipient_evidence.checked_at',
                (self.preparation.manifest_hash,slot,now,code))

    def acknowledge(self, slot: int, signature: str, now: int):
        self.preparation.verify_acknowledgement(slot,signature)
        with closing(self._connect()) as con,con:
            con.execute('BEGIN IMMEDIATE')
            row=self._row(con,slot)
            # Do not turn a normal wallet review into a sixty-second race.
            # Preparation checks freshness before opening the wallet; final
            # genesis admission rechecks the actual coin before issuance.
            if not row or row['error_code'] or not row['coin_id']:
                raise ValueError('recipient confirmation is required before acknowledgement')
            if row['acknowledgement']:
                # Different valid ECDSA encodings may express the same consent.
                # A retry never changes its original receipt/time.
                return
            con.execute('UPDATE generation_recipient_evidence SET acknowledgement=?,acknowledged_at=? '
                'WHERE manifest=? AND slot=?',(signature,now,self.preparation.manifest_hash,slot))

    def signatures(self) -> dict[int,str]:
        with closing(self._connect()) as con:
            return {r['slot']:r['acknowledgement'] for r in con.execute(
                'SELECT slot,acknowledgement FROM generation_recipient_evidence WHERE manifest=? AND acknowledgement IS NOT NULL',
                (self.preparation.manifest_hash,))}

    def review(self, now: int) -> dict:
        result=self.preparation.review()
        with closing(self._connect()) as con:
            for recipient in result['recipients']:
                row=self._row(con,recipient['administratorSlot'])
                confirmed=bool(row and row['coin_id'] and not row['error_code'])
                recipient.update(confirmedCoinId=row['coin_id'] if row else None,
                    confirmedHeight=row['confirmed_height'] if row else None,
                    lastCheckedAt=row['checked_at'] if row else None,
                    errorCode=row['error_code'] if row else None,
                    confirmed=confirmed,
                    confirmationFresh=bool(confirmed and 0<=now-row['checked_at']<=CONFIRMATION_FRESH_SECONDS),
                    acknowledgedAt=row['acknowledged_at'] if row else None,
                    stage='CHECK_REQUIRED' if not confirmed else ('ACKNOWLEDGED' if row['acknowledgement'] else 'AWAITING_ACKNOWLEDGEMENT'))
        result['recipientPreparationComplete']=all(r['confirmed'] and r['acknowledgedAt'] for r in result['recipients'])
        # This status can NEVER open genesis. Final source/recovery and chain
        # admission must recheck every recipient and all acknowledgements.
        result['genesisAuthorized']=False
        result['nextAction']='FINAL_GENESIS_REVIEW' if result['recipientPreparationComplete'] else 'COMPLETE_RECIPIENT_VAULTS'
        return result
