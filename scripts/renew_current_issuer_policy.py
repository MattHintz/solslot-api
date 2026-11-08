#!/usr/bin/env python3
"""Explicit stopped-journal, unused-policy renewal; never called by the app.

Observe first, review the fingerprint, then separately authorize renewal. The
receipt retains both pinned commitments. No forwarding row, signature, budget
slot or reservation history is removed or rewritten. _bind_policy stays strict.
"""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from solslot_api.generation_customer_purchase_policy import read_current_issuer_policy,validate_purchase_policy_renewal


def _connect(path,mode):
    path=Path(path).absolute();info=path.lstat()
    if path.is_symlink()or not stat.S_ISREG(info.st_mode):
        raise ValueError('CURRENT_ISSUER_RENEWAL_REGULAR_JOURNAL_REQUIRED')
    db=sqlite3.connect(path.as_uri()+'?mode='+mode,uri=True,isolation_level=None,timeout=5)
    fresh=path.lstat()
    if (fresh.st_dev,fresh.st_ino)!=(info.st_dev,info.st_ino):
        db.close();raise ValueError('CURRENT_ISSUER_RENEWAL_JOURNAL_CHANGED')
    return db


def fingerprint(db):
    """Hash all existing schema and rows except the single policy binding value."""
    schema=db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name").fetchall()
    tables=[]
    for kind,name,_,_ in schema:
        if kind!='table'or name=='issuer_policy':continue
        rows=db.execute('SELECT * FROM "'+name.replace('"','""')+'"').fetchall()
        encoded=[json.dumps([{'blobHex':v.hex()}if isinstance(v,bytes)else v for v in row],
            sort_keys=True,separators=(',',':'))for row in rows]
        tables.append([name,sorted(encoded)])
    return '0x'+sha256(json.dumps([schema,tables],sort_keys=True,separators=(',',':')).encode()).hexdigest()


def _binding(db):
    rows=db.execute('SELECT id,commitment FROM issuer_policy').fetchall()
    if len(rows)!=1 or rows[0][0]!=1:raise ValueError('CURRENT_ISSUER_RENEWAL_EXACT_BINDING_REQUIRED')
    return rows[0][1]


def observe(path):
    db=_connect(path,'ro')
    try:
        db.execute('BEGIN')
        return {'schema':'solslot.current-issuer-policy-renewal-observation.v1',
            'commitment':_binding(db),'forwardingRows':db.execute('SELECT count(*) FROM issuer_forwarding').fetchone()[0],
            'journalFingerprint':fingerprint(db)}
    finally:db.close()


def renew_unused_journal(path,prior,current,*,expected_fingerprint,action_envelope,stopped,now):
    validate_purchase_policy_renewal(prior,current,now=now)
    if (re.fullmatch(r'0x[0-9a-f]{64}',expected_fingerprint or '')is None
            or re.fullmatch(r'[A-Za-z0-9:._/-]{1,200}',action_envelope or '')is None
            or not callable(stopped)or stopped()is not True):
        raise ValueError('CURRENT_ISSUER_RENEWAL_STOPPED_REVIEW_REQUIRED')
    db=_connect(path,'rw')
    try:
        db.execute('BEGIN EXCLUSIVE')
        if _binding(db)!=prior.commitment:raise ValueError('CURRENT_ISSUER_RENEWAL_PRIOR_BINDING_CHANGED')
        if db.execute('SELECT count(*) FROM issuer_forwarding').fetchone()[0]!=0:
            raise ValueError('CURRENT_ISSUER_RENEWAL_UNUSED_JOURNAL_REQUIRED')
        before=fingerprint(db)
        if before!=expected_fingerprint:raise ValueError('CURRENT_ISSUER_RENEWAL_FINGERPRINT_CHANGED')
        changed=db.execute('UPDATE issuer_policy SET commitment=? WHERE id=1 AND commitment=?',
            (current.commitment,prior.commitment))
        if changed.rowcount!=1 or fingerprint(db)!=before:
            raise ValueError('CURRENT_ISSUER_RENEWAL_JOURNAL_CHANGED')
        if _binding(db)!=current.commitment or stopped()is not True:
            raise ValueError('CURRENT_ISSUER_RENEWAL_STOPPED_REVIEW_REQUIRED')
        db.execute('COMMIT')
        return {'schema':'solslot.current-issuer-policy-renewal.v1','actionEnvelopeId':action_envelope,
            'priorCommitment':prior.commitment,'renewedCommitment':current.commitment,
            'journalFingerprint':before,'forwardingRows':0,'renewedAt':now}
    except BaseException:
        if db.in_transaction:db.execute('ROLLBACK')
        raise
    finally:db.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=['observe','renew'])
    parser.add_argument('--journal',required=True)
    for name in ('prior-policy','prior-policy-hash','current-policy','current-policy-hash',
            'expected-fingerprint','action-envelope','service-unit'):
        parser.add_argument('--'+name)
    args=parser.parse_args()
    if args.mode=='observe':result=observe(args.journal)
    else:
        if not all(getattr(args,n)for n in ('prior_policy','prior_policy_hash','current_policy',
                'current_policy_hash','expected_fingerprint','action_envelope','service_unit')):
            parser.error('renew requires both pinned policies, reviewed fingerprint, ActionEnvelope and stopped service unit')
        if re.fullmatch(r'[A-Za-z0-9@_.-]+\.service',args.service_unit)is None:parser.error('exact service unit required')
        def stopped():
            result=subprocess.run(['systemctl','show','--property=ActiveState','--value',args.service_unit],
                check=True,capture_output=True,text=True,timeout=10)
            return result.stdout.strip()=='inactive'
        result=renew_unused_journal(args.journal,
            read_current_issuer_policy(args.prior_policy,args.prior_policy_hash),
            read_current_issuer_policy(args.current_policy,args.current_policy_hash),
            expected_fingerprint=args.expected_fingerprint,action_envelope=args.action_envelope,
            stopped=stopped,now=int(time.time()))
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':main()
