"""Reconstruct collection rows and accepted objects in private temporary storage.

No live database is opened and no arbitrary SQL from an archive is executed.
This verifies collection data recovery, not a full protocol service restart.
"""
import base64
import hashlib
import re
import sqlite3
import tempfile
from pathlib import Path
from collection_snapshot import TABLES,canonical

NAME=re.compile(r'[a-z][a-z0-9_]{0,79}\Z')
TEMP_ROOT=Path('/run/solslot-collection-recovery-ae181')

def verify_isolated_restore(manifest,payloads):
    schemas=manifest['tableSchemas']
    if set(schemas)!=set(TABLES):raise ValueError('Recovery table schema differs')
    with tempfile.TemporaryDirectory(prefix='solslot-restore-',dir=TEMP_ROOT) as folder:
        root=Path(folder)
        con=sqlite3.connect(root/'collections.db')
        try:
            for table in TABLES:
                columns=schemas[table]
                if not 0<len(columns)<=100:raise ValueError('Recovery column cap differs')
                definitions=[];keys=[]
                for column in columns:
                    name=column['name'];kind=column['type'].upper()
                    if not NAME.fullmatch(name) or kind not in ('TEXT','INTEGER','REAL','BLOB','NUMERIC',''):
                        raise ValueError('Recovery column contract differs')
                    definitions.append('"'+name+'" '+kind+(' NOT NULL' if column['notNull'] else ''))
                    if column['primaryKey']:keys.append((column['primaryKey'],name))
                if keys:definitions.append('PRIMARY KEY ('+','.join('"'+name+'"' for _,name in sorted(keys))+')')
                con.execute('CREATE TABLE '+table+' ('+','.join(definitions)+')')
                names=[column['name'] for column in columns]
                for row in manifest['tables'][table]:
                    if set(row)!=set(names):raise ValueError('Recovery row shape differs')
                    values=[]
                    for name in names:
                        value=row[name]
                        if isinstance(value,dict):
                            if set(value)!= {'binaryB64'}:raise ValueError('Recovery binary value differs')
                            value=base64.b64decode(value['binaryB64'],validate=True)
                        values.append(value)
                    con.execute('INSERT INTO '+table+' VALUES ('+','.join('?' for _ in names)+')',values)
                con.row_factory=sqlite3.Row
                restored=[]
                for row in con.execute('SELECT * FROM '+table+' ORDER BY rowid'):
                    restored.append({k:({'binaryB64':base64.b64encode(v).decode()} if isinstance(v,bytes) else v)
                                     for k,v in dict(row).items()})
                if canonical(restored)!=canonical(manifest['tables'][table]):raise ValueError('Recovered collection rows differ')
            con.commit()
            if con.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise ValueError('Recovered database integrity differs')
            for item in manifest['files']:
                payload=payloads[item['sha256']]
                path=root/item['objectId']
                if not re.fullmatch('[0-9a-f]{64}',item['objectId']):raise ValueError('Recovery object identifier differs')
                path.write_bytes(payload)
                value=path.read_bytes()
                if len(value)!=item['bytes'] or hashlib.sha256(value).hexdigest()!=item['sha256']:
                    raise ValueError('Recovered file differs')
        finally:con.close()
    return True
