"""Log node error categories without transaction payloads or credentials."""
def error_code(error):
    text = str(error)
    known = ('INVALID_FEE_TOO_CLOSE_TO_ZERO','ASSERT_BEFORE_SECONDS_ABSOLUTE_FAILED',
        'ASSERT_SECONDS_ABSOLUTE_FAILED','MEMPOOL_CONFLICT','DOUBLE_SPEND','BAD_AGGREGATE_SIGNATURE',
        'UNKNOWN_UNSPENT','INVALID_SPEND_BUNDLE','COST_EXCEEDS_MAX','ASSERT_ANNOUNCE_CONSUMED_FAILED')
    for code in known:
        if code in text:return code
    if 'rejected protocol bundle' in text:return 'NODE_REJECTED'
    return 'TRANSPORT_OR_TIMEOUT'


def record_submission(path, *, network, bundle_id, provider, event, code=None, bundle=None):
    import logging, sqlite3, time, os
    logging.getLogger(__name__).info('protocol_submission network=%s bundle_id=%s provider=%s event=%s error_code=%s',
        network,bundle_id,provider,event,code)
    if not path:return
    db=sqlite3.connect(path,timeout=10)
    try:
        os.chmod(path,0o600)
        db.execute('PRAGMA synchronous=FULL')
        db.execute('''CREATE TABLE IF NOT EXISTS protocol_submission_events(
            id INTEGER PRIMARY KEY, network TEXT NOT NULL, bundle_id TEXT NOT NULL,
            provider TEXT NOT NULL, event TEXT NOT NULL, error_code TEXT, recorded_at INTEGER NOT NULL)''')
        db.execute('CREATE TABLE IF NOT EXISTS protocol_submission_bundles(bundle_id TEXT PRIMARY KEY, network TEXT NOT NULL, bundle_json TEXT NOT NULL, created_at INTEGER NOT NULL)')
        if bundle is not None:
            import json
            encoded=json.dumps(bundle,sort_keys=True,separators=(',',':'))
            existing=db.execute('SELECT bundle_json FROM protocol_submission_bundles WHERE bundle_id=?',(bundle_id,)).fetchone()
            if existing and existing[0]!=encoded:raise ValueError('Retained transaction bytes do not match their ID')
            db.execute('INSERT OR IGNORE INTO protocol_submission_bundles VALUES(?,?,?,?)',(bundle_id,network,encoded,int(time.time())))
        db.execute('INSERT INTO protocol_submission_events(network,bundle_id,provider,event,error_code,recorded_at) VALUES(?,?,?,?,?,?)',
            (network,bundle_id,provider,event,code,int(time.time())))
        db.commit()
    finally:db.close()
