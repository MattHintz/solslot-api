"""Read-only UX aggregates. Never outputs cookies, form contents or actor identifiers."""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import sqlite3
import time


def summarize(connection, since, now):
    groups, flows, unfinished = defaultdict(list), set(), {}
    accepted = connection.execute('SELECT COUNT(*) FROM alpha_telemetry_events').fetchone()[0]
    rows = connection.execute("SELECT occurred_at,event,correlation_id,latency_ms,details_json FROM alpha_telemetry_events WHERE id LIKE 'ux_%' AND event LIKE 'JOURNEY_%' AND occurred_at>=? AND occurred_at<=? ORDER BY occurred_at", (since,now))
    count = 0
    for created, event, flow, latency, details in rows:
        try: d = json.loads(details)
        except (ValueError, TypeError): continue
        if d.get('actor') == 'synthetic' or d.get('diagnostics_revision') != 'AE197': continue
        key = tuple(d.get(k,'unknown') for k in ('source','screen','action','stage','phase','wallet','error_code'))
        # The existing legacy intake cannot promote arbitrary free text into this report.
        if not all(isinstance(v,str) and v.replace('_','').isalnum() and len(v)<=30 for v in key): continue
        groups[key].append(latency)
        flows.add(flow); count+=1
        progress = (flow, 'verify_id' if d.get('action') == 'wallet_prompt' else d.get('action'))
        if d.get('phase') == 'waiting': unfinished[progress] = (created,d.get('screen'),d.get('stage'),d.get('wallet'))
        if d.get('phase') in ('completed','failed','cancelled') or d.get('phase') == 'started' and d.get('stage') != 'ui': unfinished.pop(progress,None)
    result=[]
    for key, values in sorted(groups.items()):
        durations=sorted(v for v in values if isinstance(v,int))
        result.append(dict(zip(('source','screen','action','stage','phase','wallet','error_code'),key),events=len(values),p95_latency_ms=durations[max(0,(len(durations)*95+99)//100-1)] if durations else None))
    waits=Counter((screen,stage,wallet) for created,screen,stage,wallet in unfinished.values() if now-created>=60)
    return {'window_seconds':now-since,'received_events':count,'temporary_page_flows':len(flows),'people_count':None,
        'coverage':'Consenting customer pages and operator pages only. Flows are not people; unmatched waits may mean a closed tab.',
        'storage':{'retained_rows':accepted,'row_cap':10000,'at_capacity':accepted>=10000},'groups':result,
        'waits_without_terminal_event_over_60s':[dict(screen=k[0],stage=k[1],wallet=k[2],flows=v) for k,v in sorted(waits.items())]}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--database',required=True);parser.add_argument('--hours',type=int,default=24)
    args=parser.parse_args()
    if not 1<=args.hours<=720: parser.error('hours must be between 1 and 720')
    path=Path(args.database)
    if not path.is_file() or path.is_symlink(): parser.error('existing regular database required')
    db=sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True)
    try:
        now=int(time.time());print(json.dumps(summarize(db,now-args.hours*3600,now),sort_keys=True,indent=2))
    finally:db.close()

if __name__=='__main__':main()
