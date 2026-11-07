"""Read sealing outcomes without resolving native authority or changing state.

The approval journal's consumed flag is not evidence of a committed seal.
Only the collection transaction and its audit receipt establish completion.
"""
import json
from pathlib import Path
import re
import sqlite3
from contextlib import closing

from .generation_storage import generation_path


def seal_execution(value, settings):
    if value['operation'] != 'collection.seal':
        return None
    binding = value['request_binding']
    match = re.fullmatch(r'(?:/protocol-api/next)?/admin/collections/([^/]+)/seal', binding['path'])
    if not match or binding['method'] != 'POST' or binding.get('ifMatch') != '"%s"' % value['revision']:
        return {'state': 'unavailable'}
    path = settings.admin_db_path
    if path == ':memory:':
        return {'state': 'unavailable'}
    if settings.deployment_generation_id:
        path = generation_path(str(Path(path).parent / 'collections.sqlite'), settings.deployment_generation_id)
    try:
        # No writable store constructor, schema migration, or native Chia object.
        with closing(sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)) as con:
            con.row_factory = sqlite3.Row
            con.execute('PRAGMA query_only=ON')
            if settings.deployment_generation_id:
                rows = con.execute('SELECT generation_id,network FROM deployment_generation_binding').fetchall()
                if [tuple(row) for row in rows] != [(settings.deployment_generation_id, settings.network)]:
                    return {'state': 'unavailable'}
            row = con.execute('SELECT revision,state,metadata_root,sealed_at FROM property_collections WHERE id=?', (match[1],)).fetchone()
            if row is None or row['revision'] != value['revision']:
                return {'state': 'revision_changed'}
            events = con.execute("SELECT details_json,occurred_at FROM property_collection_audit_events WHERE collection_id=? AND action='COLLECTION_SEALED' ORDER BY occurred_at DESC LIMIT 200", (match[1],)).fetchall()
            for event in events:
                details = json.loads(event['details_json'])
                if (row['state'] in ('SEALED', 'PUBLISHED') and row['metadata_root'] is not None
                        and details.get('metadataRoot') == '0x' + bytes(row['metadata_root']).hex()
                        and event['occurred_at'] == row['sealed_at']):
                    # Older successful seals lack operation IDs; match their
                    # actual immutable postcondition, never consumed_at alone.
                    if (details.get('operationId') is None and value['consumed_at'] is not None) or (
                            details.get('operationId') is not None and
                            details['operationId'] == value['operation_id']
                            and details.get('payloadHash') == value['payload_hash']):
                        return {'state': 'confirmed', 'metadataRoot': details['metadataRoot']}
            if row['state'] in ('DRAFT', 'REVIEW'):
                return {'state': 'retry_required' if value['consumed_at'] is not None else 'not_started'}
            return {'state': 'unavailable'}
    except (OSError, ValueError, TypeError, KeyError, sqlite3.Error):
        return {'state': 'unavailable'}
