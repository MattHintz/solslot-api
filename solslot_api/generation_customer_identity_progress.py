"""Read-only display hints from already saved stamp submission journals.

These hints grant no authority and never establish confirmed identity. Only
the native vault/receipt check may return the confirmed enrollment status.
"""


def saved_stamp_progress(record, attempt, funded):
    if not record or record.get('status') != 'stamp_pending':
        return None
    result = {'state': 'RECONCILING', 'broadcastState': 'UNKNOWN', 'resumeAvailable': False}
    if not attempt or not attempt.get('bundle_hex'):
        return result
    if funded is not None:
        status = funded.get('status')
        if status in ('mempool', 'confirmed'):
            return {**result, 'state': 'NETWORK_CONFIRMATION', 'broadcastState': 'SENT'}
        # A funded candidate is committed before dispatch. A crash after that
        # commit but before the event must be reconciled by the existing POST
        # submit path before its exact bytes can be resent.
        if status == 'prepared':
            return {**result, 'state': 'READY_TO_RESUME', 'resumeAvailable': True}
        return result
    if attempt.get('dispatch_status') == 'not_submitted' and attempt.get('dispatch_count') == 0:
        return {**result, 'state': 'READY_TO_RESUME', 'broadcastState': 'NOT_SENT', 'resumeAvailable': True}
    if attempt.get('dispatch_status') == 'submitted' and attempt.get('dispatch_count', 0) > 0:
        return {**result, 'state': 'NETWORK_CONFIRMATION', 'broadcastState': 'SENT'}
    return result
