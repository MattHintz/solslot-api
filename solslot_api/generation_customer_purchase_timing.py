"""Bounded, process-local observations; never an authority for checkout work."""
from collections import OrderedDict
import asyncio
from contextvars import ContextVar
from threading import Lock
from time import monotonic_ns

STAGES = ('quote_verification', 'queue', 'reservation_verification', 'validator_quorum',
          'freshness_verification', 'funding_admission', 'confirmation_observation')
MAX_INTENTS = 128
MAX_COUNT = 65535
MAX_MILLISECONDS = 2**31 - 1
_attempt = ContextVar('checkout_timing_attempt', default=None)


def health_sample(attempt, sampled_at):
    """Build a fixed-shape, identifier-free sample for existing worker health."""
    try:
        if (not isinstance(attempt, dict) or attempt.get('scope') != 'worker_cycle'
                or attempt.get('outcome') not in ('success', 'error', 'cancelled')
                or type(sampled_at) is not int or not 0 <= sampled_at <= 2**53-1):
            return None
        total, remaining, stages = attempt['totalMs'], attempt['unattributedMs'], attempt['stagesMs']
        valid = lambda x: type(x) is int and 0 <= x <= MAX_MILLISECONDS
        if (not valid(total) or not valid(remaining) or remaining > total or not isinstance(stages, dict)
                or any(k not in STAGES or not valid(v) for k, v in stages.items())
                or sum(stages.values()) + remaining != total):
            return None
        return {'measurementScope':'originating_process_worker_cycle', 'sampledAt':sampled_at,
            'outcome':attempt['outcome'], 'totalMs':total, 'unattributedMs':remaining,
            'stagesMs':{stage:stages.get(stage) for stage in STAGES}}
    except Exception:
        return None


def retained_health_sample(value):
    """Revalidate an existing receipt before retaining it on an idle cycle."""
    try:
        if value.get('measurementScope') != 'originating_process_worker_cycle':
            return None
        stages=value['stagesMs']
        if not isinstance(stages,dict) or set(stages)!=set(STAGES):return None
        return health_sample({'scope':'worker_cycle','outcome':value['outcome'],
            'totalMs':value['totalMs'],'unattributedMs':value['unattributedMs'],
            'stagesMs':{k:v for k,v in stages.items() if v is not None}},value['sampledAt'])
    except Exception:
        return None


class CheckoutTimings:
    def __init__(self):
        self._rows = OrderedDict()
        self._lock = Lock()

    def record(self, identity, stage, started, ended=None):
        # All instrumentation is best effort, including clock/lock failures.
        try:
            if stage not in STAGES or not isinstance(identity, str):
                return
            elapsed = max(0, min(MAX_MILLISECONDS, ((monotonic_ns() if ended is None else ended) - started) // 1_000_000))
            with self._lock:
                row = self._rows.setdefault(identity, {})
                self._rows.move_to_end(identity)
                while len(self._rows) > MAX_INTENTS:
                    self._rows.popitem(last=False)
                old = row.get(stage, {'count': 0, 'totalMs': 0, 'lastMs': 0})
                row[stage] = {'count': min(MAX_COUNT, old['count'] + 1),
                    'totalMs': min(MAX_MILLISECONDS, old['totalMs'] + elapsed), 'lastMs': elapsed}
                row['_lastCompleted'] = stage
        except Exception:
            pass

    def snapshot(self, identity):
        try:
            with self._lock:
                row = self._rows.get(identity, {})
                attempt = row.get('_latestAttempt')
                return {'scope': 'process_lifetime', 'lastCompleted': row.get('_lastCompleted'),
                    'latestAttempt': ({**attempt, 'stagesMs': dict(attempt['stagesMs'])} if attempt else None), 'stages': {
                    stage: dict(row[stage]) if stage in row else None for stage in STAGES}}
        except Exception:
            return {'scope': 'unavailable', 'lastCompleted': None, 'latestAttempt': None, 'stages': {stage: None for stage in STAGES}}

    def attempt(self, identity, value):
        try:
            with self._lock:
                row = self._rows.setdefault(identity, {})
                row['_latestAttempt'] = value
                self._rows.move_to_end(identity)
                while len(self._rows) > MAX_INTENTS:
                    self._rows.popitem(last=False)
        except Exception:
            pass

    def attempt_marker(self, identity):
        with self._lock:
            return self._rows.get(identity, {}).get('_latestAttempt')


def start():
    try:
        return monotonic_ns()
    except Exception:
        return None


def record(service, identity, stage, started, ended=None):
    try:
        if started is not None:
            service._checkout_timings.record(identity, stage, started, ended)
    except Exception:
        pass


async def measured(service, identity, stage, operation):
    began = start()
    value = await operation
    ended = start()
    if began is not None and ended is not None:
        record(service, identity, stage, began, ended)
        try:
            current = _attempt.get()
            if current is not None and current['identity'] == identity and stage in STAGES:
                duration = max(0, min(MAX_MILLISECONDS, (ended - began) // 1_000_000))
                current['stages'][stage] = min(MAX_MILLISECONDS, current['stages'].get(stage, 0) + duration)
        except Exception:
            pass
    return value


async def worker_attempt(service, identity, operation):
    """Time one worker cycle; measured stages are sequential wall intervals.

    Quorum measures its parallel wall interval, not the sum of validator calls.
    Queue and chain wait are not inferred from this local process observation.
    """
    began = start()
    current = {'identity': identity, 'stages': {}}
    token = None
    outcome = 'success'
    try:
        try:
            token = _attempt.set(current)
        except Exception:
            pass
        return await operation
    except BaseException as exc:
        outcome = 'cancelled' if isinstance(exc, asyncio.CancelledError) else 'error'
        raise
    finally:
        ended = start()
        try:
            if token is not None:
                _attempt.reset(token)
            if began is not None and ended is not None:
                total = max(0, min(MAX_MILLISECONDS, (ended - began) // 1_000_000))
                covered = min(total, sum(current['stages'].values()))
                service._checkout_timings.attempt(identity, {'scope': 'worker_cycle',
                    'outcome': outcome, 'totalMs': total, 'stagesMs': dict(current['stages']),
                    'unattributedMs': total - covered})
        except Exception:
            pass
