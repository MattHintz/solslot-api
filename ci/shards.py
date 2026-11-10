"""Exact collection, bounded sharding and fail-closed CI receipts.

Receipts are same-run evidence, never reusable cached test verdicts. Each worker
recollects the full suite before selecting its shard. Unsupported collection
structures fail rather than silently dropping tests.
"""
from __future__ import annotations
import argparse
from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys

SCHEMA = 'solslot.ci-shards.v1'
NODE_ENTRY = 'ci/node-freeze-entry.mjs'


def require(value, message):
    if not value:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def digest(value):
    return sha256(canonical(value)).hexdigest()


def identity():
    # Explicit PR-head checkout avoids mixing an advertised head with merge bytes.
    result = subprocess.run(['git', 'rev-parse', 'HEAD'], capture_output=True, text=True)
    actual = result.stdout.strip() if result.returncode == 0 else 'local-fixture'
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        expected = os.environ.get('CI_SOURCE_SHA', '')
        require(re.fullmatch('[0-9a-f]{40}', expected) and actual == expected, 'Exact tested checkout required')
    return {'sourceCommit': actual, **{key: os.environ.get(key, 'local') for key in
            ('GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'PROTOCOL_REF')}}


def read(path):
    return json.loads(Path(path).read_text())


def write(path, value):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def checked_ids(ids):
    require(isinstance(ids, list) and ids and all(isinstance(x, str) and x for x in ids), 'Nonempty test collection required')
    require(len(set(ids)) == len(ids), 'Duplicate collected test identities')
    return sorted(ids)


def assignments(ids, count):
    require(type(count) is int and 1 <= count <= 4, 'Shard count must be 1..4')
    ids = checked_ids(ids)
    require(len(ids) >= count, 'Every shard must contain tests')
    return [ids[index::count] for index in range(count)]


def make_plan(kind, ids, count, skipped=None):
    require(not skipped, 'Collection skips are not allowed')
    ids = checked_ids(ids)
    value = {'schema': SCHEMA, 'kind': kind, 'identity': identity(), 'tests': ids,
             'collectionSkipped': sorted(skipped or []), 'shards': assignments(ids, count)}
    return {**value, 'digest': digest(value)}


def validate_plan(plan, kind=None):
    raw = {k: v for k, v in plan.items() if k != 'digest'}
    require(plan.get('schema') == SCHEMA and plan.get('digest') == digest(raw), 'Plan integrity differs')
    require(plan.get('identity') == identity(), 'Plan is from another commit, run, attempt or protocol')
    require(plan.get('kind') in ('pytest', 'node') and (kind is None or plan['kind'] == kind), 'Wrong test runner')
    require(plan.get('shards') == assignments(plan['tests'], len(plan['shards'])), 'Collection or shard assignment differs')
    require(plan['tests'] == checked_ids(plan['tests']), 'Collection must be canonical')
    require(plan.get('collectionSkipped') == [], 'Collection skips are not allowed')
    return plan


class PytestAccounting:
    def __init__(self, plan=None, index=None):
        self.plan, self.index = plan, index
        self.collected, self.finished, self.collection_skipped = [], [], []
        self.reports = []

    def pytest_collectreport(self, report):
        if report.skipped:
            self.collection_skipped.append(report.nodeid)

    def pytest_collection_modifyitems(self, session, config, items):
        self.collected = checked_ids([item.nodeid for item in items])
        if self.plan is not None:
            require(self.collected == self.plan['tests'], 'Worker collection differs from plan (new, missing or duplicate test)')
            selected = set(self.plan['shards'][self.index])
            keep = [item for item in items if item.nodeid in selected]
            config.hook.pytest_deselected(items=[item for item in items if item.nodeid not in selected])
            items[:] = keep

    def pytest_runtest_logreport(self, report):
        self.reports.append({'id': report.nodeid, 'when': report.when, 'outcome': report.outcome,
                             'xfail': hasattr(report, 'wasxfail')})

    def pytest_runtest_logfinish(self, nodeid, location):
        self.finished.append(nodeid)


def pytest_run(plan=None, index=None):
    import pytest
    # Run after ordinary selectors, so any drift or deselection is detected.
    PytestAccounting.pytest_collection_modifyitems = pytest.hookimpl(trylast=True)(PytestAccounting.pytest_collection_modifyitems)
    plugin = PytestAccounting(plan, index)
    args = ['tests', '-q', '--durations=20', '-W', 'error::pytest.PytestUnraisableExceptionWarning']
    if plan is None:
        args += ['--collect-only']
    code = int(pytest.main(args, plugins=[plugin]))
    return code, plugin


def node_command(args, env=None):
    result = subprocess.run(['node', *args], capture_output=True, text=True, env=env)
    if result.stderr:
        print(result.stderr, file=sys.stderr, end='')
    return result


def node_collect(entry=NODE_ENTRY):
    result = node_command(['ci/node-collection.mjs', entry])
    require(result.returncode == 0, 'Node collection failed')
    rows = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    require(len(rows) == 1 and set(rows[0]) == {'collection'}, 'Unexpected Node collection output')
    return checked_ids(rows[0]['collection'])


def node_run(plan, index, entry=NODE_ENTRY):
    require(node_collect(entry) == plan['tests'], 'Worker collection differs from plan')
    env = {**os.environ, 'CI_NODE_ALL': json.dumps(plan['tests']),
           'CI_NODE_SELECTED': json.dumps(plan['shards'][index])}
    result = node_command(['--test', '--import=./ci/node-register-shard.mjs',
                           '--test-reporter=./ci/node-reporter.mjs', entry], env=env)
    completed = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    require(all(e.get('nesting') == 0 and e.get('type') == 'test' for e in completed),
            'Nested tests or suites require an explicit collection/accounting update')
    require(all(e['event'] == 'test:pass' and not e.get('skip') and not e.get('todo') for e in completed),
            'Selected Node test failed, skipped or remained TODO')
    return result.returncode, [e['name'] for e in completed], completed


def receipt(plan, index, finished, code, reports=None):
    return {'schema': SCHEMA, 'identity': identity(), 'kind': plan['kind'], 'planDigest': plan['digest'],
            'index': index, 'collected': plan['tests'], 'selected': plan['shards'][index],
            'finished': finished, 'exitCode': code, 'reports': reports or []}


def validate_receipt(plan, value):
    require(value.get('schema') == SCHEMA and value.get('identity') == plan['identity'] and
            value.get('kind') == plan['kind'] and value.get('planDigest') == plan['digest'], 'Wrong receipt lineage')
    index = value.get('index')
    require(type(index) is int and 0 <= index < len(plan['shards']), 'Unknown shard index')
    require(type(value.get('exitCode')) is int and value['exitCode'] == 0, 'Shard did not complete successfully')
    require(value.get('collected') == plan['tests'] and value.get('selected') == plan['shards'][index], 'Worker collection or selection differs')
    require(Counter(value.get('finished', [])) == Counter(plan['shards'][index]), 'Selected tests did not finish exactly once')
    reports = value.get('reports', [])
    if plan['kind'] == 'pytest':
        expected = Counter((nodeid, phase) for nodeid in plan['shards'][index]
                           for phase in ('setup', 'call', 'teardown'))
        require(Counter((r.get('id'), r.get('when')) for r in reports) == expected,
                'Every pytest case must execute setup, body and teardown exactly once')
        require(all(r.get('outcome') == 'passed' and r.get('xfail') is False for r in reports),
                'Failed, skipped or xfail pytest cases are not complete coverage')
    else:
        require(Counter(r.get('name') for r in reports) == Counter(plan['shards'][index]),
                'Node completion reports differ from selected tests')
        require(all(r.get('event') == 'test:pass' and r.get('nesting') == 0 and
                    r.get('type') == 'test' and r.get('skip') is False and
                    r.get('todo') is False for r in reports), 'Node test verdicts are not all passed')



def aggregate(plan, receipts, needs):
    validate_plan(plan)
    require(set(needs) == {'test-plan', 'test-shards'} and all(v.get('result') == 'success' for v in needs.values()),
            'A required CI group failed, was missing, skipped or cancelled')
    require(len(receipts) == len(plan['shards']), 'Missing or extra shard receipts')
    require(Counter(v.get('index') for v in receipts) == Counter(range(len(plan['shards']))), 'Missing or duplicate shard index')
    for value in receipts:
        validate_receipt(plan, value)
    require(Counter(x for v in receipts for x in v['finished']) == Counter(plan['tests']), 'Full suite not accounted exactly once')
    return {'state': 'EXACT_SUITE_PASSED', 'kind': plan['kind'], 'tests': len(plan['tests']),
            'shards': len(plan['shards']), 'planDigest': plan['digest'], 'identity': plan['identity']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('plan', 'run', 'aggregate'))
    parser.add_argument('--kind', choices=('pytest', 'node'))
    parser.add_argument('--plan', default='ci-results/plan.json')
    parser.add_argument('--out')
    parser.add_argument('--count', type=int, default=4)
    parser.add_argument('--index', type=int)
    parser.add_argument('--receipts', default='ci-results')
    args = parser.parse_args()
    if args.command == 'plan':
        require(args.kind is not None, 'Runner kind required')
        if args.kind == 'pytest':
            code, plugin = pytest_run()
            require(code == 0, 'Pytest collection failed')
            plan = make_plan('pytest', plugin.collected, args.count, plugin.collection_skipped)
        else:
            plan = make_plan('node', node_collect(), args.count)
        write(args.plan, plan)
        print(json.dumps({'collected': len(plan['tests']), 'shards': list(map(len, plan['shards'])), 'digest': plan['digest']}))
    elif args.command == 'run':
        plan = validate_plan(read(args.plan), args.kind)
        require(type(args.index) is int and 0 <= args.index < len(plan['shards']), 'Exact shard index required')
        if plan['kind'] == 'pytest':
            code, plugin = pytest_run(plan, args.index)
            require(sorted(plugin.collection_skipped) == plan['collectionSkipped'], 'Collection skip evidence changed')
            value = receipt(plan, args.index, plugin.finished, code, plugin.reports)
        else:
            code, finished, reports = node_run(plan, args.index)
            value = receipt(plan, args.index, finished, code, reports)
        write(args.out or f'ci-results/shard-{args.index}.json', value)
        validate_receipt(plan, value)
    else:
        plan = read(args.plan)
        values = [read(path) for path in sorted(Path(args.receipts).rglob('shard-*.json'))]
        print(json.dumps(aggregate(plan, values, json.loads(os.environ['NEEDS_JSON'])), sort_keys=True))


if __name__ == '__main__':
    main()
