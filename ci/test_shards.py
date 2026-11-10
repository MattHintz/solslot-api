"""Fast guards for collection completeness and the required-check boundary."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import shutil
import unittest
from unittest.mock import patch
import shards


class Accounting(unittest.TestCase):
    def setUp(self):
        self.plan = shards.make_plan('pytest', [f'tests/test_a.py::test_{n}' for n in range(12)], 4)
        self.receipts = [shards.receipt(self.plan, i, ids, 0, [{'id': nodeid, 'when': phase, 'outcome': 'passed', 'xfail': False} for nodeid in ids for phase in ('setup','call','teardown')]) for i, ids in enumerate(self.plan['shards'])]
        self.needs = {k: {'result': 'success'} for k in ('test-plan', 'test-shards')}

    def test_all_collected_cases_are_assigned_and_finished_once(self):
        self.assertEqual(shards.aggregate(self.plan, self.receipts, self.needs)['tests'], 12)
        self.assertEqual(shards.make_plan('pytest', list(reversed(self.plan['tests'])), 4), self.plan)

    def test_new_cases_are_included_automatically(self):
        updated = shards.make_plan('pytest', self.plan['tests'] + ['tests/test_new.py::test_new'], 4)
        self.assertIn('tests/test_new.py::test_new', sum(updated['shards'], []))
        with self.assertRaises(ValueError): shards.aggregate(updated, self.receipts, self.needs)

    def test_empty_duplicate_and_excess_shard_collection_rejected(self):
        for ids, count in [([], 4), (['same', 'same'], 1), (['one'], 4), (list('abcdef'), 5)]:
            with self.subTest(ids=ids, count=count), self.assertRaises(ValueError): shards.make_plan('pytest', ids, count)

    def test_failed_skipped_cancelled_missing_and_pending_groups_rejected(self):
        for group in self.needs:
            for state in ('failure', 'cancelled', 'skipped', 'pending', None):
                value = copy.deepcopy(self.needs);value[group]['result'] = state
                with self.subTest(group=group, state=state), self.assertRaises(ValueError): shards.aggregate(self.plan, self.receipts, value)
        for value in ({}, {'test-plan': {'result': 'success'}}, {**self.needs, 'extra': {'result': 'success'}}):
            with self.assertRaises(ValueError): shards.aggregate(self.plan, self.receipts, value)

    def test_missing_extra_duplicate_failed_or_partial_receipts_rejected(self):
        for kind in ('missing', 'extra', 'duplicate-index', 'duplicate-test', 'omitted-test', 'wrong-selection', 'wrong-collection', 'failed'):
            values = copy.deepcopy(self.receipts)
            if kind == 'missing': values.pop()
            elif kind == 'extra': values.append(values[0])
            elif kind == 'duplicate-index': values[-1] = values[0]
            elif kind == 'duplicate-test': values[0]['finished'].append(values[0]['finished'][0])
            elif kind == 'omitted-test': values[0]['finished'].pop()
            elif kind == 'wrong-selection': values[0]['selected'] = []
            elif kind == 'wrong-collection': values[0]['collected'] = values[0]['collected'][:-1]
            elif kind == 'failed': values[0]['exitCode'] = 1
            with self.subTest(kind=kind), self.assertRaises(ValueError): shards.aggregate(self.plan, values, self.needs)

    def test_incomplete_or_nonpassing_phase_evidence_rejected(self):
        for change in ('missing', 'duplicate', 'skipped', 'failed', 'xfail'):
            values = copy.deepcopy(self.receipts)
            reports = values[0]['reports']
            if change == 'missing': reports.pop()
            elif change == 'duplicate': reports.append(reports[0])
            elif change == 'xfail': reports[0]['xfail'] = True
            else: reports[0]['outcome'] = change
            with self.subTest(change=change), self.assertRaises(ValueError):
                shards.aggregate(self.plan, values, self.needs)
        with self.assertRaises(ValueError):
            shards.make_plan('pytest', self.plan['tests'], 4, ['tests/skipped.py'])

    def test_wrong_head_protocol_run_attempt_or_plan_cannot_be_replayed(self):
        for field in ('sourceCommit', 'GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'PROTOCOL_REF'):
            values = copy.deepcopy(self.receipts);values[0]['identity'][field] = 'wrong'
            with self.subTest(field=field), self.assertRaises(ValueError): shards.aggregate(self.plan, values, self.needs)
        values = copy.deepcopy(self.receipts);values[0]['planDigest'] = 'wrong'
        with self.assertRaises(ValueError): shards.aggregate(self.plan, values, self.needs)

    def test_plan_integrity_and_coverage_rechecked(self):
        for field in ('tests', 'shards'):
            plan = copy.deepcopy(self.plan);plan[field].pop()
            with self.assertRaises(ValueError): shards.validate_plan(plan)
        plan = copy.deepcopy(self.plan);plan['shards'][0] = []
        plan['digest'] = shards.digest({k:v for k,v in plan.items() if k != 'digest'})
        with self.assertRaises(ValueError): shards.validate_plan(plan)

    def test_ci_checkout_must_match_deliberate_source_head(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS':'true', 'CI_SOURCE_SHA':'0'*40}):
            with self.assertRaises(ValueError): shards.identity()

    def test_required_workflow_contract(self):
        root = Path(__file__).resolve().parent.parent
        api = root / '.github/workflows/api-ci.yml'
        path = api if api.exists() else root / '.github/workflows/customer-presentation-freeze.yml'
        text = path.read_text()
        self.assertIn('max-parallel: 4', text);self.assertIn('fail-fast: false', text)
        self.assertIn('if: ${{ always() }}', text)
        self.assertIn('needs: [test-plan, test-shards]', text)
        self.assertIn('github.event.pull_request.head.sha || github.sha', text)
        self.assertIn('if-no-files-found: error', text)
        self.assertNotIn('continue-on-error', text);self.assertNotIn('paths:', text)
        self.assertIn('  verify:' if api.exists() else '  protected-core:', text)
        self.assertIn('ci/shards.py aggregate', text)
        expected = {'test-plan':30, 'test-shards':90, 'verify':5} if api.exists() else {'test-plan':15, 'test-shards':60, 'protected-core':5}
        for job, minutes in expected.items():
            self.assertIn(f'  {job}:\n    timeout-minutes: {minutes}\n', text)


@unittest.skipUnless(Path('ci/node-collection.mjs').exists(), 'Customer Node runner only')
class NodeRehearsal(unittest.TestCase):
    def test_real_node_processes_execute_the_same_collected_names_once(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder);entry = p/'sample.mjs';output = p/'ran.txt'
            names = ['brackets [x]', 'dollars $', 'slashes /', 'literal .*', 'unicode café', 'quote "x"', 'new test', 'last']
            entry.write_text("import test from 'node:test';import {appendFileSync} from 'node:fs';\n" + '\n'.join(
                f'test({json.dumps(name)},()=>appendFileSync({json.dumps(str(output))},{json.dumps(name+chr(10))}));' for name in names))
            ids = shards.node_collect(str(entry));self.assertEqual(set(ids), set(names));self.assertFalse(output.exists())
            plan = shards.make_plan('node', ids, 4)
            receipts = []
            for index in range(4):
                code, finished, reports = shards.node_run(plan, index, str(entry))
                receipts.append(shards.receipt(plan, index, finished, code, reports))
            self.assertEqual(shards.aggregate(plan, receipts, {k:{'result':'success'} for k in ('test-plan','test-shards')})['tests'], 8)
            self.assertCountEqual(output.read_text().splitlines(), names)

    def test_new_unimported_freeze_file_is_collected_automatically(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); scripts = root/'slui/scripts'; scripts.mkdir(parents=True)
            shutil.copytree(Path('ci'), root/'ci', ignore=shutil.ignore_patterns('__pycache__'))
            (scripts/'check-security-release-freeze.test.mjs').write_text("import test from 'node:test';test('original',()=>{});\n")
            (scripts/'new-release-freeze.test.mjs').write_text("import test from 'node:test';test('new unimported',()=>{});\n")
            result=subprocess.run(['node','ci/node-collection.mjs','ci/node-freeze-entry.mjs'],cwd=root,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertCountEqual(json.loads(result.stdout)['collection'], ['original','new unimported'])

    def test_new_named_test_changes_worker_collection(self):
        with tempfile.TemporaryDirectory() as folder:
            entry = Path(folder)/'sample.mjs';entry.write_text("import test from 'node:test';test('a',()=>{});\n")
            plan = shards.make_plan('node', shards.node_collect(str(entry)), 1)
            entry.write_text(entry.read_text()+"test('new',()=>{});\n")
            with self.assertRaisesRegex(ValueError, 'collection differs'): shards.node_run(plan, 0, str(entry))

    def test_nested_failed_skipped_or_duplicate_tests_never_pass_as_complete(self):
        cases = ["test('a',()=>{throw Error('expected fixture failure')});",
                 "test('a',async t=>{await t.test('inner',()=>{});});",
                 "test.skip('a',()=>{});", "test('a',()=>{});test('a',()=>{});",
                 "test('a',()=>process.exit(0));", "test('a',()=>process.exit(1));"]
        for body in cases:
            with self.subTest(body=body), tempfile.TemporaryDirectory() as folder:
                entry = Path(folder)/'sample.mjs';entry.write_text("import test from 'node:test';"+body)
                with self.assertRaises(ValueError):
                    plan=shards.make_plan('node', shards.node_collect(str(entry)), 1)
                    code, finished, reports=shards.node_run(plan,0,str(entry))
                    shards.validate_receipt(plan, shards.receipt(plan,0,finished,code,reports))


@unittest.skipUnless(importlib.util.find_spec('pytest'), 'API pytest runtime only')
class PytestRehearsal(unittest.TestCase):
    def test_actual_collection_and_four_isolated_workers_preserve_every_nodeid(self):
        runner = str(Path(shards.__file__).resolve())
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder);(p/'tests').mkdir()
            (p/'tests/test_sample.py').write_text('import pytest\n@pytest.mark.parametrize("n",range(8))\ndef test_case(n,tmp_path):\n assert n>=0\n (tmp_path/"isolated").write_text(str(n))\n')
            env={k:v for k,v in os.environ.items() if not k.startswith('GITHUB_') and k!='PYTEST_ADDOPTS'}
            env['PYTEST_DISABLE_PLUGIN_AUTOLOAD']='1'
            def run(*args):
                result=subprocess.run([sys.executable,runner,*args],cwd=p,env=env,capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            run('plan','--kind','pytest','--count','4')
            for i in range(4):run('run','--kind','pytest','--index',str(i))
            plan=shards.read(p/'ci-results/plan.json');values=[shards.read(p/f'ci-results/shard-{i}.json')for i in range(4)]
            with patch.object(shards,'identity',return_value=plan['identity']):
                self.assertEqual(shards.aggregate(plan,values,{k:{'result':'success'}for k in ('test-plan','test-shards')})['tests'],8)
            (p/'tests/test_new.py').write_text('def test_new(): pass\n')
            result=subprocess.run([sys.executable,runner,'run','--kind','pytest','--index','0'],cwd=p,env=env,capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)

    def test_real_pytest_skips_xfails_and_collection_skips_fail_closed(self):
        runner = str(Path(shards.__file__).resolve())
        cases = {
            'setup skip': "import pytest\n@pytest.mark.skip(reason='fixture')\ndef test_case(): pass\n",
            'body skip': "import pytest\ndef test_case(): pytest.skip('fixture')\n",
            'xfail': "import pytest\n@pytest.mark.xfail(reason='fixture')\ndef test_case(): assert False\n",
            'empty reason xpass': "import pytest\n@pytest.mark.xfail(reason='',strict=False)\ndef test_case(): pass\n",
            'clean exit': "import pytest\ndef test_case(): pytest.exit('fixture',returncode=0)\n",
            'hard exit': "import os\ndef test_case(): os._exit(0)\n",
            'collection skip': "import pytest\npytest.skip('fixture',allow_module_level=True)\n",
        }
        for label, body in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as folder:
                p=Path(folder);(p/'tests').mkdir()
                (p/'tests/test_control.py').write_text('def test_control(): pass\n')
                (p/'tests/test_skip.py').write_text(body)
                env={k:v for k,v in os.environ.items() if not k.startswith('GITHUB_') and k!='PYTEST_ADDOPTS'}
                env['PYTEST_DISABLE_PLUGIN_AUTOLOAD']='1'
                result=subprocess.run([sys.executable,runner,'plan','--kind','pytest','--count','1'],cwd=p,env=env,capture_output=True,text=True)
                if label == 'collection skip': self.assertNotEqual(result.returncode,0)
                else:
                    self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                    result=subprocess.run([sys.executable,runner,'run','--kind','pytest','--index','0'],cwd=p,env=env,capture_output=True,text=True)
                    if label == 'hard exit':
                        self.assertFalse((p/'ci-results/shard-0.json').exists(), 'A crashed worker must not publish a receipt')
                        plan=shards.read(p/'ci-results/plan.json')
                        with patch.object(shards,'identity',return_value=plan['identity']), self.assertRaises(ValueError):
                            shards.aggregate(plan,[],{k:{'result':'success'}for k in ('test-plan','test-shards')})
                    else: self.assertNotEqual(result.returncode,0,result.stdout+result.stderr)


if __name__ == '__main__': unittest.main()
