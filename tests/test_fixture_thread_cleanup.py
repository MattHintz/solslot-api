"""Exercise actual fixture teardown before a later RPC worker can collect CLVM."""
from pathlib import Path

pytest_plugins = ['pytester']


def test_base_fixture_cycles_are_collected_before_the_next_worker(pytester, monkeypatch):
    repo = Path(__file__).resolve().parents[1]
    monkeypatch.setenv('PYTHONPATH', str(repo))
    pytester.makeconftest((repo/'tests/conftest.py').read_text())
    pytester.makepyfile('''
import gc
import threading
import weakref
from concurrent.futures import ThreadPoolExecutor
import pytest
from tests.test_base_inventory_holds import base_case, close

state = {}

@pytest.mark.asyncio
async def test_create_real_cyclic_base_fixture(tmp_path, monkeypatch):
    gc.collect()
    # Control automatic timing only inside this isolated regression process.
    # The real suite fixture must explicitly finalize on the creating thread.
    gc.disable()
    c = await base_case(tmp_path, monkeypatch)
    close(c)
    state['reference'] = weakref.ref(c.worker.faucet.key.puzzle)
    state['owner'] = threading.get_ident()
    state['finalized'] = []
    weakref.finalize(c.worker.faucet.key.puzzle,
        lambda: state['finalized'].append(threading.get_ident()))
    # c is retained by real node/submitter closures until monkeypatch teardown.

def test_next_worker_cannot_collect_the_previous_fixture():
    try:
        assert state['reference']() is None, 'previous Base fixture survived teardown'
        assert state['finalized'] == [state['owner']]
        with ThreadPoolExecutor(max_workers=1) as pool:
            assert pool.submit(threading.get_ident).result() != state['owner']
            pool.submit(gc.collect).result()
        assert state['finalized'] == [state['owner']]
    finally:
        gc.collect()
        gc.enable()
''')
    result = pytester.runpytest_subprocess(
        '-q', '-W', 'error::pytest.PytestUnraisableExceptionWarning', timeout=60,
    )
    result.assert_outcomes(passed=2)
