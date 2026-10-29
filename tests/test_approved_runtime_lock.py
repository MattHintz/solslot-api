"""The independent approved runtime baseline must constrain CI resolution."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('runtime_lock_check',ROOT/'scripts/check_runtime_lock.py')
check=importlib.util.module_from_spec(spec);spec.loader.exec_module(check)
TEXT=(ROOT/'constraints.lock').read_text()
BASELINE=json.loads((ROOT/'ci/approved-runtime-v1.json').read_text())


def test_candidate_matches_approved_runtime():
    assert check.check_lock(TEXT,BASELINE)>90


@pytest.mark.parametrize('changed',[
    TEXT.replace('cryptography==50.0.2','cryptography==50.0.0'),
    '\n'.join(line for line in TEXT.splitlines() if not line.startswith('starlette==')),
    TEXT.replace('https://codeload.github.com/Chia-Network/chia_puzzles','https://unreviewed.invalid/chia_puzzles'),
    TEXT+'\ncryptography==50.0.0\n',
])
def test_changed_missing_duplicate_or_unreviewed_runtime_pin_is_rejected(changed):
    with pytest.raises(ValueError):check.check_lock(changed,BASELINE)


def test_non_testnet_baseline_is_rejected():
    value=deepcopy(BASELINE);value['network']='mainnet'
    with pytest.raises(ValueError,match='Testnet'):check.check_lock(TEXT,value)
