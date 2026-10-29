"""Require CI's application dependency pins to match the approved runtime."""
from pathlib import Path
import json
import re


def normalized(name):
    return re.sub(r'[-_.]+', '-', name).lower()


def check_lock(text, baseline):
    if (baseline.get('schema') != 'solslot.ci-approved-runtime.v1'
            or baseline.get('network') != 'testnet11' or baseline.get('testOnly') is not True):
        raise ValueError('An explicit reviewed Testnet runtime baseline is required')
    pins, direct = {}, {}
    for line in text.splitlines():
        match = re.fullmatch(r'([A-Za-z0-9_.-]+)==([^ ;]+)', line.strip())
        if match:
            name = normalized(match[1])
            if name in pins:
                raise ValueError('Duplicate runtime constraint: '+name)
            pins[name] = match[2]
        elif ' @ ' in line:
            name, url = line.strip().split(' @ ', 1)
            name = normalized(name)
            if name in direct:
                raise ValueError('Duplicate direct runtime source: '+name)
            direct[name] = url
    errors = []
    for name, expected in baseline['runtimePins'].items():
        if pins.get(name) != expected:
            errors.append(f'{name}: expected approved {expected}, found {pins.get(name, "missing")}')
    for name, expected in baseline['directSources'].items():
        if direct.get(name) != expected:
            errors.append(name+': approved immutable source differs')
    if errors:
        raise ValueError('CI/runtime dependency drift; obtain a reviewed amendment:\n'+'\n'.join(errors))
    return len(baseline['runtimePins'])+len(baseline['directSources'])


def main():
    root = Path(__file__).resolve().parents[1]
    count = check_lock((root/'constraints.lock').read_text(),
        json.loads((root/'ci/approved-runtime-v1.json').read_text()))
    print(f'Approved Testnet runtime parity passed for {count} application dependencies; no installation performed.')


if __name__ == '__main__':
    main()
