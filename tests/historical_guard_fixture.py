"""Run retained deployment guards against their exact historical API source.

The immutable operational factories are not changed. Current generation source
must not masquerade as a past guarded release. Only isolated test subprocesses
receive the historical source; the application never imports this helper.
"""
import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile


def isolated_guard(root: Path, code: str, commit: str):
    raw = subprocess.check_output(['git', 'archive', '--format=tar', commit, 'solslot_api'], cwd=root)
    with tempfile.TemporaryDirectory(prefix='solslot-held-guard-') as folder:
        release = Path(folder)
        api = release / 'api'
        api.mkdir()
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            for member in archive.getmembers():
                if member.isdir():
                    continue
                name = Path(member.name)
                assert member.isfile() and not name.is_absolute() and '..' not in name.parts
                assert name.parts[0] == 'solslot_api'
                target = api / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.extractfile(member).read())
        result = subprocess.run([sys.executable, '-c', code], cwd=api,
            env={**os.environ, 'PYTHONDONTWRITEBYTECODE':'1',
                'SOLSLOT_TEST_GUARD_ROOT':str(root),
                'PYTHONPATH':os.pathsep.join([str(api),os.environ.get('PYTHONPATH','')])},
            capture_output=True,text=True,timeout=40)
        assert result.returncode == 0, result.stderr
