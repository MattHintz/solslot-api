"""Isolated interpreter entry: only root-owned installed modules join sys.path."""
from pathlib import Path
import os
import sys
root=Path('/opt/solslot/generation-recovery-AE222')
for p in (root,*root.parents):
    info=p.lstat()
    if p.is_symlink() or info.st_uid!=0 or info.st_mode&0o022:raise RuntimeError('Recovery installation is not protected')
sys.path.insert(0,str(root))
from generation_worker import run,stage_tokens
if sys.argv[1:]==['--stage-identity']:stage_tokens()
elif sys.argv[1:]==['--snapshot']:
    from generation_export import child_snapshot
    child_snapshot()
elif sys.argv[1:]==['--media-snapshot']:
    from generation_export import child_snapshot
    child_snapshot(media=True)
elif sys.argv[1:]==[]:run()
else:raise RuntimeError('Unsupported recovery entry action')
