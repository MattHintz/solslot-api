from copy import deepcopy
import pytest
from generation_health import validate_receipt
from generation_replication import replicate
from test_generation_replication import package, Azure, KEY, GEN, SOURCE


def test_only_fresh_live_matching_generation_can_satisfy_recovery_gate(tmp_path):
    receipt=replicate(package(tmp_path),Azure(),KEY,GEN,SOURCE,parent=tmp_path,clock=lambda:1234)
    assert validate_receipt(receipt,GEN,SOURCE,now=1234)==receipt


@pytest.mark.parametrize('fault',['synthetic','generation','source','principal','stale','future','not_restored','count','url','etag','nan'])
def test_drill_stale_or_changed_recovery_receipt_cannot_admit_launch(tmp_path,fault):
    receipt=replicate(package(tmp_path),Azure(),KEY,GEN,SOURCE,parent=tmp_path,clock=lambda:1234)
    if fault=='synthetic':receipt['purpose']='SYNTHETIC_RESTORE_DRILL'
    elif fault=='generation':receipt['generationId']='0x'+'44'*32
    elif fault=='source':receipt['sourceHash']='0x'+'44'*32
    elif fault=='principal':receipt['principalId']='different'
    elif fault=='stale':receipt['restoredAt']=1
    elif fault=='future':receipt['checkedAt']=1300
    elif fault=='not_restored':receipt['restoreMatches']=False
    elif fault=='count':receipt['databaseCount']=0
    elif fault=='url':receipt['manifest']['blobName']='https://other-host/object'
    elif fault=='etag':receipt['manifest']['etag']=None
    elif fault=='nan':receipt['checkedAt']=float('nan')
    with pytest.raises(ValueError):validate_receipt(receipt,GEN,SOURCE,now=1234)
