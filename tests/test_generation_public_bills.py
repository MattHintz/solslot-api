"""Public review must expose the effects committed by a native governance bill."""
import pytest
from chia.types.blockchain_format.program import Program

from solslot_api.generation_chain_evidence import public_bill


def mint_bill():
    return [b'MINT_TEST_ONLY',b'c'*32,b'e'*32,25]


def grant_bill():
    return [b'GRANT',b'r'*32,[[4,b'a'*32,b'',10000],[3,b'z'*32,b'',960000]]]


def test_public_mint_binds_test_purpose_edition_and_exact_count():
    bill=Program.to(mint_bill());view=public_bill(bill)
    assert view=={'kind':'MINT_TEST_ONLY','billHash':'0x'+bill.get_tree_hash().hex(),
        'testMint':{'purpose':'TEST_ONLY','collectionId':'0x'+(b'c'*32).hex(),
            'editionHash':'0x'+(b'e'*32).hex(),'deedCount':25}}
    # This commitment is not a mutable title, invented valuation or production approval.
    assert set(view['testMint'])=={'purpose','collectionId','editionHash','deedCount'}


def test_public_grant_exposes_all_destinations_amounts_and_nonvoting_types():
    bill=Program.to(grant_bill());view=public_bill(bill)
    assert view=={'kind':'GRANT','billHash':'0x'+bill.get_tree_hash().hex(),
        'grant':{'reserveCoinId':'0x'+(b'r'*32).hex(),'outputs':[
            {'kind':4,'ownerPuzzleHash':'0x'+(b'a'*32).hex(),'lockId':None,'amount':10000},
            {'kind':3,'ownerPuzzleHash':'0x'+(b'z'*32).hex(),'lockId':None,'amount':960000}]}}


@pytest.mark.parametrize('fault',['missing','extra','unknown','mainnet-kind','zero-count','large-count',
    'negative-count','zero-collection','wrong-edition','noncanonical-count'])
def test_mint_review_fails_closed(fault):
    raw=mint_bill()
    if fault=='missing':raw.pop()
    elif fault=='extra':raw.append(1)
    elif fault=='unknown':raw[0]=b'UNKNOWN'
    elif fault=='mainnet-kind':raw[0]=b'MINT_PRODUCTION'
    elif fault=='zero-count':raw[3]=0
    elif fault=='large-count':raw[3]=101
    elif fault=='negative-count':raw[3]=-1
    elif fault=='zero-collection':raw[1]=bytes(32)
    elif fault=='wrong-edition':raw[2]=b'e'*31
    elif fault=='noncanonical-count':raw[3]=b'\x00\x19'
    with pytest.raises((ValueError,TypeError)):public_bill(Program.to(raw))


@pytest.mark.parametrize('fault',['missing','extra','no-outputs','too-many','wrong-source','zero-source',
    'holder','locked','lock','zero-owner','wrong-owner','zero-amount','excess','noncanonical-amount','duplicate','dotted'])
def test_grant_review_fails_closed(fault):
    raw=grant_bill();row=raw[2][0]
    if fault=='missing':raw.pop()
    elif fault=='extra':raw.append(1)
    elif fault=='no-outputs':raw[2]=[]
    elif fault=='too-many':raw[2]=[[4,bytes([v+1])*32,b'',1] for v in range(33)]
    elif fault=='wrong-source':raw[1]=b'r'*31
    elif fault=='zero-source':raw[1]=bytes(32)
    elif fault=='holder':row[0]=1
    elif fault=='locked':row[0]=2
    elif fault=='lock':row[2]=b'l'*32
    elif fault=='zero-owner':row[1]=bytes(32)
    elif fault=='wrong-owner':row[1]=b'a'*31
    elif fault=='zero-amount':row[3]=0
    elif fault=='excess':row[3]=50000
    elif fault=='noncanonical-amount':row[3]=b'\x00\x27\x10'
    elif fault=='duplicate':raw[2]=[row,row]
    elif fault=='dotted':raw[2]=(row,1)
    with pytest.raises((ValueError,TypeError)):public_bill(Program.to(raw))
