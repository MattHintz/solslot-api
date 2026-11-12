"""Export synthetic public native bills for independent browser reconstruction."""
import json
import sys
from pathlib import Path

from chia.types.blockchain_format.program import Program
from solslot_api.generation_chain_evidence import public_bill

raw_bills=[
    [b'UPGRADE',0,[b's'*32,[[b'c'*32,b'o'*32,b'n'*32,2,1,b'PRESERVE_STATE']]]],
    [b'PARAMETERS',b'p'*32,b'l'*32,1,b'v'*32,[3600,300,100,70,30,86400]],
    [b'REOPEN',1,31],
    [b'MINT_TEST_ONLY',b'c'*32,b'e'*32,25],
    [b'GRANT',b'r'*32,[[4,b'a'*32,b'',10000],[3,b'z'*32,b'',960000]]],
]
vectors=[{'billClvm':'0x'+bytes(bill).hex(),'review':public_bill(bill)} for bill in map(Program.to,raw_bills)]
Path(sys.argv[1]).write_text(json.dumps(vectors,indent=2)+'\n',encoding='utf-8')
