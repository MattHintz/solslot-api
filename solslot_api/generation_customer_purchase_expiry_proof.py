"""Strict validation for the retained native reservation expiry proof."""
def valid_expiry_proof(proof,binding):
    return (isinstance(proof,dict) and all(proof.get(k)==v for k,v in binding.items())
        and proof.get('allInputsUnspentAndClear') is True
        and type(proof.get('peakHeight')) is int and proof['peakHeight']>0
        and type(proof.get('peakTimestamp')) is int and proof['peakTimestamp']>=binding['absoluteExpiry'])
