# Identity receipt adapter binding

A vault identity stamp reached its confirmed Sepolia event and valid owner signature, but all three validators returned HTTP 503. Each validator correctly authenticated its signed artifact. Its adapter to the coordinator receipt reader omitted `zkpassport_verifier_adapter_address`, so the receipt reader's independent runtime-binding check rejected the same artifact before requesting a validator signature.

Pass the validator's configured `evm_verifier_adapter_address` explicitly into the receipt-reader settings. The regression test exercises the real artifact runtime-binding verifier, including a conflicting inherited environment value, and ensures mismatched forwarder, adapter and emitter bindings still fail.

For the existing disposable Testnet11 deployment, operator action `AE-SOLSLOT-VALIDATOR-ADAPTER-20260923-88` supplies only the exact already-signed adapter address through a systemd public configuration drop-in. All three validators were restarted individually and returned healthy authenticated mTLS responses with the original signed artifact. This restores the missing setting without changing frozen source files, keys, ledgers, the two-of-three threshold, or contract addresses. The explicit code handoff prevents this configuration dependence in future source releases.

The failed stamp attempt is a separate retained runtime record. Fixing the adapter does not renew its timestamp, delete it, sign a transaction, or mark a vault verified. Any recovery must reconcile the existing attempt and preserve its history before a fresh owner-authorized stamp is attempted. Only a confirmed Chia successor with the expected identity commitment completes verification.
