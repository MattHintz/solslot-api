"""Fresh customer vault launch assembly for a confirmed generation.

No endpoint, key selection, journal migration, broadcast or ID admission is
enabled by this module. A service must obtain current native generation evidence
and reserve the exact funding parent before presenting consent. It must retain
the operation before dispatch and prove confirmation before opening a session.
"""
from dataclasses import dataclass

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton
from chia_rs import AugSchemeMPL, G1Element, G2Element
from chia_rs.sized_bytes import bytes32
from eth_keys import keys

from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_transactions import NativeOperation, SingletonTip
from solslot_puzzles.generation_vault import vault_inner
from solslot_puzzles.vault_driver import (
    AUTH_TYPE_BLS, AUTH_TYPE_SECP256K1, one_leaf_merkle_root, puzzle_for_p2_vault,
)
from .evm_auth import recover_evm_signer, normalize_evm_address
from .singleton_launcher import launcher_coin_for_parent
from .vault_launcher import build_and_sign_launch


@dataclass(frozen=True)
class CustomerLaunchBindings:
    generation: bytes32
    preparation_manifest: bytes32
    pool_launcher: bytes32
    bridge_policy: bytes32
    vault_module: bytes32

    def validate(self):
        fields = (self.generation, self.preparation_manifest, self.pool_launcher,
                  self.bridge_policy, self.vault_module)
        if any(not isinstance(v, bytes32) or v == bytes32.zeros for v in fields):
            raise ValueError('fresh customer launch requires exact nonzero generation bindings')
        if self.vault_module != load_puzzle('vault_singleton_inner_generation_v1.clsp').get_tree_hash():
            raise ValueError('customer launch requires the reviewed generation custody module')
        return self


@dataclass(frozen=True)
class CustomerLaunchConsent:
    bindings: CustomerLaunchBindings
    nonce: bytes32
    owner: str
    auth_type: str
    funding_coin_id: bytes32
    vault_launcher_id: bytes32
    expires_at: int

    def validate(self):
        self.bindings.validate()
        if (any(not isinstance(v, bytes32) or v == bytes32.zeros for v in
                (self.nonce, self.funding_coin_id, self.vault_launcher_id))
                or type(self.expires_at) is not int or not 0 < self.expires_at < 2**64):
            raise ValueError('registration consent requires exact nonce, reserved parent and expiry')
        if self.auth_type == 'evm':
            if self.owner != normalize_evm_address(self.owner):
                raise ValueError('registration owner must be a canonical EVM address')
        elif self.auth_type == 'chia_bls':
            if not isinstance(self.owner, str) or not self.owner.startswith('0x'):
                raise ValueError('registration owner must be a canonical BLS public key')
            try:
                raw = bytes.fromhex(self.owner[2:])
                key = G1Element.from_bytes(raw)
            except (ValueError, TypeError) as exc:
                raise ValueError('registration owner must be a valid BLS public key') from exc
            if key == G1Element() or self.owner != '0x' + bytes(key).hex():
                raise ValueError('registration owner must be a nonidentity canonical BLS key')
        else:
            raise ValueError('registration supports EVM or Chia BLS owners only')
        return self

    def message(self):
        self.validate()
        h = lambda v: '0x' + v.hex()
        return {'generationId': h(self.bindings.generation),
                'preparationManifest': h(self.bindings.preparation_manifest),
                'network': 'testnet11', 'poolLauncherId': h(self.bindings.pool_launcher),
                'bridgePolicyHash': h(self.bindings.bridge_policy),
                'vaultModuleHash': h(self.bindings.vault_module),
                'owner': self.owner, 'authType': self.auth_type,
                'fundingCoinId': h(self.funding_coin_id),
                'vaultLauncherId': h(self.vault_launcher_id),
                'nonce': h(self.nonce), 'expiresAt': self.expires_at,
                'purpose': 'CREATE_FRESH_CUSTOMER_VAULT_REQUIRES_NEW_ID_CHECK'}

    def typed_data(self):
        if self.auth_type != 'evm':
            raise ValueError('EVM typed consent requires an EVM owner')
        message = self.message()
        types = [{'name': name, 'type': ('uint64' if name == 'expiresAt' else
                  'bytes32' if name.endswith(('Id', 'Hash', 'Manifest')) or name == 'nonce' else 'string')}
                 for name in message]
        # Owner is an address in the typed message, never a string selected by
        # the service after signing. The generation is also the domain salt.
        next(row for row in types if row['name'] == 'owner')['type'] = 'address'
        return {'types': {'EIP712Domain': [
                    {'name': 'name', 'type': 'string'}, {'name': 'version', 'type': 'string'},
                    {'name': 'salt', 'type': 'bytes32'}], 'SolslotFreshVaultRegistration': types},
                'primaryType': 'SolslotFreshVaultRegistration',
                'domain': {'name': 'Solslot fresh Testnet vault', 'version': '1',
                           'salt': '0x' + self.bindings.generation.hex()}, 'message': message}

    def bls_message(self):
        if self.auth_type != 'chia_bls':
            raise ValueError('BLS consent requires a BLS owner')
        message = self.message()
        return bytes(Program.to([b'SOLSLOT_FRESH_CUSTOMER_VAULT_V1',
            [[name.encode(), value] for name, value in sorted(message.items())]]).get_tree_hash())

    def verified_owner(self, signature: str, now: int) -> tuple[bytes, int]:
        self.validate()
        if type(now) is not int or now <= 0 or now >= self.expires_at:
            raise ValueError('fresh customer registration consent expired')
        if not isinstance(signature, str) or not signature.startswith('0x'):
            raise ValueError('registration requires a canonical wallet signature')
        if self.auth_type == 'evm':
            recovered = recover_evm_signer(self.typed_data(), signature)
            if recovered.address != self.owner:
                raise ValueError('registration signature belongs to another owner')
            # Pubkey recovery is part of the exact consent, not another prompt.
            keys.PublicKey.from_compressed_bytes(recovered.compressed_pubkey)
            return recovered.compressed_pubkey, AUTH_TYPE_SECP256K1
        try:
            sig = G2Element.from_bytes(bytes.fromhex(signature[2:]))
        except (ValueError, TypeError) as exc:
            raise ValueError('registration BLS signature is malformed') from exc
        digest = bytes(Program.to(('Chia Signed Message', self.bls_message())).get_tree_hash())
        key = G1Element.from_bytes(bytes.fromhex(self.owner[2:]))
        if not AugSchemeMPL.verify(key, digest, sig):
            raise ValueError('registration signature belongs to another owner or generation')
        return bytes(key), AUTH_TYPE_BLS


def assemble_customer_launch(*, bindings: CustomerLaunchBindings,
        consent: CustomerLaunchConsent, signature: str, funding_coin: Coin,
        faucet, now: int) -> NativeOperation:
    """Create only the exact signed fresh vault and unchanged-owner change.

    Network fees are attached by the separately bounded submission policy after
    native validation; this assembler neither selects fees nor broadcasts.
    """
    bindings.validate()
    if consent.bindings != bindings:
        raise ValueError('registration consent belongs to another confirmed generation')
    owner, auth = consent.verified_owner(signature, now)
    if consent.expires_at - now > 300:
        raise ValueError('customer registration consent exceeds the five-minute window')
    launcher = launcher_coin_for_parent(funding_coin)
    if (funding_coin.name() != consent.funding_coin_id
            or launcher.name() != consent.vault_launcher_id):
        raise ValueError('registration funding differs from the exact reserved destination')
    launched = build_and_sign_launch(faucet=faucet,
        faucet_coin_json=funding_coin.to_json_dict(), owner_pubkey=owner,
        auth_type=auth, pool_launcher_id=bindings.pool_launcher,
        zkpassport_bridge_policy_hash=bindings.bridge_policy, generation_vault=True)
    inner = vault_inner(vault_launcher_id=launcher.name(), owner_pubkey=owner,
        auth_type=auth, members_merkle_root=one_leaf_merkle_root(owner),
        pool_launcher_id=bindings.pool_launcher, zkpassport_bridge_policy_hash=bindings.bridge_policy)
    if (launched.vault_launcher_id != launcher.name()
            or launched.vault_full_puzhash != puzzle_for_singleton(launcher.name(), inner).get_tree_hash()):
        raise ValueError('customer vault launch differs from the reviewed native bindings')
    from chia.wallet.util.compute_additions import compute_additions_with_cost
    spends = tuple(launched.spend_bundle.coin_spends)
    if len(spends) != 2 or spends[0].coin != funding_coin or spends[1].coin != launcher:
        raise ValueError('customer launch has unexpected inputs')
    funding_outputs, _ = compute_additions_with_cost(spends[0], max_cost=11_000_000_000)
    expected = [launcher]
    if funding_coin.amount > 1:
        from chia_rs.sized_ints import uint64
        expected.append(Coin(funding_coin.name(), funding_coin.puzzle_hash, uint64(int(funding_coin.amount) - 1)))
    if sorted(funding_outputs, key=lambda c: c.name()) != sorted(expected, key=lambda c: c.name()):
        raise ValueError('customer launch changes unrelated funding outputs')
    children, _ = compute_additions_with_cost(spends[1], max_cost=5_000_000)
    if len(children) != 1:
        raise ValueError('customer launcher must create one exact custody coin')
    tip = SingletonTip(launcher.name(), inner, children[0], spends[1]).validate()
    p2 = puzzle_for_p2_vault(launcher.name())
    if p2.get_tree_hash() == bytes32.zeros:
        raise ValueError('customer receiving puzzle cannot be zero')
    return NativeOperation(bindings.generation, 'CREATE_CUSTOMER_VAULT', spends, (tip,),
        aggregated_signature=launched.spend_bundle.aggregated_signature)
