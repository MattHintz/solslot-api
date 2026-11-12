"""One current-generation, ID-bound native TXCH purchase quote.

Reuses the existing primary offer artifact and immutable mint fee destinations.
No HTTP input can select a treasury, change the sealed dollars or replace the
price operator set. This constructs no wallet spend and reserves no input.
"""
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import MOD as _P2_MOD
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.generation_primary_price import SignedPrimaryPrice
from solslot_puzzles.generation_statutes import GenerationStatutes
from solslot_puzzles.payment_artifacts_v3 import build_xch_purchase_artifact
from solslot_puzzles.vault_driver import puzzle_for_p2_vault
from .generation_customer_inventory import CurrentPrimaryInventory
from .generation_customer_vault import CurrentCustomerVault
from .generation_customer_test_conversion import FixedTestnetConversion

_P2_MOD_BYTES=bytes(_P2_MOD)


def current_customer_xch_quote(*,inventory:CurrentPrimaryInventory,vault:CurrentCustomerVault,
        deed_launcher:bytes32,price:SignedPrimaryPrice,nonce:bytes32,now:int,expires_at:int,
        proceeds=None,forwarding_policy=None):
    if (not isinstance(inventory,CurrentPrimaryInventory) or not isinstance(vault,CurrentCustomerVault)
            or inventory.generation!=vault.generation or not vault.identity_verified):
        raise ValueError('CURRENT_PURCHASE_FRESH_ID_REQUIRED')
    if (type(now)is not int or type(expires_at)is not int or not now<expires_at<=now+300
            or not isinstance(nonce,bytes32) or nonce==bytes32.zeros):
        raise ValueError('CURRENT_PURCHASE_REVIEW_WINDOW_CHANGED')
    item=inventory.require_available(deed_launcher)
    terms=item.original.terms
    if (terms.collection_id!=inventory.collection or terms.metadata_root!=inventory.metadata_root
            or terms.metadata_anchor_id!=inventory.edition or terms.network!='testnet11'
            or terms.inventory_version!=4 or not terms.generation_batch_bindings):
        raise ValueError('CURRENT_PURCHASE_MINT_BINDING_CHANGED')
    bindings=list(Program.from_bytes(terms.generation_batch_bindings).as_iter())
    if len(bindings)!=8 or bindings[0].as_atom()!=bytes(inventory.generation):
        raise ValueError('CURRENT_PURCHASE_GENERATION_BINDING_CHANGED')
    # Both pools are reconstructed from native state, never from a request.
    vault_fields=list(vault.inner.uncurry()[1].as_iter())
    if len(vault_fields)!=9 or vault_fields[7].as_atom()!=bytes(inventory.pool_launcher_id):
        raise ValueError('CURRENT_PURCHASE_VAULT_POOL_CHANGED')
    statutes=[history.state for history in inventory.evidence.economic_components.values()
              if isinstance(history.state,GenerationStatutes)]
    if len(statutes)!=1 or statutes[0].generation!=inventory.generation:
        raise ValueError('CURRENT_PURCHASE_STATUTES_UNAVAILABLE')
    if inventory.evidence.registry.state.pause_mask & 8:
        raise ValueError('CURRENT_PRIMARY_PURCHASES_PAUSED')
    if isinstance(price,FixedTestnetConversion):
        price.verify_policy(forwarding_policy,now=now,expires_at=expires_at)
    else:
        if (not isinstance(price,SignedPrimaryPrice)or not price.round.valid_from<=now
                or getattr(forwarding_policy,'test_usd_minor_per_txch',None)is not None):
            raise ValueError('CURRENT_PURCHASE_PRICE_UNAVAILABLE')
        operators=tuple(value.as_atom() for value in bindings[7].as_iter())
        price.verify(operators,asset=bytes32.zeros,decimals=12,expires_at=expires_at,
            maximum_age=statutes[0].values[1])
    if terms.technology_fee_bps!=100:
        raise ValueError('CURRENT_PURCHASE_FEE_REVIEW_REQUIRED')
    # Native acceptance exposed a historical route that pays gross to a wallet
    # and never funds the technology-fee splitter. Never quote that route as an
    # enabled purchase. A preimage must match the *actual immutable* inventory
    # destination and the current generation's separate company/reward custody.
    if proceeds is None and forwarding_policy is None:
        raise ValueError('CURRENT_PURCHASE_FEE_ROUTE_UNSUPPORTED')
    from solslot_puzzles.generation_primary_proceeds import PrimaryProceedsSplitter
    from solslot_puzzles.generation_revenue import CompanyRevenue,PrimaryFeeSplitter
    expected_fees=PrimaryFeeSplitter(inventory.evidence.governance.state.sgt,statutes[0].launcher_id,
        CompanyRevenue(inventory.generation,inventory.evidence.registry.state.administrator_id))
    if forwarding_policy is not None:
        from .generation_customer_issuer import TestnetIssuerPolicy
        from .generation_customer_collection_policy import TestnetCollectionIssuerPolicy
        from chia_rs import G1Element
        if proceeds is not None or not isinstance(forwarding_policy,(TestnetIssuerPolicy,TestnetCollectionIssuerPolicy)):
            raise ValueError('CURRENT_PURCHASE_FEE_ROUTE_CHANGED')
        if isinstance(forwarding_policy,TestnetIssuerPolicy):
            forwarding_policy.require_terms(terms,now=now)
            if forwarding_policy.buyer_vault!=vault.launcher or expires_at>forwarding_policy.expires_at:
                raise ValueError('CURRENT_PURCHASE_FEE_ROUTE_CHANGED')
        else:
            forwarding_policy.require_terms(terms)
            forwarding_policy.require_verified_vault(vault,launcher=vault.launcher,auth_type='chia_bls')
        if (forwarding_policy.generation!=inventory.generation
                or forwarding_policy.collection!=inventory.collection or forwarding_policy.edition!=inventory.edition
                or forwarding_policy.metadata_root!=inventory.metadata_root
                or expected_fees.inner().get_tree_hash()!=forwarding_policy.fee_puzzle
                or Program.from_bytes(_P2_MOD_BYTES).curry(G1Element.from_bytes(forwarding_policy.issuer_public_key)).get_tree_hash()!=terms.protocol_puzhash):
            raise ValueError('CURRENT_PURCHASE_FEE_ROUTE_CHANGED')
        proceeds=PrimaryProceedsSplitter.for_terms(terms.protocol_puzhash,expected_fees,
            terms.base_amount_minor,terms.technology_fee_minor)
    if (not isinstance(proceeds,PrimaryProceedsSplitter)
            or proceeds.generation!=inventory.generation
            or proceeds.fees.bindings!=inventory.evidence.governance.state.sgt
            or proceeds.fees.statutes_id!=statutes[0].launcher_id
            or proceeds.fees.revenue!=CompanyRevenue(inventory.generation,inventory.evidence.registry.state.administrator_id)
            or proceeds.fees.inner().get_tree_hash()!=terms.protocol_treasury_puzzle_hash
            or proceeds.principal_weight*terms.technology_fee_minor!=proceeds.fee_weight*terms.base_amount_minor
            or (forwarding_policy is None and proceeds.inner().get_tree_hash()!=terms.protocol_puzhash)
            or tuple(statutes[0].values[2:5])!=(100,70,30)):
        raise ValueError('CURRENT_PURCHASE_FEE_ROUTE_CHANGED')
    quote=build_xch_purchase_artifact(network='testnet11',collection_id=terms.collection_id,
        deed_launcher_id=terms.deed_launcher_id,metadata_root=terms.metadata_root,
        metadata_anchor_id=terms.metadata_anchor_id,share_ppm=terms.share_ppm,
        base_amount_minor=terms.base_amount_minor,technology_fee_bps=terms.technology_fee_bps,
        protocol_treasury_puzzle_hash=terms.protocol_treasury_puzzle_hash,
        zkpassport_root=vault.root,vault_launcher_id=vault.launcher,
        vault_p2_puzzle_hash=puzzle_for_p2_vault(vault.launcher).get_tree_hash(),
        authorization_nonce=nonce,authorization_expires_at=expires_at,
        quote_expires_at=expires_at,oracle_round=price.round)
    if forwarding_policy is not None and isinstance(forwarding_policy,TestnetCollectionIssuerPolicy):
        forwarding_policy.require_purchase(quote,terms,vault,launcher=vault.launcher,auth_type='chia_bls',now=now)
    if forwarding_policy is not None and int(quote.rail_amount)>forwarding_policy.maximum_gross_mojos:
        raise ValueError('CURRENT_PURCHASE_ISSUER_AMOUNT_CAP')
    return quote
