"""Collection destinations come from the generation's frozen native authority."""
from .generation_index import load_generation_read_anchor
from solslot_puzzles.generation_mint import GenerationMint


def collection_mint_authority(settings):
    if not settings.deployment_generation_id:
        return None
    if settings.network != 'testnet11':
        raise ValueError('Test edition authority requires Testnet11')
    anchor = load_generation_read_anchor(settings)
    matches = [m for m in anchor.economic_components if isinstance(m, GenerationMint)
        and m.launcher_id == anchor.governance.mint_id and m.component() in anchor.registry.components]
    if len(matches) != 1 or '0x'+matches[0].generation.hex() != settings.deployment_generation_id:
        raise ValueError('Confirmed generation mint authority is unavailable')
    mint = matches[0]
    return {'generationId':settings.deployment_generation_id, 'network':'testnet11',
        'componentId':'0x'+mint.component_id.hex(), 'treasuryPuzzleHash':'0x'+mint.treasury_puzzle_hash.hex()}
