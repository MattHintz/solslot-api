"""Read-only primary-node transport for the private generation signers.

The endpoint is the retained full node, through a private TLS gateway on its
own host. This is never a coordinator projection or an advisory fallback.
Signing still uses the separate, existing mutual-TLS signer boundary.
"""
from __future__ import annotations

import json
import re
import ssl
from pathlib import Path

from .chia_provider import ChiaProvider, ChiaProviderConfig, ChiaProviderError
from .coinset_client import CoinsetClient


PRIMARY_READER_URL = 'https://10.77.0.10:9543/v1/generation/chain'
HEX32 = re.compile(r'^0x[0-9a-f]{64}$')
READ_METHODS = frozenset(('get_network_info', 'get_blockchain_state',
    'get_coin_record_by_name', 'get_puzzle_and_solution', 'get_block_record'))


def checked_read(method, body):
    if method not in READ_METHODS or type(body) is not dict:
        raise ValueError('PRIMARY_READER_METHOD_REJECTED')
    fields = {'get_network_info': (), 'get_blockchain_state': (),
        'get_coin_record_by_name': ('name',),
        'get_puzzle_and_solution': ('coin_id', 'height'),
        'get_block_record': ('header_hash',)}[method]
    if set(body) != set(fields):
        raise ValueError('PRIMARY_READER_PARAMETERS_REJECTED')
    for key in fields:
        value = body[key]
        if key == 'height':
            if type(value) is not int or not 0 < value < 2**32:
                raise ValueError('PRIMARY_READER_PARAMETERS_REJECTED')
        elif type(value) is not str or not HEX32.fullmatch(value):
            raise ValueError('PRIMARY_READER_PARAMETERS_REJECTED')
    return body


def decode_request(raw):
    if len(raw) > 512:
        raise ValueError('PRIMARY_READER_REQUEST_TOO_LARGE')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('PRIMARY_READER_DUPLICATE_PARAMETER')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=unique)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError('PRIMARY_READER_PARAMETERS_REJECTED') from exc


class PrimaryReadClient(CoinsetClient):
    async def _post(self, path, body):
        checked_read(path.removeprefix('/'), body)
        return await super()._post(path, body)


class ReadOnlyChiaProvider(ChiaProvider):
    async def close(self):
        await self.primary.close()

    async def push_tx(self, *_args, **_kwargs):
        raise ChiaProviderError('PRIMARY_READER_CANNOT_BROADCAST')

    async def push_tx_confirmed_in_primary_mempool(self, *_args, **_kwargs):
        raise ChiaProviderError('PRIMARY_READER_CANNOT_BROADCAST')


def private_primary_reader(settings):
    if (settings.network != 'testnet11' or settings.generation_primary_url != PRIMARY_READER_URL
            or not settings.generation_primary_ca_cert_path
            or settings.generation_primary_client_cert_path
            or settings.generation_primary_client_key_path):
        raise ValueError('EXACT_PRIVATE_PRIMARY_READER_REQUIRED')
    ca = Path(settings.generation_primary_ca_cert_path)
    context = ssl.create_default_context(cafile=str(ca))
    # SAN 10.77.0.10 and the existing private CA are both checked. No client
    # credential is copied: WireGuard authenticates the restricted reader IPs.
    primary = PrimaryReadClient(PRIMARY_READER_URL, timeout=15,
        ssl_context=context, provider_label='private-native-primary-reader')
    # There is deliberately no separately reachable fallback. Primary-only
    # proof calls fail closed, and both broadcast methods reject before I/O.
    return ReadOnlyChiaProvider(primary, primary, ChiaProviderConfig(
        network='testnet11', primary_url=PRIMARY_READER_URL,
        fallback_url=PRIMARY_READER_URL, primary_required=True))
