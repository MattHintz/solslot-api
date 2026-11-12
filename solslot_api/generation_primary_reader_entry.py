"""Private reader startup. Full-node credentials stay on their existing host."""
import os

from .chia_provider import ChiaProviderConfig, create_chia_provider
from .generation_primary_reader_app import create_primary_reader_app


def local_reader_provider(*, ca, cert, key):
    if not all(type(path) is str and path.startswith('/') for path in (ca, cert, key)):
        raise ValueError('LOCAL_PRIMARY_READER_TLS_PATHS_REQUIRED')
    return create_chia_provider(ChiaProviderConfig(network='testnet11',
        primary_url='https://127.0.0.1:18555',
        fallback_url='https://127.0.0.1:18555', primary_required=True,
        primary_ca_cert_path=ca, primary_client_cert_path=cert,
        primary_client_key_path=key))


def create_app():
    return create_primary_reader_app(provider=local_reader_provider(
        ca=os.environ['SOLSLOT_NATIVE_READER_CA'],
        cert=os.environ['SOLSLOT_NATIVE_READER_CERT'],
        key=os.environ['SOLSLOT_NATIVE_READER_KEY']))
