"""Settings for the isolated enrollment issuer, never the public coordinator."""
from __future__ import annotations

import ipaddress
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def require_tls_file(value: str, *, private: bool = False) -> str:
    path = Path(value)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError('Issuer TLS files must be absolute regular files, not symlinks.')
    if private and path.stat().st_mode & 0o077:
        raise ValueError('Issuer TLS private keys must not be accessible by group or other.')
    return str(path)


def private_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_loopback or any(address in ipaddress.ip_network(cidr) for cidr in
        (('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16') if address.version == 4 else ('fc00::/7',)))


class EnrollmentSignerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix='SOLSLOT_ENROLLMENT_SIGNER_', env_file=None, extra='ignore')
    signing_enabled: bool = False
    bind_host: str = '127.0.0.1'
    bind_port: Literal[8793] = 8793
    tls_cert_file: str = ''
    tls_key_file: str = ''
    tls_client_ca_file: str = ''
    tls_client_cert_sha256: str = Field('', pattern=r'^(?:[0-9a-f]{64})?$')
    public_artifact_path: str = './state/public_artifact_v4.json'
    expected_artifact_hash: str = ''
    release_metadata_path: str = './release.json'
    runtime_environment: Literal['staging', 'production'] = 'production'
    network: Literal['testnet11'] = 'testnet11'
    zkpassport_evm_chain_id: Literal[8453] = 8453
    enrollment_permit_release_identity: str = ''
    enrollment_permit_issuer_key_ref: str = ''
    enrollment_permit_identity_client_id: str = ''
    expected_context_hash: str = ''
    expected_emitter: str = ''
    expected_issuer: str = ''

    @model_validator(mode='after')
    def private_listener(self) -> 'EnrollmentSignerSettings':
        if not private_ip(self.bind_host):
            raise ValueError('Enrollment issuer must bind a loopback or private IP.')
        return self

    @property
    def alpha_writes_enabled(self) -> bool:
        # Compatibility with the existing Key Vault transport's gate. This
        # role has no coordinator, payment, validator, ledger or mint routes.
        return self.signing_enabled

    def require_mtls_listener(self) -> tuple[str, str, str]:
        if not self.tls_client_cert_sha256 or self.tls_client_cert_sha256 == '0' * 64:
            raise ValueError('Enrollment issuer requires the exact coordinator client certificate SHA-256.')
        return (require_tls_file(self.tls_cert_file), require_tls_file(self.tls_key_file, private=True),
            require_tls_file(self.tls_client_ca_file))


@lru_cache(maxsize=1)
def get_enrollment_signer_settings() -> EnrollmentSignerSettings:
    return EnrollmentSignerSettings()
