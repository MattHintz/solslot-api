"""Configuration owned exclusively by an isolated validator signer."""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Literal, Any

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


_HEX32_RE = re.compile(r"^(0x)?[0-9a-fA-F]{64}$")
_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_PUBKEY_RE = re.compile(r"^(0x)?[0-9a-fA-F]{96}$")


class ValidatorSettings(BaseSettings):
    """Fail-closed signer settings.

    The signer uses a dedicated prefix and intentionally does not read an env
    file. Systemd supplies non-secret configuration and a path to a credential
    file; the seed itself never enters the process environment.
    """

    model_config = SettingsConfigDict(
        env_prefix="SOLSLOT_VALIDATOR_",
        env_file=None,
        extra="ignore",
    )

    deployment_environment: Literal["staging-alpha", "production-alpha"] | None = None

    signer_index: int = Field(..., ge=0, le=2)
    seed_file: str
    ledger_db_path: str = "./state/validator_signatures_v2.db"
    public_artifact_path: str = "./state/public_artifact_v4.json"
    release_metadata_path: str = "./release.json"

    network: Literal["testnet11"] = "testnet11"
    coinset_base_url: str = "https://testnet11.api.coinset.org"
    evm_rpc_url: str
    evm_chain_id: int = 11155111
    enrollment_activation: dict[str, Any] | None = None
    evm_min_confirmations: int = Field(12, ge=12, le=12)
    proof_max_age_seconds: int = Field(7 * 24 * 60 * 60, ge=3600, le=7 * 24 * 60 * 60)
    claim_clock_skew_seconds: int = Field(90, ge=10, le=300)

    bridge_policy_hash: str
    roster_pubkeys: list[str] = Field(min_length=3, max_length=3)
    evm_forwarder_address: str
    evm_verifier_adapter_address: str
    evm_attestation_emitter_address: str
    base_sepolia_rpc_url: str = ""
    base_sepolia_spoke_address: str = ""
    base_sepolia_usdc_address: str = ""
    base_return_puzzle_hash: str = ""
    base_sepolia_min_confirmations: int = Field(12, ge=12, le=100)
    stripe_settlement_enabled: bool = False
    stripe_account_id: str = ""
    stripe_mode: Literal["test", "live"] = "test"
    stripe_restricted_key_file: str = ""
    stripe_api_url: str = "https://api.stripe.com"

    @field_validator("evm_chain_id", mode="before")
    @classmethod
    def _enrollment_chain(cls, value: Any) -> int:
        # BaseSettings receives numeric environment values as text.
        if isinstance(value, str) and value in ("11155111", "84532"):
            return int(value)
        if type(value) is int and value in (11155111, 84532):
            return value
        raise ValueError("enrollment chain must be Ethereum Sepolia or selected Base Sepolia")

    @field_validator("bridge_policy_hash")
    @classmethod
    def _hex32(cls, value: str) -> str:
        if not _HEX32_RE.fullmatch(value):
            raise ValueError("bridge_policy_hash must be a 32-byte hex value")
        return "0x" + value.removeprefix("0x").lower()

    @field_validator("roster_pubkeys")
    @classmethod
    def _pubkeys(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            if not _PUBKEY_RE.fullmatch(value):
                raise ValueError("roster_pubkeys entries must be 48-byte hex values")
            normalized.append("0x" + value.removeprefix("0x").lower())
        if len(set(normalized)) != 3:
            raise ValueError("roster_pubkeys must contain three distinct keys")
        return normalized

    @field_validator(
        "evm_forwarder_address",
        "evm_verifier_adapter_address",
        "evm_attestation_emitter_address",
    )
    @classmethod
    def _address(cls, value: str) -> str:
        if not _ADDRESS_RE.fullmatch(value):
            raise ValueError("EVM addresses must be 0x-prefixed 20-byte values")
        return value.lower()

    @model_validator(mode="after")
    def _permit_deployment(self) -> "ValidatorSettings":
        if self.enrollment_activation is None:
            if self.evm_chain_id != 11155111:
                raise ValueError("Base Sepolia enrollment requires complete activation evidence")
            return self
        from solslot_puzzles.enrollment_activation import validate_enrollment_activation
        value = self.enrollment_activation
        if self.evm_chain_id != 84532 or self.deployment_environment is None:
            raise ValueError("permit signer requires an explicit alpha environment and Base Sepolia")
        try:
            checked = validate_enrollment_activation(value, source_shas=value["sourceShas"],
                ceremony_id=value["deploymentId"], emitter=self.evm_attestation_emitter_address,
                validator_pubkeys=[bytes.fromhex(k[2:]) for k in self.roster_pubkeys],
                environment=self.deployment_environment)
        except (KeyError, TypeError) as exc:
            raise ValueError("permit signer activation evidence is incomplete") from exc
        if checked["bridgePolicyHash"] != self.bridge_policy_hash:
            raise ValueError("permit signer bridge policy does not reconstruct")
        self.enrollment_activation = checked
        return self

    @model_validator(mode="after")
    def _https_endpoints(self) -> "ValidatorSettings":
        if not self.coinset_base_url.startswith("https://"):
            raise ValueError("coinset_base_url must use HTTPS")
        if not self.evm_rpc_url.startswith("https://"):
            raise ValueError("evm_rpc_url must use HTTPS")
        if self.base_sepolia_rpc_url and not self.base_sepolia_rpc_url.startswith(
            "https://"
        ):
            raise ValueError("base_sepolia_rpc_url must use HTTPS")
        if not self.stripe_api_url.startswith("https://"):
            raise ValueError("stripe_api_url must use HTTPS")
        for value, label in (
            (self.base_sepolia_spoke_address, "base_sepolia_spoke_address"),
            (self.base_sepolia_usdc_address, "base_sepolia_usdc_address"),
        ):
            if value and not _ADDRESS_RE.fullmatch(value):
                raise ValueError(f"{label} must be a 20-byte EVM address")
        if self.base_return_puzzle_hash and not _HEX32_RE.fullmatch(
            self.base_return_puzzle_hash
        ):
            raise ValueError("base_return_puzzle_hash must be a 32-byte hash")
        if self.base_sepolia_rpc_url and not self.base_return_puzzle_hash:
            raise ValueError(
                "Base settlement requires the reviewed return puzzle hash"
            )
        if self.stripe_settlement_enabled:
            if not self.stripe_account_id.startswith("acct_"):
                raise ValueError(
                    "Stripe settlement requires a configured Stripe account ID"
                )
            if not self.stripe_restricted_key_file:
                raise ValueError(
                    "Stripe settlement requires a restricted read-key file"
                )
        return self


@lru_cache(maxsize=1)
def get_validator_settings() -> ValidatorSettings:
    return ValidatorSettings()


__all__ = ["ValidatorSettings", "get_validator_settings"]
