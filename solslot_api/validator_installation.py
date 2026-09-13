"""Read-only artifact installation preflight against the complete signer config."""
from __future__ import annotations
import json
import shlex
import subprocess
from pathlib import Path
from .validator_settings import ValidatorSettings
from .validator_service import load_validator_artifact


class _InstallationSettings(ValidatorSettings):
    @classmethod
    def settings_customise_sources(cls, settings_cls, init_settings, env_settings, dotenv_settings, file_secret_settings):
        # Install checks use only the supplied file, never the operator shell.
        return (init_settings,)


def validator_unit_environment() -> dict[str, str]:
    """Read only unit-owned credential references and index, never credential values."""
    raw = subprocess.check_output(['systemctl','show','--property','Environment','--value',
        'solslot-validator.service'], text=True)
    allowed = {'signer_index','seed_file','stripe_restricted_key_file'}
    result = {}
    for item in shlex.split(raw):
        name, sep, value = item.partition('=')
        if sep and name.startswith('SOLSLOT_VALIDATOR_'):
            field = name.removeprefix('SOLSLOT_VALIDATOR_').lower()
            if field in allowed:
                if field in result:
                    raise ValueError('validator unit has duplicate credential or signer metadata')
                result[field] = value
    return result


def validate_install_candidate(environment_file: str, artifact_path: str, release_path: str,
        *, unit_environment: dict[str, str] | None = None) -> str:
    values = {}
    prefix = 'SOLSLOT_VALIDATOR_'
    for raw in Path(environment_file).read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if '=' not in line:
            raise ValueError('validator environment contains a malformed line')
        name, value = line.split('=', 1)
        field = name.removeprefix(prefix).lower()
        if not name.startswith(prefix) or field not in ValidatorSettings.model_fields or field in values:
            raise ValueError('validator environment has an unknown or duplicate field')
        values[field] = json.loads(value) if field in ('roster_pubkeys','enrollment_activation') else value
    unit = unit_environment or {}
    if set(unit) - {'signer_index','seed_file','stripe_restricted_key_file'}:
        raise ValueError('unsupported validator unit configuration')
    # EnvironmentFile values override unit Environment values, as in systemd.
    values = {**unit, **values}
    # The seed is a systemd credential. Artifact validation does not read it.
    values['seed_file'] = '/not-read-by-artifact-install-preflight'
    values['public_artifact_path'] = artifact_path
    values['release_metadata_path'] = release_path
    settings = _InstallationSettings(**values)
    artifact, _ = load_validator_artifact(settings)
    return str(artifact['artifactHash'])
