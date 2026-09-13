#!/usr/bin/env bash
set -euo pipefail
umask 077

[ "$#" -eq 1 ] || { echo "usage: sudo $0 SIGNED_ARTIFACT_JSON" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

artifact="$(readlink -f "$1")"
[ -f "$artifact" ] || { echo "signed artifact is missing" >&2; exit 1; }
release_dir="$(readlink -f /opt/solslot/validator/current)"
[ -d "$release_dir" ] || { echo "validator release is not installed" >&2; exit 1; }
environment_file=/etc/solslot-validator/validator.env
[ -f "$environment_file" ] || { echo "validator environment is missing" >&2; exit 1; }

target="$(
  "$release_dir/.venv/bin/python" - "$environment_file" <<'PY'
import pathlib
import sys

key = "SOLSLOT_VALIDATOR_PUBLIC_ARTIFACT_PATH"
values = []
for raw_line in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    line = raw_line.strip()
    if not line or line.startswith("#"):
        continue
    if "=" not in line:
        raise SystemExit("validator environment contains a malformed line")
    name, value = line.split("=", 1)
    if name == key:
        values.append(value)
if len(values) != 1:
    raise SystemExit(f"validator environment must define {key} exactly once")
target = pathlib.Path(values[0])
if not target.is_absolute():
    raise SystemExit("validator public artifact path must be absolute")
print(target)
PY
)"
[ -d "$(dirname "$target")" ] || { echo "validator artifact directory is missing" >&2; exit 1; }

artifact_hash="$(
  "$release_dir/.venv/bin/python" - "$environment_file" "$artifact" "$release_dir/release.json" <<'PY'
import sys
from solslot_api.validator_installation import validate_install_candidate, validator_unit_environment
try:
    artifact_hash = validate_install_candidate(*sys.argv[1:], unit_environment=validator_unit_environment())
except Exception:
    raise SystemExit("candidate artifact does not match the complete installed signer configuration") from None
print(artifact_hash)
PY
)"

temporary="$(mktemp "$(dirname "$target")/.public-artifact.XXXXXX")"
trap 'rm -f "$temporary"' EXIT
install -m 0640 -o solslot-validator -g solslot-validator "$artifact" "$temporary"
mv -f "$temporary" "$target"
trap - EXIT
systemctl restart solslot-validator.service
systemctl is-active --quiet solslot-validator.service
main_pid="$(systemctl show --property MainPID --value solslot-validator.service)"
[ "$main_pid" -gt 0 ] || { echo "validator service has no running process" >&2; exit 1; }
runtime_target="$(
  "$release_dir/.venv/bin/python" - "$main_pid" <<'PY'
import pathlib
import sys

environment = pathlib.Path(f"/proc/{int(sys.argv[1])}/environ").read_bytes()
prefix = b"SOLSLOT_VALIDATOR_PUBLIC_ARTIFACT_PATH="
values = [item[len(prefix):] for item in environment.split(b"\0") if item.startswith(prefix)]
if len(values) != 1:
    raise SystemExit("running validator lacks one effective public artifact path")
print(values[0].decode("utf-8"))
PY
)"
[ "$runtime_target" = "$target" ] || {
  echo "running validator reads a different public artifact path" >&2
  exit 1
}
echo "Artifact installed; authenticated fleet health must still pass from the coordinator." >&2
printf '%s\n' "$artifact_hash"
