#!/usr/bin/env bash
set -euo pipefail

python_bin="${PYTHON:-python}"

"$python_bin" -m pip check
"$python_bin" -m pip_audit \
  --skip-editable \
  --progress-spinner off
