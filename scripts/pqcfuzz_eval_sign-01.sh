#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "$0")/.." && pwd)
exec "${PQCFUZZ_PYTHON:-python3}" "$repo_root/scripts/pqcfuzz_target.py" "${1:-run}" --target sign-01 --algorithm Aigis-Sig+ --parameter-set Aigis-Sig+-I --api sig_verify --profile gcc-reference "${@:2}"
