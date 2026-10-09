#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "$0")/.." && pwd)
exec "${PQCFUZZ_PYTHON:-python3}" "$repo_root/scripts/pqcfuzz_target.py" "${1:-run}" --target kem-02 --algorithm Amoeba --parameter-set Amoeba-576 --api kem_dec --profile gcc-reference "${@:2}"
