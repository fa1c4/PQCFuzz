#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "$0")/.." && pwd)
exec "${PQCFUZZ_PYTHON:-python3}" "$repo_root/scripts/pqcfuzz_target.py" "${1:-run}" --target kem-27 --algorithm 'NTRE Key Encapsulation Mechanism' --parameter-set NTRE-128 --api kem_dec --profile gcc-reference "${@:2}"
