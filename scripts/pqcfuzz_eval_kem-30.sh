#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "$0")/.." && pwd)
exec "${PQCFUZZ_PYTHON:-python3}" "$repo_root/scripts/pqcfuzz_target.py" "${1:-run}" --target kem-30 --algorithm PolarLAC --parameter-set POLARLAC-128 --api kem_dec --profile gcc-reference "${@:2}"
