#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "$0")/.." && pwd)
exec "${PQCFUZZ_PYTHON:-python3}" "$repo_root/scripts/pqcfuzz_target.py" "${1:-run}" --target kex-01 --algorithm ADKEX --parameter-set ADKEX-128 --api kex_derive_ss_a+b --profile gcc-reference "${@:2}"
