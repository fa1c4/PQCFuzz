#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "$0")/.." && pwd)
exec "${PQCFUZZ_PYTHON:-python3}" "$repo_root/scripts/pqcfuzz_target.py" "${1:-run}" --target hash-15 --algorithm Litchi --parameter-set Litchi-XOF --api CryptHash --profile gcc-core-wrapper "${@:2}"
