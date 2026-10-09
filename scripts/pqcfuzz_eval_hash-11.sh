#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "$0")/.." && pwd)
exec "${PQCFUZZ_PYTHON:-python3}" "$repo_root/scripts/pqcfuzz_target.py" "${1:-run}" --target hash-11 --algorithm Garnet --parameter-set Garnet_512_Cap1024 --api CryptHash --profile gcc-reference "${@:2}"
