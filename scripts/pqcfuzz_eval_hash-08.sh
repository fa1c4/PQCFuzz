#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "$0")/.." && pwd)
exec "${PQCFUZZ_PYTHON:-python3}" "$repo_root/scripts/pqcfuzz_target.py" "${1:-run}" --target hash-08 --algorithm Duet --parameter-set Duet-512 --api CryptHash --profile gcc-ref-opt "${@:2}"
