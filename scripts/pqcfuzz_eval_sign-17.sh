#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "$0")/.." && pwd)
exec "${PQCFUZZ_PYTHON:-python3}" "$repo_root/scripts/pqcfuzz_target.py" "${1:-run}" --target sign-17 --algorithm 'OPS Digital Signature Algorithm' --parameter-set OPSsig-128 --api sig_verify --profile gcc-reference "${@:2}"
