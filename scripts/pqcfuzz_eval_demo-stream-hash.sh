#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "$0")/.." && pwd)
exec "${PQCFUZZ_PYTHON:-python}" "$repo_root/scripts/pqcfuzz_target.py" "${1:-run}" --target demo-stream-hash --algorithm DEMO-HASH --api stream "${@:2}"
