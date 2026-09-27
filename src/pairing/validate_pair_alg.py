#!/usr/bin/env python3
"""Validate an externally supplied PQCFuzz pair_alg file."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from pairing.pair_alg_loader import PairAlgError, load_pair_alg


DEFAULT_PAIR_ALG = Path("src/config/pair_alg.default.json")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pair-alg", default=str(DEFAULT_PAIR_ALG), help="explicit algorithm-pair JSON")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    document = load_pair_alg(args.pair_alg)
    enabled = [pair for pair in document["pairs"] if pair["status"] == "enabled"]
    print(f"validated {args.pair_alg}: {len(document['pairs'])} pairs, {len(enabled)} enabled")
    for pair in enabled:
        contract = pair["exchange_contract"]
        if pair["primitive_type"] == "kem":
            detail = (
                f"pk={contract.get('public_key_exchange')} ct={contract.get('ciphertext_exchange')} "
                f"sk={contract.get('secret_key_exchange')}"
            )
        elif pair["primitive_type"] == "kex":
            detail = (
                f"pk={contract.get('public_key_exchange')} peer={contract.get('peer_key_exchange')} "
                f"sk={contract.get('secret_key_exchange')}"
            )
        else:
            detail = f"pk={contract.get('public_key_exchange')} sig={contract.get('signature_exchange')}"
        print(f"  {pair['pair_id']}: {pair['algorithm']} {detail}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PairAlgError as exc:
        print(f"validate_pair_alg error: {exc}", file=sys.stderr)
        raise SystemExit(1)
