#!/usr/bin/env python3
"""Regenerate the SIKE/SIDH reference fixtures from the pinned source.

Usage:
    python3 scripts/generate_sike_sidh_fixtures.py [--binary-root DIR]

The hook CLI is rebuilt under --binary-root (default /tmp/pqcfuzz_sike_fixtures)
and the JSON fixtures are written to tests/fixtures/sike_sidh/.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
TESTS_ROOT = REPO_ROOT / "tests"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))
if str(TESTS_ROOT) not in sys.path:
    sys.path.insert(0, str(TESTS_ROOT))

import _sike_util as util  # noqa: E402

KAT_RESPONSES = {
    "SIKE-p434": "PQCkemKAT_374.rsp",
    "SIKE-p503": "PQCkemKAT_434.rsp",
    "SIKE-p610": "PQCkemKAT_524.rsp",
    "SIKE-p751": "PQCkemKAT_644.rsp",
}


def parse_kat(path: Path, limit: int = 3) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("count ="):
            if current:
                records.append(current)
                if len(records) >= limit:
                    return records
                current = {}
            continue
        if " = " in line:
            key, value = line.split(" = ", 1)
            current[key] = value
    if current and len(records) < limit:
        records.append(current)
    return records


def run_cli(binary: Path, *args: str) -> dict[str, str]:
    output = subprocess.run([str(binary), *args], cwd=util.REPO_ROOT, check=True, capture_output=True, text=True)
    result: dict[str, str] = {}
    for line in output.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            result[key.strip()] = value.strip()
    return result


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary-root", default="/tmp/pqcfuzz_sike_fixtures")
    args = parser.parse_args()
    binary_root = Path(args.binary_root)
    binary_root.mkdir(parents=True, exist_ok=True)
    fixture_dir = REPO_ROOT / "tests" / "fixtures" / "sike_sidh"
    fixture_dir.mkdir(parents=True, exist_ok=True)

    kat_records: dict[str, list[dict[str, str]]] = {}
    sidh_records: dict[str, dict[str, str]] = {}
    case_records: dict[str, dict[str, object]] = {}

    for algorithm, response in KAT_RESPONSES.items():
        binary = util.compile_hook_cli(algorithm, binary_root / algorithm)
        entry = util.PARAMS[algorithm]
        parsed = parse_kat(util.SIKE_ROOT / "KAT" / response)
        verified: list[dict[str, str]] = []
        for record in parsed:
            got = run_cli(binary, "kat", record["seed"])
            for field in ("pk", "sk", "ct", "ss"):
                assert got[field].lower() == record[field].lower(), (algorithm, field)
            verified.append(
                {
                    "seed": record["seed"].lower(),
                    "pk": record["pk"].lower(),
                    "sk": record["sk"].lower(),
                    "ct": record["ct"].lower(),
                    "ss": record["ss"].lower(),
                }
            )
        kat_records[entry["suffix"]] = verified

        # Deterministic SIDH transcript for the same parameter set.
        sidh_pk = entry["pk_len"]
        scalar_a = bytearray((0x11 + i * 7) & 0xFF for i in range(entry["sk_a_len"]))
        scalar_b = bytearray((0x89 + i * 5) & 0xFF for i in range(entry["sk_b_len"]))
        a_bits = entry["e2"]
        b_bits = (3 ** entry["e3"]).bit_length() - 1
        scalar_a[-1] &= (1 << (a_bits % 8)) - 1 if a_bits % 8 else 0xFF
        scalar_b[-1] &= (1 << (b_bits % 8)) - 1 if b_bits % 8 else 0xFF
        scalar_a = bytes(scalar_a)
        scalar_b = bytes(scalar_b)
        result = run_cli(binary, "sidh", scalar_a.hex(), scalar_b.hex())
        assert result["shared_a"] == result["shared_b"], algorithm
        assert len(result["pk_a"]) == sidh_pk * 2 and len(result["shared_a"]) == entry["shared_len"] * 2
        sidh_records[entry["suffix"]] = {
            "scalar_a": scalar_a.hex(),
            "scalar_b": scalar_b.hex(),
            "pk_a": result["pk_a"],
            "pk_b": result["pk_b"],
            "shared_a": result["shared_a"],
            "shared_b": result["shared_b"],
        }

        # Baseline plus a c1-flipped gate candidate for the model lane.
        coins = bytes((0x42 + i * 3) & 0xFF for i in range(96))
        baseline = run_cli(binary, "derive", coins.hex())
        ct = bytes.fromhex(baseline["ct"])
        fail_ct = bytearray(ct)
        fail_ct[entry["pk_len"]] ^= 0x01
        baseline_gate = run_cli(binary, "gate", baseline["sk"], baseline["ct"])
        gate = run_cli(binary, "gate", baseline["sk"], bytes(fail_ct).hex())
        case_records[entry["suffix"]] = {
            "coins": coins.hex(),
            "pk": baseline["pk"],
            "sk": baseline["sk"],
            "ct": baseline["ct"],
            "ss": baseline["ss"],
            "baseline_gate": baseline_gate["gate"],
            "baseline_m": baseline_gate["m"],
            "baseline_r": baseline_gate["r"],
            "baseline_expected": baseline_gate["expected"],
            "fail_ct": bytes(fail_ct).hex(),
            "fail_gate": gate["gate"],
            "fail_m": gate["m"],
            "fail_r": gate["r"],
            "fail_expected": gate["expected"],
        }
        print(f"verified {algorithm}: {len(verified)} KAT records, gate={gate['gate']}")

    kat_path = fixture_dir / "sike_kat_reference.json"
    kat_path.write_text(
        json.dumps(
            {
                "family": "SIKE",
                "source": "microsoft/PQCrypto-SIDH @ 98a028a KAT/PQCkemKAT_*.rsp (first three records)",
                "records": kat_records,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    sidh_path = fixture_dir / "sidh_reference.json"
    sidh_path.write_text(
        json.dumps(
            {
                "family": "SIDH",
                "source": "deterministic transcripts generated from the pinned generic reference",
                "records": sidh_records,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    cases_path = fixture_dir / "sike_cases.json"
    cases_path.write_text(
        json.dumps(
            {
                "family": "SIKE",
                "source": "deterministic coins; gate classification from the pinned isogeny reference",
                "records": case_records,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    for path in (kat_path, sidh_path, cases_path):
        print(f"wrote {path.relative_to(REPO_ROOT)} sha256={sha256_file(path)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
