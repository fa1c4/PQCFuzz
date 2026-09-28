#!/usr/bin/env python3
"""Extract SNOVA round-2 KAT fixtures from the official PQCLAB-SNOVA/SNOVA_KAT tree.

The official response files are ~20 MB each, so only the first record (count = 0)
of every parameter-set/backend/secret-key-format combination is materialized.
Public keys, signed messages and seed-form secret keys are stored as full hex;
expanded secret keys are stored by SHA-256 because the large parameter sets have
hundreds of kilobytes of expanded key material.

Usage:
  python3 scripts/generate_snova_fixtures.py --kat-root /path/to/SNOVA_KAT
  python3 scripts/generate_snova_fixtures.py --check --kat-root /path/to/SNOVA_KAT

The generated file records the SHA-256 of every source response file (including
the gzip-compressed 75/33/2 responses) so the fixture can be audited against
the pinned upstream commit recorded in src/config/source_locks/snova.json.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "snova" / "kat_reference.json"

PARAMETER_SETS = [
    # (v, o, l, category)
    (37, 17, 2, 1),
    (25, 8, 3, 1),
    (24, 5, 4, 1),
    (56, 25, 2, 3),
    (49, 11, 3, 3),
    (37, 8, 4, 3),
    (24, 5, 5, 3),
    (75, 33, 2, 5),
    (66, 15, 3, 5),
    (60, 10, 4, 5),
    (29, 6, 5, 5),
]

BACKENDS = ["AES", "SHAKE"]
SK_FORMATS = ["SSK", "ESK"]

KAT_REPO_COMMIT = "a1bf39dc59c14a3348c27d66aa5197fc22041a56"
KAT_REPO_URL = "https://github.com/PQCLAB-SNOVA/SNOVA_KAT"

# Expanded secret keys can be hundreds of kilobytes; only SSK hex is stored.
FULL_SK_FORMATS = {"SSK"}


def algorithm_name(v: int, o: int, l: int, backend: str) -> str:
    return f"SNOVA-R2-{v}-{o}-16-{l}-{backend}"


def record_paths(v: int, o: int, l: int, backend: str, sk_format: str):
    dir_name = f"SNOVA_{v}_{o}_16_{l}"
    if backend == "SHAKE":
        dir_name += "_SHAKE"
    dir_name += f"_{sk_format}"
    base = f"SNOVA_{v}_{o}_{l}"
    if backend == "SHAKE":
        base += "_SHAKE"
    file_name = f"PQCsignKAT_{base}_{sk_format}.rsp"
    return dir_name, file_name


def parse_first_record(text: str) -> dict:
    record: dict = {}
    field = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#"):
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if key == "count":
                if record:
                    break
                record["count"] = int(value)
                field = "count"
                continue
            record[key] = value
            field = key
        elif field in {"pk", "sk", "sm", "msg"}:
            record[field] += line
    return record


def read_first_record(rsp_path: Path) -> dict:
    if rsp_path.suffix == ".gz":
        with gzip.open(rsp_path, "rt", errors="ignore") as handle:
            text = handle.read(8 << 20)
    else:
        text = rsp_path.read_text(errors="ignore")
    return parse_first_record(text)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_hex(value: str) -> str:
    return hashlib.sha256(bytes.fromhex(value)).hexdigest()


def build_fixture(kat_root: Path) -> dict:
    records = []
    for v, o, l, category in PARAMETER_SETS:
        for backend in BACKENDS:
            for sk_format in SK_FORMATS:
                dir_name, file_name = record_paths(v, o, l, backend, sk_format)
                rsp_path = kat_root / dir_name / file_name
                compressed = False
                if not rsp_path.is_file():
                    rsp_path = rsp_path.with_suffix(".rsp.gz")
                    compressed = True
                if not rsp_path.is_file():
                    raise SystemExit(f"missing KAT response file for {dir_name}/{file_name}")
                fields = read_first_record(rsp_path)
                for required in ("seed", "mlen", "msg", "pk", "sk", "smlen", "sm"):
                    if required not in fields:
                        raise SystemExit(f"{rsp_path}: missing field {required}")
                entry = {
                    "algorithm": algorithm_name(v, o, l, backend),
                    "backend": backend,
                    "sk_format": sk_format,
                    "v": v,
                    "o": o,
                    "l": l,
                    "category": category,
                    "kat_dir": dir_name,
                    "rsp_file": rsp_path.name,
                    "rsp_compressed": compressed,
                    "rsp_sha256": file_sha256(rsp_path),
                    "count": fields["count"],
                    "seed_hex": fields["seed"].lower(),
                    "mlen": int(fields["mlen"]),
                    "msg_hex": fields["msg"].lower(),
                    "pk_hex": fields["pk"].lower(),
                    "pk_sha256": sha256_hex(fields["pk"]),
                    "sk_sha256": sha256_hex(fields["sk"]),
                    "smlen": int(fields["smlen"]),
                    "sm_hex": fields["sm"].lower(),
                    "sm_sha256": sha256_hex(fields["sm"]),
                }
                if sk_format in FULL_SK_FORMATS:
                    entry["sk_hex"] = fields["sk"].lower()
                records.append(entry)
    return {
        "description": (
            "Official SNOVA round-2 KAT fixtures (count=0 record per parameter "
            "set/backend/secret-key format), extracted from "
            f"{KAT_REPO_URL} commit {KAT_REPO_COMMIT}. Public keys, signed "
            "messages and seed-form secret keys are full bytes; expanded "
            "secret keys are bound by SHA-256."
        ),
        "source": {
            "repository": KAT_REPO_URL,
            "commit": KAT_REPO_COMMIT,
            "extraction_script": "scripts/generate_snova_fixtures.py",
            "record": "first response record (count=0)",
        },
        "records": records,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--kat-root",
        type=Path,
        default=REPO_ROOT / "projects" / "SNOVA_KAT",
        help="checkout of PQCLAB-SNOVA/SNOVA_KAT at the pinned round-2 commit",
    )
    parser.add_argument("--check", action="store_true", help="fail if the checked-in fixture is stale")
    args = parser.parse_args(argv)

    if not args.kat_root.is_dir():
        print(f"SNOVA KAT root not found: {args.kat_root}", file=sys.stderr)
        print("clone https://github.com/PQCLAB-SNOVA/SNOVA_KAT at " + KAT_REPO_COMMIT, file=sys.stderr)
        return 2
    fixture = build_fixture(args.kat_root)
    rendered = json.dumps(fixture, indent=2, sort_keys=False) + "\n"
    if args.check:
        if not FIXTURE_PATH.is_file() or FIXTURE_PATH.read_text() != rendered:
            print(f"stale SNOVA KAT fixture: {FIXTURE_PATH}", file=sys.stderr)
            return 1
        print("SNOVA KAT fixture is current")
        return 0
    FIXTURE_PATH.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE_PATH.write_text(rendered)
    print(f"wrote {FIXTURE_PATH} ({len(fixture['records'])} records)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
