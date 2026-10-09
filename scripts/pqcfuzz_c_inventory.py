#!/usr/bin/env python3
"""Pin the five C-tier submitted source trees and specification PDFs."""
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RANKING = ROOT / "plans/ngcc_target_value_ranking.md"
OUT = ROOT / "workspace/c_targets_sop/inventory.json"
ROW = re.compile(r"^\| \[([^]]+)\]\([^)]*\) \| (.*?) \| (0\.\d+) \| ([SABC]) \|")


def file_sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def main():
    rows = []
    for line in RANKING.read_text().splitlines():
        match = ROW.match(line)
        if not match or match.group(4) != "C":
            continue
        target, name, score, _ = match.groups()
        root = ROOT / "third_party" / target
        source, pdf = root / "source", root / "specification.pdf"
        if not source.is_dir() or not pdf.is_file():
            raise SystemExit(f"missing submitted source/PDF: {target}")
        paths = list(source.rglob("*"))
        if any(path.is_symlink() for path in paths):
            raise SystemExit(f"source symlink needs review: {target}")
        files = sorted(path for path in paths if path.is_file() and "__pycache__" not in path.parts)
        digest = hashlib.sha256()
        for path in files:
            digest.update(path.relative_to(source).as_posix().encode())
            digest.update(bytes.fromhex(file_sha(path)))
        rows.append({"target": target, "name": name, "score": float(score),
                     "primitive": target.split("-")[0], "source_sha256": digest.hexdigest(),
                     "source_files": len(files),
                     "source_bytes": sum(path.stat().st_size for path in files),
                     "document_sha256": file_sha(pdf),
                     "standard_headers": [path.relative_to(source).as_posix() for path in files
                                          if path.name.endswith("_AlgorithmInstance.h")],
                     "kat_texts": [path.relative_to(source).as_posix() for path in files
                                   if path.name.startswith("KAT_") and path.suffix.lower() in (".txt", ".rsp")]})
        print(target, len(files), flush=True)
    if {row["target"] for row in rows} != {"sign-33", "kem-17", "kex-01", "kex-04", "hash-22"}:
        raise SystemExit("C-tier ranking changed; review required")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"targets": len(rows), "source_mib": round(sum(x["source_bytes"] for x in rows)/1048576, 1),
                      "inventory": str(OUT)}))


if __name__ == "__main__":
    main()
