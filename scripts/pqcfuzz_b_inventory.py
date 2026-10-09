#!/usr/bin/env python3
"""Pin and inventory all B-tier NGCC submissions without executing them."""
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RANKING = ROOT / "plans/ngcc_target_value_ranking.md"
OUT = ROOT / "workspace/b_targets_sop/inventory.json"
ROW = re.compile(r"^\| \[([^]]+)\]\([^)]*\) \| (.*?) \| (0\.\d+) \| ([SABC]) \|")


def file_sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def tree_sha(files, source):
    digest = hashlib.sha256()
    for path in files:
        digest.update(path.relative_to(source).as_posix().encode())
        digest.update(bytes.fromhex(file_sha(path)))
    return digest.hexdigest()


def main():
    rows = []
    for line in RANKING.read_text().splitlines():
        match = ROW.match(line)
        if not match or match.group(4) != "B":
            continue
        target, name, score, _ = match.groups()
        root = ROOT / "third_party" / target
        source, document = root / "source", root / "specification.pdf"
        if not source.is_dir() or not document.is_file():
            raise SystemExit(f"missing submitted input for {target}")
        all_paths = list(source.rglob("*"))
        symlinks = [p for p in all_paths if p.is_symlink()]
        if symlinks:
            raise SystemExit(f"symlinks require inspection: {target}")
        files = sorted(p for p in all_paths if p.is_file() and "__pycache__" not in p.parts)
        headers = [p.relative_to(source).as_posix() for p in files
                   if p.name in ("CryptHash_AlgorithmInstance.h", "KEM_AlgorithmInstance.h",
                                  "SIG_AlgorithmInstance.h", "KEX_AlgorithmInstance.h")]
        kats = [p.relative_to(source).as_posix() for p in files
                if p.suffix.lower() in (".txt", ".rsp") and
                ("KAT" in p.name.upper() or "test_vector" in p.as_posix().lower())]
        row = {"target": target, "name": name, "score": float(score),
               "primitive": target.split("-")[0], "source_sha256": tree_sha(files, source),
               "source_files": len(files), "source_bytes": sum(p.stat().st_size for p in files),
               "document_sha256": file_sha(document),
               "api_headers": headers, "kat_texts": kats, "symlinks": 0}
        rows.append(row)
        print(target, row["source_files"], len(headers), len(kats), flush=True)
    if len(rows) != 74 or dict(Counter(x["primitive"] for x in rows)) != {
            "sign": 28, "kem": 28, "kex": 7, "hash": 11}:
        raise SystemExit("B-tier ranking count changed; inspect before using inventory")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"targets": len(rows), "primitive_counts": dict(Counter(x["primitive"] for x in rows)),
                      "source_mib": round(sum(x["source_bytes"] for x in rows) / 1048576, 1),
                      "inventory": str(OUT)}))


if __name__ == "__main__":
    main()
