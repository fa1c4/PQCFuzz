#!/usr/bin/env python3
"""Qualify remaining source-declared A-tier hash profiles against one submitted KAT."""
import hashlib
import json
import multiprocessing as mp
import re
import subprocess
from pathlib import Path

import pqcfuzz_a_hash_probe as base

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "workspace/a_targets_sop/probes/hash_secondary"


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    inventory = json.loads((ROOT / "workspace/a_targets_sop/full_public_api_inventory.json").read_text())
    registry = {x["target"]: x for x in json.loads((ROOT / "configs/targets.json").read_text())["targets"]}
    rows = []
    for target in inventory["targets"]:
        if target["primitive"] != "hash":
            continue
        tid = target["target"]
        source = ROOT / "third_party" / tid / "source"
        present = {x["parameter_set"] for x in registry[tid]["apis"]}
        seen = set()
        for h in target["headers"]:
            name = h["parameter_or_variant"]
            if name in present or name in seen:
                continue
            seen.add(name)
            header = source / h["path"]
            data = header.read_text(errors="replace")
            identity = re.search(r'#define\s+ALGORITHM_INSTANCE\s+"([^"]+)"', data)
            bits = re.search(r'#define\s+DIGEST_BIT_LENGTH\s+(\d+)', data)
            row = {"target": tid, "parameter_set": name, "header": h["path"],
                   "header_sha256": h["sha256"]}
            if not identity or not bits or identity.group(1) != name:
                row["status"] = "header_identity_unparsed"
                rows.append(row)
                continue
            digest_bits = int(bits.group(1))
            row["digest_bits"] = digest_bits
            candidates = sorted((p for p in source.rglob("KAT_2_12_" + name + ".txt")
                                 if "Others" not in p.parts), key=lambda p: (len(p.parts), str(p)))
            if not candidates:
                row["status"] = "submitted_kat_missing"
                rows.append(row)
                continue
            kat = candidates[0]
            row["kat"] = str(kat.relative_to(source))
            row["kat_sha256"] = hashlib.sha256(kat.read_bytes()).hexdigest()
            match = base.KAT.search(kat.read_text(encoding="ascii").replace("\r\n", "\n"))
            if not match:
                row["status"] = "kat_parse_failed"
                rows.append(row)
                continue
            message_bits, message_hex, output_bits, expected = match.groups()
            if int(output_bits) != digest_bits or digest_bits % 8:
                row["status"] = "kat_profile_mismatch"
                rows.append(row)
                continue
            files = sorted(p for p in header.parent.glob("*.c") if p.name not in base.EXCLUDE_C)
            row["sources"] = [str(p.relative_to(source)) for p in files]
            library = OUT / (tid + "-" + re.sub(r"[^A-Za-z0-9]", "", name) + ".so")
            cmd = ["gcc", "-std=c11", "-O2", "-fPIC", "-shared", "-Wl,-z,defs",
                   "-o", str(library), *(str(p) for p in files)]
            try:
                built = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                row["build_returncode"] = built.returncode
                row["build_stderr_tail"] = built.stderr[-1000:]
                if built.returncode:
                    row["status"] = "build_failed"
                else:
                    queue = mp.Queue()
                    child = mp.Process(target=base.call_one,
                                       args=(library, digest_bits, message_hex,
                                             int(message_bits), expected, queue))
                    child.start()
                    child.join(15)
                    if child.is_alive():
                        child.kill()
                        child.join()
                        row["status"] = "call_timeout"
                    elif child.exitcode or queue.empty():
                        row["status"] = "call_crash"
                        row["call_exitcode"] = child.exitcode
                    else:
                        row.update(queue.get_nowait())
                        row["status"] = "one_kat_match" if row["kat_match"] else "one_kat_mismatch"
            except Exception as exc:
                row["status"] = "probe_error"
                row["error"] = repr(exc)
            rows.append(row)
            (OUT / "report.json").write_text(json.dumps(rows, indent=2) + "\n")
            print(json.dumps({"target": tid, "parameter_set": name, "status": row["status"]}), flush=True)
    (OUT / "report.json").write_text(json.dumps(rows, indent=2) + "\n")
    print(json.dumps({"count": len(rows), "statuses":
                      {s: sum(x["status"] == s for x in rows)
                       for s in sorted({x["status"] for x in rows})}}))


if __name__ == "__main__":
    main()
