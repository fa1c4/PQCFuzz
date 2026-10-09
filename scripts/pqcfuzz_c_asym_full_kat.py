#!/usr/bin/env python3
"""Call every public submitted KAT record through one run-local asymmetric adapter."""
import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = {"sign-33": "verify", "kem-17": "decapsulate",
              "kex-01": "derive_roles", "kex-04": "derive_roles"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    run = parser.parse_args().run.resolve()
    manifest = json.loads((run / "manifest.json").read_text())
    target, instance = manifest["target"], manifest["parameter_set"]
    if target not in OPERATIONS or not run.is_relative_to(ROOT / "workspace" / target / "runs"):
        raise SystemExit("wrong run target/path")
    package = run / "package"
    cfg = json.loads((package / "data/instances.json").read_text())[instance]
    kat = (run / "source" / cfg["kat"]).resolve()
    if not kat.is_relative_to(run / "source"):
        raise SystemExit("KAT escapes run-local source")
    digest = hashlib.sha256()
    with kat.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    if digest.hexdigest() != cfg["kat_sha256"]:
        raise SystemExit("KAT digest changed")
    module_spec = importlib.util.spec_from_file_location("run_adapter", package / "implement/adapter.py")
    adapter = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(adapter)
    matched = 0
    for index, row in enumerate(cfg["records"]):
        value = {"instance": instance, "operation": OPERATIONS[target], "record_index": index}
        result = adapter.invoke(value, run / "source", {"parameter_set": instance})
        expected = "accepted" if target == "sign-33" else row["expected_ss"]
        if result.get("reached") is not True or result.get("status") != "ok" or \
                result.get("output") != expected or \
                (target != "sign-33" and result.get("guard_modified") is not False) or \
                (target.startswith("kex-") and result.get("peer_output") != expected):
            raise SystemExit(f"{target} {instance} submitted KAT mismatch at row {index}")
        matched += 1
    if matched != 10:
        raise SystemExit("expected ten submitted KAT records")
    report = {"target": target, "parameter_set": instance,
              "run": str(run.relative_to(ROOT)), "kat": cfg["kat"],
              "kat_sha256": cfg["kat_sha256"], "records": matched,
              "api_calls": matched * (2 if target.startswith("kex-") else 1),
              "status": "submitted_kat_match",
              "scope": "direct diagnostic on public submitted vectors; not a separate SOP oracle"}
    output = ROOT / "workspace/c_targets_sop/full_kat_api" / f"{instance}.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
