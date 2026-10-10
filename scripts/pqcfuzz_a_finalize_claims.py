#!/usr/bin/env python3
"""Reconcile expanded A-tier scope and local-vector provenance in draft claims."""
import hashlib
import json
import re
from pathlib import Path

import pqcfuzz_a_full_api_onboard as full

ROOT = Path(__file__).resolve().parents[1]
INTRO = re.compile(r"This document covers public submitted KAT records only, under the exact\n"
                   r"`(?:kem_dec|sig_verify)` API\. The algorithm construction and correctness context is\n")
REPLACEMENT = ("This document covers source-pinned public vector records and public API relations\n"
               "for the named parameter sets. The algorithm construction and correctness context is\n")


def write(path, value):
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(value, encoding="utf-8")
    temp.replace(path)


def main():
    registry = {x["target"]: x for x in json.loads((ROOT / "configs/targets.json").read_text())["targets"]}
    for target in sorted(full.PDF_ROUNDTRIP):
        entry = registry[target]
        spec_path = ROOT / entry["specification"]
        spec = spec_path.read_text()
        spec = INTRO.sub(REPLACEMENT, spec, count=1)
        if target == "sign-10":
            start = spec.index("## FACTODSA512-K —")
            end = spec.find("\n## ", start + 3)
            if end < 0:
                end = len(spec)
            section = spec[start:end].replace("Both valid submitted records",
                                              "Both valid locally regenerated KAT-generator records")
            spec = spec[:start] + section + spec[end:]
        write(spec_path, spec)
        manifest_path = ROOT / "oracles" / target / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        if target == "sign-10":
            for item in manifest["instances"]:
                if item["parameter_set"] != "Facto-DSA-512":
                    continue
                item["capabilities"]["submitted_kat"] = False
                item["capabilities"]["generated_kat"] = True
                for oracle in item["oracles"]:
                    oracle["required_capabilities"] = [
                        "generated_kat" if x == "submitted_kat" else x
                        for x in oracle["required_capabilities"]]
            for design in (ROOT / "oracles/sign-10/design/Facto-DSA").rglob("FACTODSA512-*.md"):
                text = design.read_text()
                text = text.replace("submitted_kat", "generated_kat")
                text = text.replace("exact submitted-vector relation", "exact locally regenerated vector relation")
                text = text.replace("Valid indexed submitted record", "Valid indexed locally regenerated record")
                text = text.replace("Both valid submitted records", "Both valid locally regenerated KAT-generator records")
                text = text.replace("exact submitted length", "exact locally regenerated length")
                write(design, text)
        manifest["spec_sha256"] = hashlib.sha256(spec_path.read_bytes()).hexdigest()
        write(manifest_path, json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"updated_specs": len(full.PDF_ROUNDTRIP),
                      "generated_vector_instance": "sign-10/Facto-DSA-512"}))


if __name__ == "__main__":
    main()
