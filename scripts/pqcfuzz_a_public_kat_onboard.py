#!/usr/bin/env python3
"""Register one source-pinned, submitted-KAT instance for each A-tier asym target."""
import hashlib
import json
import os
import tempfile
from pathlib import Path

import pqcfuzz_c_public_kat_onboard as base

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "workspace/a_targets_sop/probes/asymmetric/auto/report.json"
PDF_PAGES = {
    "sign-01": 11, "sign-10": 6, "sign-17": 6, "sign-23": 16,
    "sign-31": 4, "kem-01": 8, "kem-02": 9, "kem-04": 7,
    "kem-15": 10, "kem-16": 5, "kem-19": 11, "kem-26": 25,
    "kem-27": 18, "kem-28": 6, "kem-29": 11, "kem-30": 15,
    "kem-36": 5,
}
VARIABLE_SIGNATURE_NOTE = """
The submitted `SIG_AlgorithmInstance.c` returns `SIG_BYTES` from
`sig_get_sn_len_bytes`; its KAT driver allocates that amount before `sig_sign`
updates `Sn_Len`. The archived first record has `Sn_Len = 2009` while the
getter returns 2015 for this build. The adapter therefore treats the getter
as an allocation upper bound and checks the exact submitted record length
separately. This is an API observation, not a new PDF-level normative claim.
"""


def source_digest(path):
    digest = hashlib.sha256()
    for file in sorted(p for p in path.rglob("*") if p.is_file() and
                       "__pycache__" not in p.parts):
        digest.update(file.relative_to(path).as_posix().encode())
        digest.update(bytes.fromhex(hashlib.sha256(file.read_bytes()).hexdigest()))
    return digest.hexdigest()


def main():
    reports = json.loads(PROBE.read_text())
    inventory = {x["target"]: x for x in
                 json.loads((ROOT / "workspace/a_targets_sop/inventory.json").read_text())}
    if set(PDF_PAGES) != {x["target"] for x in reports} or any(
            x["status"] != "first_vector_match" for x in reports):
        raise SystemExit("all 17 first-vector API probes must match before registration")
    settings = {}
    sources = {}
    for row in reports:
        target = row["target"]
        entry = inventory[target]
        if source_digest(ROOT / "third_party" / target / "source") != entry["source_sha256"]:
            raise SystemExit("runtime source digest mismatch: " + target)
        primitive = "signature" if row["primitive"] == "sign" else "kem"
        settings[target] = {
            "algorithm": entry["name"], "primitive": primitive,
            "api": "sig_verify" if primitive == "signature" else "kem_dec",
            "instances": [row["parameter_set"]],
            "locator": f"PDF p. {PDF_PAGES[target]} (algorithm context)",
            "property": "S03" if primitive == "signature" else "K03",
        }
        sources[target] = {key: row[key] for key in
                           ("kat", "kat_sha256", "sources", "includes", "flags")}
        if target == "sign-01":
            # Its submitted Sn_Len (2009) is below the 2015-byte allocation getter.
            sources[target]["variable_signature_length"] = True
    base.SETTINGS = settings
    base.source_config = lambda target, instance, source: dict(sources[target])
    registry_path = ROOT / "configs/targets.json"
    registry = json.loads(registry_path.read_text())
    present = {row["target"] for row in registry["targets"]}
    added = []
    for target in settings:
        if target in present:
            continue
        base.one_target(target, inventory[target], registry)
        if target == "sign-01":
            spec_path = ROOT / "oracles/spec/sign-01-Aigis-Sig+.md"
            with spec_path.open("a", encoding="utf-8") as stream:
                stream.write(VARIABLE_SIGNATURE_NOTE)
            manifest_path = ROOT / "oracles/sign-01/manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["spec_sha256"] = hashlib.sha256(spec_path.read_bytes()).hexdigest()
            base.dump(manifest_path, manifest)
            design_path = (ROOT / "oracles/sign-01/design/Aigis-Sig+/sig_verify/"
                           "AIGISSIGI-KAT-01.md")
            text = design_path.read_text()
            line = "- Signature length: The submitted KAT's exact `Sn_Len` must match its bytes and be no larger than `sig_get_sn_len_bytes()`, which is an allocation bound for this instance (first record 2009 versus getter 2015).\n"
            text = text.replace("- Baseline:", line + "- Baseline:", 1)
            design_path.write_text(text)
        added.append(target)
    if added:
        fd, temp = tempfile.mkstemp(prefix="targets-a-asym-", suffix=".json",
                                    dir=registry_path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(json.dumps(registry, indent=2, ensure_ascii=False) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, registry_path)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)
    print(json.dumps({"registered": added,
                      "instances": {target: settings[target]["instances"] for target in added}}))


if __name__ == "__main__":
    main()
