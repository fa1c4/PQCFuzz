#!/usr/bin/env python3
"""Generate the additional source-pinned S-tier hash SOP instances.

The submitted source trees and specification PDFs stay immutable. Run after
checking the locators below against each original PDF.
"""
import hashlib
import json
import re
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ROW = re.compile(r"Msg_Len = (\d+)\nMsg = ([0-9A-F]*)\nDst_Len = (\d+)\nDst = ([0-9A-F]+)")
SAMPLES = (0, 1, 7, 8, 63, 64, 65, 511, 512, 513, 1023, 1024, 1025, 2047, 4096)
SPECS = {
    "hash-03": ("C-Hash", "PDF pp. 5–6 §1.1 and p. 14 §1.4", (1024,)),
    "hash-15": ("Litchi", "PDF pp. 7–8 §2.2 and p. 11 §2.5", (512, 768, 1024)),
    "hash-16": ("LLH", "PDF pp. 5–6 §§1.4.2, 2.2, Tables 1–3", (256, 768, 1024)),
    "hash-23": ("QILIN", "PDF pp. 4–5 §1.2 Algorithm 1 and p. 19 family table", (768, 1024)),
    "hash-28": ("XRH-1", "PDF pp. 13–14 §1.3 and Algorithm 4", (768, 1024)),
    "hash-29": ("XRH-2", "PDF pp. 13–14 §1.3 and Algorithm 4", (768, 1024)),
    "hash-34": ("WChain", "PDF pp. 6–9 §§2.2, 3.1–3.2 and Algorithm 1", (1024,)),
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def dump(path, value):
    write(path, json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def instance_name(target, bits):
    return {"hash-03": "C-Hash", "hash-34": "WChain-V2"}.get(target, SPECS[target][0]) + f"-{bits}"


def submitted_kat(source, target, instance, bits):
    if target == "hash-03":
        rel = f"C Hash/Test_Vectors/KAT_2_12_CHash_{bits}.txt"
    elif target == "hash-15":
        rel = f"Litchi/Test_Vectors/KAT_2_12_litchi_{bits}.txt"
    elif target == "hash-16":
        rel = f"LLH/Implementations and Test_Vectors/LLH_C/API_CryptHash/Test_Vectors/KAT_2_12_LLH-{bits}.txt"
    elif target == "hash-34":
        rel = f"WChain/Implementations and Test_Vectors/Test_Vectors/KAT_2_12_{instance}.txt"
    else:
        rel = f"{SPECS[target][0]}/Test_Vectors/KAT_2_12_{instance}.txt"
    path = source / rel
    rows = []
    for index, match in enumerate(ROW.finditer(path.read_text(encoding="ascii"))):
        message_bits, message, digest_bits, digest = match.groups()
        if index != int(message_bits) or int(digest_bits) != bits:
            raise ValueError(f"KAT index/output mismatch: {path} {index}")
        if index in SAMPLES:
            rows.append({"message_bits": index, "message_hex": message.lower(),
                         "digest_hex": digest.lower(), "source_record_index": index})
    if len(rows) != len(SAMPLES):
        raise ValueError(f"missing selected KAT rows: {path}")
    return {"source_path": rel, "source_sha256": sha(path), "records": rows}


def claim(instance, bits, locator, kat):
    tag = re.sub(r"[^A-Za-z0-9]", "", instance).upper()
    diff_id, kat_id = f"{tag}-DIFF-01", f"{tag}-KAT-01"
    diff_claim, kat_claim = f"{tag}-D", f"{tag}-K"
    source_note = ("submitted fixed-length core and CryptHash wrapper" if instance.startswith("Litchi-")
                   else "submitted reference and optimized CryptHash backends")
    a, b = (("core", "wrapper") if instance.startswith("Litchi-") else ("reference", "optimized"))
    text = f"""
## {diff_claim} — {instance} submitted path agreement

- Source locator: {locator}; submitted instance headers under `Implementations` identify `{instance}` and `{bits}`-bit output.
- Class: candidate specification construction and submitted API identity.
- Scope: {instance}, exact `{bits}`-bit digest, public bitstrings, {source_note}, little-endian x86-64 host.
- Claim: For the same valid bitstring and digest length, the two submitted paths for `{instance}` should return the same deterministic digest.
- Preconditions: Exact input bytes and bit length, `{bits}`-bit output, and the same archived source snapshot.
- Limitations: Shared code lineage can conceal common defects. Agreement does not prove independent conformance or a computational security claim; disagreement does not identify a faulty path.
- Extraction inference/ambiguity: Cross-path agreement follows from their common deterministic instance identity; the PDF does not make a software-backend claim. Unsupported digest lengths are excluded.

## {kat_claim} — {instance} submitted KAT control

- Source locator: `{kat['source_path']}` in the archived submission, SHA-256 `{kat['source_sha256']}`, with `Msg_Len`, `Msg`, `Dst_Len` and `Dst` fields.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact selected `{bits}`-bit KAT rows, their source indices and both registered paths for `{instance}`.
- Claim: Each exact submitted input should reproduce its own recorded `{bits}`-bit digest through the selected path.
- Preconditions: Row bytes, bit length, output length, source-file digest and parameter set all match their pinned records.
- Limitations: Vectors may share defects with the implementation. A mismatch is candidate consistency evidence only; finite testing proves no security property.
- Extraction inference/ambiguity: The submitted vector is an experimental control and requires human specification review before normative promotion.
"""
    def design(oid, cid, pattern):
        relation = (f"identical {bits}-bit outputs from `{a}` and `{b}` for one bitstring, also equal to a pinned KAT digest when present"
                    if pattern == "P3" else "each exact KAT input yields its own submitted digest")
        intervention = (f"switch `{a}` to `{b}` with message and output length fixed" if pattern == "P3"
                        else "switch between two distinct pinned KAT records on the same path")
        return f"""# {oid}: {instance} {pattern} source-pinned relation

- Claim: `{cid}` in the draft extraction; source locator: {locator if pattern == 'P3' else kat['source_path']}.
- Property: X05 version 1, exact algorithm identity and interoperability.
- Pattern: {pattern} version 1, {'cross-path differential' if pattern == 'P3' else 'submitted known-answer conformance'}.
- Extraction status: draft (`unverified_spec`); failures remain candidate-only.
- Scope: `{instance}` `{bits}`-bit `CryptHash` profile and the two submitted paths `{a}`/`{b}`.
- Preconditions: Canonical MSB-first bitstring storage, exact requested output length, successful target calls and pinned source identity. KAT expectations require exact source path, SHA-256 and row index.
- Baseline: A valid public message with `{bits}`-bit output on `{a}` or a selected KAT path.
- Intervention: {intervention}; the paired structured mutator records changed fields and effectiveness.
- Expected relation: {relation}.
- Observable: Actual target reachability, status, output length, digest bytes{' and output canary' if instance.startswith('Litchi-') else ''}.
- Positive control: Selected submitted 512-bit message row (P3), or the 512/513-bit distinct rows (P1), passes through real submitted code.
- Negative control: Identical structured inputs, or the same KAT row twice, set `effective=false` and yield `inconclusive`.
- Fault control: Flip one bit of an observed digest after a real call; the predicate must reject it in smoke only.
- Required capabilities: `bit_input`, `submitted_kat` for P1 and `dual_backend` or `core_wrapper_comparison` for P3.
- Predicate: Check exact instance and provenance, both successful calls and output lengths; compare the observed digest(s) to the expected relation. A mismatch becomes `counterexample_candidate` only.
- Paired mutator: `implement/mutator/{'variant_diff_' if pattern == 'P3' else 'variant_kat_'}{bits}.py`.
- Limitations: Submitted paths and KATs are not independent specification witnesses. A finite campaign cannot prove collision, preimage or other computational security claims.
"""
    return (text, (diff_id, diff_claim, design(diff_id, diff_claim, "P3")),
            (kat_id, kat_claim, design(kat_id, kat_claim, "P1")))


def module_text(bits, kind, role, backends, canary, corpus_name):
    common = """import importlib.util\nimport json\nfrom pathlib import Path\n\n_PACKAGE = Path(__file__).resolve().parents[2] if __file__.split('/implement/mutator/')[0] != __file__ else Path(__file__).resolve().parents[1]\n_SPEC = importlib.util.spec_from_file_location('variant_common', _PACKAGE / 'implement/variant_common.py')\n_COMMON = importlib.util.module_from_spec(_SPEC)\n_SPEC.loader.exec_module(_COMMON)\n"""
    # The mutator lives one directory deeper than the oracle.
    common = common.replace("Path(__file__).resolve().parents[2] if __file__.split('/implement/mutator/')[0] != __file__ else Path(__file__).resolve().parents[1]",
                            "Path(__file__).resolve().parents[2]" if role == "mutator" else "Path(__file__).resolve().parents[1]")
    common += f"_CORPUS = json.loads((_PACKAGE / 'data/{corpus_name}').read_text(encoding='utf-8'))\n_BITS = {bits}\n_BACKENDS = {backends!r}\n_CANARY = {canary}\n\n"
    if role == "mutator":
        if kind == "diff":
            return common + "def generate(seed, iteration):\n    return _COMMON.diff_generate(seed, iteration, _CORPUS, _BITS, _BACKENDS)\n\ndef smoke_cases():\n    return _COMMON.diff_smoke(_CORPUS, _BITS, _BACKENDS)\n"
        return common + "def generate(seed, iteration):\n    return _COMMON.kat_generate(seed, iteration, _CORPUS, _BITS, _BACKENDS)\n\ndef smoke_cases():\n    return _COMMON.kat_smoke(_CORPUS, _BITS, _BACKENDS)\n"
    if kind == "diff":
        return common + "def evaluate(case, baseline, mutated):\n    return _COMMON.diff_evaluate(case, baseline, mutated, _CORPUS, _BITS, _BACKENDS, _CANARY)\n\ndef fault_observation(mutated):\n    return _COMMON.fault_observation(mutated)\n"
    return common + "def evaluate(case, baseline, mutated):\n    return _COMMON.kat_evaluate(case, baseline, mutated, _CORPUS, _BITS, _BACKENDS, _CANARY)\n\ndef fault_observation(mutated):\n    return _COMMON.fault_observation(mutated)\n"


def main():
    config_path = ROOT / "configs/targets.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    assert config["schema_version"] == 2
    for target, (algorithm, locator, bit_lengths) in SPECS.items():
        record = next(row for row in config["targets"] if row["target"] == target)
        package = ROOT / "oracles" / target
        source = ROOT / "third_party" / target / "source"
        manifest_path = package / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest["schema_version"] == 1:
            original = {key: manifest.pop(key) for key in ("parameter_set", "api", "profiles", "adapter", "capabilities", "oracles")}
            manifest["schema_version"] = 2
            manifest["instances"] = [original]
        spec_path = ROOT / record["specification"]
        spec = spec_path.read_text(encoding="utf-8").replace("extract_version: 1", "extract_version: 2")
        for bits in bit_lengths:
            instance = instance_name(target, bits)
            corpus = submitted_kat(source, target, instance, bits)
            corpus_name = "kat_" + re.sub(r"[^a-z0-9]", "", instance.lower()) + "_subset.json"
            dump(package / "data" / corpus_name, corpus)
            claim_text, diff, kat = claim(instance, bits, locator, corpus)
            if f"## {diff[1]} —" not in spec:
                spec += claim_text
            for oid, _, design in (diff, kat):
                write(package / "design" / algorithm / "CryptHash" / f"{oid}.md", design)
            backends = ("core", "wrapper") if target == "hash-15" else ("reference", "optimized")
            canary = target == "hash-15"
            for kind in ("diff", "kat"):
                write(package / "implement" / "mutator" / f"variant_{kind}_{bits}.py",
                      module_text(bits, kind, "mutator", backends, canary, corpus_name))
                write(package / "implement" / f"variant_{kind}_{bits}_oracle.py",
                      module_text(bits, kind, "oracle", backends, canary, corpus_name))
            template = record["apis"][0]["profiles"][0]
            profile = json.loads(json.dumps(template))
            profile["build"] = [["python3", "{run}/package/implement/variant_build.py", "{source}", "{run}", instance]]
            profile["options"] = {"parameter_set": instance, "digest_bits": bits}
            profile["iterations"] = 32
            api = {"name": "CryptHash", "parameter_set": instance, "profiles": [profile]}
            if not any(row["parameter_set"] == instance and row["name"] == "CryptHash"
                       for row in record["apis"]):
                record["apis"].append(api)
            caps = {"bit_input": True, "submitted_kat": True,
                    "dual_backend": target != "hash-15", "core_wrapper_comparison": target == "hash-15",
                    "output_canary": canary, "rng_control": False, "fault_injection": False,
                    "intermediate_state": False, "decapsulation_failure": False}
            oracles = []
            for oid, cid, _, pattern in ((*diff, "P3"), (*kat, "P1")):
                kind = "diff" if pattern == "P3" else "kat"
                required = (["core_wrapper_comparison", "bit_input", "output_canary"]
                            if kind == "diff" and canary else
                            ["dual_backend", "bit_input"] if kind == "diff" else
                            ["bit_input", "submitted_kat", "output_canary"] if canary else
                            ["bit_input", "submitted_kat"])
                oracles.append({"id": oid, "version": 1, "claim": cid,
                                "property": "X05", "property_version": 1,
                                "pattern": pattern, "pattern_version": 1,
                                "design": f"design/{algorithm}/CryptHash/{oid}.md",
                                "oracle": f"implement/variant_{kind}_{bits}_oracle.py",
                                "mutator": f"implement/mutator/variant_{kind}_{bits}.py",
                                "required_capabilities": required,
                                "applicable_primitives": ["hash"]})
            if not any(row["parameter_set"] == instance and row["api"] == "CryptHash"
                       for row in manifest["instances"]):
                manifest["instances"].append({"parameter_set": instance, "api": "CryptHash",
                                               "profiles": [profile["id"]],
                                               "adapter": "implement/variant_adapter.py",
                                               "capabilities": caps, "oracles": oracles})
        write(spec_path, spec)
        manifest["spec_sha256"] = sha(spec_path)
        dump(manifest_path, manifest)
        shutil.copy2(ROOT / "oracles/hash-23/implement/variant_common.py",
                     package / "implement/variant_common.py") if target != "hash-23" else None
    dump(config_path, config)


if __name__ == "__main__":
    main()
