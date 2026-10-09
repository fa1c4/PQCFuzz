#!/usr/bin/env python3
"""Register all three source-pinned Pavelor CryptHash instances."""
import hashlib
import importlib.util
import json
import os
import re
import shutil
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = "hash-22"
ALGORITHM = "Pavelor"
ROOT_IN_SOURCE = "Pavelor/Implementations and Test_Vectors/API_CryptHash"
ROW = re.compile(r"Msg_Len = (\d+)\nMsg = ([0-9A-F]*)\nDst_Len = (\d+)\nDst = ([0-9A-F]+)")
SAMPLES = (0, 1, 7, 8, 63, 64, 65, 511, 512, 513, 1023, 1024,
           1025, 2047, 2048, 2049, 4095, 4096)


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def dump(path, value):
    write(path, json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    inventory = next(row for row in json.loads((ROOT / "workspace/c_targets_sop/inventory.json").read_text())
                     if row["target"] == TARGET)
    source = ROOT / "third_party" / TARGET / "source"
    package = ROOT / "oracles" / TARGET
    spec_path = ROOT / "oracles/spec/hash-22-Pavelor.md"
    config_path = ROOT / "configs/targets.json"
    registry = json.loads(config_path.read_text())
    if any(row["target"] == TARGET for row in registry["targets"]):
        raise SystemExit("Pavelor already registered; inspect before changing")
    module_spec = importlib.util.spec_from_file_location("s_hash_generator",
                          ROOT / "scripts/pqcfuzz_generate_s_hash_instances.py")
    s_hash = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(s_hash)
    shutil.copy2(ROOT / "oracles/hash-23/implement/variant_common.py",
                 package / "implement/variant_common.py") if package.is_dir() else None
    (package / "implement/mutator").mkdir(parents=True, exist_ok=True)
    if not (package / "implement/variant_common.py").exists():
        shutil.copy2(ROOT / "oracles/hash-23/implement/variant_common.py",
                     package / "implement/variant_common.py")
    build = '''"""Compile exact run-local Pavelor reference and AES/SSE submitted paths."""
import pathlib
import subprocess
import sys

def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: variant_build.py SOURCE RUN INSTANCE")
    source, run = pathlib.Path(sys.argv[1]).resolve(), pathlib.Path(sys.argv[2]).resolve()
    instance = sys.argv[3]
    if source != run / "source" or run.parent.parent.name != "hash-22" or \\
            instance not in ("Pavelor-512", "Pavelor-768", "Pavelor-1024") or sys.byteorder != "little":
        raise SystemExit("wrong source, run or instance")
    cpu = pathlib.Path("/proc/cpuinfo").read_text().lower()
    if " aes " not in cpu or "sse4_1" not in cpu:
        raise SystemExit("optimized Pavelor requires AES-NI and SSE4.1")
    root = source / "Pavelor/Implementations and Test_Vectors/API_CryptHash/Implementations"
    output = run / "build"
    output.mkdir(exist_ok=True)
    prefix = instance.lower().replace("-", "")
    for backend, subdirectory in (("reference", "Reference_Implementation"),
                                  ("optimized", "Optimized_Implementation")):
        file = root / subdirectory / instance / "CryptHash_AlgorithmInstance.c"
        if not file.is_file():
            raise SystemExit("missing submitted source " + str(file))
        flags = ["gcc", "-std=c11", "-O2", "-fPIC", "-shared", "-Wl,-z,defs"]
        if backend == "optimized":
            flags += ["-maes", "-msse4.1"]
        subprocess.run(flags + ["-o", str(output / f"{prefix}-{backend}.so"), str(file)], check=True)
        print(backend + ": " + str(file.relative_to(source)), flush=True)

if __name__ == "__main__":
    main()
'''
    write(package / "implement/variant_build.py", build)
    adapter = '''"""Invoke exact run-local Pavelor CryptHash instance and output canary."""
import ctypes
import re
import sys
from pathlib import Path

_LIBRARIES = {}

def invalid(reason):
    return {"reached": False, "status": "invalid_input", "output": None,
            "output_length": 0, "diagnostic": reason}

def invoke(structured_input, source_root, profile):
    if not isinstance(structured_input, dict) or not isinstance(profile, dict):
        return invalid("input/profile must be objects")
    instance, bits = profile.get("parameter_set"), profile.get("digest_bits")
    if instance not in ("Pavelor-512", "Pavelor-768", "Pavelor-1024") or \\
            bits != int(instance.split("-")[-1]) or structured_input.get("digest_bits") != bits:
        return invalid("wrong instance or digest length")
    backend, length, message_hex = (structured_input.get("backend"),
                                     structured_input.get("message_bits"),
                                     structured_input.get("message_hex"))
    if backend not in ("reference", "optimized") or not isinstance(length, int) or \\
            isinstance(length, bool) or not 0 <= length <= 8192 or \\
            not isinstance(message_hex, str) or re.fullmatch(r"[0-9a-f]*", message_hex) is None:
        return invalid("invalid backend or message")
    if len(message_hex) != 2 * ((length + 7) // 8):
        return invalid("message storage length differs from bit length")
    message = bytes.fromhex(message_hex)
    if length % 8 and message[-1] & ((1 << (8 - length % 8)) - 1):
        return invalid("non-canonical unused trailing bits")
    source = Path(source_root).resolve()
    if source.name != "source" or source.parent.parent.parent.name != "hash-22" or sys.byteorder != "little":
        return invalid("wrong run-local source or host byte order")
    library_path = source.parent / "build" / f"{instance.lower().replace('-', '')}-{backend}.so"
    if not library_path.is_file():
        return invalid("run-local library missing")
    key = str(library_path)
    if key not in _LIBRARIES:
        library = ctypes.CDLL(key)
        library.CryptHash.argtypes = (ctypes.c_int, ctypes.c_void_p,
                                      ctypes.c_ulonglong, ctypes.c_void_p)
        library.CryptHash.restype = ctypes.c_int
        _LIBRARIES[key] = library
    input_buffer = ctypes.create_string_buffer(message if message else b"\\x00")
    digest_bytes = bits // 8
    output = (ctypes.c_ubyte * (digest_bytes + 16))(*([0xa5] * (digest_bytes + 16)))
    code = _LIBRARIES[key].CryptHash(bits, input_buffer, length, output)
    return {"reached": True, "status": "ok" if code == 0 else "api_error",
            "output": bytes(output[:digest_bytes]).hex() if code == 0 else None,
            "output_length": digest_bytes if code == 0 else 0,
            "return_code": code, "guard_modified": any(value != 0xa5 for value in output[digest_bytes:]),
            "backend": backend, "parameter_set": instance, "api": "CryptHash"}
'''
    write(package / "implement/variant_adapter.py", adapter)
    spec = f'''---
status: draft
target: {TARGET}
algorithm: {ALGORITHM}
source_path: third_party/{TARGET}/source
source_sha256: {inventory['source_sha256']}
document_path: third_party/{TARGET}/specification.pdf
document_sha256: {inventory['document_sha256']}
source_version: NGCC Round 1 submitted archive
extract_version: 1
---

# Pavelor draft claim extraction

The original PDF pp. 5–8 §1.2, Algorithms 1–4 defines the three fixed-output
Pavelor instances, their rate/capacity choices, padding and digest generation.
Only the submitted `CryptHash` interface is in scope here. The PDF's collision
and preimage complexity claims are outside finite SOP conformance testing.
'''
    instances, apis = [], []
    for bits in (512, 768, 1024):
        instance = f"Pavelor-{bits}"
        kat_relative = f"{ROOT_IN_SOURCE}/Test_Vector/KAT_2_12_{instance}.txt"
        kat_path = source / kat_relative
        rows = []
        for index, match in enumerate(ROW.finditer(kat_path.read_text(encoding="ascii"))):
            message_bits, message_hex, digest_bits, digest_hex = match.groups()
            if index != int(message_bits) or int(digest_bits) != bits:
                raise ValueError(f"KAT record mismatch {instance} {index}")
            if index in SAMPLES:
                rows.append({"message_bits": index, "message_hex": message_hex.lower(),
                             "digest_hex": digest_hex.lower(), "source_record_index": index})
        if len(rows) != len(SAMPLES):
            raise ValueError(f"missing sampled KAT rows: {instance}")
        corpus = {"source_path": kat_relative, "source_sha256": sha(kat_path), "records": rows}
        corpus_name = f"kat_pavelor{bits}_subset.json"
        dump(package / "data" / corpus_name, corpus)
        tag = f"PAVELOR{bits}"
        diff_id, kat_id = f"{tag}-DIFF-01", f"{tag}-KAT-01"
        spec += f'''
## {tag}-D — {instance} submitted backend agreement

- Source locator: `third_party/{TARGET}/specification.pdf`, PDF pp. 5–8 §1.2, Algorithms 1–4; submitted `{instance}` reference and optimized `CryptHash_AlgorithmInstance.h` paths.
- Class: deterministic construction and submitted API identity; backend equality is an extraction inference, not a PDF statement about software.
- Scope: exact `{instance}` fixed-output `CryptHash` call with canonical message bitstring, successful calls and identical output length.
- Claim: Both submitted paths for one named instance should produce equal `{bits}`-bit digests for the same input.
- Preconditions: Identical message bytes/bit length, exact output length, compatible profiles and pinned source.
- Extraction inference/ambiguity: Backend equality follows from common deterministic instance identity, not a PDF software statement.
- Limitations: Shared lineage can hide defects; difference alone does not identify which path is faulty. Finite comparisons do not prove computational security.

## {tag}-K — {instance} submitted KAT consistency

- Source locator: `{kat_relative}`, SHA-256 `{corpus['source_sha256']}`, fields `Msg_Len`, `Msg`, `Dst_Len`, `Dst`.
- Class: submitted vector observation, not independent normative truth.
- Scope: exact indexed rows and `{instance}` `CryptHash` backends.
- Claim: Each recorded input reproduces its own submitted `{bits}`-bit digest.
- Preconditions: Exact bytes, bit length, output length, record index, KAT hash and source version.
- Extraction inference/ambiguity: Vector generation may share implementation lineage.
- Limitations: Mismatch remains candidate-only and finite samples prove no security property.
'''
        oracles = []
        for kind, pattern, claim_id, oid in (("diff", "P3", f"{tag}-D", diff_id),
                                              ("kat", "P1", f"{tag}-K", kat_id)):
            design_path = f"design/{ALGORITHM}/CryptHash/{oid}.md"
            relation = ("reference and optimized digests match for the same bitstring, and a bound KAT digest when present"
                        if kind == "diff" else "both exact submitted KAT rows yield their own recorded digests")
            intervention = ("switch only the submitted backend" if kind == "diff" else
                            "switch between two distinct indexed KAT rows on one backend")
            write(package / design_path, f'''# {oid}: {instance} source-pinned relation

- Claim: `{claim_id}` in `oracles/spec/{spec_path.name}`; PDF pp. 5–8 §1.2 for the algorithm and `{kat_relative}` for KAT observations.
- Property: X05 version 1. Pattern: {pattern} version 1.
- Extraction status: draft; results are `unverified_spec` candidates.
- Scope/preconditions: Exact `{instance}` `{bits}`-bit `CryptHash`, canonical bitstring storage, successful target calls, pinned source and exact KAT provenance when used.
- Baseline: Valid public input on the submitted reference path.
- Intervention: {intervention}; paired mutator records changed fields and effectiveness.
- Expected relation: {relation}.
- Observables: Target reachability, status, output bytes and length, 16-byte output canary, exact vector path/hash/index when applicable.
- Positive control: Real submitted 512-bit row for P3, distinct 512/513-bit rows for P1.
- Negative control: Identical input/backends or repeated KAT row is ineffective and `inconclusive`.
- Fault control: Flip one observed digest bit after a real call in smoke; predicate must reject it.
- Required capabilities: bit_input, submitted_kat, dual_backend, output_canary as relevant.
- Predicate: Validate scope/provenance/calls and compare the observed bytes against the declared relation; failure is candidate-only.
- Paired mutator: `implement/mutator/variant_{kind}_{bits}.py`.
- Limitation: Shared implementation/vector lineage; no finite proof of collision or preimage security.
''')
            write(package / f"implement/mutator/variant_{kind}_{bits}.py",
                  s_hash.module_text(bits, kind, "mutator", ("reference", "optimized"), True, corpus_name))
            write(package / f"implement/variant_{kind}_{bits}_oracle.py",
                  s_hash.module_text(bits, kind, "oracle", ("reference", "optimized"), True, corpus_name))
            oracles.append({"id": oid, "version": 1, "claim": claim_id, "property": "X05",
                            "property_version": 1, "pattern": pattern, "pattern_version": 1,
                            "design": design_path, "oracle": f"implement/variant_{kind}_{bits}_oracle.py",
                            "mutator": f"implement/mutator/variant_{kind}_{bits}.py",
                            "required_capabilities": (["dual_backend", "bit_input", "output_canary"] if kind == "diff"
                                                      else ["bit_input", "submitted_kat", "output_canary"]),
                            "applicable_primitives": ["hash"]})
        caps = {"dual_backend": True, "bit_input": True, "submitted_kat": True,
                "output_canary": True, "rng_control": False, "fault_injection": False,
                "intermediate_state": False, "decapsulation_failure": False}
        profile_name = "gcc-ref-opt-aes"
        instances.append({"parameter_set": instance, "api": "CryptHash", "profiles": [profile_name],
                          "adapter": "implement/variant_adapter.py", "capabilities": caps,
                          "oracles": oracles})
        profile = {"id": profile_name,
                   "build": [["python3", "{run}/package/implement/variant_build.py", "{source}", "{run}", instance]],
                   "dependencies": ["python", "gcc"], "timeout_seconds": 90,
                   "cpu_seconds": 90, "memory_mb": 1024,
                   "disk_mb": (inventory["source_bytes"] + 1048575) // 1048576 + 160,
                   "iterations": 24, "concurrency": 1, "seed_policy": "fixed",
                   "seed": 22000 + bits, "retention_days": 30,
                   "sensitive_inputs": False, "access_policy": "public_test_only",
                   "options": {"parameter_set": instance, "digest_bits": bits}}
        apis.append({"name": "CryptHash", "parameter_set": instance, "profiles": [profile]})
    write(spec_path, spec)
    manifest = {"schema_version": 2, "target": TARGET, "algorithm": ALGORITHM,
                "primitive": "hash", "source_digest": inventory["source_sha256"],
                "spec_sha256": sha(spec_path), "instances": instances}
    dump(package / "manifest.json", manifest)
    registry["targets"].append({"target": TARGET, "algorithm": ALGORITHM,
                                "primitive": "hash", "source": f"third_party/{TARGET}/source",
                                "source_digest": inventory["source_sha256"],
                                "specification": f"oracles/spec/{spec_path.name}", "apis": apis})
    fd, temporary = tempfile.mkstemp(prefix="targets-c-", suffix=".json", dir=config_path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(registry, indent=2, ensure_ascii=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, config_path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    wrapper = ROOT / "scripts/pqcfuzz_eval_hash-22.sh"
    write(wrapper, '#!/usr/bin/env bash\nset -euo pipefail\n'
          'repo_root=$(cd "$(dirname "$0")/.." && pwd)\n'
          'exec "${PQCFUZZ_PYTHON:-python3}" "$repo_root/scripts/pqcfuzz_target.py" '
          '"${1:-run}" --target hash-22 --algorithm Pavelor --parameter-set Pavelor-512 '
          '--api CryptHash --profile gcc-ref-opt-aes "${@:2}"\n')
    wrapper.chmod(0o755)
    print(json.dumps({"target": TARGET, "instances": [x["parameter_set"] for x in instances]}))


if __name__ == "__main__":
    main()
