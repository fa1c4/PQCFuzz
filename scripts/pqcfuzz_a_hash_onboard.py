#!/usr/bin/env python3
"""Generate source-pinned, draft SOP packages for qualified A-tier hash-512 paths.

Only targets with primary reference and optimized one-KAT diagnostic matches
are eligible. This generator does not claim full target/function coverage.
"""
import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path

from pypdf import PdfReader

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "workspace/a_targets_sop"
ELIGIBLE = {"hash-01", "hash-02", "hash-04", "hash-06", "hash-07", "hash-08",
            "hash-09", "hash-12", "hash-13", "hash-17", "hash-21", "hash-24",
            "hash-25", "hash-26", "hash-33", "hash-35"}
KAT_RE = re.compile(r"Msg_Len = (\d+)\nMsg = ([0-9A-F]*)\nDst_Len = (\d+)\nDst = ([0-9A-F]+)")
SELECT = (0, 1, 7, 8, 63, 64, 65, 511, 512, 513, 1023, 1024,
          1025, 2047, 2048, 2049, 4095, 4096)
PDF_LOCATORS = {
    "hash-01": "PDF pp. 8–9, 18", "hash-02": "PDF pp. 4, 10",
    "hash-04": "PDF p. 4", "hash-06": "PDF pp. 7–9",
    "hash-07": "PDF pp. 9–10", "hash-08": "PDF pp. 13–14, 18",
    "hash-09": "PDF pp. 5, 10", "hash-12": "PDF p. 4",
    "hash-13": "PDF pp. 6, 11", "hash-17": "PDF pp. 4, 10",
    "hash-21": "PDF p. 5", "hash-24": "PDF pp. 4–5, 15",
    "hash-25": "PDF pp. 5, 13", "hash-26": "PDF p. 4",
    "hash-33": "PDF pp. 7–8", "hash-35": "PDF pp. 5–8",
}


def dump(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def create(target, inv, ref, opt, *, algorithm_override=None, locator_override=None,
           build_options=None, reference_only=False):
    source = ROOT / "third_party" / target / "source"
    instance = ref["instance"]
    if ref["status"] != "one_kat_match" or (not reference_only and
                                               opt["status"] != "one_kat_match"):
        raise ValueError(f"unqualified target {target}")
    if ref["digest_bits"] != 512 or not (instance.endswith("-512") or
                                         instance.endswith("_512") or instance.endswith("512") or
                                         instance == "Garnet_512_Cap1024"):
        raise ValueError(f"unexpected instance {instance}")
    algorithm = algorithm_override or (instance[:-4] if instance.endswith(("-512", "_512"))
                                       else instance[:-3])
    kat_path = source / ref["kat"]
    kat_bytes = kat_path.read_bytes()
    if hashlib.sha256(kat_bytes).hexdigest() != ref["kat_sha256"]:
        raise ValueError(f"KAT changed: {target}")
    matches = list(KAT_RE.finditer(kat_bytes.decode("ascii").replace("\r\n", "\n")))
    if not matches or max(SELECT) >= len(matches):
        raise ValueError(f"insufficient KAT rows: {target}")
    records = []
    for index in SELECT:
        bits, message, output_bits, digest = matches[index].groups()
        if int(output_bits) != 512 or int(bits) != index:
            raise ValueError(f"unexpected KAT record {target} {index}")
        data = bytes.fromhex(message)
        if len(data) != (int(bits) + 7) // 8 or len(digest) != 128:
            raise ValueError(f"malformed KAT record {target} {index}")
        if int(bits) % 8 and data[-1] & ((1 << (8 - int(bits) % 8)) - 1):
            raise ValueError(f"non-canonical KAT row {target} {index}")
        records.append({"message_bits": int(bits), "message_hex": message.lower(),
                        "digest_hex": digest.lower(), "source_record_index": index})
    locator = locator_override or PDF_LOCATORS[target]
    reader = PdfReader(ROOT / "third_party" / target / "specification.pdf")
    if not reader.pages:
        raise ValueError(f"empty target PDF: {target}")
    package = ROOT / "oracles" / target
    (package / "implement/mutator").mkdir(parents=True, exist_ok=True)
    dump(package / "data/kat_512_subset.json", {"source_path": ref["kat"],
         "source_sha256": ref["kat_sha256"], "records": records})
    dump(package / "data/build_sources.json", {"instance": instance,
         "reference": ref["sources"],
         "optimized": [] if reference_only else opt["sources"],
         "backends": ["reference"] if reference_only else ["reference", "optimized"],
         **(build_options or {})})
    shutil.copyfile(ROOT / "oracles/hash-23/implement/variant_common.py",
                    package / "implement/common.py")
    build = '''"""Build only pinned submitted source files in the run-local tree."""
import json
import pathlib
import subprocess
import sys

TARGET = "__TARGET__"

def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: build.py SOURCE RUN")
    source, run = pathlib.Path(sys.argv[1]).resolve(), pathlib.Path(sys.argv[2]).resolve()
    if source != run / "source" or run.parent.parent.name != TARGET or sys.byteorder != "little":
        raise SystemExit("wrong run-local source, target, or byte order")
    spec = json.loads((pathlib.Path(__file__).resolve().parents[1] / "data/build_sources.json").read_text())
    build_dir = run / "build"
    build_dir.mkdir(exist_ok=True)
    for backend in spec.get("backends", ("reference", "optimized")):
        paths = [(source / item).resolve() for item in spec[backend]]
        if not paths or any(not p.is_file() or not p.is_relative_to(source) for p in paths):
            raise SystemExit("missing or escaping submitted source")
        compiler = spec.get("compilers", {}).get(backend, "gcc")
        if compiler not in ("gcc", "g++"):
            raise SystemExit("unsupported pinned compiler")
        flags = [compiler, "-std=c++17" if compiler == "g++" else "-std=c11",
                 "-O2", "-fPIC", "-shared", "-Wl,-z,defs"]
        for relative in spec.get("include_dirs", []):
            directory = (source / relative).resolve()
            if not directory.is_dir() or not directory.is_relative_to(source):
                raise SystemExit("missing or escaping include directory")
            flags.extend(["-I", str(directory)])
        if backend == "optimized":
            flags.append("-march=native")
        if TARGET == "hash-01" and backend == "optimized":
            flags.extend(["-DAFS_TREDM_BENCH_IMPL_AVX2=1", "-DAFS_TREDM_USE_AVX2=1",
                          "-DAFS_TREDM_S6_CANONICAL_AVX2=1", "-mavx2"])
        if TARGET == "hash-26" and backend == "optimized":
            flags[0] = "g++"
            flags.append("-std=c++17")
        output = build_dir / ("hash512-" + backend + ".so")
        command = flags + ["-o", str(output), *(str(p) for p in paths)]
        if TARGET == "hash-26" and backend == "optimized":
            command.append("-lcrypto")
        subprocess.run(command, check=True)
        print(backend + ": " + ", ".join(str(p.relative_to(source)) for p in paths), flush=True)

if __name__ == "__main__":
    main()
'''.replace("__TARGET__", target)
    (package / "implement/build.py").write_text(build, encoding="utf-8")
    adapter = '''"""Invoke exact run-local submitted 512-bit CryptHash path."""
import ctypes
import re
import sys
from pathlib import Path

TARGET = "__TARGET__"
INSTANCE = "__INSTANCE__"
_FUNCTIONS = {}
_BACKENDS = __BACKENDS__

def _invalid(reason):
    return {"reached": False, "status": "invalid_input", "output": None,
            "output_length": 0, "diagnostic": reason}

def invoke(structured_input, source_root, profile):
    if not isinstance(structured_input, dict) or not isinstance(profile, dict):
        return _invalid("input/profile must be objects")
    if profile.get("parameter_set") != INSTANCE or profile.get("digest_bits") != 512 or sys.byteorder != "little":
        return _invalid("wrong parameter set, output length, or byte order")
    backend = structured_input.get("backend")
    bits = structured_input.get("message_bits")
    message_hex = structured_input.get("message_hex")
    if backend not in _BACKENDS or structured_input.get("digest_bits") != 512:
        return _invalid("backend/output mismatch")
    if not isinstance(bits, int) or isinstance(bits, bool) or not 0 <= bits <= 8192:
        return _invalid("invalid bit length")
    if not isinstance(message_hex, str) or re.fullmatch(r"[0-9a-f]*", message_hex) is None:
        return _invalid("invalid hex message")
    if len(message_hex) != 2 * ((bits + 7) // 8):
        return _invalid("message storage length differs from bit length")
    message = bytes.fromhex(message_hex)
    if bits % 8 and message[-1] & ((1 << (8 - bits % 8)) - 1):
        return _invalid("nonzero unused trailing bits")
    source = Path(source_root).resolve()
    if source.name != "source" or source.parent.parent.parent.name != TARGET:
        return _invalid("wrong run-local source identity")
    library = source.parent / "build" / ("hash512-" + backend + ".so")
    if not library.is_file():
        return _invalid("run-local library missing")
    if backend not in _FUNCTIONS:
        function = ctypes.CDLL(str(library)).CryptHash
        function.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p)
        function.restype = ctypes.c_int
        _FUNCTIONS[backend] = function
    input_buffer = ctypes.create_string_buffer(message if message else b"\\x00")
    output = (ctypes.c_ubyte * 80)(*([0xa5] * 80))
    result = _FUNCTIONS[backend](512, input_buffer, bits, output)
    return {"reached": True, "status": "ok" if result == 0 else "api_error",
            "output": bytes(output[:64]).hex() if result == 0 else None,
            "output_length": 64 if result == 0 else 0, "return_code": result,
            "guard_modified": any(x != 0xa5 for x in output[64:]),
            "backend": backend, "parameter_set": INSTANCE, "api": "CryptHash"}
'''.replace("__TARGET__", target).replace("__INSTANCE__", instance).replace(
        "__BACKENDS__", repr(("reference",) if reference_only else ("reference", "optimized")))
    (package / "implement/adapter.py").write_text(adapter, encoding="utf-8")
    for kind in ("kat", "diff"):
        common_path = "implement/common.py"
        load = ('''import importlib.util
import json
from pathlib import Path
_PACKAGE = Path(__file__).resolve().parents[__PARENTS__]
_SPEC = importlib.util.spec_from_file_location("a_hash_common", _PACKAGE / "__COMMON__")
_COMMON = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_COMMON)
_CORPUS = json.loads((_PACKAGE / "data/kat_512_subset.json").read_text())
_BACKENDS = __BACKENDS__
''')
        load = load.replace("__BACKENDS__", repr(("reference",) if reference_only
                                                else ("reference", "optimized")))
        oracle = load.replace("__PARENTS__", "1").replace("__COMMON__", common_path)
        oracle += f'''\ndef evaluate(case, baseline, mutated):
    return _COMMON.{kind}_evaluate(case, baseline, mutated, _CORPUS, 512, _BACKENDS, True)

def fault_observation(mutated):
    return _COMMON.fault_observation(mutated)
'''
        (package / f"implement/{kind}_oracle.py").write_text(oracle, encoding="utf-8")
        mutator = load.replace("__PARENTS__", "2").replace("__COMMON__", common_path)
        mutator += f'''\ndef generate(seed, iteration):
    return _COMMON.{kind}_generate(seed, iteration, _CORPUS, 512, _BACKENDS)

def smoke_cases():
    return _COMMON.{kind}_smoke(_CORPUS, 512, _BACKENDS)
'''
        (package / f"implement/mutator/{kind}.py").write_text(mutator, encoding="utf-8")
    spec_path = ROOT / "oracles/spec" / f"{target}-{algorithm}.md"
    spec = f'''---
status: draft
target: {target}
algorithm: {algorithm}
source_path: third_party/{target}/source
source_sha256: {inv['source_sha256']}
document_path: third_party/{target}/specification.pdf
document_sha256: {inv['document_sha256']}
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# {instance} draft claim extraction

The original source and PDF are pinned above. This extract covers only the
`{instance}` submitted `CryptHash` API. The cited construction and parameter
discussion is on {locator}; the exact source and PDF files are authoritative.

## S1 — Same-instance deterministic digest agreement

- Source locator: `third_party/{target}/specification.pdf`, {locator}; submitted `{ref['header']}` and the corresponding optimized implementation listed in `data/build_sources.json`.
- Class: submitted construction/API identity; backend agreement is an extraction inference.
- Scope: `{instance}`, 512-bit digest, `CryptHash`, canonical public bitstrings, reference and optimized submitted paths in this pinned source tree.
- Claim: For the same valid bitstring and 512-bit output profile, both submitted implementations of this named hash instance should return the same digest.
- Preconditions: Identical message bytes and exact bit length, both calls succeed, same source snapshot and fixed instance.
- Extraction inference/ambiguity: The PDF defines the named hash construction; equality across software paths follows from their shared instance identity, not an explicit PDF statement about backends. This is draft until human review.
- Limitations: Shared code may hide common errors; agreement proves neither independent conformance nor collision/preimage security. A mismatch does not identify the faulty path.

## S2 — Submitted KAT consistency

- Source locator: `{ref['kat']}`, SHA-256 `{ref['kat_sha256']}`, fields `Msg_Len`, `Msg`, `Dst_Len`, `Dst`.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact pinned 512-bit KAT records and the two submitted `{instance}` `CryptHash` paths.
- Claim: The exact recorded message and bit length should reproduce its corresponding submitted digest on each backend.
- Preconditions: Exact record index, bytes, bit length, output length and KAT-file digest are bound in the case.
- Extraction inference/ambiguity: Vector provenance is the archive itself; the vector generator may share implementation lineage.
- Limitations: A mismatch is candidate consistency evidence requiring review. Finite KAT sampling proves no computational security property.
'''
    if reference_only:
        spec = re.sub(r"\n## S1 —.*?(?=\n## S2 —)", "", spec, flags=re.S)
        spec = spec.replace(f"the two submitted `{instance}` `CryptHash` paths",
                            f"the registered reference `{instance}` `CryptHash` path")
    spec_path.write_text(spec, encoding="utf-8")
    designs = {
        "KAT": f'''# {instance} submitted KAT consistency

- Claim: S2 in `oracles/spec/{spec_path.name}`; source locator `{ref['kat']}`, SHA-256 `{ref['kat_sha256']}`.
- Property: X05 version 1, exact algorithm identity against submitted vectors.
- Pattern: P1 version 1, known-answer/reference conformance.
- Extraction status: draft; results are `unverified_spec` candidates.
- Scope: `{instance}`, submitted `CryptHash`, 512-bit KAT digest, exact archived source and registered profile.
- Preconditions: Two distinct exact pinned KAT rows, canonical message storage, exact bit lengths, same requested backend, successful calls and 64-byte outputs.
- Baseline: One pinned KAT row on a submitted backend.
- Intervention: Switch message bytes/bit length to a second pinned KAT row, retaining backend and profile. The paired mutator records changed fields and effectiveness.
- Expected relation: Each actual digest equals its own pinned `Dst` value; no equality of different-message digests is assumed.
- Observable: Target reachability, status, output bytes/length and output-buffer canary; exact vector indices/path/SHA in case evidence.
- Positive control: Distinct 512- and 513-bit KAT inputs yield their own recorded digests through actual target calls.
- Negative control: Repeating one row is ineffective and yields `inconclusive`.
- Fault control: Flip one observed digest bit after a real target call during smoke; the predicate must reject it.
- Required capabilities: `bit_input`, `submitted_kat`, `output_canary`.
- Predicate: With exact provenance/input binding and observable successful calls, compare each digest to its own expected row. False relation is candidate-only.
- Paired mutator: `implement/mutator/kat.py`.
- Limitations: Submitted vectors may share implementation lineage; finite testing proves no security property.
''',
        "DIFF": f'''# {instance} submitted backend agreement

- Claim: S1 in `oracles/spec/{spec_path.name}`; source locator `{locator}` and submitted backend files in `data/build_sources.json`.
- Property: X05 version 1, same-instance algorithm identity.
- Pattern: P3 version 1, cross-backend differential.
- Extraction status: draft; results are `unverified_spec` candidates.
- Scope: `{instance}`, 512-bit `CryptHash`, pinned reference and optimized implementations, canonical public bitstrings.
- Preconditions: Identical bitstring and output length on both backends, successful calls and 64-byte outputs.
- Baseline: Reference backend on one valid bitstring.
- Intervention: Switch only backend to the optimized submitted path; the paired mutator records that change.
- Expected relation: Digests agree for the same bitstring; when an exact KAT row is used, both also equal the bound submitted digest.
- Observable: Target reachability, status, output bytes/length and output-buffer canary; exact KAT provenance when applicable.
- Positive control: Both paths agree on the same 512-bit submitted KAT input through actual target calls.
- Negative control: No backend switch is ineffective and yields `inconclusive`.
- Fault control: Flip one observed digest bit after real calls during smoke; predicate must reject it.
- Required capabilities: `dual_backend`, `bit_input`, `output_canary`.
- Predicate: With matching structured input and observable calls, compare outputs and any bound KAT expectation. False relation is candidate-only.
- Paired mutator: `implement/mutator/diff.py`.
- Limitations: Shared implementation lineage, profile-specific behavior and absent independent reference limit inference; finite testing proves no security property.
'''}
    oracle_records = []
    selected_oracles = [("KAT", "P1", "S2", ["bit_input", "submitted_kat", "output_canary"])]
    if not reference_only:
        selected_oracles.insert(0, ("DIFF", "P3", "S1",
                                    ["dual_backend", "bit_input", "output_canary"]))
    for kind, pattern, claim, capabilities in selected_oracles:
        ident = f"{algorithm}512-{kind}-01"
        design = f"design/{algorithm}/CryptHash/{ident}.md"
        (package / design).parent.mkdir(parents=True, exist_ok=True)
        (package / design).write_text(designs[kind], encoding="utf-8")
        oracle_records.append({"id": ident, "version": 1, "claim": claim,
             "property": "X05", "property_version": 1, "pattern": pattern,
             "pattern_version": 1, "design": design,
             "oracle": f"implement/{kind.lower()}_oracle.py",
             "mutator": f"implement/mutator/{kind.lower()}.py",
             "required_capabilities": capabilities, "applicable_primitives": ["hash"]})
    manifest = {"schema_version": 2, "target": target, "algorithm": algorithm,
        "primitive": "hash", "source_digest": inv["source_sha256"],
        "spec_sha256": hashlib.sha256(spec_path.read_bytes()).hexdigest(),
        "instances": [{"parameter_set": instance, "api": "CryptHash",
            "profiles": ["gcc-reference" if reference_only else "gcc-ref-opt"],
            "adapter": "implement/adapter.py",
            "capabilities": {"dual_backend": not reference_only, "bit_input": True,
                "submitted_kat": True, "output_canary": True,
                "rng_control": False, "fault_injection": False,
                "intermediate_state": False, "decapsulation_failure": False},
            "oracles": oracle_records}]}
    dump(package / "manifest.json", manifest)
    profile_name = "gcc-reference" if reference_only else "gcc-ref-opt"
    profile = {"id": profile_name, "build": [["python3",
        "{run}/package/implement/build.py", "{source}", "{run}"]],
        "dependencies": ["python", "gcc"], "timeout_seconds": 90,
        "cpu_seconds": 90, "memory_mb": 1024,
        "disk_mb": max(128, (inv["source_bytes"] + (1 << 20) - 1) // (1 << 20) + 128),
        "iterations": 18, "concurrency": 1, "seed_policy": "fixed",
        "seed": int(target.split("-")[1]) * 1000 + 512,
        "retention_days": 30, "sensitive_inputs": False,
        "access_policy": "public_test_only",
        "options": {"parameter_set": instance, "digest_bits": 512}}
    entry = {"target": target, "algorithm": algorithm, "primitive": "hash",
        "source": f"third_party/{target}/source", "source_digest": inv["source_sha256"],
        "specification": f"oracles/spec/{spec_path.name}",
        "apis": [{"name": "CryptHash", "parameter_set": instance,
                  "profiles": [profile]}]}
    wrapper = ROOT / "scripts" / f"pqcfuzz_eval_{target}.sh"
    wrapper.write_text(
        "#!/usr/bin/env bash\nset -euo pipefail\n"
        'repo_root=$(cd "$(dirname "$0")/.." && pwd)\n'
        f'exec "${{PQCFUZZ_PYTHON:-python3}}" "$repo_root/scripts/pqcfuzz_target.py" '
        f'"${{1:-run}}" --target {target} --algorithm {algorithm} '
        f'--parameter-set {instance} --api CryptHash --profile {profile_name} "${{@:2}}"\n',
        encoding="utf-8")
    wrapper.chmod(0o755)
    return entry


def main():
    config_path = ROOT / "configs/targets.json"
    registry = json.loads(config_path.read_text())
    present = {x["target"] for x in registry["targets"]}
    if ELIGIBLE <= present:
        print(json.dumps({"registered": [], "already_registered": sorted(ELIGIBLE)}))
        return
    inventory = {x["target"]: x for x in json.loads((WORK / "inventory.json").read_text())}
    references = {x["target"]: x for x in json.loads((WORK / "probes/report.json").read_text())}
    optimized = {x["target"]: x for x in json.loads((WORK / "probes/optimized.json").read_text())}
    special = json.loads((WORK / "probes/special/report.json").read_text())
    special_by_key = {(x["target"], x["backend"]): x for x in special}
    for target in ("hash-01", "hash-26"):
        optimized[target] = special_by_key[(target, "optimized")]
    custom = {
        "hash-06": ("Cuishen-512", "Cuishen/Test_Vectors/KAT_2_12_Cuishen-512.txt",
                    "Cuishen/Implementations/Reference_Implementation/Cuishen-512/CryptHash_Cuishen-512.h"),
        "hash-08": ("Duet-512", "Duet/Test_Vectors/KAT_2_12_Duet-512.txt",
                    "Duet/Implementations/Reference_Implementation/Duet-512/CryptHash_Duet-512.h"),
        "hash-35": ("Wish512", "Wish/Test_Vectors/Test_Vector/Wish512/KAT_2_12_Wish512.txt",
                    "Wish/Implementations/Reference_Implementation/Wish512_reference/CryptHash_AlgorithmInstance.h"),
    }
    for target, (instance, kat, header) in custom.items():
        kat_sha = hashlib.sha256((ROOT / "third_party" / target / "source" / kat).read_bytes()).hexdigest()
        references[target] = {**special_by_key[(target, "reference")],
                              "instance": instance, "digest_bits": 512,
                              "header": header, "kat": kat, "kat_sha256": kat_sha}
        optimized[target] = special_by_key[(target, "optimized")]
    entries = [create(target, inventory[target], references[target], optimized[target])
               for target in sorted(ELIGIBLE - present)]
    registry["targets"].extend(entries)
    payload = json.dumps(registry, indent=2, ensure_ascii=False) + "\n"
    fd, temp = tempfile.mkstemp(prefix="targets-a-", suffix=".json", dir=config_path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, config_path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    print(json.dumps({"registered": [e["target"] for e in entries],
                      "parameter_sets": [e["apis"][0]["parameter_set"] for e in entries]}))


if __name__ == "__main__":
    main()
