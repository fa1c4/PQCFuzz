#!/usr/bin/env python3
"""Register ADKEX/DKEX submitted-transcript role-agreement SOP slices."""
import hashlib
import importlib.util
import json
import os
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {"kex-01": ("ADKEX", "PDF pp. 32–33 matching-session correctness", 2),
           "kex-04": ("DKEX", "PDF pp. 27–28 matching-session correctness", 3)}


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def dump(path, value):
    write(path, json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def kat_meta(path, expected_passes):
    records, row = [], {}
    with path.open("rb") as stream:
        for line in stream:
            if line.startswith(b"Count =") and row:
                records.append(row)
                row = {}
            if b" = " not in line:
                continue
            key, value = line.rstrip(b"\r\n").split(b" = ", 1)
            key = key.decode("ascii")
            if key in ("Count", "Pass_Num", "SS_Len"):
                row[key] = int(value)
            elif key == "SS":
                row["expected_ss"] = value.decode("ascii").lower()
    if row:
        records.append(row)
    if len(records) != 10 or [x["Count"] for x in records] != list(range(10)) or \
            any(x["Pass_Num"] != expected_passes for x in records):
        raise ValueError(f"KAT count/pass mismatch: {path}")
    return records


BUILD = '''"""Compile exact run-local ADKEX/DKEX submitted reference implementation."""
import hashlib
import json
import pathlib
import subprocess
import sys

TARGET = "__TARGET__"
ALG = "__ALG__"

def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: build.py SOURCE RUN INSTANCE")
    source, run = pathlib.Path(sys.argv[1]).resolve(), pathlib.Path(sys.argv[2]).resolve()
    instance = sys.argv[3]
    if source != run / "source" or run.parent.parent.name != TARGET:
        raise SystemExit("wrong run-local source")
    config = json.loads((pathlib.Path(__file__).resolve().parents[1] / "data/instances.json").read_text())
    if instance not in config:
        raise SystemExit("unknown instance")
    cfg = config[instance]
    kat = (source / cfg["kat"]).resolve()
    if not kat.is_file() or not kat.is_relative_to(source):
        raise SystemExit("invalid KAT path")
    digest = hashlib.sha256()
    offsets = []
    with kat.open("rb") as stream:
        while True:
            position = stream.tell()
            line = stream.readline()
            if not line:
                break
            digest.update(line)
            if line.startswith(b"Count ="):
                offsets.append(position)
        offsets.append(stream.tell())
    if digest.hexdigest() != cfg["kat_sha256"] or len(offsets) != 11:
        raise SystemExit("KAT digest/count mismatch")
    build = run / "build"
    build.mkdir(exist_ok=True)
    (build / f"{instance}-offsets.json").write_text(json.dumps(offsets))
    directory = (source / cfg["implementation_dir"]).resolve()
    if not directory.is_dir() or not directory.is_relative_to(source):
        raise SystemExit("invalid implementation directory")
    level = int(instance.split("-")[-1])
    flags = ["-std=c99", "-O2", "-fcommon", "-fPIC", "-DDKE_FORCE_SCALAR",
             f"-DADKEX_MODE={level}", f"-DDKE_MODE={level}", "-DDKE_HASH=0", "-DDKE_RANDOM=0"]
    output = build / f"{instance}.so"
    if ALG == "ADKEX":
        names = "sm3 dke_sm3 dke_hash reduce ntt poly polyvec random_sampling dke_utils packing verify dkecpa dkecca randombytes drng auxfunc adkex_derand KEX_AlgorithmInstance KAT_KEX".split()
        files = [directory / (name + ".c") for name in names]
        if any(not file.is_file() for file in files):
            raise SystemExit("missing submitted reference source")
        command = ["gcc", *flags, "-shared", "-Wl,-z,defs", "-I", str(directory),
                   "-o", str(output), *(str(file) for file in files), "-lm"]
        subprocess.run(command, check=True)
    else:
        dil_level = 2 if level == 128 else 5
        flags += ["-DADKEX_SIG_BACKEND_MLDSA", f"-DADKEX_SIG_MLDSA_LEVEL={dil_level}",
                  f"-DDILITHIUM_MODE={dil_level}"]
        groups = (("core", "sm3 dke_sm3 dke_hash reduce ntt poly polyvec random_sampling dke_utils packing verify dkecpa drng auxfunc".split(), directory, []),
                  ("dil", "fips202 ntt packing poly polyvec reduce rounding sign symmetric-shake".split(), directory / "dilithium", ["-I", str(directory / "dilithium")]),
                  ("lay", "adkex_derand adkex_sig_mldsa KEX_AlgorithmInstance KAT_KEX randombytes".split(), directory, ["-I", str(directory), "-I", str(directory / "dilithium")]))
        objects = []
        objdir = build / f"{instance}-objects"
        objdir.mkdir(exist_ok=True)
        for prefix, names, root, includes in groups:
            for name in names:
                file = root / (name + ".c")
                if not file.is_file() or not file.resolve().is_relative_to(source):
                    raise SystemExit("missing or escaping submitted source")
                obj = objdir / f"{prefix}_{name}.o"
                subprocess.run(["gcc", *flags, *includes, "-c", str(file), "-o", str(obj)], check=True)
                objects.append(obj)
        subprocess.run(["gcc", "-shared", "-Wl,-z,defs", "-o", str(output),
                        *(str(obj) for obj in objects), "-lm"], check=True)
    print(instance + ": reference KEX library ready", flush=True)

if __name__ == "__main__":
    main()
'''

ADAPTER = '''"""Derive both submitted KEX roles on one indexed public transcript."""
import ctypes
import json
from pathlib import Path

TARGET = "__TARGET__"
LIBRARIES = {}

def invalid(reason):
    return {"reached": False, "status": "invalid_input", "output": None,
            "output_length": 0, "diagnostic": reason}

def record(path, offsets, index):
    with path.open("rb") as stream:
        stream.seek(offsets[index])
        block = stream.read(offsets[index + 1] - offsets[index])
    row = {}
    for line in block.splitlines():
        if b" = " in line:
            key, value = line.split(b" = ", 1)
            row[key.decode("ascii")] = value.decode("ascii").strip()
    if int(row.get("Count", -1)) != index:
        raise ValueError("KAT record index mismatch")
    return row

def buffer(row, key):
    raw = bytes.fromhex(row[key])
    if len(raw) != int(row[key + "_Len"]):
        raise ValueError("KAT field length mismatch: " + key)
    return ctypes.create_string_buffer(raw if raw else b"\\x00"), len(raw)

def invoke(structured_input, source_root, profile):
    if not isinstance(structured_input, dict) or not isinstance(profile, dict):
        return invalid("input/profile must be objects")
    source = Path(source_root).resolve()
    if source.name != "source" or source.parent.parent.parent.name != TARGET:
        return invalid("wrong run-local target")
    package = source.parent / "package"
    config = json.loads((package / "data/instances.json").read_text())
    instance = profile.get("parameter_set")
    if instance not in config or structured_input.get("instance") != instance or \\
            structured_input.get("operation") != "derive_roles":
        return invalid("wrong instance or operation")
    index = structured_input.get("record_index")
    if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < 10:
        return invalid("invalid record index")
    offsets_path = source.parent / "build" / f"{instance}-offsets.json"
    lib_path = source.parent / "build" / f"{instance}.so"
    if not offsets_path.is_file() or not lib_path.is_file():
        return invalid("run-local build missing")
    cfg = config[instance]
    row = record(source / cfg["kat"], json.loads(offsets_path.read_text()), index)
    passes = cfg["passes"]
    if int(row["Pass_Num"]) != passes:
        return invalid("pass count mismatch")
    if instance not in LIBRARIES:
        LIBRARIES[instance] = ctypes.CDLL(str(lib_path))
    lib = LIBRARIES[instance]
    lib.kex_get_passes_num.restype = ctypes.c_ulonglong
    lib.kex_get_ss_len_bytes.restype = ctypes.c_ulonglong
    expected_length = int(row["SS_Len"])
    if lib.kex_get_passes_num() != passes or lib.kex_get_ss_len_bytes() != expected_length:
        return invalid("submitted API length/pass getter mismatch")
    args = (ctypes.c_void_p, ctypes.c_ulonglong) * 4 + \\
           (ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong))
    outputs = {}
    codes = {}
    guards = {}
    for role, fields in (("a", ("SKa", "PKb", "M2", "Pass1_Sta" if passes == 2 else "Pass3_Sta")),
                         ("b", ("SKb", "PKa", "M1" if passes == 2 else "M3", "Pass2_Stb"))):
        pairs = [buffer(row, field) for field in fields]
        fn = getattr(lib, "kex_derive_ss_" + role)
        fn.argtypes = args
        fn.restype = ctypes.c_int
        result = (ctypes.c_ubyte * (expected_length + 16))(*([0xa5] * (expected_length + 16)))
        length = ctypes.c_ulonglong(expected_length)
        code = fn(*(part for pair in pairs for part in pair), result, ctypes.byref(length))
        outputs[role] = bytes(result[:expected_length]).hex() if code == 0 and length.value == expected_length else None
        codes[role] = code
        guards[role] = any(value != 0xa5 for value in result[expected_length:])
    success = all(codes[role] == 0 and outputs[role] is not None for role in ("a", "b"))
    return {"reached": True, "status": "ok" if success else "api_error",
            "output": outputs["a"], "peer_output": outputs["b"],
            "output_length": expected_length if success else 0,
            "return_code_a": codes["a"], "return_code_b": codes["b"],
            "guard_modified": any(guards.values()), "parameter_set": instance,
            "api": "kex_derive_ss_a+b", "passes": passes}
'''

ORACLE = '''"""Compare both KEX roles and the exact submitted session key."""
import json
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
DATA = json.loads((PACKAGE / "data/instances.json").read_text())
INSTANCE = "__INSTANCE__"

def evaluate(case, baseline, mutated):
    cfg = DATA[INSTANCE]
    left, right = case.get("baseline", {}), case.get("mutated", {})
    provenance = case.get("kat_provenance", {})
    applicable = (isinstance(left, dict) and isinstance(right, dict) and
                  left.get("instance") == right.get("instance") == INSTANCE and
                  left.get("operation") == right.get("operation") == "derive_roles" and
                  provenance.get("path") == cfg["kat"] and
                  provenance.get("sha256") == cfg["kat_sha256"] and
                  all(isinstance(x.get("record_index"), int) and
                      not isinstance(x.get("record_index"), bool) and
                      0 <= x["record_index"] < 10 for x in (left, right)))
    expected = tuple(cfg["records"][x["record_index"]]["expected_ss"]
                     for x in (left, right)) if applicable else (None, None)
    observations = (baseline, mutated)
    observable = all(isinstance(o, dict) and o.get("reached") is True and
                     o.get("status") == "ok" and
                     o.get("output_length") == len(want) // 2 and
                     o.get("guard_modified") is False and
                     o.get("passes") == cfg["passes"] for o, want in zip(observations, expected)) if applicable else False
    holds = observable and all(o.get("output") == o.get("peer_output") == want
                               for o, want in zip(observations, expected))
    return {"applicable": bool(applicable), "observable": bool(observable), "holds": bool(holds),
            "expected": expected,
            "actual": tuple({"a": o.get("output"), "b": o.get("peer_output")} for o in observations),
            "explanation": "source-pinned matching-session final-role agreement"}

def fault_observation(mutated):
    altered = dict(mutated)
    value = altered.get("peer_output")
    if isinstance(value, str) and len(value) >= 2:
        altered["peer_output"] = f"{int(value[:2], 16) ^ 1:02x}" + value[2:]
    return altered
'''


def main():
    public = importlib.util.spec_from_file_location("c_public", ROOT / "scripts/pqcfuzz_c_public_kat_onboard.py")
    module = importlib.util.module_from_spec(public)
    public.loader.exec_module(module)
    registry_path = ROOT / "configs/targets.json"
    registry = json.loads(registry_path.read_text())
    present = {x["target"] for x in registry["targets"]}
    inventory = {x["target"]: x for x in
                 json.loads((ROOT / "workspace/c_targets_sop/inventory.json").read_text())}
    added = []
    for target, (algorithm, locator, passes) in TARGETS.items():
        if target in present:
            continue
        source = ROOT / "third_party" / target / "source"
        package = ROOT / "oracles" / target
        spec_path = ROOT / "oracles/spec" / f"{target}-{algorithm}.md"
        spec = f'''---
status: draft
target: {target}
algorithm: {algorithm}
source_path: third_party/{target}/source
source_sha256: {inventory[target]['source_sha256']}
document_path: third_party/{target}/specification.pdf
document_sha256: {inventory[target]['document_sha256']}
source_version: NGCC Round 1 submitted archive
extract_version: 1
---

# {algorithm} draft matching-session extraction

The original specification's matching-session correctness relation is at
{locator}. This extract covers only final role derivation from exact public
submitted transcripts. It does not test full handshake generation, authentication,
replay resistance or forward secrecy; those require separate source-backed oracles.
'''
        configs, instances, apis = {}, [], []
        for level in (128, 256, 512):
            instance = f"{algorithm}-{level}"
            kat_relative = f"Test_Vectors/KAT_KEX_{instance}.txt"
            kat = source / kat_relative
            cfg = {"kat": kat_relative, "kat_sha256": sha(kat), "passes": passes,
                   "implementation_dir": f"Implementations/Reference_Implementation/{instance}",
                   "records": kat_meta(kat, passes)}
            configs[instance] = cfg
            tag = f"{algorithm}{level}"
            claim, oid = f"{tag}-C", f"{tag}-ROLE-01"
            spec += f'''
## {claim} — {instance} final matching-session role agreement

- Source locator: `third_party/{target}/specification.pdf`, {locator}; `{kat_relative}`, SHA-256 `{cfg['kat_sha256']}`.
- Class: proposed matching-session correctness relation and submitted-vector observation.
- Scope: `{instance}` final `kex_derive_ss_a/b` calls on the ten exact public submitted transcripts, with {passes} passes.
- Claim: Both honest matching roles derive the same submitted session key for an exact valid transcript.
- Preconditions: Identical session record index/source hash, exact role keys, final messages and states, successful API calls and output lengths.
- Extraction inference/ambiguity: These vectors are same-lineage controls; matching keys on archived transcripts do not imply authentication or freshness.
- Limitations: Probabilistic protocol correctness and cryptographic AKE security cannot be proven by finite vectors; full handshake paths are outside this slice.
'''
            design_path = f"design/{algorithm}/kex_derive_ss_a+b/{oid}.md"
            write(package / design_path, f'''# {oid}: final-role matching-session relation

- Claim: `{claim}` in `oracles/spec/{spec_path.name}`, {locator} and `{kat_relative}`.
- Property: X05 version 1, aligned peer interoperability. Pattern: P2 version 1, complementary role derivation on one matching transcript.
- Extraction status: draft (`unverified_spec`); any failure remains candidate-only.
- Scope/preconditions: `{instance}`, exact indexed {passes}-pass submitted transcript, correct role keys/final messages/states and pinned source/KAT hashes.
- Baseline: Both roles derive on one valid public submitted transcript.
- Intervention: Switch to another indexed valid transcript while retaining instance and role/API mapping; paired mutator records the changed index.
- Expected relation: For each record, both derived secrets agree with each other and with that record's submitted session key.
- Observables: Two actual target calls, return statuses, output bytes/lengths, canaries and pass count.
- Positive control: Two distinct records invoke both role APIs and satisfy the relation.
- Negative control: Repeating one record is ineffective and yields `inconclusive`.
- Fault control: Flip one observed responder-secret bit after real calls; predicate rejects it.
- Required capabilities: submitted_kat, indexed_public_vector, dual_role_derivation, output_canary.
- Predicate: Validate exact source/provenance/scope, successful calls and two expected role outputs; mismatch is candidate-only.
- Paired mutator: `implement/mutator/role_{level}.py`.
- Limitations: Submitted-vector lineage; no handshake-generation, authentication, replay or full-function coverage claim.
''')
            write(package / f"implement/mutator/role_{level}.py",
                  module.MUTATOR.replace("__INSTANCE__", instance).replace("__OPERATION__", "derive_roles"))
            write(package / f"implement/role_{level}_oracle.py",
                  ORACLE.replace("__INSTANCE__", instance))
            caps = {"submitted_kat": True, "indexed_public_vector": True,
                    "dual_role_derivation": True, "output_canary": True,
                    "rng_control": False, "fault_injection": False,
                    "intermediate_state": False, "decapsulation_failure": False}
            instances.append({"parameter_set": instance, "api": "kex_derive_ss_a+b",
                              "profiles": ["gcc-reference"], "adapter": "implement/adapter.py",
                              "capabilities": caps,
                              "oracles": [{"id": oid, "version": 1, "claim": claim,
                                           "property": "X05", "property_version": 1,
                                           "pattern": "P2", "pattern_version": 1,
                                           "design": design_path,
                                           "oracle": f"implement/role_{level}_oracle.py",
                                           "mutator": f"implement/mutator/role_{level}.py",
                                           "required_capabilities": ["submitted_kat", "indexed_public_vector",
                                                                     "dual_role_derivation", "output_canary"],
                                           "applicable_primitives": ["kex"]}]})
            profile = {"id": "gcc-reference",
                       "build": [["python3", "{run}/package/implement/build.py", "{source}", "{run}", instance]],
                       "dependencies": ["python", "gcc"], "timeout_seconds": 180,
                       "cpu_seconds": 180, "memory_mb": 2048,
                       "disk_mb": (inventory[target]["source_bytes"] + 1048575) // 1048576 + 256,
                       "iterations": 10, "concurrency": 1, "seed_policy": "fixed",
                       "seed": 100000 + level + int(target.split("-")[1]),
                       "retention_days": 30, "sensitive_inputs": False,
                       "access_policy": "public_test_only", "options": {"parameter_set": instance}}
            apis.append({"name": "kex_derive_ss_a+b", "parameter_set": instance,
                         "profiles": [profile]})
        dump(package / "data/instances.json", configs)
        write(package / "implement/build.py", BUILD.replace("__TARGET__", target).replace("__ALG__", algorithm))
        write(package / "implement/adapter.py", ADAPTER.replace("__TARGET__", target))
        write(spec_path, spec)
        dump(package / "manifest.json", {"schema_version": 2, "target": target,
             "algorithm": algorithm, "primitive": "kex",
             "source_digest": inventory[target]["source_sha256"], "spec_sha256": sha(spec_path),
             "instances": instances})
        registry["targets"].append({"target": target, "algorithm": algorithm,
                                    "primitive": "kex", "source": f"third_party/{target}/source",
                                    "source_digest": inventory[target]["source_sha256"],
                                    "specification": f"oracles/spec/{spec_path.name}", "apis": apis})
        wrapper = ROOT / "scripts" / f"pqcfuzz_eval_{target}.sh"
        write(wrapper, '#!/usr/bin/env bash\nset -euo pipefail\n'
              'repo_root=$(cd "$(dirname "$0")/.." && pwd)\n'
              f'exec "${{PQCFUZZ_PYTHON:-python3}}" "$repo_root/scripts/pqcfuzz_target.py" '
              f'"${{1:-run}}" --target {target} --algorithm {algorithm} '
              f'--parameter-set {algorithm}-128 --api kex_derive_ss_a+b --profile gcc-reference "${{@:2}}"\n')
        wrapper.chmod(0o755)
        added.append(target)
    if added:
        fd, temporary = tempfile.mkstemp(prefix="targets-c-kex-", suffix=".json", dir=registry_path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(json.dumps(registry, indent=2, ensure_ascii=False) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, registry_path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    print(json.dumps({"registered": added}))


if __name__ == "__main__":
    main()
