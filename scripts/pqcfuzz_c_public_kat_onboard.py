#!/usr/bin/env python3
"""Register public submitted-KAT SOP slices for VDOO and HEP-QC instances."""
import hashlib
import json
import os
import shlex
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SETTINGS = {
    "sign-33": {"algorithm": "VDOO", "primitive": "signature", "api": "sig_verify",
                "instances": ["VDOO-128", "VDOO-256", "VDOO-512"],
                "locator": "PDF p. 10 Algorithm 5 and p. 23 §7.5–7.7",
                "property": "S03"},
    "kem-17": {"algorithm": "HEP-QC", "primitive": "kem", "api": "kem_dec",
                "instances": ["hep-qc-1", "hep-qc-3", "hep-qc-5", "hep-qc-7"],
                "locator": "PDF pp. 16–18 §3.7 Algorithms 4–6 and Table 4.1",
                "property": "K03"},
}


def dump(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def metadata(path, primitive):
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
            if key in ("Count", "PK_Len", "SK_Len", "Sn_Len", "CT_Len", "SS_Len"):
                row[key] = int(value)
            elif key == "SS" and primitive == "kem":
                row["expected_ss"] = value.decode("ascii").lower()
    if row:
        records.append(row)
    if len(records) != 10 or [x["Count"] for x in records] != list(range(10)):
        raise ValueError(f"unexpected KAT record indices: {path}")
    return records


BUILD = '''"""Compile one exact submitted instance and index its public KAT records."""
import hashlib
import json
import pathlib
import subprocess
import sys

TARGET = "__TARGET__"

def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: build.py SOURCE RUN INSTANCE")
    source, run = pathlib.Path(sys.argv[1]).resolve(), pathlib.Path(sys.argv[2]).resolve()
    instance = sys.argv[3]
    if source != run / "source" or run.parent.parent.name != TARGET:
        raise SystemExit("wrong run-local source")
    data = json.loads((pathlib.Path(__file__).resolve().parents[1] / "data/instances.json").read_text())
    if instance not in data:
        raise SystemExit("unknown instance")
    cfg = data[instance]
    kat = (source / cfg["kat"]).resolve()
    if not kat.is_file() or not kat.is_relative_to(source):
        raise SystemExit("missing or escaping KAT path")
    h = hashlib.sha256()
    offsets = []
    with kat.open("rb") as stream:
        while True:
            position = stream.tell()
            line = stream.readline()
            if not line:
                break
            h.update(line)
            if line.startswith(b"Count ="):
                offsets.append(position)
        offsets.append(stream.tell())
    if h.hexdigest() != cfg["kat_sha256"] or len(offsets) != 11:
        raise SystemExit("submitted KAT digest or row count changed")
    build = run / "build"
    build.mkdir(exist_ok=True)
    (build / f"{instance}-offsets.json").write_text(json.dumps(offsets))
    files = [(source / item).resolve() for item in cfg["sources"]]
    includes = [(source / item).resolve() for item in cfg["includes"]]
    if any(not p.is_file() or not p.is_relative_to(source) for p in files) or \\
            any(not p.is_dir() or not p.is_relative_to(source) for p in includes):
        raise SystemExit("invalid pinned build paths")
    command = ["gcc", "-std=c99" if TARGET == "sign-33" else "-std=c11", "-O2", "-fPIC",
               "-shared", "-Wl,-z,defs", *cfg["flags"],
               *(flag for p in includes for flag in ("-I", str(p))),
               "-o", str(build / f"{instance}.so"), *(str(p) for p in files)]
    subprocess.run(command, check=True)
    print(instance + ": compiled " + str(len(files)) + " pinned source files", flush=True)

if __name__ == "__main__":
    main()
'''

ADAPTER = '''"""Call actual submitted API on an indexed public KAT record."""
import ctypes
import json
from pathlib import Path

TARGET = "__TARGET__"
PRIMITIVE = "__PRIMITIVE__"
LIBRARIES = {}

def invalid(reason):
    return {"reached": False, "status": "invalid_input", "output": None,
            "output_length": 0, "diagnostic": reason}

def record(path, offsets, index):
    with path.open("rb") as stream:
        stream.seek(offsets[index])
        block = stream.read(offsets[index + 1] - offsets[index])
    values = {}
    for line in block.splitlines():
        if b" = " in line:
            key, value = line.split(b" = ", 1)
            values[key.decode("ascii")] = value.decode("ascii")
    if int(values.get("Count", -1)) != index:
        raise ValueError("KAT record index mismatch")
    return values

def buffer(value):
    raw = bytes.fromhex(value)
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
            structured_input.get("operation") != ("verify" if PRIMITIVE == "signature" else "decapsulate"):
        return invalid("wrong instance or operation")
    index = structured_input.get("record_index")
    if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < 10:
        return invalid("invalid record index")
    path = source / config[instance]["kat"]
    offsets_path = source.parent / "build" / f"{instance}-offsets.json"
    lib_path = source.parent / "build" / f"{instance}.so"
    if not offsets_path.is_file() or not lib_path.is_file():
        return invalid("run-local build missing")
    offsets = json.loads(offsets_path.read_text())
    row = record(path, offsets, index)
    if instance not in LIBRARIES:
        LIBRARIES[instance] = ctypes.CDLL(str(lib_path))
    lib = LIBRARIES[instance]
    if PRIMITIVE == "signature":
        pk, pklen = buffer(row["PK"])
        sn, snlen = buffer(row["Sn"])
        message, mlen = buffer(row["M"])
        if pklen != int(row["PK_Len"]) or snlen != int(row["Sn_Len"]) or \\
                mlen != int(row["M_Len"]):
            return invalid("KAT length mismatch")
        lib.sig_get_pk_len_bytes.restype = ctypes.c_ulonglong
        lib.sig_get_sn_len_bytes.restype = ctypes.c_ulonglong
        maximum_snlen = lib.sig_get_sn_len_bytes()
        variable_snlen = config[instance].get("variable_signature_length", False)
        if pklen != lib.sig_get_pk_len_bytes() or snlen > maximum_snlen or \\
                (not variable_snlen and snlen != maximum_snlen):
            return invalid("submitted length getter mismatch")
        fn = lib.sig_verify
        fn.argtypes = (ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p,
                       ctypes.c_ulonglong, ctypes.c_void_p, ctypes.c_ulonglong)
        fn.restype = ctypes.c_int
        code = fn(pk, pklen, sn, snlen, message, mlen)
        return {"reached": True, "status": "ok" if code == 0 else "reject",
                "output": "accepted" if code == 0 else "rejected", "output_length": 1,
                "return_code": code, "parameter_set": instance, "api": "sig_verify"}
    sk, sklen = buffer(row["SK"])
    ct, ctlen = buffer(row["CT"])
    expected_len = int(row["SS_Len"])
    if sklen != int(row["SK_Len"]) or ctlen != int(row["CT_Len"]):
        return invalid("KAT length mismatch")
    for name, length in (("kem_get_sk_len_bytes", sklen), ("kem_get_ct_len_bytes", ctlen),
                         ("kem_get_ss_len_bytes", expected_len)):
        fn = getattr(lib, name)
        fn.restype = ctypes.c_ulonglong
        if fn() != length:
            return invalid("submitted length getter mismatch: " + name)
    fn = lib.kem_dec
    fn.argtypes = (ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p,
                   ctypes.c_ulonglong, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong))
    fn.restype = ctypes.c_int
    output = (ctypes.c_ubyte * (expected_len + 16))(*([0xa5] * (expected_len + 16)))
    result_len = ctypes.c_ulonglong(expected_len)
    code = fn(sk, sklen, ct, ctlen, output, ctypes.byref(result_len))
    return {"reached": True, "status": "ok" if code == 0 else "api_error",
            "output": bytes(output[:expected_len]).hex() if code == 0 else None,
            "output_length": result_len.value if code == 0 else 0,
            "guard_modified": any(x != 0xa5 for x in output[expected_len:]),
            "return_code": code, "parameter_set": instance, "api": "kem_dec"}
'''

MUTATOR = '''"""Pair distinct source-pinned submitted KAT records."""
import json
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[2]
DATA = json.loads((PACKAGE / "data/instances.json").read_text())
INSTANCE = "__INSTANCE__"
OPERATION = "__OPERATION__"

def pair(a, b):
    cfg = DATA[INSTANCE]
    left = {"instance": INSTANCE, "operation": OPERATION, "record_index": a}
    right = {"instance": INSTANCE, "operation": OPERATION, "record_index": b}
    return {"baseline": left, "mutated": right,
            "kat_provenance": {"path": cfg["kat"], "sha256": cfg["kat_sha256"]},
            "changed_fields": ["record_index"] if a != b else [],
            "intervention": "select a different submitted KAT record" if a != b else "none",
            "effective": a != b,
            "effectiveness_evidence": {"distinct_record_indices": a != b,
                                       "same_instance_and_operation": True}}

def generate(seed, iteration):
    return pair((seed + iteration) % 10, (seed + iteration + 1) % 10)

def smoke_cases():
    return {"positive": pair(0, 1), "negative": pair(0, 0)}
'''

ORACLE = '''"""Evaluate exact submitted vector validity or shared-secret bytes."""
import json
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
DATA = json.loads((PACKAGE / "data/instances.json").read_text())
INSTANCE = "__INSTANCE__"
PRIMITIVE = "__PRIMITIVE__"

def evaluate(case, baseline, mutated):
    cfg = DATA[INSTANCE]
    left, right = case.get("baseline", {}), case.get("mutated", {})
    provenance = case.get("kat_provenance", {})
    operation = "verify" if PRIMITIVE == "signature" else "decapsulate"
    applicable = (isinstance(left, dict) and isinstance(right, dict) and
                  left.get("instance") == right.get("instance") == INSTANCE and
                  left.get("operation") == right.get("operation") == operation and
                  provenance.get("path") == cfg["kat"] and
                  provenance.get("sha256") == cfg["kat_sha256"] and
                  all(isinstance(x.get("record_index"), int) and
                      not isinstance(x.get("record_index"), bool) and
                      0 <= x["record_index"] < 10 for x in (left, right)))
    observations = (baseline, mutated)
    expected = ("accepted", "accepted") if PRIMITIVE == "signature" else tuple(
        cfg["records"][x["record_index"]]["expected_ss"] for x in (left, right)) if applicable else (None, None)
    output_length = 1 if PRIMITIVE == "signature" else len(expected[0]) // 2 if applicable else 0
    observable = all(isinstance(o, dict) and o.get("reached") is True and
                     o.get("status") == "ok" and o.get("output_length") == output_length and
                     (PRIMITIVE == "signature" or o.get("guard_modified") is False)
                     for o in observations)
    holds = observable and tuple(o.get("output") for o in observations) == expected
    return {"applicable": bool(applicable), "observable": bool(observable), "holds": bool(holds),
            "expected": expected, "actual": tuple(o.get("output") for o in observations),
            "explanation": "exact indexed submitted-KAT API consistency"}

def fault_observation(mutated):
    altered = dict(mutated)
    if PRIMITIVE == "signature":
        altered["output"] = "rejected"
    elif isinstance(altered.get("output"), str) and len(altered["output"]) >= 2:
        value = altered["output"]
        altered["output"] = f"{int(value[:2], 16) ^ 1:02x}" + value[2:]
    return altered
'''


def source_config(target, instance, source):
    if target == "sign-33":
        level = instance.split("-")[1]
        root = f"Implementation/Reference_Implementation/vdoo_{level}"
        names = "auxfunc.c blas_comm.c drng.c parallel_matrix_op.c rng.c utils.c api.c SIG_AlgorithmInstance.c vdoo_keypair.c vdoo_sign.c vdoo_verif.c".split()
        return {"kat": f"Test_Vectors/KAT_SIG_{instance}.txt",
                "sources": [f"{root}/{name}" for name in names],
                "includes": [root], "flags": [f"-DVDOO_{level}"]}
    root = "Implementations"
    names = [*sorted((source / root / "Implementations/common").glob("*.c")),
             *sorted((source / root / "Implementations/ref").glob("*.c")),
             *sorted((source / root / "Implementations/ref" / instance).glob("*.c")),
             source / root / "Lib/drng/drng.c", source / root / "Lib/auxfunc/auxfunc.c",
             source / root / "Tests/kats/KAT_KEM.c"]
    includes = [f"{root}/Implementations/common", f"{root}/Implementations/common/{instance}",
                f"{root}/Implementations/ref", f"{root}/Implementations/ref/{instance}",
                f"{root}/Lib/drng", f"{root}/Lib/auxfunc"]
    return {"kat": f"Test_Vectors/{instance}/KAT_KEM_AlgorithmInstance.txt",
            "sources": [x.relative_to(source).as_posix() for x in names],
            "includes": includes, "flags": []}


def one_target(target, inventory, registry):
    settings = SETTINGS[target]
    source = ROOT / "third_party" / target / "source"
    package = ROOT / "oracles" / target
    spec_path = ROOT / "oracles/spec" / f"{target}-{settings['algorithm']}.md"
    entries, instance_configs, apis = [], {}, []
    spec = f'''---
status: draft
target: {target}
algorithm: {settings['algorithm']}
source_path: third_party/{target}/source
source_sha256: {inventory['source_sha256']}
document_path: third_party/{target}/specification.pdf
document_sha256: {inventory['document_sha256']}
source_version: NGCC Round 1 submitted archive
extract_version: 1
---

# {settings['algorithm']} draft claim extraction

This document covers public submitted KAT records only, under the exact
`{settings['api']}` API. The algorithm construction and correctness context is
at {settings['locator']}. Original PDF and archived source are authoritative.
'''
    for instance in settings["instances"]:
        cfg = source_config(target, instance, source)
        kat = source / cfg["kat"]
        cfg["kat_sha256"] = sha(kat)
        cfg["records"] = metadata(kat, settings["primitive"])
        instance_configs[instance] = cfg
        tag = "".join(char for char in instance.upper() if char.isalnum())
        claim, oid = f"{tag}-K", f"{tag}-KAT-01"
        spec += f'''
## {claim} — {instance} submitted valid-vector consistency

- Source locator: {settings['locator']}; `{cfg['kat']}`, SHA-256 `{cfg['kat_sha256']}`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `{instance}` `{settings['api']}` on the ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record is accepted by verification.
''' if settings["primitive"] == "signature" else f'''
## {claim} — {instance} submitted valid-vector consistency

- Source locator: {settings['locator']}; `{cfg['kat']}`, SHA-256 `{cfg['kat_sha256']}`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `{instance}` `{settings['api']}` on ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record decapsulates to its recorded shared secret.
'''
        spec += '''- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.
'''
        design_path = f"design/{settings['algorithm']}/{settings['api']}/{oid}.md"
        write(package / design_path, f'''# {oid}: exact submitted-vector relation

- Claim: `{claim}` in `oracles/spec/{spec_path.name}`, source locator {settings['locator']} and `{cfg['kat']}`.
- Property: {settings['property']} version 1. Pattern: P1 version 1.
- Extraction status: draft (`unverified_spec`).
- Scope/preconditions: `{instance}` `{settings['api']}`, exact indexed public submitted KAT, archived source/KAT SHA and declared output/status semantics.
- Baseline: A valid indexed submitted record (index 0 in smoke).
- Intervention: Switch to a different valid record (index 1 in smoke) while retaining instance and API; paired mutator records index change.
- Expected relation: {'Both records are accepted by sig_verify.' if settings['primitive'] == 'signature' else 'Both records decapsulate to their own archived shared secrets.'}
- Observables: Actual API reachability, status, output/length, parameter set and output canary for KEM.
- Positive control: Two distinct valid records pass through the real target API.
- Negative control: Repeating one record is ineffective and becomes `inconclusive`.
- Fault control: Change the observed acceptance/secret after a real call; the predicate must reject it.
- Required capabilities: submitted_kat, indexed_public_vector{', output_canary' if settings['primitive'] == 'kem' else ''}.
- Predicate: Require exact provenance/scope, successful reachable calls and expected status/secret on each indexed record; failure is candidate-only.
- Paired mutator: `implement/mutator/kat_{tag.lower()}.py`.
- Limitations: Same-lineage submitted vectors, no negative-input or full-function coverage, no finite security proof.
''')
        write(package / f"implement/mutator/kat_{tag.lower()}.py",
              MUTATOR.replace("__INSTANCE__", instance).replace("__OPERATION__",
              "verify" if settings["primitive"] == "signature" else "decapsulate"))
        write(package / f"implement/kat_{tag.lower()}_oracle.py",
              ORACLE.replace("__INSTANCE__", instance).replace("__PRIMITIVE__", settings["primitive"]))
        caps = {"submitted_kat": True, "indexed_public_vector": True,
                "output_canary": settings["primitive"] == "kem", "rng_control": False,
                "fault_injection": False, "intermediate_state": False,
                "decapsulation_failure": False}
        entries.append({"parameter_set": instance, "api": settings["api"],
                        "profiles": ["gcc-reference"], "adapter": "implement/adapter.py",
                        "capabilities": caps,
                        "oracles": [{"id": oid, "version": 1, "claim": claim,
                                     "property": settings["property"], "property_version": 1,
                                     "pattern": "P1", "pattern_version": 1,
                                     "design": design_path,
                                     "oracle": f"implement/kat_{tag.lower()}_oracle.py",
                                     "mutator": f"implement/mutator/kat_{tag.lower()}.py",
                                     "required_capabilities": ["submitted_kat", "indexed_public_vector"] +
                                                              (["output_canary"] if settings["primitive"] == "kem" else []),
                                     "applicable_primitives": [settings["primitive"]]}]})
        profile = {"id": "gcc-reference",
                   "build": [["python3", "{run}/package/implement/build.py", "{source}", "{run}", instance]],
                   "dependencies": ["python", "gcc"], "timeout_seconds": 180,
                   "cpu_seconds": 180, "memory_mb": 4096,
                   "disk_mb": (inventory["source_bytes"] + 1048575) // 1048576 + 256,
                   "iterations": 8, "concurrency": 1, "seed_policy": "fixed",
                   "seed": sum(ord(c) for c in instance) + 33000,
                   "retention_days": 30, "sensitive_inputs": False,
                   "access_policy": "public_test_only", "options": {"parameter_set": instance}}
        apis.append({"name": settings["api"], "parameter_set": instance, "profiles": [profile]})
    dump(package / "data/instances.json", instance_configs)
    write(package / "implement/build.py", BUILD.replace("__TARGET__", target))
    write(package / "implement/adapter.py", ADAPTER.replace("__TARGET__", target)
          .replace("__PRIMITIVE__", settings["primitive"]))
    write(spec_path, spec)
    dump(package / "manifest.json", {"schema_version": 2, "target": target,
         "algorithm": settings["algorithm"], "primitive": settings["primitive"],
         "source_digest": inventory["source_sha256"], "spec_sha256": sha(spec_path),
         "instances": entries})
    registry["targets"].append({"target": target, "algorithm": settings["algorithm"],
                                "primitive": settings["primitive"],
                                "source": f"third_party/{target}/source",
                                "source_digest": inventory["source_sha256"],
                                "specification": f"oracles/spec/{spec_path.name}", "apis": apis})
    first = settings["instances"][0]
    wrapper = ROOT / "scripts" / f"pqcfuzz_eval_{target}.sh"
    write(wrapper, '#!/usr/bin/env bash\nset -euo pipefail\n'
          'repo_root=$(cd "$(dirname "$0")/.." && pwd)\n'
          f'exec "${{PQCFUZZ_PYTHON:-python3}}" "$repo_root/scripts/pqcfuzz_target.py" '
          f'"${{1:-run}}" --target {shlex.quote(target)} --algorithm {shlex.quote(settings["algorithm"])} '
          f'--parameter-set {shlex.quote(first)} --api {shlex.quote(settings["api"])} --profile gcc-reference "${{@:2}}"\n')
    wrapper.chmod(0o755)


def main():
    config_path = ROOT / "configs/targets.json"
    registry = json.loads(config_path.read_text())
    present = {x["target"] for x in registry["targets"]}
    inventory = {x["target"]: x for x in
                 json.loads((ROOT / "workspace/c_targets_sop/inventory.json").read_text())}
    added = []
    for target in SETTINGS:
        if target in present:
            continue
        one_target(target, inventory[target], registry)
        added.append(target)
    if added:
        fd, temporary = tempfile.mkstemp(prefix="targets-c-asym-", suffix=".json", dir=config_path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(json.dumps(registry, indent=2, ensure_ascii=False) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, config_path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    print(json.dumps({"registered": added,
                      "instances": {target: SETTINGS[target]["instances"] for target in added}}))


if __name__ == "__main__":
    main()
