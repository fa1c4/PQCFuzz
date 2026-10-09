"""Registered target-package runtime. Standard-library only; legacy suites are separate."""
import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import re
import signal
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKER = ROOT / "src/runtime/target_worker.py"
VERDICTS = ("pass", "counterexample_candidate", "inconclusive", "not_applicable", "unsupported", "harness_error")


class ConfigError(Exception):
    pass


class UnsupportedError(ConfigError):
    pass


class NotApplicableError(ConfigError):
    pass


def require(test, message):
    if not test:
        raise ConfigError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def tree_sha(path):
    digest = hashlib.sha256()
    path = Path(path)
    for file in sorted(p for p in path.rglob("*") if p.is_file() and "__pycache__" not in p.parts):
        digest.update(file.relative_to(path).as_posix().encode())
        digest.update(bytes.fromhex(sha(file)))
    return digest.hexdigest()


def inside(relative, root=ROOT):
    require(isinstance(relative, str) and relative and not Path(relative).is_absolute(), "path must be relative")
    result = (root / relative).resolve()
    require(result.is_relative_to(root.resolve()), "path escapes registered root: " + relative)
    require(result.exists(), "missing registered path: " + relative)
    return result


def object_keys(value, keys, label):
    require(isinstance(value, dict), label + " must be object")
    require(set(value) == set(keys), label + " keys mismatch: " + str(set(value) ^ set(keys)))


def catalog_ids(path, pattern):
    text = path.read_text(encoding="utf-8")
    ids = re.findall(pattern, text, re.MULTILINE)
    require(len(ids) == len(set(ids)), "duplicate knowledge IDs in " + str(path))
    return set(ids)


def spec_status(path):
    text = path.read_text(encoding="utf-8")
    match = re.match(r"\A---\s*\n(.*?)\n---\s*\n", text, re.S)
    require(match is not None, "spec front matter missing")
    fields = {}
    for line in match.group(1).splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            fields[key.strip()] = value.strip().strip('"')
    require(fields.get("status") in ("draft", "verified"), "invalid spec status")
    for key in ("target", "algorithm", "source_path", "source_sha256", "document_path", "document_sha256", "source_version", "extract_version"):
        require(fields.get(key), "spec missing " + key)
    if fields["status"] == "verified":
        require(fields.get("reviewer") and fields.get("review_date"), "verified spec missing review evidence")
    return fields, text


def validate(args):
    config_path = ROOT / "configs/targets.json"
    require(config_path.is_file() and not config_path.is_symlink(),
            "missing or linked configs/targets.json")
    config = json.loads(config_path.read_text(encoding="utf-8"))
    object_keys(config, ("schema_version", "targets"), "registry")
    require(config["schema_version"] in (1, 2), "unknown registry schema")
    require(isinstance(config["targets"], list), "targets must be array")
    names = [(x.get("target"), x.get("algorithm")) for x in config["targets"]]
    require(len(names) == len(set(names)), "duplicate target/algorithm")
    source_ids = {}
    for record in config["targets"]:
        name = record.get("target")
        digest = record.get("source_digest")
        if name in source_ids:
            require(source_ids[name] == digest, "target name collision with different source")
        source_ids[name] = digest
    matches = [x for x in config["targets"] if args.target in (None, x.get("target"))
               and args.algorithm in (None, x.get("algorithm"))]
    require(len(matches) == 1, "unknown or ambiguous target/algorithm")
    target = matches[0]
    object_keys(target, ("target", "algorithm", "primitive", "source", "source_digest", "specification", "apis"), "target")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", target["target"]), "invalid target name")
    source = inside(target["source"])
    require(source.is_relative_to((ROOT / "third_party" / target["target"]).resolve()),
            "source outside target third_party directory")
    require(not any(p.is_symlink() for p in source.rglob("*")), "source symlink is not isolated")
    require(source.is_dir() and tree_sha(source) == target["source_digest"], "source digest mismatch")
    spec = inside(target["specification"])
    require(spec.parent == (ROOT / "oracles/spec").resolve(), "spec outside oracles/spec")
    fields, spec_text = spec_status(spec)
    require(fields["target"] == target["target"] and fields["algorithm"] == target["algorithm"], "spec identity mismatch")
    require(fields["source_path"] == target["source"] and fields["source_sha256"] == target["source_digest"], "spec source mismatch")
    document = inside(fields["document_path"])
    require(document.is_relative_to((ROOT / "third_party" / target["target"]).resolve()),
            "spec document outside target third_party directory")
    require(sha(document) == fields["document_sha256"], "original specification digest mismatch")
    claim_ids = re.findall(r"(?m)^###?\s+([A-Za-z0-9._-]+)\s+[—:-]", spec_text)
    require(claim_ids and len(claim_ids) == len(set(claim_ids)), "missing or duplicate spec claim IDs")
    api_keys = [(x.get("name"), x.get("parameter_set")) for x in target["apis"]]
    require(len(api_keys) == len(set(api_keys)), "duplicate API/parameter set")
    if config["schema_version"] == 1:
        api_names = [x.get("name") for x in target["apis"]]
        require(len(api_names) == len(set(api_names)), "duplicate API")
    parameter_set = getattr(args, "parameter_set", None)
    apis = [x for x in target["apis"] if args.api in (None, x.get("name"))
            and parameter_set in (None, x.get("parameter_set"))]
    require(len(apis) == 1, "unknown or ambiguous API/parameter set")
    api = apis[0]
    object_keys(api, ("name", "parameter_set", "profiles"), "API")
    profile_names = [x.get("id") for x in api["profiles"]]
    require(len(profile_names) == len(set(profile_names)), "duplicate profile")
    profiles = [x for x in api["profiles"] if args.profile in (None, x.get("id"))]
    require(len(profiles) == 1, "unknown or ambiguous profile")
    profile = profiles[0]
    require(args.iterations is None or args.iterations > 0, "iterations must be positive")
    object_keys(profile, ("id", "build", "dependencies", "timeout_seconds", "cpu_seconds", "memory_mb",
                          "disk_mb", "iterations", "concurrency", "seed_policy", "seed",
                          "retention_days", "sensitive_inputs", "access_policy", "options"), "profile")
    for key in ("timeout_seconds", "disk_mb", "iterations", "concurrency", "retention_days"):
        require(isinstance(profile[key], int) and profile[key] > 0, "invalid " + key)
    require(profile["seed_policy"] == "fixed" and isinstance(profile["seed"], int), "unsupported seed policy")
    require(isinstance(profile["options"], dict), "profile options must be object")
    if "parameter_set" in profile["options"]:
        require(profile["options"].get("parameter_set") == api["parameter_set"],
                "profile parameter set mismatch")
    require(profile["concurrency"] == 1, "parallel isolation not implemented for this profile")
    require(profile["sensitive_inputs"] is False and profile["access_policy"] == "public_test_only",
            "sensitive evidence access policy cannot be enforced on this host")
    require(isinstance(profile["build"], list) and all(isinstance(x, list) and x and
            all(isinstance(y, str) for y in x) for x in profile["build"]), "invalid build argv")
    for budget in ("cpu_seconds", "memory_mb"):
        require(profile[budget] is None or (isinstance(profile[budget], int) and profile[budget] > 0), "invalid " + budget)
    if os.name == "nt":
        require(profile["cpu_seconds"] is None and profile["memory_mb"] is None,
                "finite CPU/memory budget unenforceable on Windows")
    source_bytes = sum(p.stat().st_size for p in source.rglob("*") if p.is_file())
    require(source_bytes <= profile["disk_mb"] * 1024 * 1024, "source exceeds disk budget")
    for dep in profile["dependencies"]:
        require(dep == "python" or shutil.which(dep), "missing dependency: " + dep)
    manifest_path = ROOT / "oracles" / target["target"] / "manifest.json"
    require(manifest_path.is_file(), "missing target manifest")
    require(manifest_path.parent.resolve().is_relative_to((ROOT / "oracles").resolve()),
            "package escapes oracles directory")
    require(not any(p.is_symlink() for p in manifest_path.parent.rglob("*")),
            "package symlink is not isolated")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") == 1:
        object_keys(manifest, ("schema_version", "target", "algorithm", "primitive", "parameter_set", "api",
                               "profiles", "source_digest", "spec_sha256", "adapter", "capabilities", "oracles"), "manifest")
    elif manifest.get("schema_version") == 2:
        require(profile["options"].get("parameter_set") == api["parameter_set"],
                "v2 profile parameter set missing or mismatched")
        object_keys(manifest, ("schema_version", "target", "algorithm", "primitive",
                               "source_digest", "spec_sha256", "instances"), "manifest")
        instances = manifest["instances"]
        require(isinstance(instances, list) and instances, "manifest instances missing")
        instance_keys = [(x.get("api"), x.get("parameter_set")) for x in instances]
        require(len(instance_keys) == len(set(instance_keys)), "duplicate manifest instance")
        matched = [x for x in instances if x.get("api") == api["name"]
                   and x.get("parameter_set") == api["parameter_set"]]
        require(len(matched) == 1, "unregistered API/parameter set")
        instance = matched[0]
        object_keys(instance, ("parameter_set", "api", "profiles", "adapter",
                               "capabilities", "oracles"), "manifest instance")
        manifest = {**{key: value for key, value in manifest.items() if key != "instances"},
                    **instance}
    else:
        raise ConfigError("unknown manifest schema")
    for key, expected in (("target", target["target"]), ("algorithm", target["algorithm"]),
                          ("primitive", target["primitive"]), ("parameter_set", api["parameter_set"]),
                          ("api", api["name"]), ("source_digest", target["source_digest"]),
                          ("spec_sha256", sha(spec))):
        require(manifest[key] == expected, "manifest " + key + " mismatch")
    require(profile["id"] in manifest["profiles"], "profile not registered")
    package = manifest_path.parent
    adapter = inside(manifest["adapter"], package)
    require(adapter.is_file() and adapter.relative_to(package).parts[0] == "implement"
            and adapter.suffix == ".py",
            "adapter path violates package contract")
    require(isinstance(manifest["capabilities"], dict), "invalid capabilities")
    props = catalog_ids(ROOT / "knowledge/property/security_property.md", r"^\|\s*([A-Z][0-9]{2})\s*\|")
    patterns = catalog_ids(ROOT / "knowledge/oracles/patterns.md", r"^###\s+(P[0-9]+)\s+")
    ids = [x.get("id") for x in manifest["oracles"]]
    require(len(ids) == len(set(ids)), "duplicate oracle")
    oracles = [x for x in manifest["oracles"] if args.oracle in (None, x.get("id"))]
    require(bool(oracles), "unknown oracle ID")
    selected = []
    for item in oracles:
        object_keys(item, ("id", "version", "claim", "property", "property_version", "pattern",
                           "pattern_version", "design", "oracle", "mutator", "required_capabilities",
                           "applicable_primitives"), "oracle")
        require(isinstance(item["applicable_primitives"], list), "invalid primitive scope")
        if target["primitive"] not in item["applicable_primitives"]:
            raise NotApplicableError("property/pattern not applicable to primitive for " + item["id"])
        require(item["property"] in props and item["pattern"] in patterns, "unknown or inactive knowledge ID")
        require(item["property_version"] == 1 and item["pattern_version"] == 1, "knowledge version mismatch")
        require(item["version"] > 0, "invalid oracle version")
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", item["id"]),
                "invalid oracle ID")
        expected_design = "design/%s/%s/%s.md" % (target["algorithm"], api["name"], item["id"])
        require(item["design"] == expected_design, "oracle design path mismatch")
        claim_match = re.search(r"(?ms)^###?\s+" + re.escape(item["claim"]) +
                                r"\s+[—:-](.*?)(?=^###?\s+|\Z)", spec_text)
        require(claim_match is not None, "unlinked spec claim " + item["claim"])
        for field in ("Source locator", "Scope", "Claim", "Limitations"):
            require(re.search(r"(?mi)^- " + field + r":\s*\S", claim_match.group(1)),
                    "claim " + item["claim"] + " missing " + field)
        paths = {key: inside(item[key], package) for key in ("design", "oracle", "mutator")}
        require(all(x.is_file() for x in paths.values()), "oracle artifact missing")
        require("/mutator/" in paths["mutator"].as_posix(), "mutator outside paired directory")
        missing = [x for x in item["required_capabilities"] if manifest["capabilities"].get(x) is not True]
        if missing:
            raise UnsupportedError("unsupported capabilities for " + item["id"] + ": " + ",".join(missing))
        selected.append((item, paths))
    return config_path, target, api, profile, manifest_path, manifest, source, spec, adapter, selected


def verdict(trace):
    case, base, mutated, relation = (trace["case"], trace["baseline_observation"],
                                     trace["mutated_observation"], trace["relation"])
    if not case.get("effective"):
        return "inconclusive"
    if not base.get("reached") or not mutated.get("reached"):
        return "harness_error"
    if base.get("status") != "ok":
        return "inconclusive"
    if not relation.get("applicable"):
        return "not_applicable"
    if not relation.get("observable"):
        return "inconclusive"
    if relation.get("holds") is True:
        return "pass"
    if relation.get("holds") is False:
        return "counterexample_candidate"
    return "harness_error"


def process(argv, cwd, env, timeout, cpu=None, memory=None):
    preexec = None
    if os.name != "nt" and (cpu is not None or memory is not None):
        import resource
        def limits():
            if cpu is not None:
                resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
            if memory is not None:
                size = memory * 1024 * 1024
                resource.setrlimit(resource.RLIMIT_AS, (size, size))
        preexec = limits
    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    try:
        child = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True, preexec_fn=preexec,
                                 start_new_session=os.name != "nt", creationflags=creationflags)
    except OSError as exc:
        return {"exit_code": None, "stdout": "", "stderr": str(exc), "timeout": False}
    timed_out = False
    try:
        stdout, stderr = child.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(child.pid), "/T", "/F"],
                           capture_output=True, check=False)
            try:
                child.kill()
            except OSError:
                pass
        else:
            os.killpg(child.pid, signal.SIGKILL)
        stdout, stderr = child.communicate()
    return {"exit_code": child.returncode, "stdout": stdout[-20000:],
            "stderr": stderr[-20000:], "timeout": timed_out}


def run(args, selected):
    config_path, target, api, profile, manifest_path, manifest, source, spec, adapter, oracles = selected
    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:12]
    run_dir = ROOT / "workspace" / target["target"] / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    for name in ("tmp", "cache", "source", "package", "snapshots"):
        (run_dir / name).mkdir()
    shutil.copytree(source, run_dir / "source", dirs_exist_ok=True)
    require(tree_sha(run_dir / "source") == target["source_digest"], "isolated source copy mismatch")
    shutil.copytree(manifest_path.parent, run_dir / "package", dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    package_digest = tree_sha(manifest_path.parent)
    require(tree_sha(run_dir / "package") == package_digest, "isolated package copy mismatch")
    original_document = inside(spec_status(spec)[0]["document_path"])
    for name, source_file in (("original_spec" + original_document.suffix, original_document),
                              ("spec.md", spec), ("targets.json", config_path),
                              ("security_property.md", ROOT / "knowledge/property/security_property.md"),
                              ("patterns.md", ROOT / "knowledge/oracles/patterns.md")):
        shutil.copy2(source_file, run_dir / "snapshots" / name)
    env = os.environ.copy()
    env.update({"HOME": str(run_dir / "cache"), "USERPROFILE": str(run_dir / "cache"),
                "APPDATA": str(run_dir / "cache"), "LOCALAPPDATA": str(run_dir / "cache"),
                "PIP_CACHE_DIR": str(run_dir / "cache"),
                "TMP": str(run_dir / "tmp"), "TEMP": str(run_dir / "tmp"),
                "TMPDIR": str(run_dir / "tmp"), "XDG_CACHE_HOME": str(run_dir / "cache"),
                "PYTHONDONTWRITEBYTECODE": "1"})
    evidence = "unverified_spec" if spec_status(spec)[0]["status"] == "draft" else "verified_spec"
    trace = []
    diagnostics = []
    stage = "ready"
    for index, argv in enumerate(profile["build"]):
        expanded = [x.replace("{source}", str(run_dir / "source")).replace("{run}", str(run_dir)) for x in argv]
        result = process(expanded, run_dir, env, profile["timeout_seconds"],
                         profile["cpu_seconds"], profile["memory_mb"])
        diagnostics.append({"stage": "build", "index": index, **result})
        if result["exit_code"] != 0 or result["timeout"]:
            stage = "blocked"
            break
    if stage == "ready":
        for item, paths in oracles:
            for mode, n in (("smoke", 1), ("campaign", args.iterations or profile["iterations"])):
                if mode == "campaign" and args.command == "smoke":
                    continue
                if stage != "ready":
                    break
                for iteration in range(n):
                    payload = {"mode": mode, "seed": args.seed if args.seed is not None else profile["seed"],
                               "iteration": iteration, "source_root": str(run_dir / "source"),
                               "profile": profile["options"],
                               "adapter": str(run_dir / "package" / adapter.relative_to(manifest_path.parent)),
                               "oracle": str(run_dir / "package" / paths["oracle"].relative_to(manifest_path.parent)),
                               "mutator": str(run_dir / "package" / paths["mutator"].relative_to(manifest_path.parent))}
                    payload_path = run_dir / ("input-%s-%s-%d.json" % (item["id"], mode, iteration))
                    result_path = run_dir / ("worker-%s-%s-%d.json" % (item["id"], mode, iteration))
                    payload_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
                    result = process([sys.executable, str(WORKER), "--payload", str(payload_path),
                                      "--result", str(result_path)], run_dir, env,
                                     profile["timeout_seconds"], profile["cpu_seconds"], profile["memory_mb"])
                    diagnostics.append({"stage": mode, "oracle": item["id"], "iteration": iteration, **result})
                    if result["exit_code"] != 0 or result["timeout"] or not result_path.exists():
                        trace.append({"oracle": item["id"], "mode": mode, "iteration": iteration,
                                      "verdict": "harness_error", "process": result})
                        stage = "failed"
                        break
                    records = json.loads(result_path.read_text(encoding="utf-8"))
                    for record in records:
                        status = verdict(record)
                        if mode == "smoke":
                            if record["kind"] == "positive":
                                fault = record["fault_relation"]
                                fault_detected = (fault.get("applicable") is True and
                                                  fault.get("observable") is True and fault.get("holds") is False)
                                if status != "pass" or not fault_detected:
                                    stage = "failed"
                            elif record["kind"] == "negative" and status != "inconclusive":
                                stage = "failed"
                        record.update({"oracle": item["id"], "mode": mode, "iteration": iteration,
                                       "verdict": status, "process": result})
                        trace.append(record)
                    size = sum(p.stat().st_size for p in run_dir.rglob("*") if p.is_file())
                    if size > profile["disk_mb"] * 1024 * 1024:
                        stage = "blocked"
                        diagnostics.append({"stage": mode, "error": "disk budget exceeded"})
                    if stage != "ready":
                        break
    counts = {key: sum(t.get("verdict") == key for t in trace if t.get("mode") == "campaign") for key in VERDICTS}
    spec_text = spec.read_text(encoding="utf-8")
    oracle_by_id = {item["id"]: item for item, _ in oracles}
    def candidate_record(index, row):
        item = oracle_by_id[row["oracle"]]
        block = re.search(r"(?ms)^###?\s+" + re.escape(item["claim"]) +
                          r"\s+[—:-](.*?)(?=^###?\s+|\Z)", spec_text).group(1)
        def field(name):
            match = re.search(r"(?mi)^- " + name + r":\s*(.+)$", block)
            return match.group(1).strip() if match else None
        return {"oracle": row["oracle"], "iteration": row["iteration"], "trace_index": index,
                "claim_id": item["claim"], "claim": field("Claim"),
                "source_locator": field("Source locator"), "limitations": field("Limitations"),
                "property": item["property"], "pattern": item["pattern"],
                "spec_snapshot": "snapshots/spec.md", "trace_path": "trace.json",
                "replay_status": "not_run"}
    report = {"target": target["target"], "algorithm": target["algorithm"],
              "parameter_set": api["parameter_set"], "api": api["name"],
              "profile": profile["id"], "evidence_class": evidence, "stage": stage, "counts": counts,
              "candidates": [candidate_record(i, t) for i, t in enumerate(trace)
                             if t.get("mode") == "campaign" and t.get("verdict") == "counterexample_candidate"],
              "confirmed_findings": 0, "replay_status": "not_run"}
    (run_dir / "trace.json").write_text(json.dumps(trace, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (run_dir / "diagnostics.json").write_text(json.dumps(diagnostics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (run_dir / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    dependency_versions = {}
    for dependency in profile["dependencies"]:
        if dependency == "python":
            dependency_versions[dependency] = sys.version.split()[0]
        else:
            probe = process([shutil.which(dependency), "--version"], run_dir, env,
                            min(profile["timeout_seconds"], 3))
            dependency_versions[dependency] = (probe["stdout"] or probe["stderr"]).splitlines()[:1]
    manifest_out = {"schema_version": 1, "trace_version": 1, "run_id": run_id,
                    "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                    "target": target["target"], "algorithm": target["algorithm"], "primitive": target["primitive"],
                    "parameter_set": api["parameter_set"], "api": api["name"], "profile": profile["id"],
                    "oracle_ids": [x[0]["id"] for x in oracles], "source_sha256": target["source_digest"],
                    "spec_sha256": sha(spec), "spec_status": spec_status(spec)[0]["status"],
                    "spec_source_version": spec_status(spec)[0]["source_version"],
                    "original_spec_path": spec_status(spec)[0]["document_path"],
                    "original_spec_sha256": sha(original_document),
                    "config_sha256": sha(config_path), "package_sha256": tree_sha(manifest_path.parent),
                    "evidence_class": evidence, "seed": args.seed if args.seed is not None else profile["seed"],
                    "budget": {k: profile[k] for k in ("timeout_seconds", "cpu_seconds", "memory_mb", "disk_mb", "iterations")},
                    "retention_days": profile["retention_days"],
                    "expires_utc": (dt.datetime.now(dt.timezone.utc) +
                                    dt.timedelta(days=profile["retention_days"])).isoformat(),
                    "replay_status": "not_run",
                    "stage": stage, "counts": counts,
                    "file_hashes": {p.relative_to(run_dir).as_posix(): sha(p) for p in sorted(run_dir.rglob("*")) if p.is_file()}}
    (run_dir / "manifest.json").write_text(json.dumps(manifest_out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (run_dir / "manifest.sha256").write_text(sha(run_dir / "manifest.json") + "  manifest.json\n", encoding="utf-8")
    for file in run_dir.rglob("*"):
        if file.is_file():
            file.chmod(0o444)
    print(json.dumps({"run": str(run_dir), "stage": stage, "counts": counts, "evidence_class": evidence}))
    return 0 if stage == "ready" else 1



def verify_run(path):
    run_dir = Path(path).resolve()
    require(run_dir.is_relative_to((ROOT / "workspace").resolve()), "run outside workspace")
    require(run_dir.parent.name == "runs", "invalid run directory")
    manifest_path = run_dir / "manifest.json"
    digest_path = run_dir / "manifest.sha256"
    require(manifest_path.is_file() and digest_path.is_file(), "missing manifest integrity record")
    require(digest_path.read_text(encoding="utf-8").split()[0] == sha(manifest_path),
            "manifest digest mismatch")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    require(manifest.get("schema_version") == 1 and manifest.get("trace_version") == 1,
            "unknown run schema")
    listed = set(manifest["file_hashes"])
    actual = {p.relative_to(run_dir).as_posix() for p in run_dir.rglob("*") if p.is_file()}
    require(actual == listed | {"manifest.json", "manifest.sha256"}, "run file set mismatch")
    for relative, expected in manifest["file_hashes"].items():
        file = inside(relative, run_dir)
        require(sha(file) == expected, "run file digest mismatch: " + relative)
    return {"run": str(run_dir), "integrity": "ok", "files": len(listed)}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("list", "preflight", "smoke", "run", "all", "verify"))
    parser.add_argument("--run")
    parser.add_argument("--target")
    parser.add_argument("--algorithm")
    parser.add_argument("--parameter-set")
    parser.add_argument("--api")
    parser.add_argument("--profile")
    parser.add_argument("--oracle")
    parser.add_argument("--iterations", type=int)
    parser.add_argument("--seed", type=int)
    parser.add_argument("--expanded", action="store_true", help="list registered API/profile combinations")
    args = parser.parse_args()
    try:
        if args.command == "verify":
            require(args.run, "verify requires --run")
            print(json.dumps(verify_run(args.run)))
            return 0
        if args.command == "list":
            config = json.loads((ROOT / "configs/targets.json").read_text(encoding="utf-8"))
            if args.expanded:
                for target in config["targets"]:
                    for api in target["apis"]:
                        for profile in api["profiles"]:
                            print("\t".join((target["target"], target["algorithm"], api["parameter_set"],
                                             api["name"], profile["id"])))
            else:
                print(json.dumps([{"target": t["target"], "algorithm": t["algorithm"]} for t in config["targets"]]))
            return 0
        selected = validate(args)
        if args.command == "preflight":
            print(json.dumps({"stage": "ready", "target": selected[1]["target"],
                              "parameter_set": selected[2]["parameter_set"],
                              "oracles": [x[0]["id"] for x in selected[-1]]}))
            return 0
        return run(args, selected)
    except UnsupportedError as exc:
        print(json.dumps({"stage": "blocked", "classification": "unsupported", "error": str(exc)}), file=sys.stderr)
        return 2
    except NotApplicableError as exc:
        print(json.dumps({"stage": "blocked", "classification": "not_applicable", "error": str(exc)}), file=sys.stderr)
        return 2
    except (ConfigError, OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(json.dumps({"stage": "blocked", "error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
