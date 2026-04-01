#!/usr/bin/env python3
"""Generate self-sufficient differential fuzzing jobs and runtime artifacts."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "differential_fuzzer/config/fuzzing.config.json"
PAIRS_PATH = ROOT / "pairing_differential_targets/data/pairs.json"
OUTPUT_PATH = ROOT / "differential_fuzzer/data/fuzzer_jobs.json"

REQUIRED_JOB_STATUS = "pending"
SUPPORTED_PRIMITIVES = {"kem", "sig", "kpke"}
REQUIRED_OPERATIONS_BY_PRIMITIVE = {
    "kem": {"keygen", "encaps", "decaps"},
    "sig": {"keygen", "sign", "verify"},
    "kpke": {"kpke_keygen", "kpke_encrypt", "kpke_decrypt"},
}


class ValidationError(RuntimeError):
    """Raised when job generation or artifact rendering cannot satisfy the contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValidationError(f"{label} file is missing: {path.relative_to(ROOT)}") from exc
    except json.JSONDecodeError as exc:
        raise ValidationError(f"{label} is not valid JSON: {exc}") from exc


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def load_config() -> dict[str, Any]:
    config = load_json(CONFIG_PATH, "fuzzing config")
    require(isinstance(config, dict), "fuzzing.config.json must be a JSON object")
    required = {
        "template_by_primitive",
        "default_oracle_mode",
        "default_determinism_policy",
        "enabled_subtests",
        "mismatch_labels",
        "replay_policy",
        "crash_artifact_policy",
        "sanitizer_build_flags",
        "resource_defaults",
    }
    missing = required.difference(config)
    require(not missing, f"fuzzing.config.json is missing fields: {sorted(missing)}")
    for primitive_type in SUPPORTED_PRIMITIVES:
        require(primitive_type in config["template_by_primitive"], f"missing template for primitive '{primitive_type}'")
        require(primitive_type in config["default_oracle_mode"], f"missing default oracle mode for primitive '{primitive_type}'")
        require(primitive_type in config["enabled_subtests"], f"missing enabled_subtests for primitive '{primitive_type}'")
        require(primitive_type in config["mismatch_labels"], f"missing mismatch_labels for primitive '{primitive_type}'")
    determinism = config["default_determinism_policy"]
    for key in ("prefer_seeded_keygen", "prefer_seeded_encaps", "prefer_seeded_sign", "compare_raw_signature_bytes"):
        require(isinstance(determinism.get(key), bool), f"default_determinism_policy.{key} must be boolean")
    require(isinstance(config["sanitizer_build_flags"], list), "sanitizer_build_flags must be a list")
    require(isinstance(config["resource_defaults"], dict), "resource_defaults must be an object")
    return config


def load_pairs() -> list[dict[str, Any]]:
    payload = load_json(PAIRS_PATH, "pairs")
    require(isinstance(payload, list), "pairs.json must be an array")
    return payload


def require_string(value: Any, field_name: str, context: str) -> str:
    require(isinstance(value, str) and value.strip(), f"{context}: {field_name} must be a non-empty string")
    return value.strip()


def validate_bundle(bundle: Any, primitive_type: str, context: str) -> dict[str, Any]:
    require(isinstance(bundle, dict), f"{context}: bundle must be an object")
    required = {
        "project_id",
        "project_name",
        "implementation_id",
        "api_variant",
        "backend_variant",
        "build",
        "abi",
        "capabilities",
        "operations",
    }
    missing = required.difference(bundle)
    require(not missing, f"{context}: missing bundle fields {sorted(missing)}")

    operations = bundle["operations"]
    require(isinstance(operations, dict), f"{context}: operations must be an object")
    required_ops = REQUIRED_OPERATIONS_BY_PRIMITIVE[primitive_type]
    require(required_ops.issubset(operations), f"{context}: missing required operations {sorted(required_ops.difference(operations))}")

    abi = bundle["abi"]
    require(isinstance(abi, dict), f"{context}: abi must be an object")
    for key in ("pk_len", "sk_len", "ct_len", "ss_len", "sig_max_len", "msg_len"):
        require(key in abi, f"{context}: abi missing '{key}'")
    if primitive_type == "kem":
        require(isinstance(abi["pk_len"], int) and abi["pk_len"] > 0, f"{context}: invalid abi.pk_len")
        require(isinstance(abi["sk_len"], int) and abi["sk_len"] > 0, f"{context}: invalid abi.sk_len")
        require(isinstance(abi["ct_len"], int) and abi["ct_len"] > 0, f"{context}: invalid abi.ct_len")
        require(isinstance(abi["ss_len"], int) and abi["ss_len"] > 0, f"{context}: invalid abi.ss_len")
        require(abi["sig_max_len"] is None, f"{context}: kem sig_max_len must be null")
        require(abi["msg_len"] is None, f"{context}: kem msg_len must be null")
    elif primitive_type == "sig":
        require(isinstance(abi["pk_len"], int) and abi["pk_len"] > 0, f"{context}: invalid abi.pk_len")
        require(isinstance(abi["sk_len"], int) and abi["sk_len"] > 0, f"{context}: invalid abi.sk_len")
        require(abi["ct_len"] is None, f"{context}: sig ct_len must be null")
        require(abi["ss_len"] is None, f"{context}: sig ss_len must be null")
        require(isinstance(abi["sig_max_len"], int) and abi["sig_max_len"] > 0, f"{context}: invalid abi.sig_max_len")
        require(abi["msg_len"] is None, f"{context}: sig msg_len must be null")
    else:
        require(isinstance(abi["pk_len"], int) and abi["pk_len"] > 0, f"{context}: invalid abi.pk_len")
        require(isinstance(abi["sk_len"], int) and abi["sk_len"] > 0, f"{context}: invalid abi.sk_len")
        require(isinstance(abi["ct_len"], int) and abi["ct_len"] > 0, f"{context}: invalid abi.ct_len")
        require(abi["ss_len"] is None, f"{context}: kpke ss_len must be null")
        require(abi["sig_max_len"] is None, f"{context}: kpke sig_max_len must be null")
        require(isinstance(abi["msg_len"], int) and abi["msg_len"] > 0, f"{context}: invalid abi.msg_len")

    capabilities = bundle["capabilities"]
    require(isinstance(capabilities, dict), f"{context}: capabilities must be an object")
    for key in ("supports_keygen_derand", "supports_encaps_derand", "supports_sign_derand", "wire_format_class", "interop_class"):
        require(key in capabilities, f"{context}: capabilities missing '{key}'")
    return bundle


def validate_pair_structure(pair: Any) -> dict[str, Any]:
    require(isinstance(pair, dict), "pair record must be an object")
    required = {
        "pair_id",
        "family",
        "family_slug",
        "parameter_set",
        "primitive_type",
        "left",
        "right",
        "interop_policy",
        "status",
    }
    missing = required.difference(pair)
    require(not missing, f"pair record missing fields: {sorted(missing)}")
    primitive_type = require_string(pair["primitive_type"], "primitive_type", pair.get("pair_id", "pair"))
    require(primitive_type in SUPPORTED_PRIMITIVES, f"{pair['pair_id']}: unsupported primitive_type '{primitive_type}'")
    require(pair["status"] == "enabled", f"{pair['pair_id']}: pair status must be 'enabled' to generate a job")
    validate_bundle(pair["left"], primitive_type, f"{pair['pair_id']}:left")
    validate_bundle(pair["right"], primitive_type, f"{pair['pair_id']}:right")
    require(isinstance(pair["interop_policy"], dict), f"{pair['pair_id']}: interop_policy must be an object")
    return pair


def select_template(primitive_type: str, config: dict[str, Any]) -> str:
    template = require_string(config["template_by_primitive"][primitive_type], f"template_by_primitive.{primitive_type}", "config")
    require((ROOT / template).exists(), f"template not found: {template}")
    return template


def derive_oracle_mode(primitive_type: str, config: dict[str, Any]) -> str:
    return require_string(config["default_oracle_mode"][primitive_type], f"default_oracle_mode.{primitive_type}", "config")


def derive_determinism_policy(config: dict[str, Any]) -> dict[str, bool]:
    policy = dict(config["default_determinism_policy"])
    return {
        "prefer_seeded_keygen": bool(policy["prefer_seeded_keygen"]),
        "prefer_seeded_encaps": bool(policy["prefer_seeded_encaps"]),
        "prefer_seeded_sign": bool(policy["prefer_seeded_sign"]),
        "compare_raw_signature_bytes": bool(policy["compare_raw_signature_bytes"]),
    }


def derive_enabled_subtests(primitive_type: str, config: dict[str, Any]) -> list[str]:
    subtests = config["enabled_subtests"][primitive_type]
    require(isinstance(subtests, list) and subtests, f"enabled_subtests.{primitive_type} must be a non-empty list")
    return [require_string(item, "subtest", f"enabled_subtests.{primitive_type}") for item in subtests]


def derive_mismatch_labels(primitive_type: str, config: dict[str, Any]) -> list[str]:
    labels = config["mismatch_labels"][primitive_type]
    require(isinstance(labels, list) and labels, f"mismatch_labels.{primitive_type} must be a non-empty list")
    return [require_string(item, "mismatch_label", f"mismatch_labels.{primitive_type}") for item in labels]


def make_job_id(pair_id: str) -> str:
    return f"job_{pair_id}"


def make_workspace_paths(job_id: str) -> dict[str, str]:
    return {
        "generated_harness": f"workspace/tmp/{job_id}/generated_harness.cpp",
        "generated_config": f"workspace/tmp/{job_id}/generated_config.json",
        "build_dir": f"workspace/build/{job_id}",
        "run_dir": f"workspace/runs/{job_id}",
        "result_dir": f"workspace/results/{job_id}",
        "crash_dir": f"workspace/crashes/{job_id}",
    }


def make_job_record(pair: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    primitive_type = pair["primitive_type"]
    template = select_template(primitive_type, config)
    job_id = make_job_id(pair["pair_id"])
    paths = make_workspace_paths(job_id)
    job = {
        "job_id": job_id,
        "pair_id": pair["pair_id"],
        "family": pair["family"],
        "family_slug": pair["family_slug"],
        "parameter_set": pair["parameter_set"],
        "primitive_type": primitive_type,
        "harness_template": template,
        "generated_harness": paths["generated_harness"],
        "generated_config": paths["generated_config"],
        "build_dir": paths["build_dir"],
        "run_dir": paths["run_dir"],
        "result_dir": paths["result_dir"],
        "crash_dir": paths["crash_dir"],
        "oracle_mode": derive_oracle_mode(primitive_type, config),
        "enabled_subtests": derive_enabled_subtests(primitive_type, config),
        "determinism_policy": derive_determinism_policy(config),
        "interop_policy": pair["interop_policy"],
        "mismatch_labels": derive_mismatch_labels(primitive_type, config),
        "sanitizer_build_flags": list(config["sanitizer_build_flags"]),
        "resource_defaults": dict(config["resource_defaults"]),
        "replay_policy": dict(config["replay_policy"]),
        "crash_artifact_policy": dict(config["crash_artifact_policy"]),
        "left": pair["left"],
        "right": pair["right"],
        "status": REQUIRED_JOB_STATUS,
    }
    validate_job_record(job)
    return job


def make_generated_config(job: dict[str, Any]) -> dict[str, Any]:
    primitive_type = job["primitive_type"]
    required_operations = sorted(REQUIRED_OPERATIONS_BY_PRIMITIVE[primitive_type])
    cross_exchange_values = [value for value in job["interop_policy"].values() if value == "declared-compatible"]
    generated = {
        "job_id": job["job_id"],
        "pair_id": job["pair_id"],
        "family": job["family"],
        "parameter_set": job["parameter_set"],
        "primitive_type": primitive_type,
        "oracle_mode": job["oracle_mode"],
        "abi": {
            "left": job["left"]["abi"],
            "right": job["right"]["abi"],
        },
        "capability_flags": {
            "left": {
                "supports_keygen_derand": job["left"]["capabilities"]["supports_keygen_derand"],
                "supports_encaps_derand": job["left"]["capabilities"]["supports_encaps_derand"],
                "supports_sign_derand": job["left"]["capabilities"]["supports_sign_derand"],
            },
            "right": {
                "supports_keygen_derand": job["right"]["capabilities"]["supports_keygen_derand"],
                "supports_encaps_derand": job["right"]["capabilities"]["supports_encaps_derand"],
                "supports_sign_derand": job["right"]["capabilities"]["supports_sign_derand"],
            },
        },
        "determinism_policy": job["determinism_policy"],
        "interop_policy": job["interop_policy"],
        "enabled_subtests": job["enabled_subtests"],
        "mismatch_labels": job["mismatch_labels"],
        "paths": {
            "generated_harness": job["generated_harness"],
            "result_dir": job["result_dir"],
            "crash_dir": job["crash_dir"],
            "run_dir": job["run_dir"],
        },
        "replay_policy": job["replay_policy"],
        "sanity_checks": {
            "required_operations": required_operations,
            "cross_exchange_allowed": len(cross_exchange_values) == len(job["interop_policy"]),
            "raw_signature_byte_comparison_allowed": job["determinism_policy"]["compare_raw_signature_bytes"],
        },
    }
    validate_generated_config(generated)
    return generated


def validate_job_record(job: dict[str, Any]) -> None:
    required = {
        "job_id",
        "pair_id",
        "family",
        "family_slug",
        "parameter_set",
        "primitive_type",
        "harness_template",
        "generated_harness",
        "generated_config",
        "build_dir",
        "run_dir",
        "result_dir",
        "crash_dir",
        "oracle_mode",
        "enabled_subtests",
        "determinism_policy",
        "interop_policy",
        "mismatch_labels",
        "sanitizer_build_flags",
        "resource_defaults",
        "replay_policy",
        "crash_artifact_policy",
        "left",
        "right",
        "status",
    }
    missing = required.difference(job)
    require(not missing, f"{job.get('job_id', 'job')}: missing job fields {sorted(missing)}")
    require(job["status"] == REQUIRED_JOB_STATUS, f"{job['job_id']}: status must be '{REQUIRED_JOB_STATUS}'")
    validate_bundle(job["left"], job["primitive_type"], f"{job['job_id']}:left")
    validate_bundle(job["right"], job["primitive_type"], f"{job['job_id']}:right")
    require(stable_json(job["left"]["abi"]) == stable_json(job["right"]["abi"]), f"{job['job_id']}: left/right ABI must agree for v1 job generation")
    for key in ("prefer_seeded_keygen", "prefer_seeded_encaps", "prefer_seeded_sign", "compare_raw_signature_bytes"):
        require(key in job["determinism_policy"], f"{job['job_id']}: missing determinism field '{key}'")
        require(isinstance(job["determinism_policy"][key], bool), f"{job['job_id']}: determinism field '{key}' must be boolean")


def validate_generated_config(generated_config: dict[str, Any]) -> None:
    required = {
        "job_id",
        "pair_id",
        "family",
        "parameter_set",
        "primitive_type",
        "oracle_mode",
        "abi",
        "capability_flags",
        "determinism_policy",
        "interop_policy",
        "enabled_subtests",
        "mismatch_labels",
        "paths",
        "replay_policy",
        "sanity_checks",
    }
    missing = required.difference(generated_config)
    require(not missing, f"{generated_config.get('job_id', 'generated_config')}: missing generated config fields {sorted(missing)}")
    require(isinstance(generated_config["enabled_subtests"], list) and generated_config["enabled_subtests"], f"{generated_config['job_id']}: enabled_subtests must be non-empty")
    require(isinstance(generated_config["mismatch_labels"], list) and generated_config["mismatch_labels"], f"{generated_config['job_id']}: mismatch_labels must be non-empty")


def render_cpp_string(value: str) -> str:
    return json.dumps(value)


def render_cpp_bool(value: bool) -> str:
    return "true" if value else "false"


def render_cpp_string_list(values: list[str]) -> str:
    return ", ".join(render_cpp_string(value) for value in values)


def render_harness(job: dict[str, Any], generated_config: dict[str, Any]) -> str:
    primitive_type = job["primitive_type"]
    template_text = (ROOT / job["harness_template"]).read_text(encoding="utf-8")
    interop_values = list(job["interop_policy"].values())
    cross_exchange_allowed = all(value == "declared-compatible" for value in interop_values)
    replacements = {
        "{{GENERATED_CONFIG_PATH}}": job["generated_config"],
        "{{JOB_ID}}": job["job_id"],
        "{{PAIR_ID}}": job["pair_id"],
        "{{ORACLE_MODE}}": job["oracle_mode"],
        "{{LEFT_IMPLEMENTATION_ID}}": job["left"]["implementation_id"],
        "{{RIGHT_IMPLEMENTATION_ID}}": job["right"]["implementation_id"],
        "{{RESULT_DIR}}": job["result_dir"],
        "{{CRASH_DIR}}": job["crash_dir"],
        "{{ENABLED_SUBTESTS}}": render_cpp_string_list(job["enabled_subtests"]),
        "{{MISMATCH_LABELS}}": render_cpp_string_list(job["mismatch_labels"]),
        "{{LEFT_PK_LEN}}": str(job["left"]["abi"]["pk_len"]),
        "{{LEFT_SK_LEN}}": str(job["left"]["abi"]["sk_len"]),
        "{{RIGHT_PK_LEN}}": str(job["right"]["abi"]["pk_len"]),
        "{{RIGHT_SK_LEN}}": str(job["right"]["abi"]["sk_len"]),
        "{{PREFER_SEEDED_KEYGEN}}": render_cpp_bool(job["determinism_policy"]["prefer_seeded_keygen"]),
        "{{PREFER_SEEDED_ENCAPS}}": render_cpp_bool(job["determinism_policy"]["prefer_seeded_encaps"]),
        "{{PREFER_SEEDED_SIGN}}": render_cpp_bool(job["determinism_policy"]["prefer_seeded_sign"]),
        "{{COMPARE_RAW_SIGNATURE_BYTES}}": render_cpp_bool(job["determinism_policy"]["compare_raw_signature_bytes"]),
        "{{CROSS_EXCHANGE_ALLOWED}}": render_cpp_bool(generated_config["sanity_checks"]["cross_exchange_allowed"]),
        "{{CROSS_VERIFY_ALLOWED}}": render_cpp_bool(generated_config["sanity_checks"]["cross_exchange_allowed"]),
    }
    if primitive_type == "kem":
        replacements["{{LEFT_CT_LEN}}"] = str(job["left"]["abi"]["ct_len"])
        replacements["{{LEFT_SS_LEN}}"] = str(job["left"]["abi"]["ss_len"])
        replacements["{{RIGHT_CT_LEN}}"] = str(job["right"]["abi"]["ct_len"])
        replacements["{{RIGHT_SS_LEN}}"] = str(job["right"]["abi"]["ss_len"])
    elif primitive_type == "sig":
        replacements["{{LEFT_SIG_MAX_LEN}}"] = str(job["left"]["abi"]["sig_max_len"])
        replacements["{{RIGHT_SIG_MAX_LEN}}"] = str(job["right"]["abi"]["sig_max_len"])
    else:
        replacements["{{LEFT_CT_LEN}}"] = str(job["left"]["abi"]["ct_len"])
        replacements["{{LEFT_MSG_LEN}}"] = str(job["left"]["abi"]["msg_len"])
        replacements["{{RIGHT_CT_LEN}}"] = str(job["right"]["abi"]["ct_len"])
        replacements["{{RIGHT_MSG_LEN}}"] = str(job["right"]["abi"]["msg_len"])
    rendered = template_text
    for placeholder, value in replacements.items():
        rendered = rendered.replace(placeholder, value)
    require("{{" not in rendered, f"{job['job_id']}: harness template contains unresolved placeholders")
    return rendered


def validate_jobs(jobs: list[dict[str, Any]]) -> None:
    require(isinstance(jobs, list), "jobs output must be an array")
    seen = set()
    for job in jobs:
        validate_job_record(job)
        require(job["job_id"] not in seen, f"duplicate job_id '{job['job_id']}'")
        seen.add(job["job_id"])


def materialize_artifacts(job: dict[str, Any], generated_config: dict[str, Any], harness_text: str) -> None:
    tmp_dir = ROOT / f"workspace/tmp/{job['job_id']}"
    for directory in (
        tmp_dir,
        ROOT / job["build_dir"],
        ROOT / job["run_dir"],
        ROOT / job["result_dir"],
        ROOT / job["crash_dir"],
    ):
        directory.mkdir(parents=True, exist_ok=True)

    write_json(ROOT / job["generated_config"], generated_config)
    (ROOT / job["generated_harness"]).write_text(harness_text, encoding="utf-8")


def main() -> int:
    config = load_config()
    pairs = load_pairs()
    validated_pairs = [validate_pair_structure(pair) for pair in sorted(pairs, key=lambda item: item["pair_id"])]

    jobs: list[dict[str, Any]] = []
    rendered_artifacts: list[tuple[dict[str, Any], dict[str, Any], str]] = []
    for pair in validated_pairs:
        job = make_job_record(pair, config)
        generated_config = make_generated_config(job)
        harness_text = render_harness(job, generated_config)
        jobs.append(job)
        rendered_artifacts.append((job, generated_config, harness_text))

    validate_jobs(jobs)
    for job, generated_config, harness_text in rendered_artifacts:
        materialize_artifacts(job, generated_config, harness_text)
    write_json(OUTPUT_PATH, jobs)
    print(f"wrote {OUTPUT_PATH.relative_to(ROOT)} with {len(jobs)} fuzzer jobs")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValidationError as exc:
        print(f"diff_fuzzer error: {exc}", file=sys.stderr)
        raise SystemExit(1)
