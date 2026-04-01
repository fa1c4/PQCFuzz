#!/usr/bin/env python3
"""Validate and normalize manual operation mappings into canonical mapping.json."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "design_implementation_mapper/config/mapper.config.json"
MANUAL_PATH = ROOT / "design_implementation_mapper/data/mapping.manual.json"
OUTPUT_PATH = ROOT / "design_implementation_mapper/data/mapping.json"

SEMANTIC_KEY_RE = re.compile(r"^(?P<algorithm>[A-Za-z0-9-]+)/(?P<operation>[a-z0-9_]+)$")
PROJECT_ID_RE = re.compile(r"^[a-z0-9_]+$")
IMPLEMENTATION_ID_RE = re.compile(r"^[a-z0-9_]+$")
FUNCTION_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
ALLOWED_STATUSES = {"enabled", "todo", "manual-review"}
EXPECTED_OPERATIONS = {
    "kem": {"keygen", "encaps", "decaps"},
    "sig": {"keygen", "sign", "verify"},
    "kpke": {"kpke_keygen", "kpke_encrypt", "kpke_decrypt"},
}
PROJECT_DISPLAY_NAMES = {
    "liboqs": "liboqs",
    "pqclean": "PQClean",
}


class ValidationError(RuntimeError):
    """Raised when mapper input does not satisfy the contract."""


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


def write_mapping(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def unique_sorted_strings(values: list[Any], field_name: str, descriptor_id: str) -> list[str]:
    require(isinstance(values, list), f"{descriptor_id}: {field_name} must be a list")
    normalized = []
    for value in values:
        require(isinstance(value, str) and value.strip(), f"{descriptor_id}: {field_name} entries must be non-empty strings")
        normalized.append(value.strip())
    return sorted(dict.fromkeys(normalized))


def load_config() -> dict[str, Any]:
    config = load_json(CONFIG_PATH, "config")
    require(isinstance(config, dict), "mapper.config.json must be a JSON object")
    required = {
        "enabled_projects",
        "project_roots",
        "enabled_primitive_types",
        "enabled_algorithms",
        "manual_mapping_only",
        "validate_source_paths",
        "validate_function_names",
        "validate_build_metadata",
        "validate_abi_metadata",
        "validate_capabilities_metadata",
    }
    missing = required.difference(config)
    require(not missing, f"mapper.config.json is missing fields: {sorted(missing)}")
    require(isinstance(config["enabled_projects"], list) and config["enabled_projects"], "enabled_projects must be a non-empty list")
    require(isinstance(config["project_roots"], dict), "project_roots must be an object")
    require(isinstance(config["enabled_algorithms"], list) and config["enabled_algorithms"], "enabled_algorithms must be a non-empty list")
    require(isinstance(config["enabled_primitive_types"], list) and config["enabled_primitive_types"], "enabled_primitive_types must be a non-empty list")

    for project_id in config["enabled_projects"]:
        require(isinstance(project_id, str) and PROJECT_ID_RE.fullmatch(project_id), f"invalid enabled project_id '{project_id}'")
        require(project_id in config["project_roots"], f"missing project root for '{project_id}'")

    for key in (
        "manual_mapping_only",
        "validate_source_paths",
        "validate_function_names",
        "validate_build_metadata",
        "validate_abi_metadata",
        "validate_capabilities_metadata",
    ):
        require(isinstance(config[key], bool), f"{key} must be boolean")

    return config


def load_manual_mapping() -> dict[str, Any]:
    manual = load_json(MANUAL_PATH, "manual mapping")
    require(isinstance(manual, dict), "mapping.manual.json must be a JSON object")
    return manual


def parse_semantic_key(semantic_key: str, enabled_algorithms: list[str]) -> dict[str, str]:
    require(isinstance(semantic_key, str), "semantic key must be a string")
    match = SEMANTIC_KEY_RE.fullmatch(semantic_key)
    require(match is not None, f"invalid semantic key '{semantic_key}'")
    algorithm = match.group("algorithm")
    require(algorithm in enabled_algorithms, f"{semantic_key}: algorithm '{algorithm}' is not enabled")
    family, parameter_set = algorithm.rsplit("-", 1)
    return {
        "semantic_key": semantic_key,
        "algorithm": algorithm,
        "family": family,
        "parameter_set": parameter_set,
        "operation": match.group("operation"),
    }


def normalize_project_id(project_id: str, descriptor_id: str) -> str:
    require(isinstance(project_id, str) and project_id.strip(), f"{descriptor_id}: project_id is required")
    normalized = project_id.strip().lower()
    require(PROJECT_ID_RE.fullmatch(normalized) is not None, f"{descriptor_id}: invalid project_id '{project_id}'")
    return normalized


def normalize_project_name(project_id: str, project_name: Any) -> str:
    if isinstance(project_name, str) and project_name.strip():
        if project_id == "pqclean":
            return "PQClean"
        if project_id == "liboqs":
            return "liboqs"
        return project_name.strip()
    return PROJECT_DISPLAY_NAMES.get(project_id, project_id)


def validate_build_metadata(build: Any, descriptor_id: str) -> dict[str, Any]:
    require(isinstance(build, dict), f"{descriptor_id}: build must be an object")
    required = {
        "build_mode",
        "implementation_dir",
        "declaration_file",
        "implementation_files",
        "include_dirs",
        "common_deps",
        "defines",
    }
    missing = required.difference(build)
    require(not missing, f"{descriptor_id}: missing build fields {sorted(missing)}")

    build_mode = build["build_mode"]
    require(build_mode in {"library", "source"}, f"{descriptor_id}: unsupported build_mode '{build_mode}'")
    if build_mode == "library":
        require(isinstance(build.get("library_name"), str) and build["library_name"].strip(), f"{descriptor_id}: library build requires library_name")

    normalized = {
        "build_mode": build_mode,
        "implementation_dir": str(build["implementation_dir"]).strip(),
        "declaration_file": str(build["declaration_file"]).strip(),
        "implementation_files": unique_sorted_strings(build["implementation_files"], "build.implementation_files", descriptor_id),
        "include_dirs": unique_sorted_strings(build["include_dirs"], "build.include_dirs", descriptor_id),
        "common_deps": unique_sorted_strings(build["common_deps"], "build.common_deps", descriptor_id),
        "defines": unique_sorted_strings(build["defines"], "build.defines", descriptor_id),
    }
    require(normalized["implementation_dir"], f"{descriptor_id}: build.implementation_dir is required")
    require(normalized["declaration_file"], f"{descriptor_id}: build.declaration_file is required")
    if "library_name" in build and isinstance(build["library_name"], str) and build["library_name"].strip():
        normalized["library_name"] = build["library_name"].strip()
    return normalized


def validate_abi_metadata(abi: Any, primitive_type: str, descriptor_id: str) -> dict[str, Any]:
    require(isinstance(abi, dict), f"{descriptor_id}: abi must be an object")
    required = {"pk_len", "sk_len", "ct_len", "ss_len", "sig_max_len", "msg_len"}
    missing = required.difference(abi)
    require(not missing, f"{descriptor_id}: missing abi fields {sorted(missing)}")

    normalized = {}
    for key in required:
        value = abi[key]
        require(value is None or isinstance(value, int), f"{descriptor_id}: abi.{key} must be an integer or null")
        normalized[key] = value

    for key in ("pk_len", "sk_len"):
        require(isinstance(normalized[key], int) and normalized[key] > 0, f"{descriptor_id}: abi.{key} must be a positive integer")

    if primitive_type == "kem":
        require(isinstance(normalized["ct_len"], int) and normalized["ct_len"] > 0, f"{descriptor_id}: kem abi.ct_len must be a positive integer")
        require(isinstance(normalized["ss_len"], int) and normalized["ss_len"] > 0, f"{descriptor_id}: kem abi.ss_len must be a positive integer")
        require(normalized["sig_max_len"] is None, f"{descriptor_id}: kem abi.sig_max_len must be null")
        require(normalized["msg_len"] is None, f"{descriptor_id}: kem abi.msg_len must be null")
    elif primitive_type == "sig":
        require(normalized["ct_len"] is None, f"{descriptor_id}: sig abi.ct_len must be null")
        require(normalized["ss_len"] is None, f"{descriptor_id}: sig abi.ss_len must be null")
        require(isinstance(normalized["sig_max_len"], int) and normalized["sig_max_len"] > 0, f"{descriptor_id}: sig abi.sig_max_len must be a positive integer")
        require(normalized["msg_len"] is None, f"{descriptor_id}: sig abi.msg_len must be null")
    elif primitive_type == "kpke":
        require(isinstance(normalized["ct_len"], int) and normalized["ct_len"] > 0, f"{descriptor_id}: kpke abi.ct_len must be a positive integer")
        require(normalized["ss_len"] is None, f"{descriptor_id}: kpke abi.ss_len must be null")
        require(normalized["sig_max_len"] is None, f"{descriptor_id}: kpke abi.sig_max_len must be null")
        require(isinstance(normalized["msg_len"], int) and normalized["msg_len"] > 0, f"{descriptor_id}: kpke abi.msg_len must be a positive integer")
    else:
        raise ValidationError(f"{descriptor_id}: unsupported primitive_type '{primitive_type}'")

    return {key: normalized[key] for key in ("pk_len", "sk_len", "ct_len", "ss_len", "sig_max_len", "msg_len")}


def validate_capabilities_metadata(capabilities: Any, primitive_type: str, descriptor_id: str) -> dict[str, Any]:
    require(isinstance(capabilities, dict), f"{descriptor_id}: capabilities must be an object")
    required = {
        "supports_keygen_derand",
        "supports_encaps_derand",
        "supports_sign_derand",
        "wire_format_class",
        "interop_class",
    }
    missing = required.difference(capabilities)
    require(not missing, f"{descriptor_id}: missing capabilities fields {sorted(missing)}")

    normalized = {
        "supports_keygen_derand": capabilities["supports_keygen_derand"],
        "supports_encaps_derand": capabilities["supports_encaps_derand"],
        "supports_sign_derand": capabilities["supports_sign_derand"],
        "wire_format_class": str(capabilities["wire_format_class"]).strip(),
        "interop_class": str(capabilities["interop_class"]).strip(),
    }
    for key in ("supports_keygen_derand", "supports_encaps_derand", "supports_sign_derand"):
        require(isinstance(normalized[key], bool), f"{descriptor_id}: capabilities.{key} must be boolean")
    require(normalized["wire_format_class"], f"{descriptor_id}: capabilities.wire_format_class is required")
    require(normalized["interop_class"], f"{descriptor_id}: capabilities.interop_class is required")

    if primitive_type == "kem":
        require(not normalized["supports_sign_derand"], f"{descriptor_id}: KEM descriptors cannot support sign derandomization")
    if primitive_type == "sig":
        require(not normalized["supports_encaps_derand"], f"{descriptor_id}: SIG descriptors cannot support encaps derandomization")
    if primitive_type == "kpke":
        require(normalized["supports_keygen_derand"], f"{descriptor_id}: KPKE descriptors must support keygen derandomization")
        require(not normalized["supports_encaps_derand"], f"{descriptor_id}: KPKE descriptors cannot expose encaps derandomization")
        require(not normalized["supports_sign_derand"], f"{descriptor_id}: KPKE descriptors cannot support sign derandomization")

    return normalized


def validate_path_exists(project_root: Path, relative_path: str, descriptor_id: str, field_name: str) -> None:
    candidate = project_root / relative_path
    require(candidate.exists(), f"{descriptor_id}: {field_name} does not exist: {relative_path}")


def validate_function_reference(descriptor: dict[str, Any], project_root: Path, descriptor_id: str) -> None:
    search_paths = [descriptor["source_file"], descriptor["build"]["declaration_file"], *descriptor["build"]["implementation_files"]]
    function_name = descriptor["function"]
    for relative_path in dict.fromkeys(search_paths):
        candidate = project_root / relative_path
        if candidate.exists() and function_name in candidate.read_text(encoding="utf-8", errors="ignore"):
            return
    raise ValidationError(f"{descriptor_id}: function '{function_name}' was not found in declared source files")


def normalize_descriptor(
    semantic_fields: dict[str, str],
    project_key: str,
    descriptor: Any,
    config: dict[str, Any],
) -> dict[str, Any]:
    require(isinstance(descriptor, dict), f"{semantic_fields['semantic_key']}::{project_key}: each descriptor must be an object")
    descriptor_id = f"{semantic_fields['semantic_key']}::{project_key}::{descriptor.get('implementation_id', 'unknown')}"
    required = {
        "project_id",
        "project_name",
        "implementation_id",
        "source_file",
        "function",
        "primitive_type",
        "api_variant",
        "backend_variant",
        "status",
        "build",
        "abi",
        "capabilities",
    }
    missing = required.difference(descriptor)
    require(not missing, f"{descriptor_id}: missing descriptor fields {sorted(missing)}")

    normalized_project_id = normalize_project_id(descriptor["project_id"], descriptor_id)
    normalized_project_key = normalize_project_id(project_key, descriptor_id)
    require(normalized_project_key == normalized_project_id, f"{descriptor_id}: project grouping key does not match descriptor project_id")
    require(normalized_project_id in config["enabled_projects"], f"{descriptor_id}: project_id '{normalized_project_id}' is not enabled")

    implementation_id = str(descriptor["implementation_id"]).strip()
    require(IMPLEMENTATION_ID_RE.fullmatch(implementation_id) is not None, f"{descriptor_id}: invalid implementation_id '{implementation_id}'")

    primitive_type = str(descriptor["primitive_type"]).strip()
    require(primitive_type in config["enabled_primitive_types"], f"{descriptor_id}: primitive_type '{primitive_type}' is not enabled")
    require(semantic_fields["operation"] in EXPECTED_OPERATIONS[primitive_type], f"{descriptor_id}: operation '{semantic_fields['operation']}' is not valid for primitive '{primitive_type}'")

    status = str(descriptor["status"]).strip()
    require(status in ALLOWED_STATUSES, f"{descriptor_id}: unsupported status '{status}'")

    function_name = str(descriptor["function"]).strip()
    require(function_name, f"{descriptor_id}: function is required")
    if config["validate_function_names"]:
        require(FUNCTION_NAME_RE.fullmatch(function_name) is not None, f"{descriptor_id}: invalid function name '{function_name}'")

    normalized = {
        "project_id": normalized_project_id,
        "project_name": normalize_project_name(normalized_project_id, descriptor.get("project_name")),
        "implementation_id": implementation_id,
        "source_file": str(descriptor["source_file"]).strip(),
        "function": function_name,
        "primitive_type": primitive_type,
        "api_variant": str(descriptor["api_variant"]).strip(),
        "backend_variant": str(descriptor["backend_variant"]).strip(),
        "status": status,
        "build": validate_build_metadata(descriptor["build"], descriptor_id) if config["validate_build_metadata"] else descriptor["build"],
        "abi": validate_abi_metadata(descriptor["abi"], primitive_type, descriptor_id) if config["validate_abi_metadata"] else descriptor["abi"],
        "capabilities": validate_capabilities_metadata(descriptor["capabilities"], primitive_type, descriptor_id)
        if config["validate_capabilities_metadata"]
        else descriptor["capabilities"],
        "provenance_hint": str(descriptor.get("provenance_hint", "unknown")).strip() or "unknown",
    }

    require(normalized["source_file"], f"{descriptor_id}: source_file is required")
    require(normalized["api_variant"], f"{descriptor_id}: api_variant is required")
    require(normalized["backend_variant"], f"{descriptor_id}: backend_variant is required")

    if config["validate_source_paths"]:
        project_root = ROOT / config["project_roots"][normalized_project_id]
        validate_path_exists(project_root, normalized["source_file"], descriptor_id, "source_file")
        validate_path_exists(project_root, normalized["build"]["implementation_dir"], descriptor_id, "build.implementation_dir")
        validate_path_exists(project_root, normalized["build"]["declaration_file"], descriptor_id, "build.declaration_file")
        for path in normalized["build"]["implementation_files"]:
            validate_path_exists(project_root, path, descriptor_id, "build.implementation_files")

    if config["validate_function_names"]:
        project_root = ROOT / config["project_roots"][normalized_project_id]
        validate_function_reference(normalized, project_root, descriptor_id)

    return normalized


def validate_mapping_structure(manual_mapping: dict[str, Any], config: dict[str, Any]) -> list[dict[str, Any]]:
    flattened = []
    for semantic_key, project_map in manual_mapping.items():
        semantic_fields = parse_semantic_key(semantic_key, config["enabled_algorithms"])
        require(isinstance(project_map, dict), f"{semantic_key}: value must be a project map object")
        for project_key, descriptors in project_map.items():
            require(isinstance(descriptors, list), f"{semantic_key}/{project_key}: project value must be a list")
            for descriptor in descriptors:
                flattened.append({**semantic_fields, **normalize_descriptor(semantic_fields, project_key, descriptor, config)})
    return flattened


def deduplicate_entries(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[str, dict[str, Any]] = {}
    for record in records:
        dedupe_key = stable_json(
            {
                "semantic_key": record["semantic_key"],
                "project_id": record["project_id"],
                "implementation_id": record["implementation_id"],
                "function": record["function"],
                "source_file": record["source_file"],
            }
        )
        if dedupe_key in deduped:
            require(stable_json(deduped[dedupe_key]) == stable_json(record), f"{record['semantic_key']}: conflicting duplicate descriptor for implementation '{record['implementation_id']}'")
            continue
        deduped[dedupe_key] = record
    return sorted(
        deduped.values(),
        key=lambda item: (
            item["semantic_key"],
            item["project_id"],
            item["implementation_id"],
            item["api_variant"],
            item["backend_variant"],
            item["function"],
            item["source_file"],
        ),
    )


def validate_mapping_consistency(records: list[dict[str, Any]]) -> None:
    semantic_primitive_types: dict[str, str] = {}
    implementation_registry: dict[tuple[str, str], str] = {}

    for record in records:
        semantic_key = record["semantic_key"]
        primitive_type = record["primitive_type"]
        if semantic_key in semantic_primitive_types:
            require(semantic_primitive_types[semantic_key] == primitive_type, f"{semantic_key}: one semantic key cannot mix primitive types")
        else:
            semantic_primitive_types[semantic_key] = primitive_type

        impl_key = (record["project_id"], record["implementation_id"])
        impl_fingerprint = stable_json(
            {
                "project_id": record["project_id"],
                "project_name": record["project_name"],
                "implementation_id": record["implementation_id"],
                "primitive_type": record["primitive_type"],
                "api_variant": record["api_variant"],
                "backend_variant": record["backend_variant"],
                "status": record["status"],
                "build": record["build"],
                "abi": record["abi"],
                "capabilities": record["capabilities"],
            }
        )
        if impl_key in implementation_registry:
            require(
                implementation_registry[impl_key] == impl_fingerprint,
                f"{record['semantic_key']}: implementation_id '{record['implementation_id']}' is reused inconsistently",
            )
        else:
            implementation_registry[impl_key] = impl_fingerprint


def group_records(records: list[dict[str, Any]]) -> dict[str, dict[str, list[dict[str, Any]]]]:
    grouped: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for record in records:
        semantic_key = record["semantic_key"]
        project_id = record["project_id"]
        grouped.setdefault(semantic_key, {}).setdefault(project_id, []).append(
            {
                "project_id": record["project_id"],
                "project_name": record["project_name"],
                "implementation_id": record["implementation_id"],
                "source_file": record["source_file"],
                "function": record["function"],
                "primitive_type": record["primitive_type"],
                "api_variant": record["api_variant"],
                "backend_variant": record["backend_variant"],
                "status": record["status"],
                "build": record["build"],
                "abi": record["abi"],
                "capabilities": record["capabilities"],
                "provenance_hint": record["provenance_hint"],
            }
        )

    ordered_output: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for semantic_key in sorted(grouped):
        ordered_output[semantic_key] = {}
        for project_id in sorted(grouped[semantic_key]):
            ordered_output[semantic_key][project_id] = sorted(
                grouped[semantic_key][project_id],
                key=lambda item: (
                    item["implementation_id"],
                    item["api_variant"],
                    item["backend_variant"],
                    item["function"],
                    item["source_file"],
                ),
            )
    return ordered_output


def main() -> int:
    config = load_config()
    require(config["manual_mapping_only"], "manual_mapping_only must remain true in v1")
    manual_mapping = load_manual_mapping()
    structured_records = validate_mapping_structure(manual_mapping, config)
    deduped_records = deduplicate_entries(structured_records)
    validate_mapping_consistency(deduped_records)
    output = group_records(deduped_records)
    write_mapping(OUTPUT_PATH, output)
    print(f"wrote {OUTPUT_PATH.relative_to(ROOT)} with {len(output)} semantic mappings")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValidationError as exc:
        print(f"mapper error: {exc}", file=sys.stderr)
        raise SystemExit(1)
