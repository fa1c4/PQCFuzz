#!/usr/bin/env python3
"""Construct exact flow-level differential pairs from operation-level mappings."""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from itertools import product
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "pairing_differential_targets/config/pairing.config.json"
MAPPING_PATH = ROOT / "design_implementation_mapper/data/mapping.json"
OUTPUT_PATH = ROOT / "pairing_differential_targets/data/pairs.json"

SEMANTIC_KEY_RE = re.compile(r"^(?P<algorithm>[A-Za-z0-9-]+)/(?P<operation>[a-z0-9_]+)$")
PROJECT_ID_RE = re.compile(r"^[a-z0-9_]+$")
IMPLEMENTATION_ID_RE = re.compile(r"^[a-z0-9_]+$")
PAIR_STATUS_VALUES = {"enabled", "manual-review"}
PROVENANCE_VALUES = {"unknown", "shared-upstream-likely", "distinct-likely"}
INTEROP_VALUES = {"declared-compatible", "same-project-only", "no-cross-exchange", "manual-review"}
SUPPORTED_PRIMITIVES = {"kem", "sig", "kpke"}
REQUIRED_OPERATIONS_BY_PRIMITIVE = {
    "kem": {"keygen", "encaps", "decaps"},
    "sig": {"keygen", "sign", "verify"},
    "kpke": {"kpke_keygen", "kpke_encrypt", "kpke_decrypt"},
}
INTEROP_FIELDS_BY_PRIMITIVE = {
    "kem": ("public_key_exchange", "ciphertext_exchange"),
    "sig": ("public_key_exchange", "signature_exchange"),
    "kpke": ("public_key_exchange", "ciphertext_exchange"),
}


class ValidationError(RuntimeError):
    """Raised when flow construction cannot satisfy the pairing contract."""


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


def write_pairs(path: Path, payload: list[dict[str, Any]]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def load_config() -> dict[str, Any]:
    config = load_json(CONFIG_PATH, "pairing config")
    require(isinstance(config, dict), "pairing.config.json must be a JSON object")
    required = {
        "enabled_projects",
        "allowed_project_pairs",
        "allowed_primitive_types",
        "allowed_status",
        "allowed_implementations",
        "allowed_backend_variants",
        "variant_priority",
        "required_operations",
        "interop_requirements",
    }
    missing = required.difference(config)
    require(not missing, f"pairing.config.json is missing fields: {sorted(missing)}")
    require(isinstance(config["enabled_projects"], list) and config["enabled_projects"], "enabled_projects must be a non-empty list")
    require(isinstance(config["allowed_project_pairs"], list) and config["allowed_project_pairs"], "allowed_project_pairs must be a non-empty list")
    require(isinstance(config["allowed_primitive_types"], list) and config["allowed_primitive_types"], "allowed_primitive_types must be a non-empty list")
    require(isinstance(config["allowed_status"], list) and config["allowed_status"], "allowed_status must be a non-empty list")

    for project_id in config["enabled_projects"]:
        require(isinstance(project_id, str) and PROJECT_ID_RE.fullmatch(project_id), f"invalid enabled project_id '{project_id}'")
    for pair in config["allowed_project_pairs"]:
        require(isinstance(pair, list) and len(pair) == 2, "allowed_project_pairs entries must be two-element arrays")
        for project_id in pair:
            require(project_id in config["enabled_projects"], f"allowed project pair uses unknown project '{project_id}'")
    for primitive_type in config["allowed_primitive_types"]:
        require(primitive_type in SUPPORTED_PRIMITIVES, f"unsupported primitive type '{primitive_type}'")
        require(primitive_type in config["required_operations"], f"missing required_operations entry for '{primitive_type}'")
        require(primitive_type in config["interop_requirements"], f"missing interop_requirements entry for '{primitive_type}'")

    return config


def load_mapping() -> dict[str, Any]:
    mapping = load_json(MAPPING_PATH, "mapping")
    require(isinstance(mapping, dict), "mapping.json must be a JSON object")
    return mapping


def parse_semantic_key(semantic_key: str) -> dict[str, str]:
    require(isinstance(semantic_key, str), "semantic keys must be strings")
    match = SEMANTIC_KEY_RE.fullmatch(semantic_key)
    require(match is not None, f"invalid semantic key '{semantic_key}'")
    algorithm = match.group("algorithm")
    family, parameter_set = algorithm.rsplit("-", 1)
    return {
        "semantic_key": semantic_key,
        "family": family,
        "family_slug": "".join(ch for ch in family.lower() if ch.isalnum()),
        "parameter_set": parameter_set,
        "operation": match.group("operation"),
    }


def normalize_candidate_record(
    semantic_fields: dict[str, str],
    project_key: str,
    descriptor: Any,
    config: dict[str, Any],
) -> dict[str, Any]:
    require(isinstance(descriptor, dict), f"{semantic_fields['semantic_key']}::{project_key}: descriptor must be an object")
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
        "provenance_hint",
    }
    missing = required.difference(descriptor)
    require(not missing, f"{descriptor_id}: missing descriptor fields {sorted(missing)}")

    project_id = descriptor["project_id"]
    implementation_id = descriptor["implementation_id"]
    primitive_type = descriptor["primitive_type"]
    status = descriptor["status"]

    require(isinstance(project_id, str) and PROJECT_ID_RE.fullmatch(project_id), f"{descriptor_id}: invalid project_id")
    require(project_id == project_key, f"{descriptor_id}: project grouping key does not match descriptor project_id")
    require(project_id in config["enabled_projects"], f"{descriptor_id}: project_id '{project_id}' is not enabled")
    require(isinstance(implementation_id, str) and IMPLEMENTATION_ID_RE.fullmatch(implementation_id), f"{descriptor_id}: invalid implementation_id")
    require(primitive_type in config["allowed_primitive_types"], f"{descriptor_id}: primitive_type '{primitive_type}' is not allowed")
    require(status in config["allowed_status"], f"{descriptor_id}: status '{status}' is not allowed")
    require(semantic_fields["operation"] in config["required_operations"][primitive_type], f"{descriptor_id}: operation '{semantic_fields['operation']}' is not allowed for '{primitive_type}'")

    allowed_impls = config["allowed_implementations"].get(project_id, [])
    if allowed_impls:
        require(implementation_id in allowed_impls, f"{descriptor_id}: implementation_id is not allowed by config")

    allowed_backends = config["allowed_backend_variants"].get(project_id, [])
    if allowed_backends:
        require(descriptor["backend_variant"] in allowed_backends, f"{descriptor_id}: backend_variant is not allowed by config")

    return {
        **semantic_fields,
        "project_id": project_id,
        "project_name": descriptor["project_name"],
        "implementation_id": implementation_id,
        "primitive_type": primitive_type,
        "api_variant": descriptor["api_variant"],
        "backend_variant": descriptor["backend_variant"],
        "status": status,
        "build": descriptor["build"],
        "abi": descriptor["abi"],
        "capabilities": descriptor["capabilities"],
        "provenance_hint": descriptor["provenance_hint"],
        "source_file": descriptor["source_file"],
        "function": descriptor["function"],
    }


def read_candidates(mapping_payload: dict[str, Any], config: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = []
    for semantic_key in sorted(mapping_payload):
        project_map = mapping_payload[semantic_key]
        require(isinstance(project_map, dict), f"{semantic_key}: value must be a project map object")
        semantic_fields = parse_semantic_key(semantic_key)
        for project_key in sorted(project_map):
            descriptors = project_map[project_key]
            require(isinstance(descriptors, list), f"{semantic_key}/{project_key}: project value must be an array")
            for descriptor in descriptors:
                candidates.append(normalize_candidate_record(semantic_fields, project_key, descriptor, config))
    return sorted(
        candidates,
        key=lambda item: (
            item["family_slug"],
            item["parameter_set"],
            item["primitive_type"],
            item["project_id"],
            item["implementation_id"],
            item["operation"],
            item["function"],
        ),
    )


def bundle_key(candidate: dict[str, Any]) -> tuple[str, str, str, str, str]:
    return (
        candidate["family"],
        candidate["parameter_set"],
        candidate["primitive_type"],
        candidate["project_id"],
        candidate["implementation_id"],
    )


def group_into_bundles(candidates: list[dict[str, Any]], config: dict[str, Any]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    for candidate in candidates:
        key = bundle_key(candidate)
        bundle = grouped.setdefault(
            key,
            {
                "family": candidate["family"],
                "family_slug": candidate["family_slug"],
                "parameter_set": candidate["parameter_set"],
                "primitive_type": candidate["primitive_type"],
                "project_id": candidate["project_id"],
                "project_name": candidate["project_name"],
                "implementation_id": candidate["implementation_id"],
                "api_variant": candidate["api_variant"],
                "backend_variant": candidate["backend_variant"],
                "build": candidate["build"],
                "abi": candidate["abi"],
                "capabilities": candidate["capabilities"],
                "status": candidate["status"],
                "required_operations": config["required_operations"][candidate["primitive_type"]],
                "provenance_hints": set(),
                "operations": {},
            },
        )
        bundle["provenance_hints"].add(candidate["provenance_hint"])
        operation = candidate["operation"]
        require(operation not in bundle["operations"], f"{key}: duplicate operation '{operation}'")
        bundle["operations"][operation] = {
            "source_file": candidate["source_file"],
            "function": candidate["function"],
        }

        validate_bundle_identity(bundle, candidate, key)
        validate_bundle_build_metadata(bundle, candidate, key)
        validate_bundle_abi(bundle, candidate, key)
        validate_bundle_capabilities(bundle, candidate, key)

    finalized = []
    for key, bundle in grouped.items():
        if bundle_has_required_operations(bundle):
            bundle["provenance_hints"] = sorted(bundle["provenance_hints"])
            finalized.append(bundle)
        else:
            missing = sorted(set(bundle["required_operations"]).difference(bundle["operations"]))
            raise ValidationError(f"{key}: incomplete bundle, missing {missing}")

    return sorted(
        finalized,
        key=lambda item: (
            item["family_slug"],
            item["parameter_set"],
            item["primitive_type"],
            item["project_id"],
            item["implementation_id"],
        ),
    )


def validate_bundle_identity(bundle: dict[str, Any], candidate: dict[str, Any], key: tuple[str, str, str, str, str]) -> None:
    for field in (
        "family",
        "parameter_set",
        "primitive_type",
        "project_id",
        "implementation_id",
        "project_name",
        "api_variant",
        "backend_variant",
    ):
        require(bundle[field] == candidate[field], f"{key}: inconsistent identity field '{field}'")


def validate_bundle_build_metadata(bundle: dict[str, Any], candidate: dict[str, Any], key: tuple[str, str, str, str, str]) -> None:
    require(stable_json(bundle["build"]) == stable_json(candidate["build"]), f"{key}: inconsistent build metadata")


def validate_bundle_abi(bundle: dict[str, Any], candidate: dict[str, Any], key: tuple[str, str, str, str, str]) -> None:
    require(stable_json(bundle["abi"]) == stable_json(candidate["abi"]), f"{key}: inconsistent ABI metadata")


def validate_bundle_capabilities(bundle: dict[str, Any], candidate: dict[str, Any], key: tuple[str, str, str, str, str]) -> None:
    require(stable_json(bundle["capabilities"]) == stable_json(candidate["capabilities"]), f"{key}: inconsistent capabilities metadata")


def bundle_has_required_operations(bundle: dict[str, Any]) -> bool:
    return set(bundle["required_operations"]).issubset(bundle["operations"])


def filter_bundles(bundles: list[dict[str, Any]], config: dict[str, Any]) -> list[dict[str, Any]]:
    filtered = []
    for bundle in bundles:
        allowed_impls = config["allowed_implementations"].get(bundle["project_id"], [])
        if allowed_impls and bundle["implementation_id"] not in allowed_impls:
            continue
        allowed_backends = config["allowed_backend_variants"].get(bundle["project_id"], [])
        if allowed_backends and bundle["backend_variant"] not in allowed_backends:
            continue
        filtered.append(bundle)
    return filtered


def is_allowed_project_pair(left_project: str, right_project: str, config: dict[str, Any]) -> bool:
    return [left_project, right_project] in config["allowed_project_pairs"]


def interop_fields_for_primitive(primitive_type: str) -> tuple[str, ...]:
    try:
        return INTEROP_FIELDS_BY_PRIMITIVE[primitive_type]
    except KeyError as exc:
        raise ValidationError(f"unsupported primitive type '{primitive_type}'") from exc


def derive_interop_policy(left: dict[str, Any], right: dict[str, Any], config: dict[str, Any]) -> dict[str, str]:
    primitive_type = left["primitive_type"]
    require(primitive_type == right["primitive_type"], "interop policy requires matching primitive types")
    allowed_fields = interop_fields_for_primitive(primitive_type)
    allowed_values = config["interop_requirements"][primitive_type]

    same_wire = left["capabilities"]["wire_format_class"] == right["capabilities"]["wire_format_class"]
    same_interop = left["capabilities"]["interop_class"] == right["capabilities"]["interop_class"]
    interop_class = left["capabilities"]["interop_class"]

    if same_wire and same_interop and interop_class in INTEROP_VALUES:
        default_value = interop_class
    else:
        default_value = "manual-review"

    policy = {}
    for field in allowed_fields:
        require(field in allowed_values, f"missing interop config for {primitive_type}.{field}")
        field_value = default_value
        if field_value not in allowed_values[field]:
            if "manual-review" in allowed_values[field]:
                field_value = "manual-review"
            else:
                raise ValidationError(f"{left['implementation_id']} vs {right['implementation_id']}: interop policy '{default_value}' is not allowed for {field}")
        policy[field] = field_value
    return policy


def derive_provenance_relation(left: dict[str, Any], right: dict[str, Any]) -> str:
    left_hints = set(left.get("provenance_hints", []))
    right_hints = set(right.get("provenance_hints", []))
    shared = left_hints.intersection(right_hints)
    if any("shared-upstream" in hint for hint in shared):
        return "shared-upstream-likely"
    if left_hints and right_hints and left_hints.isdisjoint(right_hints):
        return "distinct-likely"
    return "unknown"


def backend_priority(project_id: str, backend_variant: str, config: dict[str, Any]) -> int:
    priority = config["variant_priority"].get(project_id, [])
    try:
        return priority.index(backend_variant)
    except ValueError:
        return len(priority)


def stable_pair_order(bundles: list[dict[str, Any]], config: dict[str, Any]) -> list[dict[str, Any]]:
    return sorted(
        bundles,
        key=lambda item: (
            item["family_slug"],
            item["parameter_set"],
            item["primitive_type"],
            item["project_id"],
            backend_priority(item["project_id"], item["backend_variant"], config),
            item["implementation_id"],
        ),
    )


def make_pair_id(left: dict[str, Any], right: dict[str, Any]) -> str:
    return (
        f"{left['family_slug']}{left['parameter_set']}_"
        f"{left['project_id']}_{left['implementation_id']}_vs_"
        f"{right['project_id']}_{right['implementation_id']}"
    )


def make_pair_record(left: dict[str, Any], right: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    interop_policy = derive_interop_policy(left, right, config)
    status = "enabled" if all(value != "manual-review" for value in interop_policy.values()) else "manual-review"
    return {
        "pair_id": make_pair_id(left, right),
        "family": left["family"],
        "family_slug": left["family_slug"],
        "parameter_set": left["parameter_set"],
        "primitive_type": left["primitive_type"],
        "left": {
            "project_id": left["project_id"],
            "project_name": left["project_name"],
            "implementation_id": left["implementation_id"],
            "api_variant": left["api_variant"],
            "backend_variant": left["backend_variant"],
            "build": left["build"],
            "abi": left["abi"],
            "capabilities": left["capabilities"],
            "operations": left["operations"],
        },
        "right": {
            "project_id": right["project_id"],
            "project_name": right["project_name"],
            "implementation_id": right["implementation_id"],
            "api_variant": right["api_variant"],
            "backend_variant": right["backend_variant"],
            "build": right["build"],
            "abi": right["abi"],
            "capabilities": right["capabilities"],
            "operations": right["operations"],
        },
        "interop_policy": interop_policy,
        "provenance_relation": derive_provenance_relation(left, right),
        "status": status,
    }


def generate_pairs(bundles: list[dict[str, Any]], config: dict[str, Any]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    for bundle in bundles:
        grouped[(bundle["family"], bundle["parameter_set"], bundle["primitive_type"])][bundle["project_id"]].append(bundle)

    pairs = []
    seen = set()
    for group_key in sorted(grouped):
        project_bundles = grouped[group_key]
        for left_project, right_project in config["allowed_project_pairs"]:
            if not is_allowed_project_pair(left_project, right_project, config):
                continue
            left_candidates = stable_pair_order(project_bundles.get(left_project, []), config)
            right_candidates = stable_pair_order(project_bundles.get(right_project, []), config)
            for left_bundle, right_bundle in product(left_candidates, right_candidates):
                require(left_bundle["project_id"] != right_bundle["project_id"], "same-project pairs are not allowed")
                pair_id = make_pair_id(left_bundle, right_bundle)
                if pair_id in seen:
                    continue
                seen.add(pair_id)
                pairs.append(make_pair_record(left_bundle, right_bundle, config))

    require(pairs, "no valid pairs were produced")
    return sorted(pairs, key=lambda item: item["pair_id"])


def validate_bundle_shape(bundle: dict[str, Any], primitive_type: str, label: str) -> None:
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
    require(not missing, f"{label}: missing bundle fields {sorted(missing)}")
    require(PROJECT_ID_RE.fullmatch(bundle["project_id"]) is not None, f"{label}: invalid project_id")
    require(IMPLEMENTATION_ID_RE.fullmatch(bundle["implementation_id"]) is not None, f"{label}: invalid implementation_id")
    actual_required = REQUIRED_OPERATIONS_BY_PRIMITIVE[primitive_type]
    require(actual_required.issubset(bundle["operations"]), f"{label}: missing required operations")


def validate_pair_record(pair: dict[str, Any], config: dict[str, Any]) -> None:
    required = {
        "pair_id",
        "family",
        "family_slug",
        "parameter_set",
        "primitive_type",
        "left",
        "right",
        "interop_policy",
        "provenance_relation",
        "status",
    }
    missing = required.difference(pair)
    require(not missing, f"pair record missing fields: {sorted(missing)}")
    primitive_type = pair["primitive_type"]
    require(primitive_type in config["allowed_primitive_types"], f"{pair['pair_id']}: invalid primitive_type")
    require(pair["status"] in PAIR_STATUS_VALUES, f"{pair['pair_id']}: invalid pair status")
    require(pair["provenance_relation"] in PROVENANCE_VALUES, f"{pair['pair_id']}: invalid provenance_relation")
    validate_bundle_shape(pair["left"], primitive_type, f"{pair['pair_id']}:left")
    validate_bundle_shape(pair["right"], primitive_type, f"{pair['pair_id']}:right")
    require(pair["left"]["project_id"] != pair["right"]["project_id"], f"{pair['pair_id']}: same-project pairs are not allowed")
    require(is_allowed_project_pair(pair["left"]["project_id"], pair["right"]["project_id"], config), f"{pair['pair_id']}: project pair is not allowed")

    expected_fields = interop_fields_for_primitive(primitive_type)
    require(set(pair["interop_policy"]) == set(expected_fields), f"{pair['pair_id']}: invalid interop policy fields")
    for field in expected_fields:
        value = pair["interop_policy"][field]
        require(value in INTEROP_VALUES, f"{pair['pair_id']}: invalid interop policy value '{value}'")
        require(value in config["interop_requirements"][primitive_type][field] or value == "manual-review", f"{pair['pair_id']}: interop policy value is not allowed by config")


def validate_pairs(pairs: list[dict[str, Any]], config: dict[str, Any]) -> None:
    require(isinstance(pairs, list), "pairs output must be an array")
    seen = set()
    for pair in pairs:
        validate_pair_record(pair, config)
        require(pair["pair_id"] not in seen, f"duplicate pair_id '{pair['pair_id']}'")
        seen.add(pair["pair_id"])

def main() -> int:
    config = load_config()
    mapping_payload = load_mapping()
    candidates = read_candidates(mapping_payload, config)
    require(candidates, "no candidate operation records were produced from mapping.json")
    bundles = group_into_bundles(candidates, config)
    filtered_bundles = filter_bundles(bundles, config)
    require(filtered_bundles, "no valid bundles were produced")
    pairs = generate_pairs(filtered_bundles, config)
    validate_pairs(pairs, config)
    write_pairs(OUTPUT_PATH, pairs)
    print(f"wrote {OUTPUT_PATH.relative_to(ROOT)} with {len(pairs)} flow pairs")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValidationError as exc:
        print(f"pairing error: {exc}", file=sys.stderr)
        raise SystemExit(1)
