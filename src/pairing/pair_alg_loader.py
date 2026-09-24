#!/usr/bin/env python3
"""Load and validate externally supplied PQCFuzz algorithm-pair metadata."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


PAIR_ID_RE = re.compile(r"^[a-z0-9_]+$")
SCHEME_PROFILES_DIR = Path(__file__).resolve().parents[1] / "config" / "scheme_profiles"

# Locked family metadata lives in src/config/scheme_profiles/<family>.json.
# The loader merges it into the built-in table so a family profile and its
# pair_alg file cannot drift apart.
_PROFILE_ALGORITHM_FIELDS = (
    "family",
    "primitive_type",
    "pk_len",
    "sk_len",
    "sig_max_len",
    "variant",
    "category",
    "security_level",
    "corner",
    "c_defines",
    "p",
    "z",
    "n",
    "k",
    "m",
    "g",
    "t",
    "w",
    "seed_bytes",
    "salt_bytes",
    "digest_bytes",
    "y_bits",
    "v_bits",
    "s_bits",
    "y_bytes",
    "v_bytes",
    "syn_bytes",
    "tree_nodes_to_store",
    # Falcon family fields.
    "format",
    "sig_type",
    "logn",
    "q",
    "padded_len",
    "ct_len",
    "salt_len",
    "norm_bound",
    "compressed_coefficient_limit",
    "pk_header",
    "sig_header",
    "sk_header",
    "ct_header",
    "fg_bits",
)


def load_scheme_profile_algorithms() -> dict[str, dict[str, Any]]:
    """Read parameter-set metadata from src/config/scheme_profiles/*.json."""
    algorithms: dict[str, dict[str, Any]] = {}
    if not SCHEME_PROFILES_DIR.is_dir():
        return algorithms
    for path in sorted(SCHEME_PROFILES_DIR.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict):
            continue
        for parameter_set in payload.get("parameter_sets", []):
            if not isinstance(parameter_set, dict):
                continue
            algorithm = parameter_set.get("algorithm")
            if not isinstance(algorithm, str) or not algorithm:
                continue
            metadata: dict[str, Any] = {}
            for field in ("family", "primitive_type"):
                if field in payload:
                    metadata[field] = payload[field]
            metadata.update(
                {
                    field: parameter_set[field]
                    for field in _PROFILE_ALGORITHM_FIELDS
                    if field in parameter_set
                }
            )
            missing = [
                field
                for field in ("family", "primitive_type", "pk_len", "sk_len", "sig_max_len")
                if field not in metadata
            ]
            if missing:
                raise PairAlgError(
                    f"{path.name}:{algorithm}: scheme profile is missing {', '.join(missing)}"
                )
            algorithms[algorithm] = metadata
    return algorithms


SUPPORTED_ALGORITHMS = {
    "ML-KEM-512": {
        "family": "ML-KEM",
        "primitive_type": "kem",
        "pk_len": 800,
        "sk_len": 1632,
        "ct_len": 768,
        "ss_len": 32,
        "k": 2,
        "du": 10,
        "dv": 4,
    },
    "ML-KEM-768": {
        "family": "ML-KEM",
        "primitive_type": "kem",
        "pk_len": 1184,
        "sk_len": 2400,
        "ct_len": 1088,
        "ss_len": 32,
        "k": 3,
        "du": 10,
        "dv": 4,
    },
    "ML-KEM-1024": {
        "family": "ML-KEM",
        "primitive_type": "kem",
        "pk_len": 1568,
        "sk_len": 3168,
        "ct_len": 1568,
        "ss_len": 32,
        "k": 4,
        "du": 11,
        "dv": 5,
    },
    "ML-DSA-44": {
        "family": "ML-DSA",
        "primitive_type": "sig",
        "pk_len": 1312,
        "sk_len": 2560,
        "sig_max_len": 2420,
    },
    "ML-DSA-65": {
        "family": "ML-DSA",
        "primitive_type": "sig",
        "pk_len": 1952,
        "sk_len": 4032,
        "sig_max_len": 3309,
    },
    "ML-DSA-87": {
        "family": "ML-DSA",
        "primitive_type": "sig",
        "pk_len": 2592,
        "sk_len": 4896,
        "sig_max_len": 4627,
    },
    "SLH-DSA-SHA2-128s": {
        "family": "SLH-DSA",
        "primitive_type": "sig",
        "n": 16,
        "pk_len": 32,
        "sk_len": 64,
        "sig_max_len": 7856,
        "h": 63,
        "d": 7,
        "hp": 9,
        "a": 12,
        "k": 14,
    },
    "SLH-DSA-SHAKE-128s": {
        "family": "SLH-DSA",
        "primitive_type": "sig",
        "n": 16,
        "pk_len": 32,
        "sk_len": 64,
        "sig_max_len": 7856,
        "h": 63,
        "d": 7,
        "hp": 9,
        "a": 12,
        "k": 14,
    },
    "SLH-DSA-SHA2-128f": {
        "family": "SLH-DSA",
        "primitive_type": "sig",
        "n": 16,
        "pk_len": 32,
        "sk_len": 64,
        "sig_max_len": 17088,
        "h": 66,
        "d": 22,
        "hp": 3,
        "a": 6,
        "k": 33,
    },
    "SLH-DSA-SHAKE-128f": {
        "family": "SLH-DSA",
        "primitive_type": "sig",
        "n": 16,
        "pk_len": 32,
        "sk_len": 64,
        "sig_max_len": 17088,
        "h": 66,
        "d": 22,
        "hp": 3,
        "a": 6,
        "k": 33,
    },
    "SLH-DSA-SHA2-192s": {
        "family": "SLH-DSA",
        "primitive_type": "sig",
        "n": 24,
        "pk_len": 48,
        "sk_len": 96,
        "sig_max_len": 16224,
        "h": 63,
        "d": 7,
        "hp": 9,
        "a": 14,
        "k": 17,
    },
    "SLH-DSA-SHAKE-192s": {
        "family": "SLH-DSA",
        "primitive_type": "sig",
        "n": 24,
        "pk_len": 48,
        "sk_len": 96,
        "sig_max_len": 16224,
        "h": 63,
        "d": 7,
        "hp": 9,
        "a": 14,
        "k": 17,
    },
    "SLH-DSA-SHA2-192f": {
        "family": "SLH-DSA",
        "primitive_type": "sig",
        "n": 24,
        "pk_len": 48,
        "sk_len": 96,
        "sig_max_len": 35664,
        "h": 66,
        "d": 22,
        "hp": 3,
        "a": 8,
        "k": 33,
    },
    "SLH-DSA-SHAKE-192f": {
        "family": "SLH-DSA",
        "primitive_type": "sig",
        "n": 24,
        "pk_len": 48,
        "sk_len": 96,
        "sig_max_len": 35664,
        "h": 66,
        "d": 22,
        "hp": 3,
        "a": 8,
        "k": 33,
    },
    "SLH-DSA-SHA2-256s": {
        "family": "SLH-DSA",
        "primitive_type": "sig",
        "n": 32,
        "pk_len": 64,
        "sk_len": 128,
        "sig_max_len": 29792,
        "h": 64,
        "d": 8,
        "hp": 8,
        "a": 14,
        "k": 22,
    },
    "SLH-DSA-SHAKE-256s": {
        "family": "SLH-DSA",
        "primitive_type": "sig",
        "n": 32,
        "pk_len": 64,
        "sk_len": 128,
        "sig_max_len": 29792,
        "h": 64,
        "d": 8,
        "hp": 8,
        "a": 14,
        "k": 22,
    },
    "SLH-DSA-SHA2-256f": {
        "family": "SLH-DSA",
        "primitive_type": "sig",
        "n": 32,
        "pk_len": 64,
        "sk_len": 128,
        "sig_max_len": 49856,
        "h": 68,
        "d": 17,
        "hp": 4,
        "a": 9,
        "k": 35,
    },
    "SLH-DSA-SHAKE-256f": {
        "family": "SLH-DSA",
        "primitive_type": "sig",
        "n": 32,
        "pk_len": 64,
        "sk_len": 128,
        "sig_max_len": 49856,
        "h": 68,
        "d": 17,
        "hp": 4,
        "a": 9,
        "k": 35,
    },
    "AIGIS-ENC-1": {
        "family": "AIGIS-ENC",
        "primitive_type": "kem",
        "pk_len": 672,
        "sk_len": 1568,
        "ct_len": 736,
        "ss_len": 32,
        "n": 256,
        "q": 7681,
        "k": 2,
        "c1_bits": 10,
        "c2_bits": 3,
        "pk_bits": 10,
        "poly_bytes": 416,
    },
    "AIGIS-ENC-2": {
        "family": "AIGIS-ENC",
        "primitive_type": "kem",
        "pk_len": 896,
        "sk_len": 2208,
        "ct_len": 992,
        "ss_len": 32,
        "n": 256,
        "q": 7681,
        "k": 3,
        "c1_bits": 9,
        "c2_bits": 4,
        "pk_bits": 9,
        "poly_bytes": 416,
    },
    "AIGIS-ENC-3": {
        "family": "AIGIS-ENC",
        "primitive_type": "kem",
        "pk_len": 992,
        "sk_len": 2304,
        "ct_len": 1056,
        "ss_len": 32,
        "n": 256,
        "q": 7681,
        "k": 3,
        "c1_bits": 10,
        "c2_bits": 3,
        "pk_bits": 10,
        "poly_bytes": 416,
    },
    "AIGIS-ENC-4": {
        "family": "AIGIS-ENC",
        "primitive_type": "kem",
        "pk_len": 1440,
        "sk_len": 3168,
        "ct_len": 1568,
        "ss_len": 32,
        "n": 256,
        "q": 7681,
        "k": 4,
        "c1_bits": 11,
        "c2_bits": 5,
        "pk_bits": 11,
        "poly_bytes": 416,
    },
    "AIGIS-SIG-1": {
        "family": "AIGIS-SIG",
        "primitive_type": "sig",
        "pk_len": 1056,
        "sk_len": 2448,
        "sig_max_len": 1852,
        "n": 256,
        "l": 3,
        "k": 4,
        "omega": 80,
    },
    "AIGIS-SIG-2": {
        "family": "AIGIS-SIG",
        "primitive_type": "sig",
        "pk_len": 1312,
        "sk_len": 3376,
        "sig_max_len": 2445,
        "n": 256,
        "l": 4,
        "k": 5,
        "omega": 96,
    },
    "AIGIS-SIG-3": {
        "family": "AIGIS-SIG",
        "primitive_type": "sig",
        "pk_len": 1568,
        "sk_len": 3888,
        "sig_max_len": 3046,
        "n": 256,
        "l": 5,
        "k": 6,
        "omega": 120,
    },
}

API_NAMES_BY_PRIMITIVE = {
    "kem": ("keygen", "encaps", "decaps"),
    "sig": ("keygen", "sign", "verify"),
}
ABI_FIELDS_BY_PRIMITIVE = {
    "kem": ("pk_len", "sk_len", "ct_len", "ss_len"),
    "sig": ("pk_len", "sk_len", "sig_max_len"),
}
EXCHANGE_FIELDS_BY_PRIMITIVE = {
    "kem": ("public_key_exchange", "ciphertext_exchange", "secret_key_exchange", "secret_key_format_compatible"),
    "sig": ("public_key_exchange", "signature_exchange"),
}
SIG_CAPABILITY_FIELDS = (
    "supports_context",
    "supports_seeded_sign",
    "supports_deterministic_sign",
    "supports_signed_message",
)


class PairAlgError(RuntimeError):
    """Raised when pair_alg JSON cannot satisfy the explicit-pair contract."""


SUPPORTED_ALGORITHMS.update(load_scheme_profile_algorithms())


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PairAlgError(message)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PairAlgError(f"pair_alg file is missing: {path}") from exc
    except json.JSONDecodeError as exc:
        raise PairAlgError(f"pair_alg is not valid JSON: {exc}") from exc


def require_string(value: Any, field: str, context: str) -> str:
    require(isinstance(value, str) and value.strip(), f"{context}: {field} must be a non-empty string")
    return value.strip()


def validate_algorithm_metadata(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    configured = payload.get("algorithms", {})
    require(isinstance(configured, dict), "algorithms must be an object when present")
    merged = {name: dict(meta) for name, meta in SUPPORTED_ALGORITHMS.items()}
    for algorithm, metadata in configured.items():
        require(algorithm in SUPPORTED_ALGORITHMS, f"unsupported algorithm metadata entry '{algorithm}'")
        require(isinstance(metadata, dict), f"algorithms.{algorithm} must be an object")
        expected = SUPPORTED_ALGORITHMS[algorithm]
        for field, expected_value in expected.items():
            require(metadata.get(field) == expected_value, f"algorithms.{algorithm}.{field} must be {expected_value!r}")
        merged[algorithm] = dict(metadata)
    return merged


def validate_abi(abi: Any, metadata: dict[str, Any], context: str) -> dict[str, int]:
    require(isinstance(abi, dict), f"{context}: abi must be an object")
    normalized: dict[str, int] = {}
    overrides = abi.get("abi_overrides", {})
    require(isinstance(overrides, dict), f"{context}: abi.abi_overrides must be an object")
    for field in ABI_FIELDS_BY_PRIMITIVE[metadata["primitive_type"]]:
        value = abi.get(field)
        require(isinstance(value, int) and value > 0, f"{context}: abi.{field} must be a positive integer")
        allowed = {metadata[field]}
        variants = metadata.get(f"{field}_variants")
        if isinstance(variants, list):
            allowed.update(item for item in variants if isinstance(item, int))
        if field in overrides:
            override = overrides[field]
            require(
                isinstance(override, int) and override > 0,
                f"{context}: abi.abi_overrides.{field} must be a positive integer",
            )
            require(
                override in allowed,
                f"{context}: abi.abi_overrides.{field}={override} is not a declared {metadata['family']} variant",
            )
            normalized[field] = override
            continue
        require(
            value in allowed,
            f"{context}: abi.{field}={value} does not match {metadata['family']} metadata {metadata[field]}",
        )
        normalized[field] = value
    return normalized


def validate_api_names(api_names: Any, primitive_type: str, context: str) -> dict[str, str]:
    require(isinstance(api_names, dict), f"{context}: api_names must be an object")
    normalized = {}
    for field in API_NAMES_BY_PRIMITIVE[primitive_type]:
        normalized[field] = require_string(api_names.get(field), f"api_names.{field}", context)
    if primitive_type == "sig" and api_names.get("sign_seeded") is not None:
        normalized["sign_seeded"] = require_string(api_names.get("sign_seeded"), "api_names.sign_seeded", context)
    return normalized


def validate_capabilities(capabilities: Any, metadata: dict[str, Any], context: str) -> dict[str, bool]:
    if metadata["primitive_type"] != "sig":
        return {}
    if capabilities is None:
        capabilities = {}
    require(isinstance(capabilities, dict), f"{context}: capabilities must be an object")
    normalized = {}
    for field in SIG_CAPABILITY_FIELDS:
        value = capabilities.get(field, False)
        require(isinstance(value, bool), f"{context}: capabilities.{field} must be boolean")
        normalized[field] = value
    return normalized


def validate_impl(impl: Any, metadata: dict[str, Any], context: str) -> dict[str, Any]:
    require(isinstance(impl, dict), f"{context}: implementation record must be an object")
    project_id = require_string(impl.get("project_id"), "project_id", context)
    implementation_id = require_string(impl.get("implementation_id"), "implementation_id", context)
    record = {
        "project_id": project_id,
        "project_name": require_string(impl.get("project_name", project_id), "project_name", context),
        "implementation_id": implementation_id,
        "api_names": validate_api_names(impl.get("api_names"), metadata["primitive_type"], context),
        "abi": validate_abi(impl.get("abi"), metadata, context),
        "capabilities": validate_capabilities(impl.get("capabilities"), metadata, context),
    }
    reference_version = impl.get("reference_version")
    if reference_version is not None:
        record["reference_version"] = require_string(reference_version, "reference_version", context)
    return record


def validate_exchange_contract(contract: Any, primitive_type: str, context: str) -> dict[str, bool]:
    require(isinstance(contract, dict), f"{context}: exchange_contract must be an object")
    normalized = {}
    for field in EXCHANGE_FIELDS_BY_PRIMITIVE[primitive_type]:
        value = contract.get(field, False) if field == "secret_key_format_compatible" else contract.get(field)
        require(isinstance(value, bool), f"{context}: exchange_contract.{field} must be boolean")
        normalized[field] = value
    return normalized


def validate_pair(pair: Any, algorithms: dict[str, dict[str, Any]]) -> dict[str, Any]:
    require(isinstance(pair, dict), "pair record must be an object")
    pair_id = require_string(pair.get("pair_id"), "pair_id", "pair")
    require(PAIR_ID_RE.fullmatch(pair_id) is not None, f"{pair_id}: pair_id must match {PAIR_ID_RE.pattern}")
    algorithm = require_string(pair.get("algorithm"), "algorithm", pair_id)
    require(algorithm in algorithms, f"{pair_id}: unsupported algorithm '{algorithm}'")
    metadata = algorithms[algorithm]
    primitive_type = require_string(pair.get("primitive_type"), "primitive_type", pair_id)
    require(primitive_type == metadata["primitive_type"], f"{pair_id}: primitive_type must be {metadata['primitive_type']!r}")
    status = require_string(pair.get("status"), "status", pair_id)
    require(status in {"enabled", "disabled"}, f"{pair_id}: status must be enabled or disabled")

    return {
        "pair_id": pair_id,
        "algorithm": algorithm,
        "algorithm_family": metadata["family"],
        "primitive_type": primitive_type,
        "algorithm_metadata": dict(metadata),
        "left": validate_impl(pair.get("left"), metadata, f"{pair_id}:left"),
        "right": validate_impl(pair.get("right"), metadata, f"{pair_id}:right"),
        "exchange_contract": validate_exchange_contract(pair.get("exchange_contract"), primitive_type, pair_id),
        "provenance_relation": require_string(pair.get("provenance_relation"), "provenance_relation", pair_id),
        "status": status,
    }


def load_pair_alg(path: str | Path) -> dict[str, Any]:
    pair_alg_path = Path(path)
    payload = load_json(pair_alg_path)
    require(isinstance(payload, dict), "pair_alg root must be an object")
    require(payload.get("version") == 1, "pair_alg.version must be 1")
    algorithms = validate_algorithm_metadata(payload)
    raw_pairs = payload.get("pairs")
    require(isinstance(raw_pairs, list), "pair_alg.pairs must be an array")

    pairs = [validate_pair(pair, algorithms) for pair in raw_pairs]
    seen = set()
    for pair in pairs:
        require(pair["pair_id"] not in seen, f"duplicate pair_id '{pair['pair_id']}'")
        seen.add(pair["pair_id"])

    return {
        "version": 1,
        "source_path": str(pair_alg_path),
        "algorithms": algorithms,
        "pairs": pairs,
    }


def enabled_pairs_for_family(document: dict[str, Any], algorithm_family: str) -> list[dict[str, Any]]:
    return [
        pair
        for pair in document["pairs"]
        if pair["status"] == "enabled" and pair["algorithm_family"] == algorithm_family
    ]
