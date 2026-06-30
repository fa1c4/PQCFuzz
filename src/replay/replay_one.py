#!/usr/bin/env python3
"""Replay one PQCFuzz structured input with the native replay oracle."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from triage.classify_finding import classify_trace
from triage.poc_generator import generate_poc


ALGORITHM_BY_ENUM = {
    1: "ML-KEM-512",
    2: "ML-KEM-768",
    3: "ML-KEM-1024",
    4: "ML-DSA-44",
    5: "ML-DSA-65",
    6: "ML-DSA-87",
    7: "SLH-DSA-SHA2-128s",
    8: "SLH-DSA-SHAKE-128s",
    9: "SLH-DSA-SHA2-128f",
    10: "SLH-DSA-SHAKE-128f",
    11: "SLH-DSA-SHA2-192s",
    12: "SLH-DSA-SHAKE-192s",
    13: "SLH-DSA-SHA2-192f",
    14: "SLH-DSA-SHAKE-192f",
    15: "SLH-DSA-SHA2-256s",
    16: "SLH-DSA-SHAKE-256s",
    17: "SLH-DSA-SHA2-256f",
    18: "SLH-DSA-SHAKE-256f",
}

ORACLE_BY_ENUM = {
    1: "mlkem_local_roundtrip",
    2: "mlkem_cross_exchange_roundtrip",
    3: "mlkem_tampered_ciphertext_implicit_rejection",
    4: "mlkem_bad_randomness_sanity",
    5: "mldsa_local_sign_verify",
    6: "mldsa_cross_verify",
    7: "mldsa_mutated_signature_negative",
    8: "mldsa_mutated_message_negative",
    9: "mldsa_mutated_context_negative",
    10: "mldsa_oid_field_mutation_sanity",
    11: "mldsa_bad_randomness_sanity",
    12: "slhdsa_local_sign_verify",
    13: "slhdsa_cross_verify",
    14: "slhdsa_mutated_signature_negative",
    15: "slhdsa_mutated_message_negative",
    16: "slhdsa_mutated_context_negative",
    17: "slhdsa_bad_randomness_sanity",
    18: "kem_decaps_c",
    19: "kem_decaps_sk",
    20: "kem_encaps_badrng",
    21: "kem_encaps_pk_0",
    22: "kem_encaps_pk",
    23: "kem_keygen_badrng",
    24: "sig_keygen_badrng",
    25: "sig_sign_badrng",
    26: "sig_sign_m",
    27: "sig_sign_sk",
    28: "sig_verify_m",
    29: "sig_verify_sig",
    30: "sig_verify_pk",
}
ALGORITHM_ENUM_BY_NAME = {value: key for key, value in ALGORITHM_BY_ENUM.items()}
ORACLE_ENUM_BY_NAME = {value: key for key, value in ORACLE_BY_ENUM.items()}

EXIT_HANG = 71
EXIT_NATIVE_CRASH = 72


class ReplayError(RuntimeError):
    """Raised when replay input or job data is invalid."""


def read_u16_le(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 2 > len(data):
        raise ReplayError("truncated u16 length in PQCFuzz envelope")
    return data[offset] | (data[offset + 1] << 8), offset + 2


def read_slice(data: bytes, offset: int, length: int, label: str) -> tuple[bytes, int]:
    if offset + length > len(data):
        raise ReplayError(f"truncated {label} field in PQCFuzz envelope")
    return data[offset : offset + length], offset + length


def parse_binary_envelope(data: bytes) -> dict[str, Any]:
    if len(data) < 8 or data[:4] != b"PQCF":
        raise ReplayError("input does not start with PQCF envelope magic")
    version = data[4]
    algorithm_enum = data[5]
    oracle_enum = data[6]
    flags = data[7]
    offset = 8
    seed_len, offset = read_u16_le(data, offset)
    seed, offset = read_slice(data, offset, seed_len, "seed")
    msg_len, offset = read_u16_le(data, offset)
    msg, offset = read_slice(data, offset, msg_len, "msg")
    mutation_len, offset = read_u16_le(data, offset)
    mutation, offset = read_slice(data, offset, mutation_len, "mutation")
    extra_len, offset = read_u16_le(data, offset)
    extra, offset = read_slice(data, offset, extra_len, "extra")
    if offset != len(data):
        raise ReplayError("PQCFuzz envelope has trailing bytes after extra field")
    return {
        "magic": "PQCF",
        "version": version,
        "algorithm": ALGORITHM_BY_ENUM.get(algorithm_enum, f"UNKNOWN-{algorithm_enum}"),
        "oracle_id": ORACLE_BY_ENUM.get(oracle_enum, f"UNKNOWN-{oracle_enum}"),
        "flags": flags,
        "seed": seed,
        "msg": msg,
        "mutation": mutation,
        "extra": extra,
        "source_format": "binary-envelope",
    }


def parse_json_envelope(data: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReplayError(f"input is neither a binary PQCF envelope nor JSON envelope: {exc}") from exc
    if payload.get("magic") != "PQCF":
        raise ReplayError("JSON envelope magic must be PQCF")
    return {
        "magic": "PQCF",
        "version": int(payload.get("version", 1)),
        "algorithm": str(payload["algorithm"]),
        "oracle_id": str(payload["oracle_id"]),
        "flags": int(payload.get("flags", 0)),
        "seed": base64.b64decode(payload.get("seed_b64", "")),
        "msg": base64.b64decode(payload.get("msg_b64", "")),
        "mutation": base64.b64decode(payload.get("mutation_b64", "")),
        "extra": base64.b64decode(payload.get("extra_b64", "")),
        "source_format": "json-envelope",
    }


def parse_envelope(path: Path) -> tuple[bytes, dict[str, Any]]:
    if not path.exists():
        raise ReplayError(f"input file is missing: {path}")
    data = path.read_bytes()
    if data.startswith(b"PQCF"):
        return data, parse_binary_envelope(data)
    return data, parse_json_envelope(data)


def envelope_to_json(envelope: dict[str, Any]) -> dict[str, Any]:
    return {
        "magic": envelope["magic"],
        "version": envelope["version"],
        "algorithm": envelope["algorithm"],
        "oracle_id": envelope["oracle_id"],
        "flags": envelope["flags"],
        "seed_len": len(envelope["seed"]),
        "msg_len": len(envelope["msg"]),
        "mutation_len": len(envelope["mutation"]),
        "extra_len": len(envelope["extra"]),
        "source_format": envelope["source_format"],
    }


def encode_binary_envelope(envelope: dict[str, Any], oracle_id: str | None = None) -> bytes:
    algorithm_enum = ALGORITHM_ENUM_BY_NAME.get(envelope["algorithm"])
    selected_oracle = oracle_id or envelope["oracle_id"]
    oracle_enum = ORACLE_ENUM_BY_NAME.get(selected_oracle)
    if algorithm_enum is None:
        raise ReplayError(f"cannot encode unknown algorithm in PQCFuzz envelope: {envelope['algorithm']}")
    if oracle_enum is None:
        raise ReplayError(f"cannot encode unknown oracle in PQCFuzz envelope: {selected_oracle}")
    out = bytearray(b"PQCF")
    out.extend([int(envelope.get("version", 1)), algorithm_enum, oracle_enum, int(envelope.get("flags", 0)) & 0xFF])
    for field_name in ("seed", "msg", "mutation", "extra"):
        field = envelope[field_name]
        if len(field) > 0xFFFF:
            raise ReplayError(f"{field_name} field is too large for PQCFuzz envelope")
        out.extend(len(field).to_bytes(2, "little"))
        out.extend(field)
    return bytes(out)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def make_artifact_dir(job: dict[str, Any], input_bytes: bytes) -> Path:
    digest = hashlib.sha256(input_bytes).hexdigest()[:16]
    return REPO_ROOT / job["paths"]["result_dir"] / f"replay_{digest}"


def selected_oracle_id(job: dict[str, Any], envelope: dict[str, Any]) -> str:
    envelope_oracle = str(envelope["oracle_id"])
    job_oracles = [str(item) for item in job.get("oracles", [])]
    if envelope_oracle in job_oracles:
        return envelope_oracle
    if job_oracles:
        return job_oracles[0]
    return envelope_oracle


def adapter_and_exchange(job: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, bool]]:
    if "target" in job:
        target = job["target"]
        return target, {}, {
            "public_key_exchange": False,
            "ciphertext_exchange": False,
            "secret_key_exchange": False,
            "secret_key_format_compatible": False,
            "signature_exchange": False,
        }
    pair = job.get("pair", {})
    exchange = pair.get("exchange_contract", {})
    return pair.get("left", {}), pair.get("right", {}), {
        "public_key_exchange": bool(exchange.get("public_key_exchange", False)),
        "ciphertext_exchange": bool(exchange.get("ciphertext_exchange", False)),
        "secret_key_exchange": bool(exchange.get("secret_key_exchange", False)),
        "secret_key_format_compatible": bool(exchange.get("secret_key_format_compatible", False)),
        "signature_exchange": bool(exchange.get("signature_exchange", False)),
    }


def bool_arg(value: bool) -> str:
    return "1" if value else "0"


def replay_command(
    replay_bin: Path,
    job: dict[str, Any],
    oracle_id: str,
    artifact_dir: Path,
) -> list[str]:
    left, right, exchange = adapter_and_exchange(job)
    return [
        str(replay_bin),
        "--generated-config",
        str(artifact_dir / "generated_config.json"),
        "--input",
        str(artifact_dir / "structured_input.bin"),
        "--trace",
        str(artifact_dir / "oracle_trace.json"),
        "--job-id",
        str(job["job_id"]),
        "--pair-id",
        str(job.get("pair_id", job["job_id"])),
        "--algorithm",
        str(job["algorithm"]),
        "--primitive-type",
        str(job["primitive_type"]),
        "--oracle-id",
        oracle_id,
        "--oracle-suite",
        str(job.get("oracle_suite", "fips")),
        "--relation-mode",
        str(job.get("relation_mode", "cross-implementation")),
        "--left-project-id",
        str(left.get("project_id", "")),
        "--left-implementation-id",
        str(left.get("implementation_id", "")),
        "--right-project-id",
        str(right.get("project_id", "")),
        "--right-implementation-id",
        str(right.get("implementation_id", "")),
        "--public-key-exchange",
        bool_arg(exchange["public_key_exchange"]),
        "--ciphertext-exchange",
        bool_arg(exchange["ciphertext_exchange"]),
        "--secret-key-exchange",
        bool_arg(exchange["secret_key_exchange"]),
        "--secret-key-format-compatible",
        bool_arg(exchange["secret_key_format_compatible"]),
        "--signature-exchange",
        bool_arg(exchange["signature_exchange"]),
    ]


def sanitizer_class(stderr: str) -> str | None:
    if "UndefinedBehaviorSanitizer" in stderr:
        return "ub"
    for marker in ("AddressSanitizer", "MemorySanitizer", "LeakSanitizer"):
        if marker in stderr:
            return "memory_safety"
    return None


def synthesize_trace(
    job: dict[str, Any],
    oracle_id: str,
    finding_class: str,
    summary: str,
    *,
    returncode: int | None = None,
    timeout_seconds: int | None = None,
    stderr: str = "",
) -> dict[str, Any]:
    sanitizer = sanitizer_class(stderr)
    if sanitizer is not None:
        finding_class = sanitizer
    finding: dict[str, Any] = {"class": finding_class, "summary": summary}
    trace: dict[str, Any] = {
        "version": 1,
        "oracle_suite": job.get("oracle_suite", "fips"),
        "relation_mode": job.get("relation_mode", "cross-implementation"),
        "job_id": job["job_id"],
        "pair_id": job.get("pair_id", job["job_id"]),
        "algorithm": job["algorithm"],
        "oracle_id": oracle_id,
        "subtests": [],
        "mutations": [],
        "findings": [finding],
    }
    if returncode is not None and returncode < 0:
        trace["crash_signal"] = -returncode
    if timeout_seconds is not None:
        trace["timeout_seconds"] = timeout_seconds
    return trace


def synthesize_no_finding_trace(job: dict[str, Any], oracle_id: str) -> dict[str, Any]:
    return {
        "version": 1,
        "oracle_suite": job.get("oracle_suite", "fips"),
        "relation_mode": job.get("relation_mode", "cross-implementation"),
        "job_id": job["job_id"],
        "pair_id": job.get("pair_id", job["job_id"]),
        "algorithm": job["algorithm"],
        "oracle_id": oracle_id,
        "subtests": [],
        "mutations": [],
        "findings": [],
    }


def load_trace(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ReplayError(f"native replay wrote invalid JSON trace: {exc}") from exc


def finding_summary(trace: dict[str, Any], finding_class: str) -> str:
    for finding in trace.get("findings", []):
        if finding.get("summary"):
            return str(finding["summary"])
    return f"{finding_class} detected by {trace.get('oracle_id', 'unknown_oracle')}"


def finding_subclass(trace: dict[str, Any]) -> str:
    if trace.get("finding_subclass"):
        return str(trace["finding_subclass"])
    for finding in trace.get("findings", []):
        if finding.get("subclass"):
            return str(finding["subclass"])
    return ""


def maybe_write_finding(
    artifact_dir: Path,
    job: dict[str, Any],
    trace: dict[str, Any],
    command: list[str],
) -> None:
    finding_class = classify_trace(trace)
    if finding_class is None:
        return
    finding_id = f"{finding_class}_{hashlib.sha256(json.dumps(trace, sort_keys=True).encode('utf-8')).hexdigest()[:16]}"
    finding = {
        "version": 1,
        "finding_id": finding_id,
        "job_id": job["job_id"],
        "pair_id": job.get("pair_id", job["job_id"]),
        "algorithm": job["algorithm"],
        "oracle_suite": trace.get("oracle_suite", job.get("oracle_suite", "fips")),
        "relation_mode": trace.get("relation_mode", job.get("relation_mode", "cross-implementation")),
        "oracle_id": trace["oracle_id"],
        "finding_class": finding_class,
        "finding_subclass": finding_subclass(trace),
        "summary": finding_summary(trace, finding_class),
        "trace_path": str(artifact_dir / "oracle_trace.json"),
        "artifact_dir": str(artifact_dir),
        "replay_command": " ".join(command),
    }
    write_json(artifact_dir / "finding.json", finding)
    generate_poc(artifact_dir, finding, job)


def replay(job_path: Path, input_path: Path, replay_bin: Path | None, timeout_seconds: int) -> Path:
    job = json.loads(job_path.read_text(encoding="utf-8"))
    input_bytes, envelope = parse_envelope(input_path)
    if envelope["algorithm"] != job["algorithm"]:
        raise ReplayError(f"input algorithm {envelope['algorithm']} does not match job algorithm {job['algorithm']}")

    if replay_bin is None:
        replay_bin = REPO_ROOT / "workspace" / "build" / job["job_id"] / "replay_oracle"
    if not replay_bin.exists():
        raise ReplayError(f"native replay binary is missing: {replay_bin}")

    oracle_id = selected_oracle_id(job, envelope)
    artifact_dir = make_artifact_dir(job, input_bytes)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    structured_input = encode_binary_envelope(envelope, oracle_id)
    (artifact_dir / "structured_input.bin").write_bytes(structured_input)
    write_json(artifact_dir / "structured_input.json", envelope_to_json(envelope))
    shutil.copyfile(REPO_ROOT / job["paths"]["generated_config"], artifact_dir / "generated_config.json")
    (artifact_dir / "minimized_seed.bin").write_bytes(input_bytes)
    trace_path = artifact_dir / "oracle_trace.json"
    if trace_path.exists():
        trace_path.unlink()

    command = replay_command(replay_bin, job, oracle_id, artifact_dir)
    stdout = ""
    stderr = ""
    returncode: int | None = None
    trace: dict[str, Any] | None = None
    try:
        env = dict(os.environ)
        env["ASAN_OPTIONS"] = (env.get("ASAN_OPTIONS", "") + ":detect_leaks=0").lstrip(":")
        completed = subprocess.run(
            command,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            env=env,
        )
        stdout = completed.stdout
        stderr = completed.stderr
        returncode = completed.returncode
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", errors="replace")
        stderr = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode("utf-8", errors="replace")
        returncode = EXIT_HANG
        trace = synthesize_trace(
            job,
            oracle_id,
            "hang",
            f"native replay timed out after {timeout_seconds}s",
            timeout_seconds=timeout_seconds,
            stderr=stderr,
        )

    (artifact_dir / "stdout.txt").write_text(stdout, encoding="utf-8")
    (artifact_dir / "stderr.txt").write_text(stderr, encoding="utf-8")
    (artifact_dir / "exit_code.txt").write_text(f"{returncode if returncode is not None else ''}\n", encoding="utf-8")

    if trace is None:
        trace = load_trace(artifact_dir / "oracle_trace.json")
    if trace is None:
        if returncode is not None and returncode < 0:
            trace = synthesize_trace(
                job,
                oracle_id,
                "crash",
                f"native replay terminated by signal {-returncode}",
                returncode=returncode,
                stderr=stderr,
            )
        elif returncode == EXIT_NATIVE_CRASH:
            trace = synthesize_trace(job, oracle_id, "crash", "native replay reported a crash", returncode=returncode, stderr=stderr)
        elif returncode == EXIT_HANG:
            trace = synthesize_trace(
                job,
                oracle_id,
                "hang",
                f"native replay timed out after {timeout_seconds}s",
                timeout_seconds=timeout_seconds,
                stderr=stderr,
            )
        elif returncode == 0:
            trace = synthesize_no_finding_trace(job, oracle_id)
        else:
            trace = synthesize_trace(
                job,
                oracle_id,
                "crash",
                f"native replay exited with status {returncode} before writing a trace",
                returncode=returncode,
                stderr=stderr,
            )
    write_json(artifact_dir / "oracle_trace.json", trace)
    maybe_write_finding(artifact_dir, job, trace, command)
    return artifact_dir


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--job", required=True, help="job JSON generated by src/jobs/generate_jobs.py")
    parser.add_argument("--input", required=True, help="PQCFuzz envelope input")
    parser.add_argument("--timeout-seconds", type=int, default=30, help="native replay timeout. Default: 30")
    parser.add_argument("--replay-bin", help="optional native replay_oracle binary")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.timeout_seconds <= 0:
        raise ReplayError("--timeout-seconds must be positive")
    artifact_dir = replay(
        Path(args.job),
        Path(args.input),
        Path(args.replay_bin) if args.replay_bin else None,
        args.timeout_seconds,
    )
    try:
        display_path = artifact_dir.relative_to(REPO_ROOT)
    except ValueError:
        display_path = artifact_dir
    print(f"replayed input and wrote artifacts to {display_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReplayError as exc:
        print(f"replay_one error: {exc}", file=sys.stderr)
        raise SystemExit(1)
