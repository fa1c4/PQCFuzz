from __future__ import annotations

import json
import os
import struct
import subprocess
import textwrap
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HARNESS_DIR = ROOT / "baselines" / "libFuzzer"


FAKE_OQS_H = r"""
#ifndef FAKE_OQS_H
#define FAKE_OQS_H
#include <stddef.h>
#include <stdint.h>
typedef int OQS_STATUS;
#define OQS_SUCCESS 0
#define OQS_ERROR 1
OQS_STATUS OQS_init(void);
#endif
"""

FAKE_KEM_H = r"""
#ifndef FAKE_KEM_H
#define FAKE_KEM_H
#include <stdbool.h>
#include <oqs/oqs.h>
typedef struct OQS_KEM {
  bool ind_cca;
  size_t length_public_key;
  size_t length_secret_key;
  size_t length_ciphertext;
  size_t length_shared_secret;
} OQS_KEM;
int OQS_KEM_alg_count(void);
const char *OQS_KEM_alg_identifier(size_t);
int OQS_KEM_alg_is_enabled(const char *);
OQS_KEM *OQS_KEM_new(const char *);
void OQS_KEM_free(OQS_KEM *);
OQS_STATUS OQS_KEM_keypair(OQS_KEM *, uint8_t *, uint8_t *);
OQS_STATUS OQS_KEM_encaps(OQS_KEM *, uint8_t *, uint8_t *, const uint8_t *);
OQS_STATUS OQS_KEM_decaps(OQS_KEM *, uint8_t *, const uint8_t *, const uint8_t *);
#endif
"""

FAKE_SIG_H = r"""
#ifndef FAKE_SIG_H
#define FAKE_SIG_H
#include <oqs/oqs.h>
typedef struct OQS_SIG {
  size_t length_public_key;
  size_t length_secret_key;
  size_t length_signature;
} OQS_SIG;
int OQS_SIG_alg_count(void);
const char *OQS_SIG_alg_identifier(size_t);
int OQS_SIG_alg_is_enabled(const char *);
OQS_SIG *OQS_SIG_new(const char *);
void OQS_SIG_free(OQS_SIG *);
OQS_STATUS OQS_SIG_keypair(OQS_SIG *, uint8_t *, uint8_t *);
OQS_STATUS OQS_SIG_sign(OQS_SIG *, uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *);
OQS_STATUS OQS_SIG_verify(OQS_SIG *, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *);
#endif
"""

FAKE_RAND_H = r"""
#ifndef FAKE_RAND_H
#define FAKE_RAND_H
#include <oqs/oqs.h>
typedef void (*fake_randombytes_algorithm)(uint8_t *, size_t);
void OQS_randombytes_custom_algorithm(fake_randombytes_algorithm);
OQS_STATUS OQS_randombytes_switch_algorithm(const char *);
#endif
"""

FAKE_OQS_C = r"""
#include <oqs/kem.h>
#include <oqs/rand.h>
#include <oqs/sig.h>

#include <stdlib.h>
#include <string.h>

static fake_randombytes_algorithm randombytes_callback;
static int system_rng;

static const char *mode(void) {
  const char *value = getenv("FAKE_OQS_MODE");
  return value == NULL ? "normal" : value;
}

static int is_mode(const char *value) { return strcmp(mode(), value) == 0; }

static void randombytes(uint8_t *out, size_t size) {
  if (!system_rng && randombytes_callback != NULL) {
    randombytes_callback(out, size);
    return;
  }
  memset(out, 0x7a, size);
}

OQS_STATUS OQS_init(void) { return OQS_SUCCESS; }
void OQS_randombytes_custom_algorithm(fake_randombytes_algorithm callback) {
  randombytes_callback = callback;
  system_rng = 0;
}
OQS_STATUS OQS_randombytes_switch_algorithm(const char *ignored) {
  (void)ignored;
  system_rng = 1;
  return OQS_SUCCESS;
}

int OQS_KEM_alg_count(void) { return 1; }
const char *OQS_KEM_alg_identifier(size_t index) { return index == 0 ? "fake-kem" : NULL; }
int OQS_KEM_alg_is_enabled(const char *algorithm) { return algorithm != NULL && strcmp(algorithm, "fake-kem") == 0; }
OQS_KEM *OQS_KEM_new(const char *algorithm) {
  if (!OQS_KEM_alg_is_enabled(algorithm)) return NULL;
  OQS_KEM *kem = calloc(1, sizeof(*kem));
  if (kem != NULL) {
    kem->ind_cca = true;
    kem->length_public_key = 4;
    kem->length_secret_key = 4;
    kem->length_ciphertext = 4;
    kem->length_shared_secret = 4;
  }
  return kem;
}
void OQS_KEM_free(OQS_KEM *kem) { free(kem); }
OQS_STATUS OQS_KEM_keypair(OQS_KEM *kem, uint8_t *pk, uint8_t *sk) {
  (void)kem;
  if (is_mode("keypair_error")) return OQS_ERROR;
  randombytes(pk, 4);
  for (size_t i = 0; i < 4; ++i) sk[i] = (uint8_t)(0x20 + i);
  return OQS_SUCCESS;
}
OQS_STATUS OQS_KEM_encaps(OQS_KEM *kem, uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
  (void)kem;
  (void)pk;
  if (is_mode("encaps_error")) return OQS_ERROR;
  randombytes(ct, 4);
  ct[0] = 0x30;
  memset(ss, 0x42, 4);
  return OQS_SUCCESS;
}
OQS_STATUS OQS_KEM_decaps(OQS_KEM *kem, uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
  (void)kem;
  (void)sk;
  if (is_mode("decaps_error")) return OQS_ERROR;
  if (is_mode("kem_reject") && ct[0] != 0x30) return OQS_ERROR;
  if (is_mode("normal") && ct[0] != 0x30) memset(ss, 0x43, 4);
  else memset(ss, 0x42, 4);
  return OQS_SUCCESS;
}

int OQS_SIG_alg_count(void) { return 1; }
const char *OQS_SIG_alg_identifier(size_t index) { return index == 0 ? "fake-sig" : NULL; }
int OQS_SIG_alg_is_enabled(const char *algorithm) { return algorithm != NULL && strcmp(algorithm, "fake-sig") == 0; }
OQS_SIG *OQS_SIG_new(const char *algorithm) {
  if (!OQS_SIG_alg_is_enabled(algorithm)) return NULL;
  OQS_SIG *sig = calloc(1, sizeof(*sig));
  if (sig != NULL) {
    sig->length_public_key = 4;
    sig->length_secret_key = 4;
    sig->length_signature = 4;
  }
  return sig;
}
void OQS_SIG_free(OQS_SIG *sig) { free(sig); }
OQS_STATUS OQS_SIG_keypair(OQS_SIG *sig, uint8_t *pk, uint8_t *sk) {
  (void)sig;
  if (is_mode("sig_keypair_error")) return OQS_ERROR;
  randombytes(pk, 4);
  for (size_t i = 0; i < 4; ++i) {
    pk[i] = (uint8_t)(0x40 + i);
    sk[i] = (uint8_t)(0x50 + i);
  }
  return OQS_SUCCESS;
}
OQS_STATUS OQS_SIG_sign(OQS_SIG *sig, uint8_t *signature, size_t *signature_len,
                        const uint8_t *message, size_t message_len, const uint8_t *sk) {
  (void)sig;
  (void)message;
  (void)message_len;
  (void)sk;
  if (is_mode("sig_sign_error")) return OQS_ERROR;
  for (size_t i = 0; i < 4; ++i) signature[i] = (uint8_t)(0x60 + i);
  *signature_len = 4;
  return OQS_SUCCESS;
}
OQS_STATUS OQS_SIG_verify(OQS_SIG *sig, const uint8_t *message, size_t message_len,
                          const uint8_t *signature, size_t signature_len, const uint8_t *pk) {
  (void)sig;
  if (is_mode("sig_accept")) return OQS_SUCCESS;
  if (signature_len != 4 || message_len != 1 || message[0] != 'M' || pk[0] != 0x40 || signature[0] != 0x60) {
    return OQS_ERROR;
  }
  return OQS_SUCCESS;
}
"""

DRIVER_C = r"""
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv) {
  for (int i = 1; i < argc; ++i) {
    FILE *file = fopen(argv[i], "rb");
    if (file == NULL) return 2;
    if (fseek(file, 0, SEEK_END) != 0) return 3;
    long size = ftell(file);
    if (size < 0 || fseek(file, 0, SEEK_SET) != 0) return 4;
    uint8_t *input = malloc((size_t)size + 1);
    if (input == NULL) return 5;
    if (fread(input, 1, (size_t)size, file) != (size_t)size) return 6;
    fclose(file);
    const int result = LLVMFuzzerTestOneInput(input, (size_t)size);
    free(input);
    if (result != 0) return result;
  }
  return 0;
}
"""


def write_fake_oqs(tmp_path: Path) -> Path:
    include = tmp_path / "include" / "oqs"
    include.mkdir(parents=True)
    (include / "oqs.h").write_text(textwrap.dedent(FAKE_OQS_H), encoding="utf-8")
    (include / "kem.h").write_text(textwrap.dedent(FAKE_KEM_H), encoding="utf-8")
    (include / "sig.h").write_text(textwrap.dedent(FAKE_SIG_H), encoding="utf-8")
    (include / "rand.h").write_text(textwrap.dedent(FAKE_RAND_H), encoding="utf-8")
    fake = tmp_path / "fake_oqs.c"
    fake.write_text(textwrap.dedent(FAKE_OQS_C), encoding="utf-8")
    driver = tmp_path / "driver.c"
    driver.write_text(textwrap.dedent(DRIVER_C), encoding="utf-8")
    return tmp_path


def compile_harness(tmp_path: Path, target: str) -> Path:
    write_fake_oqs(tmp_path)
    binary = tmp_path / f"fuzz_{target}_case"
    subprocess.run(
        [
            os.environ.get("CC", "clang"),
            "-std=c11",
            "-O0",
            "-g",
            "-I",
            str(tmp_path / "include"),
            "-I",
            str(HARNESS_DIR),
            str(HARNESS_DIR / f"fuzz_{target}.c"),
            str(tmp_path / "fake_oqs.c"),
            str(tmp_path / "driver.c"),
            "-o",
            str(binary),
        ],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    )
    return binary


def envelope(
    primitive: int,
    property_id: int,
    *,
    mutation_mask: int = 1,
    mutation_offset: int = 0,
    mutation_mode: int = 0,
    message: bytes = b"",
) -> bytes:
    tape = b"rng-tape"
    header = struct.pack(
        "<BBBBIQHHIBBH",
        1,
        primitive,
        property_id,
        mutation_mode,
        0,
        0x123456789ABCDEF0,
        len(tape),
        len(message),
        mutation_offset,
        mutation_mask,
        1,
        0,
    )
    assert len(header) == 28
    return header + tape + message


def run_case(binary: Path, tmp_path: Path, mode: str, *inputs: bytes) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
    input_paths = []
    for index, value in enumerate(inputs):
        path = tmp_path / f"input-{index}.bin"
        path.write_bytes(value)
        input_paths.append(path)
    findings = tmp_path / "findings"
    diagnostics = tmp_path / "diagnostics"
    metadata = tmp_path / "metadata.json"
    env = os.environ.copy()
    env.update(
        {
            "FAKE_OQS_MODE": mode,
            "PQCDF_LIBFUZZER_PROFILE": "semantic",
            "PQCDF_LIBFUZZER_FINDINGS_DIR": str(findings),
            "PQCDF_LIBFUZZER_DIAGNOSTICS_DIR": str(diagnostics),
            "PQCDF_LIBFUZZER_METADATA_FILE": str(metadata),
            "PQCDF_LIBFUZZER_MAX_EXEMPLARS_PER_GROUP": "3",
        }
    )
    result = subprocess.run(
        [str(binary), *(str(path) for path in input_paths)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        env=env,
    )
    return result, findings, diagnostics


def finding_records(directory: Path) -> list[dict]:
    return [json.loads(path.read_text(encoding="utf-8")) for path in sorted(directory.glob("*.json"))]


def test_mutated_ciphertext_same_secret_is_a_nonfatal_finding(tmp_path: Path) -> None:
    binary = compile_harness(tmp_path, "kem")
    result, findings, _ = run_case(binary, tmp_path, "kem_equal", envelope(1, 2))

    assert result.returncode == 0, result.stderr
    [finding] = finding_records(findings)
    assert finding["property_id"] == "kem_decaps_c"
    assert finding["finding_subclass"] == "ciphertext_malleability"
    assert finding["baseline_status"] == "ok"
    assert finding["mutated_status"] == "ok"
    assert (findings / finding["input_file"]).is_file()


def test_rejected_mutated_ciphertext_is_not_a_finding(tmp_path: Path) -> None:
    binary = compile_harness(tmp_path, "kem")
    result, findings, _ = run_case(binary, tmp_path, "kem_reject", envelope(1, 2))

    assert result.returncode == 0, result.stderr
    assert finding_records(findings) == []


def test_mutated_signature_acceptance_is_recorded(tmp_path: Path) -> None:
    binary = compile_harness(tmp_path, "sig")
    result, findings, _ = run_case(binary, tmp_path, "sig_accept", envelope(2, 2, message=b"M"))

    assert result.returncode == 0, result.stderr
    [finding] = finding_records(findings)
    assert finding["property_id"] == "sig_verify_sig"
    assert finding["finding_subclass"] == "signature_malleability"


def test_ineffective_mutation_is_skipped(tmp_path: Path) -> None:
    binary = compile_harness(tmp_path, "kem")
    result, findings, _ = run_case(binary, tmp_path, "kem_equal", envelope(1, 2, mutation_mask=0))

    assert result.returncode == 0, result.stderr
    assert finding_records(findings) == []


def test_oqs_error_is_a_diagnostic_not_a_sanitizer_crash(tmp_path: Path) -> None:
    binary = compile_harness(tmp_path, "kem")
    result, findings, diagnostics = run_case(binary, tmp_path, "keypair_error", envelope(1, 2))

    assert result.returncode == 0, result.stderr
    assert finding_records(findings) == []
    [diagnostic] = finding_records(diagnostics)
    assert diagnostic["classification"] == "harness_rng_diagnostic"
    assert diagnostic["operation"] == "keypair"
    assert diagnostic["deterministic_status"] == "operation_error"


def test_two_semantic_findings_do_not_stop_the_campaign(tmp_path: Path) -> None:
    binary = compile_harness(tmp_path, "kem")
    result, findings, _ = run_case(
        binary,
        tmp_path,
        "kem_equal",
        envelope(1, 2),
        envelope(1, 3),
    )

    assert result.returncode == 0, result.stderr
    assert {record["property_id"] for record in finding_records(findings)} == {
        "kem_decaps_c",
        "kem_decaps_sk",
    }


def test_duplicate_observation_is_deduplicated_by_its_replayable_input(tmp_path: Path) -> None:
    binary = compile_harness(tmp_path, "kem")
    input_value = envelope(1, 2)
    result, findings, _ = run_case(binary, tmp_path, "kem_equal", input_value, input_value)

    assert result.returncode == 0, result.stderr
    assert len(finding_records(findings)) == 1


def test_noncanonical_mutation_plan_uses_the_review_subclass(tmp_path: Path) -> None:
    binary = compile_harness(tmp_path, "sig")
    result, findings, _ = run_case(
        binary,
        tmp_path,
        "sig_accept",
        envelope(2, 2, mutation_mode=2, message=b"M"),
    )

    assert result.returncode == 0, result.stderr
    [finding] = finding_records(findings)
    assert finding["finding_subclass"] == "accepted_noncanonical_mutation"
