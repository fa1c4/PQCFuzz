import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODULE_SOURCE = ROOT / "baselines" / "CLFuzz" / "modules" / "liboqs" / "module.cpp"


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content), encoding="utf-8")


def build_stub_module_binary(tmp_path: Path) -> Path:
    compiler = shutil.which("clang++")
    if compiler is None:
        pytest.skip("clang++ is required for the CLFuzz liboqs stub-module test")

    stub_root = tmp_path / "stub"
    include = stub_root / "include"
    write(
        include / "cryptofuzz" / "module.h",
        r'''
        #pragma once

        #include <cstdint>
        #include <optional>
        #include <string>
        #include <utility>
        #include <vector>

        namespace cryptofuzz {

        class Buffer {
         public:
          Buffer() = default;
          explicit Buffer(std::vector<uint8_t> value) : value_(std::move(value)) {}
          std::vector<uint8_t> Get() const { return value_; }

         private:
          std::vector<uint8_t> value_;
        };

        struct TestJSON {
          std::string value;
          std::string dump() const { return value; }
        };

        namespace operation {
        struct OQS_KEM_SelfTest {
          uint64_t selector = 0;
          Buffer entropy;
          Buffer mutation;
          TestJSON ToJSON() const {
            return {"{\"stub\":\"kem\",\"selector\":" + std::to_string(selector) + "}"};
          }
        };
        struct OQS_SIG_SelfTest {
          uint64_t selector = 0;
          Buffer entropy;
          Buffer message;
          Buffer mutation;
          TestJSON ToJSON() const {
            return {"{\"stub\":\"sig\",\"selector\":" + std::to_string(selector) + "}"};
          }
        };
        }  // namespace operation

        class Module {
         public:
          explicit Module(const char*) {}
          virtual ~Module() = default;
          virtual std::optional<bool> OpOQSKEMSelfTest(operation::OQS_KEM_SelfTest&) {
            return std::nullopt;
          }
          virtual std::optional<bool> OpOQSSIGSelfTest(operation::OQS_SIG_SelfTest&) {
            return std::nullopt;
          }
        };

        }  // namespace cryptofuzz
        ''',
    )
    write(
        include / "cryptofuzz" / "crypto.h",
        r'''
        #pragma once

        #include <cstddef>
        #include <cstdint>
        #include <vector>

        namespace cryptofuzz::crypto {
        inline std::vector<uint8_t> sha256(const uint8_t* data, std::size_t size) {
          std::vector<uint8_t> out(32, 0);
          for (std::size_t i = 0; i < size; ++i) out[i % out.size()] ^= data[i] + static_cast<uint8_t>(i);
          return out;
        }
        }  // namespace cryptofuzz::crypto
        ''',
    )
    write(
        include / "cryptofuzz" / "util.h",
        r'''
        #pragma once

        #include <cstdint>
        #include <string>
        #include <vector>

        namespace cryptofuzz::util {
        inline std::string BinToHex(const std::vector<uint8_t>& bytes) {
          static const char digits[] = "0123456789abcdef";
          std::string out;
          out.reserve(bytes.size() * 2);
          for (uint8_t byte : bytes) {
            out.push_back(digits[byte >> 4]);
            out.push_back(digits[byte & 15]);
          }
          return out;
        }
        }  // namespace cryptofuzz::util
        ''',
    )
    write(
        include / "oqs" / "oqs.h",
        r'''
        #pragma once

        #include <stdint.h>

        typedef int OQS_STATUS;
        #define OQS_SUCCESS 0
        #define OQS_ERROR 1

        #include <oqs/kem.h>
        #include <oqs/sig.h>
        ''',
    )
    write(
        include / "oqs" / "kem.h",
        r'''
        #pragma once

        #include <oqs/oqs.h>
        #include <stddef.h>
        #include <stdint.h>

        typedef struct OQS_KEM {
          size_t length_public_key;
          size_t length_secret_key;
          size_t length_ciphertext;
          size_t length_shared_secret;
          int ind_cca;
        } OQS_KEM;

        int OQS_KEM_alg_count(void);
        const char* OQS_KEM_alg_identifier(size_t);
        int OQS_KEM_alg_is_enabled(const char*);
        OQS_KEM* OQS_KEM_new(const char*);
        void OQS_KEM_free(OQS_KEM*);
        OQS_STATUS OQS_KEM_keypair(OQS_KEM*, uint8_t*, uint8_t*);
        OQS_STATUS OQS_KEM_encaps(OQS_KEM*, uint8_t*, uint8_t*, const uint8_t*);
        OQS_STATUS OQS_KEM_decaps(OQS_KEM*, uint8_t*, const uint8_t*, const uint8_t*);
        ''',
    )
    write(
        include / "oqs" / "sig.h",
        r'''
        #pragma once

        #include <oqs/oqs.h>
        #include <stddef.h>
        #include <stdint.h>

        typedef struct OQS_SIG {
          size_t length_public_key;
          size_t length_secret_key;
          size_t length_signature;
        } OQS_SIG;

        int OQS_SIG_alg_count(void);
        const char* OQS_SIG_alg_identifier(size_t);
        int OQS_SIG_alg_is_enabled(const char*);
        OQS_SIG* OQS_SIG_new(const char*);
        void OQS_SIG_free(OQS_SIG*);
        OQS_STATUS OQS_SIG_keypair(OQS_SIG*, uint8_t*, uint8_t*);
        OQS_STATUS OQS_SIG_sign(OQS_SIG*, uint8_t*, size_t*, const uint8_t*, size_t, const uint8_t*);
        OQS_STATUS OQS_SIG_verify(OQS_SIG*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);
        ''',
    )
    write(
        include / "oqs" / "rand.h",
        r'''
        #pragma once

        #include <oqs/oqs.h>
        #include <stddef.h>
        #include <stdint.h>

        typedef void (*fake_randombytes_algorithm)(uint8_t*, size_t);
        void OQS_randombytes_custom_algorithm(fake_randombytes_algorithm);
        OQS_STATUS OQS_randombytes_switch_algorithm(const char*);
        ''',
    )
    write(
        stub_root / "fake_oqs.cpp",
        r'''
        #include <oqs/kem.h>
        #include <oqs/rand.h>
        #include <oqs/sig.h>

        #include <cstdlib>
        #include <cstring>

        namespace {
        fake_randombytes_algorithm callback = nullptr;
        bool system_rng = false;
        const char* mode() { const char* value = std::getenv("FAKE_OQS_MODE"); return value ? value : "normal"; }
        bool is_mode(const char* value) { return std::strcmp(mode(), value) == 0; }
        void randombytes(uint8_t* out, size_t size) {
          if (!system_rng && callback) { callback(out, size); return; }
          std::memset(out, 0x7a, size);
        }
        }

        void OQS_randombytes_custom_algorithm(fake_randombytes_algorithm value) { callback = value; system_rng = false; }
        OQS_STATUS OQS_randombytes_switch_algorithm(const char*) { system_rng = true; return OQS_SUCCESS; }

        int OQS_KEM_alg_count() { return 1; }
        const char* OQS_KEM_alg_identifier(size_t index) { return index == 0 ? "fake-kem" : nullptr; }
        int OQS_KEM_alg_is_enabled(const char* algorithm) { return algorithm && std::strcmp(algorithm, "fake-kem") == 0; }
        OQS_KEM* OQS_KEM_new(const char* algorithm) {
          if (!OQS_KEM_alg_is_enabled(algorithm)) return nullptr;
          auto* kem = static_cast<OQS_KEM*>(std::calloc(1, sizeof(OQS_KEM)));
          kem->length_public_key = kem->length_secret_key = kem->length_ciphertext = kem->length_shared_secret = 4;
          kem->ind_cca = 1;
          return kem;
        }
        void OQS_KEM_free(OQS_KEM* kem) { std::free(kem); }
        OQS_STATUS OQS_KEM_keypair(OQS_KEM*, uint8_t* pk, uint8_t* sk) {
          if (is_mode("keypair_error")) return OQS_ERROR;
          randombytes(pk, 4); for (size_t i = 0; i < 4; ++i) { pk[i] = 0x10 + i; sk[i] = 0x20 + i; } return OQS_SUCCESS;
        }
            OQS_STATUS OQS_KEM_encaps(OQS_KEM*, uint8_t* ct, uint8_t* ss, const uint8_t*) {
              if (is_mode("encaps_error")) return OQS_ERROR;
              randombytes(ct, 4); std::memset(ct, 0x30, 4); std::memset(ss, 0x42, 4); return OQS_SUCCESS;
            }
            OQS_STATUS OQS_KEM_decaps(OQS_KEM*, uint8_t* ss, const uint8_t* ct, const uint8_t*) {
              if (is_mode("decaps_error")) return OQS_ERROR;
              for (size_t i = 0; i < 4; ++i) if (ct[i] != 0x30 && !is_mode("kem_find")) return OQS_ERROR;
              std::memset(ss, 0x42, 4); return OQS_SUCCESS;
        }

        int OQS_SIG_alg_count() { return 1; }
        const char* OQS_SIG_alg_identifier(size_t index) { return index == 0 ? "fake-sig" : nullptr; }
        int OQS_SIG_alg_is_enabled(const char* algorithm) { return algorithm && std::strcmp(algorithm, "fake-sig") == 0; }
        OQS_SIG* OQS_SIG_new(const char* algorithm) {
          if (!OQS_SIG_alg_is_enabled(algorithm)) return nullptr;
          auto* sig = static_cast<OQS_SIG*>(std::calloc(1, sizeof(OQS_SIG)));
          sig->length_public_key = sig->length_secret_key = sig->length_signature = 4; return sig;
        }
        void OQS_SIG_free(OQS_SIG* sig) { std::free(sig); }
        OQS_STATUS OQS_SIG_keypair(OQS_SIG*, uint8_t* pk, uint8_t* sk) {
          if (is_mode("sig_keypair_error")) return OQS_ERROR;
          for (size_t i = 0; i < 4; ++i) { pk[i] = 0x40 + i; sk[i] = 0x50 + i; } return OQS_SUCCESS;
        }
        OQS_STATUS OQS_SIG_sign(OQS_SIG*, uint8_t* signature, size_t* size, const uint8_t*, size_t, const uint8_t*) {
          if (is_mode("sig_sign_error")) return OQS_ERROR;
          for (size_t i = 0; i < 4; ++i) signature[i] = 0x60 + i; *size = 4; return OQS_SUCCESS;
        }
            OQS_STATUS OQS_SIG_verify(OQS_SIG*, const uint8_t*, size_t, const uint8_t* signature, size_t size, const uint8_t* pk) {
              if (is_mode("sig_ignore_pk")) return size == 4 && signature[0] == 0x60 && signature[1] == 0x61 && signature[2] == 0x62 && signature[3] == 0x63 ? OQS_SUCCESS : OQS_ERROR;
              if (is_mode("sig_accept_all")) return OQS_SUCCESS;
              return size == 4 && signature[0] == 0x60 && signature[1] == 0x61 && signature[2] == 0x62 && signature[3] == 0x63 && pk[0] == 0x40 && pk[1] == 0x41 && pk[2] == 0x42 && pk[3] == 0x43 ? OQS_SUCCESS : OQS_ERROR;
            }
        ''',
    )
    write(
        stub_root / "driver.cpp",
        r'''
        #include "baselines/CLFuzz/modules/liboqs/module.h"
        #include "baselines/CLFuzz/liboqs_replay_input.h"

        #include <cstdlib>
        #include <filesystem>
        #include <string>
        #include <vector>

        namespace {
        bool run_kem(cryptofuzz::module::liboqs& module, uint64_t selector) {
          cryptofuzz::operation::OQS_KEM_SelfTest op;
          op.selector = selector;
          op.entropy = cryptofuzz::Buffer({1, 2, 3});
          op.mutation = cryptofuzz::Buffer({1});
          return module.OpOQSKEMSelfTest(op).value_or(false);
        }

        bool run_sig(cryptofuzz::module::liboqs& module, uint64_t selector, uint8_t mutation) {
          cryptofuzz::operation::OQS_SIG_SelfTest op;
          op.selector = selector;
          op.entropy = cryptofuzz::Buffer({1, 2, 3});
          op.message = cryptofuzz::Buffer({'M'});
          op.mutation = cryptofuzz::Buffer({mutation});
          return module.OpOQSSIGSelfTest(op).value_or(false);
        }
        }

        int main(int argc, char** argv) {
          if (argc != 4) return 64;  // case, fake OQS mode, output root
          const std::string test_case(argv[1]);
          std::filesystem::path root(argv[3]);
          for (const char* name : {"findings", "diagnostics", "metadata", "outcomes"})
            std::filesystem::create_directories(root / name);
          setenv("FAKE_OQS_MODE", argv[2], 1);
          setenv("PQCDF_LIBOQS_FINDINGS_DIR", (root / "findings").c_str(), 1);
          setenv("PQCDF_LIBOQS_DIAGNOSTICS_DIR", (root / "diagnostics").c_str(), 1);
          setenv("PQCDF_LIBOQS_METADATA_DIR", (root / "metadata").c_str(), 1);
          setenv("PQCDF_LIBOQS_OUTCOMES_DIR", (root / "outcomes").c_str(), 1);
          setenv("PQCDF_LIBOQS_BASELINE", "CLFuzz", 1);
          const std::vector<uint8_t> raw = {'s', 't', 'u', 'b'};
          cryptofuzz::liboqs_replay::ScopedInput scoped(raw.data(), raw.size());
          cryptofuzz::module::liboqs module;
          // Low-valued selectors must still address non-round-trip properties.
          // The liboqs module divides the selector into an algorithm slot and a
          // property slot; this stub exposes one algorithm, so selector 1 is
          // the second KEM property and selector 3 is the fourth SIG property.
          if (test_case == "kem") return run_kem(module, 1) ? 0 : 1;
          if (test_case == "kem-replay-mismatch") {
            setenv("PQCDF_LIBOQS_REPLAY_MODE", "raw-input-v1", 1);
            setenv("PQCDF_LIBOQS_REPLAY_ALGORITHM", "fake-kem", 1);
            setenv("PQCDF_LIBOQS_REPLAY_PROPERTY", "kem_decaps_c", 1);
            setenv("PQCDF_LIBOQS_REPLAY_INPUT_SHA256", "0000000000000000000000000000000000000000000000000000000000000000", 1);
            setenv("PQCDF_LIBOQS_REPLAY_INPUT_RELATIVE_PATH", "replay-inputs/wrong.bin", 1);
            return run_kem(module, 1) ? 0 : 1;
          }
          if (test_case == "kem-twice") {
            return run_kem(module, 1) && run_kem(module, 7) ? 0 : 1;
          }
          if (test_case == "sig-verify-signature") return run_sig(module, 1, 1) ? 0 : 1;
          if (test_case == "sig-verify-public-key") return run_sig(module, 3, 1) ? 0 : 1;
          if (test_case == "sig-noop") return run_sig(module, 1, 0) ? 0 : 1;
          return 65;
        }
        ''',
    )
    binary = stub_root / "module-test"
    result = subprocess.run(
        [
            compiler,
            "-std=c++17",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(include),
            "-I",
            str(ROOT),
            "-I",
            str(ROOT / "baselines" / "CLFuzz"),
            str(stub_root / "fake_oqs.cpp"),
            str(stub_root / "driver.cpp"),
            str(MODULE_SOURCE),
            "-o",
            str(binary),
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert result.returncode == 0, result.stderr
    return binary


def run_case(binary: Path, root: Path, test_case: str, oqs_mode: str) -> Path:
    output = root / f"{test_case}-{oqs_mode}"
    result = subprocess.run(
        [str(binary), test_case, oqs_mode, str(output)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert result.returncode == 0, f"stdout={result.stdout}\nstderr={result.stderr}"
    return output


def records(root: Path, directory: str) -> list[dict]:
    return [json.loads(path.read_text(encoding="utf-8")) for path in sorted((root / directory).glob("*.json"))]


def test_clfuzz_liboqs_module_classifies_stubbed_outcomes_and_keeps_running(tmp_path: Path) -> None:
    binary = build_stub_module_binary(tmp_path)

    keypair_error = run_case(binary, tmp_path, "sig-verify-signature", "sig_keypair_error")
    diagnostics = records(keypair_error, "diagnostics")
    assert len(diagnostics) == 1
    assert diagnostics[0]["classification"] == "operation_diagnostic"
    assert diagnostics[0]["operation"] == "keypair"

    sign_error = run_case(binary, tmp_path, "sig-verify-signature", "sig_sign_error")
    diagnostics = records(sign_error, "diagnostics")
    assert len(diagnostics) == 1
    assert diagnostics[0]["classification"] == "operation_diagnostic"
    assert diagnostics[0]["operation"] == "sign"

    rejected_signature = run_case(binary, tmp_path, "sig-verify-signature", "normal")
    assert records(rejected_signature, "findings") == []
    passed = records(rejected_signature, "outcomes")
    assert len(passed) == 1
    assert passed[0]["classification"] == "property_passed"
    assert passed[0]["mutation_effective"] is True
    assert passed[0]["mutated_status"] == "operation_error"

    no_op = run_case(binary, tmp_path, "sig-noop", "normal")
    skipped = records(no_op, "outcomes")
    assert len(skipped) == 1
    assert skipped[0]["classification"] == "skipped"
    assert skipped[0]["mutation_effective"] is False
    assert skipped[0]["mutation_delta_hex"] == "00"
    assert skipped[0]["mutation_before_digest"] == skipped[0]["mutation_after_digest"]

    kem_finding = run_case(binary, tmp_path, "kem", "kem_find")
    findings = records(kem_finding, "findings")
    assert len(findings) == 1
    finding = findings[0]
    assert finding["finding_subclass"] == "ciphertext_malleability"
    assert finding["mutation_effective"] is True
    assert finding["replay"]["attempts_completed"] == 3
    assert finding["replay"]["reproduced_count"] == 3
    assert finding["replay"]["attempt_results"] == ["reproduced", "reproduced", "reproduced"]
    fixture = kem_finding / "findings" / finding["input"]["fixture_path"]
    assert fixture.read_bytes() == b"stub"

    mismatched_replay = run_case(binary, tmp_path, "kem-replay-mismatch", "kem_find")
    assert records(mismatched_replay, "findings") == []
    diagnostics = records(mismatched_replay, "diagnostics")
    assert len(diagnostics) == 1
    assert diagnostics[0]["diagnostic_class"] == "replay_fixture_capture_failed"
    assert diagnostics[0]["replay"]["result"] == "unreproduced"

    ignored_public_key = run_case(binary, tmp_path, "sig-verify-public-key", "sig_ignore_pk")
    findings = records(ignored_public_key, "findings")
    assert len(findings) == 1
    finding = findings[0]
    assert finding["finding_subclass"] == "ignored_public_key_bytes"
    assert finding["canonicalization_status"] == "unsupported"
    assert finding["public_key_byte_use"] == "not_observed_by_independent_probe"
    assert finding["public_key_probe_status"] == "ok"

    multiple = run_case(binary, tmp_path, "kem-twice", "kem_find")
    findings = records(multiple, "findings")
    assert len(findings) == 2
    assert all(record["replay"]["result"] == "reproduced" for record in findings)
