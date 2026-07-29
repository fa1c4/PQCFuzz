from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def compile_and_run(tmp_path: Path, source: str, extra_sources: list[str] | None = None) -> None:
    main = tmp_path / "main.cc"
    binary = tmp_path / "case"
    main.write_text(textwrap.dedent(source), encoding="utf-8")
    cxx = os.environ.get("CXX", "clang++")
    cmd = [
        cxx,
        "-std=c++17",
        "-O0",
        "-g",
        "-Isrc",
        str(main),
        "src/adapters/rng_control.cc",
        "src/adapters/liboqs/rng_control.cc",
        *(extra_sources or []),
        "-o",
        str(binary),
    ]
    subprocess.run(cmd, cwd=REPO_ROOT, check=True)
    subprocess.run([str(binary)], cwd=REPO_ROOT, check=True)


def test_rng_tape_zero_and_repeat(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include "adapters/rng_control.h"
        #include <cstdint>
        int main() {
          uint8_t zeros[2] = {0, 0};
          uint8_t out[4] = {1, 1, 1, 1};
          {
            pqcfuzz::ScopedRngOverride rng({zeros, sizeof(zeros), true});
            if (!rng.active() || !pqcfuzz_rng_fill_bytes(out, sizeof(out))) return 1;
          }
          for (uint8_t byte : out) {
            if (byte != 0) return 2;
          }
          uint8_t pattern[2] = {7, 9};
          {
            pqcfuzz::ScopedRngOverride rng({pattern, sizeof(pattern), true});
            if (!pqcfuzz_rng_fill_bytes(out, sizeof(out))) return 3;
          }
          return out[0] == 7 && out[1] == 9 && out[2] == 7 && out[3] == 9 ? 0 : 4;
        }
        """,
    )


def test_rng_driven_fake_keygen_changes_with_tape(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include "adapters/rng_control.h"
        #include <cstdint>
        int main() {
          uint8_t a[4] = {1, 2, 3, 4};
          uint8_t b[4] = {9, 8, 7, 6};
          uint8_t out_a[4] = {};
          uint8_t out_b[4] = {};
          {
            pqcfuzz::ScopedRngOverride rng({a, sizeof(a), true});
            pqcfuzz_rng_fill_bytes(out_a, sizeof(out_a));
          }
          {
            pqcfuzz::ScopedRngOverride rng({b, sizeof(b), true});
            pqcfuzz_rng_fill_bytes(out_b, sizeof(out_b));
          }
          for (int i = 0; i < 4; ++i) {
            if (out_a[i] == out_b[i]) return 1;
          }
          return 0;
        }
        """,
    )


def test_ignored_rng_keygen_is_diagnostic_not_malleability(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include "adapters/adapter_interface.h"
        #include "oracles/metamorphic_executor.h"
        namespace {
        pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
          for (size_t i = 0; i < 4; ++i) { pk[i] = 1; sk[i] = 2; }
          return PQCFUZZ_OK;
        }
        pqcfuzz_status Encaps(uint8_t *, uint8_t *, const uint8_t *) { return PQCFUZZ_API_UNSUPPORTED; }
        pqcfuzz_status Decaps(uint8_t *, const uint8_t *, const uint8_t *) { return PQCFUZZ_API_UNSUPPORTED; }
        }
        int main() {
          static const pqcfuzz_kem_adapter adapter = {"fake", "ignored_rng", "ML-KEM-768", 4, 4, 4, 4, Keygen, Encaps, Decaps};
          pqcfuzz::MetamorphicKemConfig cfg;
          cfg.job_id = "test";
          cfg.pair_id = "test";
          cfg.algorithm = "ML-KEM-768";
          cfg.oracle_id = "kem_keygen_badrng";
          cfg.target = &adapter;
          cfg.seed = {1, 2, 3};
          auto trace = pqcfuzz::ExecuteMetamorphicKemOracle(cfg);
          return trace.findings.empty() && trace.observed_relation == "OBSERVED_INTERVENTION_NOT_OBSERVED" &&
                         !trace.subtests.empty() && trace.subtests[0].skipped &&
                         trace.subtests[0].note == "intervention_not_observed" ? 0 : 1;
        }
        """,
        [
            "src/mutators/maul.cc",
            "src/oracles/metamorphic_observation.cc",
            "src/oracles/metamorphic_spec.cc",
            "src/oracles/metamorphic_executor.cc",
        ],
    )


def test_liboqs_rng_hook_uses_system_rng_when_no_tape_is_active(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include "adapters/adapter_interface.h"
        #include "oracles/metamorphic_executor.h"
        #include <cstddef>
        #include <cstdint>
        #include <cstring>

        namespace {
        using RandombytesFn = void (*)(uint8_t *, size_t);
        RandombytesFn callback = nullptr;
        int system_rng_calls = 0;

        pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
          std::memset(pk, 0x40, 4);
          std::memset(sk, 0x50, 4);
          return PQCFUZZ_OK;
        }

        pqcfuzz_status Sign(
            uint8_t *sig,
            size_t *sig_len,
            const uint8_t *,
            size_t,
            const uint8_t *,
            const uint8_t *,
            size_t) {
          uint8_t random = 0;
          if (callback == nullptr) return PQCFUZZ_INVALID_INPUT;
          callback(&random, 1);
          for (size_t i = 0; i < 4; ++i) sig[i] = static_cast<uint8_t>(random + i);
          *sig_len = 4;
          return PQCFUZZ_OK;
        }

        pqcfuzz_status Verify(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, const uint8_t *, size_t) {
          return PQCFUZZ_API_UNSUPPORTED;
        }
        }

        extern "C" void OQS_randombytes_custom_algorithm(RandombytesFn value) {
          callback = value;
        }

        extern "C" void OQS_randombytes_system(uint8_t *out, size_t out_len) {
          ++system_rng_calls;
          for (size_t i = 0; i < out_len; ++i) {
            out[i] = static_cast<uint8_t>(0xd0 + system_rng_calls + i);
          }
        }

        int main() {
          static const pqcfuzz_sig_adapter adapter = {
              "fake", "rng_fallback_sig", "ML-DSA-44", 4, 4, 4,
              1, 0, 0, Keygen, Sign, Verify, nullptr};
          pqcfuzz::MetamorphicSigConfig cfg;
          cfg.job_id = "test";
          cfg.pair_id = "test";
          cfg.algorithm = "ML-DSA-44";
          cfg.oracle_id = "sig_sign_badrng";
          cfg.target = &adapter;
          cfg.seed = {1, 2, 3};
          cfg.message = {'m'};
          auto trace = pqcfuzz::ExecuteMetamorphicSigOracle(cfg);
          if (!trace.relation_evaluable || system_rng_calls != 0) return 1;

          uint8_t sig[4] = {};
          size_t sig_len = 0;
          if (adapter.sign(sig, &sig_len, reinterpret_cast<const uint8_t *>("m"), 1, sig, nullptr, 0) != PQCFUZZ_OK) {
            return 2;
          }
          return system_rng_calls == 1 && sig_len == 4 && sig[0] == 0xd1 ? 0 : 3;
        }
        """,
        [
            "src/mutators/maul.cc",
            "src/oracles/metamorphic_observation.cc",
            "src/oracles/metamorphic_spec.cc",
            "src/oracles/metamorphic_executor.cc",
        ],
    )
