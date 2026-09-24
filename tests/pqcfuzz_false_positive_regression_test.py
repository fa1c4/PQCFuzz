from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]

from _test_sources import compile_and_run


def test_writer_rejects_stale_finding_in_not_evaluable_trace(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include "triage/finding_writer.h"
        #include <filesystem>
        #include <string>

        int main(int argc, char **argv) {
          pqcfuzz::FindingArtifactInput input;
          input.job_id = "stale";
          input.pair_id = "stale";
          input.algorithm = "ML-KEM-768";
          input.primitive = "kem";
          input.oracle_id = "kem_decaps_c";
          input.result_dir = std::string(argv[1]);
          input.generated_config_json = "{}\\n";
          input.structured_input = {1, 2, 3};
          input.trace.oracle_suite = "metamorphic";
          input.trace.relation_mode = "single-target";
          input.trace.algorithm = input.algorithm;
          input.trace.oracle_id = input.oracle_id;
          input.trace.baseline_setup_valid = false;
          input.trace.relation_evaluable = false;
          input.trace.intervention_effective = false;
          input.trace.findings.push_back({"malleability", "stale", "stale"});
          std::string artifact_dir;
          std::string error;
          if (pqcfuzz::WriteFindingArtifacts(input, &artifact_dir, &error)) return 1;
          if (error != "non_persistable_disposition") return 2;
          return std::filesystem::exists(std::filesystem::path(argv[1]) / "malleability_stale") ? 3 : 0;
        }
        """,
        args=[str(tmp_path / "run")],
    )


def test_always_reject_verifier_is_not_evaluable_not_malleability(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include "oracles/metamorphic_executor.h"
        #include <string>
        #include <vector>
        extern "C" const pqcfuzz_sig_adapter *pqcfuzz_fake_sig_always_rejects_adapter();

        int main() {
          for (const std::string oracle_id : {"sig_verify_m", "sig_verify_sig", "sig_verify_pk"}) {
            pqcfuzz::MetamorphicSigConfig cfg;
            cfg.job_id = "test";
            cfg.pair_id = "test";
            cfg.algorithm = "ML-DSA-44";
            cfg.oracle_id = oracle_id;
            cfg.target = pqcfuzz_fake_sig_always_rejects_adapter();
            cfg.message = {'m'};
            cfg.mutation = {0, 0, 0, 1};
            auto trace = pqcfuzz::ExecuteMetamorphicSigOracle(cfg);
            if (!trace.findings.empty() || trace.relation_evaluable) return 1;
            if (trace.diagnostic_event.find("baseline_precondition_failed") == std::string::npos) return 2;
          }
          return 0;
        }
        """,
        [
            "src/adapters/rng_control.cc",
            "src/adapters/liboqs/rng_control.cc",
            "src/mutators/maul.cc",
            "src/oracles/metamorphic_observation.cc",
            "src/oracles/metamorphic_spec.cc",
            "src/oracles/expected_relation.cc",
            "src/oracles/oracle_record.cc",
            "src/oracles/oracle_result.cc",
            "src/oracles/oracle_spec.cc",
            "src/oracles/metamorphic_executor.cc",
            "tests/fake_adapters/fake_sig_always_rejects.cc",
        ],
    )


def test_fips_noop_ciphertext_mutation_produces_no_finding(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include "oracles/oracle_executor.h"
        #include <cstring>

        namespace {
        pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
          std::memset(pk, 0x21, 1184);
          std::memset(sk, 0x31, 2400);
          return PQCFUZZ_OK;
        }
        pqcfuzz_status Encaps(uint8_t *ct, uint8_t *ss, const uint8_t *) {
          std::memset(ct, 0x30, 1088);
          std::memset(ss, 0x42, 32);
          return PQCFUZZ_OK;
        }
        pqcfuzz_status Decaps(uint8_t *ss, const uint8_t *, const uint8_t *) {
          std::memset(ss, 0x42, 32);
          return PQCFUZZ_OK;
        }
        const pqcfuzz_kem_adapter kAdapter = {
            "fake", "fips_noop", "ML-KEM-768", 1184, 2400, 1088, 32, Keygen, Encaps, Decaps};
        }

        int main() {
          pqcfuzz::OracleExecutorConfig cfg;
          cfg.algorithm = "ML-KEM-768";
          cfg.oracle_id = "mlkem_tampered_ciphertext_implicit_rejection";
          pqcfuzz::GetMlKemParams(cfg.algorithm, &cfg.params);
          cfg.left = &kAdapter;
          cfg.seed = {1, 2, 3};
          cfg.mutation = {1, 0, 0, 0, 0}; // xor_byte with zero delta
          auto trace = pqcfuzz::ExecuteKemOracle(cfg);
          return trace.findings.empty() && !trace.subtests.empty() && trace.subtests[0].not_applicable &&
                         !trace.subtests[0].skipped && trace.subtests[0].note == "no_effect" ? 0 : 1;
        }
        """,
    )


def test_fips_length_changing_ciphertext_mutation_is_not_applicable(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include "oracles/oracle_executor.h"
        #include <cstring>
        #include <string>
        #include <vector>

        namespace {
        // The target would always produce a distinct implicit-rejection secret,
        // so any comparison against a valid decapsulation would look like a
        // public-status violation.  A length-changing mutation must never
        // reach the target: the executor length check rejects it first.
        pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
          std::memset(pk, 0x21, 1184);
          std::memset(sk, 0x31, 2400);
          return PQCFUZZ_OK;
        }
        pqcfuzz_status Encaps(uint8_t *ct, uint8_t *ss, const uint8_t *) {
          std::memset(ct, 0x30, 1088);
          std::memset(ss, 0x42, 32);
          return PQCFUZZ_OK;
        }
        pqcfuzz_status Decaps(uint8_t *ss, const uint8_t *, const uint8_t *) {
          std::memset(ss, 0x43, 32);
          return PQCFUZZ_OK;
        }
        const pqcfuzz_kem_adapter kAdapter = {
            "fake", "length_mutation", "ML-KEM-768", 1184, 2400, 1088, 32, Keygen, Encaps, Decaps};
        }

        int main() {
          const std::vector<std::vector<uint8_t>> plans = {
              {5, 0, 0, 0, 0xAB}, // append_trailing_garbage
              {4, 0, 0, 1, 0},    // truncate to 1 byte
          };
          for (const char *oracle : {"mlkem_tampered_ciphertext_implicit_rejection",
                                     "mlkem_implicit_rejection_relations"}) {
            for (const auto &plan : plans) {
              pqcfuzz::OracleExecutorConfig cfg;
              cfg.algorithm = "ML-KEM-768";
              cfg.oracle_id = oracle;
              pqcfuzz::GetMlKemParams(cfg.algorithm, &cfg.params);
              cfg.left = &kAdapter;
              cfg.seed = {1, 2, 3};
              cfg.mutation = plan;
              auto trace = pqcfuzz::ExecuteKemOracle(cfg);
              if (!trace.findings.empty()) return 1;
              if (trace.subtests.empty()) return 2;
              for (const auto &subtest : trace.subtests) {
                if (!subtest.not_applicable) return 3;
                if (subtest.note.find("length mutation is not adjudicable") == std::string::npos) return 4;
              }
              if (trace.relation_evaluable) return 5;
              if (pqcfuzz::FinalizeDisposition(trace) != pqcfuzz::OracleDisposition::kNotApplicable) return 6;
            }
          }
          return 0;
        }
        """,
    )
