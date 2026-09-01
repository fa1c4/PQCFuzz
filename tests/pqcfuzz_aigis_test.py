from __future__ import annotations

import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from _test_sources import CORE_EXECUTOR_SOURCES, compile_and_run


def test_aigis_envelope_enum_roundtrip(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include <string>
        #include "mutators/envelope.h"

        int main() {
          const char *algorithms[] = {
              "AIGIS-ENC-1", "AIGIS-ENC-2", "AIGIS-ENC-3", "AIGIS-ENC-4",
              "AIGIS-SIG-1", "AIGIS-SIG-2", "AIGIS-SIG-3"};
          for (const char *name : algorithms) {
            const auto id = pqcfuzz::AlgorithmIdFromName(name);
            if (id == pqcfuzz::AlgorithmId::kUnknown) return 1;
            if (std::string(pqcfuzz::AlgorithmName(id)) != name) return 2;
          }
          const char *oracles[] = {
              "aigisenc_local_roundtrip", "aigisenc_cross_exchange_roundtrip",
              "aigisenc_tampered_ciphertext_implicit_rejection", "aigisenc_bad_randomness_sanity",
              "aigisenc_sk_noncanonical_coefficient", "aigissig_local_sign_verify",
              "aigissig_cross_verify", "aigissig_mutated_signature_negative",
              "aigissig_mutated_message_negative", "aigissig_mutated_context_negative",
              "aigissig_bad_randomness_sanity", "aigissig_exact_length",
              "aigissig_unused_sign_bits", "aigissig_ctx256_failure_state",
              "aigissig_determinism_profile"};
          for (const char *name : oracles) {
            const auto id = pqcfuzz::OracleIdFromName(name);
            if (id == pqcfuzz::OracleId::kUnknown) return 3;
            if (std::string(pqcfuzz::OracleName(id)) != name) return 4;
          }
          return 0;
        }
        """,
        ["src/mutators/envelope.cc"],
    )


def test_aigis_layout_regions(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include "mutators/aigis_enc_layout.h"
        #include "mutators/aigis_sig_layout.h"

        int main() {
          pqcfuzz::AigisEncParams enc{};
          if (!pqcfuzz::GetAigisEncParams("AIGIS-ENC-2", &enc)) return 1;
          if (enc.pk_len != 896 || enc.sk_len != 2208 || enc.ct_len != 992 || enc.ss_len != 32) return 2;
          const auto ct = pqcfuzz::AigisEncCiphertextRegions(enc);
          if (ct.size() != 2) return 3;
          if (ct[0].name != "ciphertext.u" || ct[0].length != 864) return 4;
          if (ct[1].name != "ciphertext.v" || ct[1].length != 128 || ct[1].offset != 864) return 5;
          const auto pk = pqcfuzz::AigisEncPublicKeyRegions(enc);
          if (pk[0].length != 864 || pk[1].name != "public_key.seed" || pk[1].length != 32) return 6;

          pqcfuzz::AigisSigParams sig{};
          if (!pqcfuzz::GetAigisSigParams("AIGIS-SIG-2", &sig)) return 7;
          if (sig.pk_len != 1312 || sig.sk_len != 3376 || sig.sig_max_len != 2445) return 8;
          const auto regions = pqcfuzz::AigisSigSignatureRegions(sig);
          if (regions.size() != 3) return 9;
          if (regions[0].name != "signature.z" || regions[0].length != 2304) return 10;
          if (regions[1].name != "signature.h" || regions[1].length != 101) return 11;
          if (regions[2].name != "signature.c" || regions[2].length != 40) return 12;
          if (regions[2].offset != 2405) return 13;
          return 0;
        }
        """,
        [
            "src/mutators/aigis_enc_layout.cc",
            "src/mutators/aigis_sig_layout.cc",
            "src/mutators/ml_kem_layout.cc",
        ],
    )


def test_pqmagic_adapter_registry_routing(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include <string>
        #include "runtime/adapter_registry.h"

        int main() {
          const pqcfuzz_kem_adapter *kem = pqcfuzz::GetKemAdapterByProjectAndId(
              "pqmagic", "pqmagic_aigis_enc_2_std_sm3");
          if (kem == nullptr) return 1;
          if (std::string(kem->project_id) != "pqmagic") return 2;
          if (std::string(kem->algorithm) != "AIGIS-ENC-2") return 3;
          if (kem->pk_len != 896 || kem->sk_len != 2208 || kem->ct_len != 992 || kem->ss_len != 32) return 4;
          pqcfuzz::AdapterRoutingExpectation expected{
              "pqmagic", "pqmagic_aigis_enc_2_std_sm3", "AIGIS-ENC-2", 896, 2208, 992, 32, 0};
          std::string error;
          if (!pqcfuzz::ValidateKemAdapterRouting(kem, expected, &error)) return 5;

          const pqcfuzz_kem_adapter *shake = pqcfuzz::GetKemAdapterByProjectAndId(
              "pqmagic", "pqmagic_aigis_enc_2_std_shake");
          if (shake == nullptr || shake == kem) return 6;
          if (std::string(shake->implementation_id) != "pqmagic_aigis_enc_2_std_shake") return 7;

          const pqcfuzz_sig_adapter *sig = pqcfuzz::GetSigAdapterByProjectAndId(
              "pqmagic", "pqmagic_aigis_sig3_std_sm3");
          if (sig == nullptr) return 8;
          if (sig->pk_len != 1568 || sig->sk_len != 3888 || sig->sig_max_len != 3046) return 9;
          if (sig->supports_context != 1 || sig->supports_deterministic_sign != 1 ||
              sig->supports_seeded_sign != 0) return 10;
          return 0;
        }
        """,
        CORE_EXECUTOR_SOURCES,
    )


def test_aigis_sk_noncanonical_mutation_and_unused_sign_bits(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include <cstdint>
        #include <vector>
        #include "mutators/aigis_enc_mutator.h"
        #include "mutators/aigis_sig_mutator.h"

        int main() {
          pqcfuzz::AigisEncParams enc{};
          pqcfuzz::GetAigisEncParams("AIGIS-ENC-2", &enc);
          std::vector<uint8_t> sk(enc.sk_len, 0x11);
          auto records = pqcfuzz::MutateAigisEncSkNoncanonicalCoefficient(enc, &sk);
          if (records.size() != 1 || !records[0].effective) return 1;
          if (sk[0] != 0x01 || (sk[1] & 0x1f) != 0x1e) return 2;  // encoded q = 7681

          pqcfuzz::AigisSigParams sig{};
          pqcfuzz::GetAigisSigParams("AIGIS-SIG-2", &sig);
          std::vector<uint8_t> signature(sig.sig_max_len, 0);
          std::vector<uint8_t> plan = {10, 2, 0, 0, 0};  // mutate_unused_sign_bits -> signature.c
          records = pqcfuzz::MutateAigisSigSignature(sig, plan, &signature);
          if (records.size() != 1 || !records[0].effective) return 3;
          const size_t last_sign_byte = sig.z_bytes + sig.hint_bytes + sig.c_bytes - 1;
          if (records[0].target != "signature.c" || records[0].offset != last_sign_byte) return 4;
          if ((signature[last_sign_byte] & 0xf0) == 0) return 5;  // a high unused sign bit must be set
          return 0;
        }
        """,
        [
            "src/mutators/aigis_enc_layout.cc",
            "src/mutators/aigis_enc_mutator.cc",
            "src/mutators/aigis_sig_layout.cc",
            "src/mutators/aigis_sig_mutator.cc",
            "src/mutators/ml_kem_layout.cc",
            "src/mutators/ml_kem_mutator.cc",
        ],
    )


def test_aigis_fips_exact_length_oracle_reports_appended_acceptance(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include <cstring>
        #include <vector>
        #include "oracles/oracle_executor.h"

        namespace {
        pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
          std::memset(pk, 0x41, 1312);
          std::memset(sk, 0x42, 3376);
          return PQCFUZZ_OK;
        }
        pqcfuzz_status Sign(uint8_t *sig, size_t *sig_len, const uint8_t *, size_t,
                            const uint8_t *, const uint8_t *, size_t) {
          std::memset(sig, 0x43, 2445);
          *sig_len = 2445;
          return PQCFUZZ_OK;
        }
        // Mirrors the PQMagic snapshot: verifies as long as siglen is not
        // shorter than the profile length (appended bytes are ignored).
        pqcfuzz_status Verify(const uint8_t *, size_t sig_len, const uint8_t *,
                              size_t, const uint8_t *, const uint8_t *, size_t) {
          return sig_len >= 2445 ? PQCFUZZ_OK : PQCFUZZ_REJECT;
        }
        const pqcfuzz_sig_adapter kAdapter = {
            "pqmagic", "pqmagic_aigis_sig2_std_sm3", "AIGIS-SIG-2",
            1312, 3376, 2445, 1, 0, 1, Keygen, Sign, Verify, nullptr};
        }

        int main() {
          pqcfuzz::SigOracleExecutorConfig cfg;
          cfg.algorithm = "AIGIS-SIG-2";
          cfg.oracle_id = "aigissig_exact_length";
          cfg.left = &kAdapter;
          cfg.message = {'m'};
          cfg.seed = {1, 2, 3};
          auto trace = pqcfuzz::ExecuteSigOracle(cfg);
          if (trace.findings.size() != 1) return 1;
          if (trace.findings[0].finding_class != "potential_crypto_vuln") return 2;
          if (trace.findings[0].finding_subclass != "appended_signature_bytes_accepted") return 3;
          if (trace.subtests.empty() || trace.subtests[0].passed) return 4;
          if (!trace.mutations.empty() && !trace.mutations[0].effective) return 5;
          return 0;
        }
        """,
        CORE_EXECUTOR_SOURCES,
    )


def test_aigis_fips_determinism_profile_conformant_when_identical(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include <cstring>
        #include "oracles/oracle_executor.h"

        namespace {
        pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
          std::memset(pk, 0x41, 1056);
          std::memset(sk, 0x42, 2448);
          return PQCFUZZ_OK;
        }
        pqcfuzz_status Sign(uint8_t *sig, size_t *sig_len, const uint8_t *, size_t,
                            const uint8_t *, const uint8_t *, size_t) {
          std::memset(sig, 0x43, 1852);
          *sig_len = 1852;
          return PQCFUZZ_OK;
        }
        pqcfuzz_status Verify(const uint8_t *, size_t, const uint8_t *, size_t,
                              const uint8_t *, const uint8_t *, size_t) {
          return PQCFUZZ_OK;
        }
        const pqcfuzz_sig_adapter kAdapter = {
            "pqmagic", "pqmagic_aigis_sig1_std_sm3", "AIGIS-SIG-1",
            1056, 2448, 1852, 1, 0, 1, Keygen, Sign, Verify, nullptr};
        }

        int main() {
          pqcfuzz::SigOracleExecutorConfig cfg;
          cfg.algorithm = "AIGIS-SIG-1";
          cfg.oracle_id = "aigissig_determinism_profile";
          cfg.left = &kAdapter;
          cfg.message = {'m'};
          cfg.seed = {1, 2, 3};
          auto trace = pqcfuzz::ExecuteSigOracle(cfg);
          if (!trace.findings.empty()) return 1;
          if (trace.subtests.empty() || !trace.subtests[0].passed) return 2;
          if (trace.mutations.size() != 0) return 3;
          return 0;
        }
        """,
        CORE_EXECUTOR_SOURCES,
    )


def test_aigis_fips_ineffective_sig_mutation_is_skipped(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include <cstring>
        #include "oracles/oracle_executor.h"

        namespace {
        pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
          std::memset(pk, 0x41, 1056);
          std::memset(sk, 0x42, 2448);
          return PQCFUZZ_OK;
        }
        pqcfuzz_status Sign(uint8_t *sig, size_t *sig_len, const uint8_t *, size_t,
                            const uint8_t *, const uint8_t *, size_t) {
          std::memset(sig, 0x00, 1852);  // all-zero signature: set_zero is a no-op
          *sig_len = 1852;
          return PQCFUZZ_OK;
        }
        pqcfuzz_status Verify(const uint8_t *, size_t, const uint8_t *, size_t,
                              const uint8_t *, const uint8_t *, size_t) {
          return PQCFUZZ_OK;
        }
        const pqcfuzz_sig_adapter kAdapter = {
            "pqmagic", "pqmagic_aigis_sig1_std_sm3", "AIGIS-SIG-1",
            1056, 2448, 1852, 1, 0, 1, Keygen, Sign, Verify, nullptr};
        }

        int main() {
          pqcfuzz::SigOracleExecutorConfig cfg;
          cfg.algorithm = "AIGIS-SIG-1";
          cfg.oracle_id = "aigissig_mutated_signature_negative";
          cfg.left = &kAdapter;
          cfg.message = {'m'};
          cfg.seed = {1, 2, 3};
          cfg.mutation = {2, 0, 0, 0};  // set_zero on an already-zero byte
          auto trace = pqcfuzz::ExecuteSigOracle(cfg);
          if (!trace.findings.empty()) return 1;  // no_effect must not become a finding
          if (trace.subtests.empty() || !trace.subtests[0].skipped) return 2;
          if (trace.subtests[0].note != "no_effect") return 3;
          return 0;
        }
        """,
        CORE_EXECUTOR_SOURCES,
    )


def test_aigis_pair_alg_loader() -> None:
    from pairing.pair_alg_loader import enabled_pairs_for_family, load_pair_alg

    document = load_pair_alg(SRC_ROOT / "config" / "pair_alg.aigis.json")
    enc = enabled_pairs_for_family(document, "AIGIS-ENC")
    sig = enabled_pairs_for_family(document, "AIGIS-SIG")
    assert len(enc) == 4 and len(sig) == 3
    assert enc[0]["left"]["project_id"] == "pqmagic"
    assert enc[0]["right"]["implementation_id"] == "pqmagic_aigis_enc_1_std_shake"
    assert sig[0]["algorithm"] == "AIGIS-SIG-1"
    assert sig[0]["left"]["capabilities"]["supports_deterministic_sign"] is True


def test_aigis_job_generation_pickers() -> None:
    from jobs.generated_config_writer import ORACLE_ENUM_BY_NAME, enabled_subtests_for_pair, oracle_ids_for_pair

    kem_pair = {"algorithm_family": "AIGIS-ENC", "primitive_type": "kem",
                "exchange_contract": {"public_key_exchange": False, "ciphertext_exchange": False,
                                      "secret_key_exchange": False, "secret_key_format_compatible": False}}
    sig_pair = {"algorithm_family": "AIGIS-SIG", "primitive_type": "sig",
                "exchange_contract": {"public_key_exchange": False, "signature_exchange": False}}
    kem_oracles = oracle_ids_for_pair(kem_pair)
    sig_oracles = oracle_ids_for_pair(sig_pair)
    assert "aigisenc_cross_exchange_roundtrip" not in kem_oracles
    assert "aigisenc_sk_noncanonical_coefficient" in kem_oracles
    assert "aigissig_cross_verify" not in sig_oracles
    assert "aigissig_exact_length" in sig_oracles
    assert "aigissig_determinism_profile" in sig_oracles
    assert ORACLE_ENUM_BY_NAME["aigisenc_local_roundtrip"] == 31
    assert ORACLE_ENUM_BY_NAME["aigissig_determinism_profile"] == 45
    kem_subtests = enabled_subtests_for_pair(kem_pair)
    assert any(sub["oracle_id"] == "aigisenc_tampered_ciphertext_implicit_rejection" for sub in kem_subtests)
    sig_subtests = enabled_subtests_for_pair(sig_pair)
    assert any(sub["oracle_id"] == "aigissig_mutated_signature_negative" for sub in sig_subtests)


def test_mutation_offsets_cover_beyond_255_bytes(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include <vector>
        #include "mutators/aigis_enc_layout.h"
        #include "mutators/aigis_enc_mutator.h"
        #include "mutators/maul.h"

        int main() {
          // Generic maul: 16-bit little-endian offset 0x03E8 == 1000.
          std::vector<uint8_t> sk(2208, 0x42);
          auto maul = pqcfuzz::MaulBytesFixedSize(sk, {0, 0xE8, 0x03, 0}, "secret_key");
          if (!maul.record.effective) return 1;
          if (maul.record.offset != 1000) return 2;
          if (maul.mutated[1000] == 0x42) return 3;

          // Field-aware mutator: region-relative offset 257 inside ciphertext.u.
          pqcfuzz::AigisEncParams enc{};
          if (!pqcfuzz::GetAigisEncParams("AIGIS-ENC-2", &enc)) return 4;
          std::vector<uint8_t> ct(enc.ct_len, 0x33);
          auto recs = pqcfuzz::MutateAigisEncCiphertext(enc, {0, 0, 0x01, 0x01, 0}, &ct);
          if (recs.size() != 1 || !recs[0].effective) return 5;
          if (recs[0].target != "ciphertext.u" || recs[0].offset != 257) return 6;
          if (ct[257] == 0x33) return 7;
          return 0;
        }
        """,
        [
            "src/mutators/maul.cc",
            "src/mutators/ml_kem_layout.cc",
            "src/mutators/ml_kem_mutator.cc",
            "src/mutators/aigis_enc_layout.cc",
            "src/mutators/aigis_enc_mutator.cc",
        ],
    )


def test_aigis_replay_enum_mirrors() -> None:
    from replay.replay_one import ALGORITHM_BY_ENUM, ORACLE_BY_ENUM

    assert ALGORITHM_BY_ENUM[19] == "AIGIS-ENC-1"
    assert ALGORITHM_BY_ENUM[25] == "AIGIS-SIG-3"
    assert ORACLE_BY_ENUM[31] == "aigisenc_local_roundtrip"
    assert ORACLE_BY_ENUM[42] == "aigissig_exact_length"
    assert ORACLE_BY_ENUM[45] == "aigissig_determinism_profile"


def test_aigis_spec_json_shape() -> None:
    enc_ids = [oracle["oracle_id"] for oracle in json.loads(
        (SRC_ROOT / "oracles" / "specs" / "aigis_enc.json").read_text(encoding="utf-8"))["oracles"]]
    sig_ids = [oracle["oracle_id"] for oracle in json.loads(
        (SRC_ROOT / "oracles" / "specs" / "aigis_sig.json").read_text(encoding="utf-8"))["oracles"]]
    assert "aigisenc_sk_noncanonical_coefficient" in enc_ids
    assert "aigissig_ctx256_failure_state" in sig_ids
    assert len(enc_ids) == 5 and len(sig_ids) == 10
