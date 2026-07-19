from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_generated_launcher_template_closes_summary_python_before_shell_helpers() -> None:
    script = (REPO_ROOT / "scripts" / "pqcfuzz_eval.sh").read_text(encoding="utf-8")
    summary_start = script.index("write_run_summary() {")
    manifest_start = script.index("write_replay_manifest() {", summary_start)
    summary_body = script[summary_start:manifest_start]

    assert 'with open(path, "w", encoding="utf-8") as f:' in summary_body
    assert "\nPY\n}\n" in summary_body
    assert 'if ! bash -n "${LAUNCHER_FILE_BY_ID[$campaign]}"; then' in script


def test_launcher_collects_sanitizer_findings_and_honors_the_sanitizer_profile() -> None:
    script = (REPO_ROOT / "scripts" / "pqcfuzz_eval.sh").read_text(encoding="utf-8")

    assert "scripts/collect_sanitizer_findings.py" in script
    assert 'LIBOQS_SANITIZER_FLAGS="-fsanitize=fuzzer-no-link,${SANITIZERS}"' in script
    assert 'FUZZER_SANITIZER_FLAGS="-fsanitize=fuzzer,${SANITIZERS}"' in script
    assert "run_mldsa_empty_context_regression" in script
    assert "detect_leaks=1" in script
    assert 'finish_campaign "completed-with-findings" 0' in script


def test_launcher_seeds_and_verifies_every_selected_oracle_with_a_global_budget() -> None:
    script = (REPO_ROOT / "scripts" / "pqcfuzz_eval.sh").read_text(encoding="utf-8")

    for oracle in (
        "kem_decaps_c", "kem_decaps_sk", "kem_encaps_badrng", "kem_encaps_pk_0", "kem_encaps_pk", "kem_keygen_badrng",
        "sig_keygen_badrng", "sig_sign_badrng", "sig_sign_m", "sig_sign_sk", "sig_verify_m", "sig_verify_sig", "sig_verify_pk",
        "mlkem_local_roundtrip", "mlkem_cross_exchange_roundtrip", "mlkem_tampered_ciphertext_implicit_rejection",
        "mlkem_bad_randomness_sanity", "mldsa_local_sign_verify", "mldsa_cross_verify",
        "mldsa_mutated_signature_negative", "mldsa_mutated_message_negative", "mldsa_mutated_context_negative",
        "mldsa_oid_field_mutation_sanity", "mldsa_bad_randomness_sanity",
    ):
        assert oracle in script
    assert "make_seed_corpus" in script
    assert "verify_oracle_coverage" in script
    assert "target_budget_seconds" in script
    assert "KEM_SECONDS" not in script
    assert "SIG_SECONDS" not in script
    assert 'right_implementation="selfref_mlkem768_via_liboqs"' in script
    assert '-DPQCFUZZ_RIGHT_PROJECT_ID="\\\"liboqs_self_reference\\\""' in script
