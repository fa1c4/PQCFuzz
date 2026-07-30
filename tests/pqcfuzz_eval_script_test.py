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
    assert "target_capability_state" in script
    assert "write_capability_manifest" in script
    assert "record_target_preflight" in script
    assert "not building non-comparable target" in script
    assert "KEM_SECONDS" not in script
    assert "SIG_SECONDS" not in script
    assert 'right_implementation="selfref_mlkem768_via_liboqs"' in script
    assert '-DPQCFUZZ_RIGHT_PROJECT_ID="\\\"liboqs_self_reference\\\""' in script


def test_generated_liboqs_mldsa_wrapper_uses_context_api_when_available() -> None:
    script = (REPO_ROOT / "scripts" / "pqcfuzz_eval.sh").read_text(encoding="utf-8")

    assert "OQS_SIG_sign_with_ctx_str" in script
    assert "OQS_SIG_verify_with_ctx_str" in script
    assert "kMlDsaSupportsContext" in script
    assert "PQCFUZZ_API_UNSUPPORTED" in script


def test_launcher_reports_preflight_and_fuzz_effectiveness_as_distinct_gates() -> None:
    script = (REPO_ROOT / "scripts" / "pqcfuzz_eval.sh").read_text(encoding="utf-8")

    assert 'RUN_PREFLIGHT_ORACLE_COVERAGE_FILE="$preflight_coverage"' in script
    assert '"preflight_oracle_coverage": preflight_coverage' in script
    assert '"fuzz_oracle_coverage": fuzz_coverage' in script
    assert '"preflight_coverage_state": preflight_coverage_state' in script
    assert '"fuzz_effectiveness_state": fuzz_effectiveness_state' in script
    assert '"fuzz_effectiveness_min_evaluable_rate": min_evaluable_rate' in script
    assert '"fuzz_effectiveness_failures": fuzz_effectiveness_failures' in script
    assert '"oracle_coverage_state": oracle_coverage_state' in script
    assert 'coverage_states.append(item.get("oracle_coverage_state") or "not-run")' in script
    assert 'elif unsupported > 0:' in script
    assert 'elif rate < min_evaluable_rate:' in script
    assert 'oracle_coverage_state != "passed"' in script
    assert '0.4.0:mlkem512' in script
    assert 'PREFLIGHT_ONLY' in script


def test_security_oracle_set_filters_eval_launcher_oracles() -> None:
    script = (REPO_ROOT / "scripts" / "pqcfuzz_eval.sh").read_text(encoding="utf-8")

    assert 'if [ "$ORACLE_SET" = "security" ]; then' in script
    assert "printf 'ORACLE_SET=%q\\n' \"$ORACLE_SET\"" in script
    assert "printf '%s\\n' '18:kem_decaps_c'" in script
    assert "printf '%s\\n' '28:sig_verify_m' '29:sig_verify_sig' '30:sig_verify_pk'" in script
    assert "SIG_ORACLE_ENUM=28" in script
    assert '"oracle_set": os.environ["EVAL_ORACLE_SET"]' in script
    assert '"oracle_set": os.environ.get("ORACLE_SET", "all")' in script
