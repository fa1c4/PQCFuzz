import hashlib
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMPACTOR = ROOT / "scripts" / "compact_baseline_results.py"


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def touch(path: Path, contents: str = "x") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")


def run_compactor(
    workspace: Path,
    baseline: str,
    version: str = "0.14.0",
    mode: str = "compact",
    skip_reason: str = "",
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    cmd = [
        sys.executable,
        str(COMPACTOR),
        "--workspace-root",
        str(workspace),
        "--baseline",
        baseline,
        "--version",
        version,
        "--mode",
        mode,
    ]
    if skip_reason:
        cmd.extend(["--skip-reason", skip_reason])
    return subprocess.run(
        cmd,
        cwd=ROOT,
        check=check,
        text=True,
        capture_output=True,
    )


def load_manifest(workspace: Path, baseline: str) -> dict:
    manifest_path = workspace / baseline / "compaction_manifest.json"
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def test_libfuzzer_compaction_keeps_summaries_logs_and_crashes(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    root = workspace / "libFuzzer"
    run_root = root / "targets-run" / "liboqs-0.14.0"

    touch(root / "targets-build" / "liboqs-0.14.0" / "object.o")
    write_json(run_root / "summary.json", {"baseline": "libFuzzer", "status": 0})
    write_json(run_root / "kem" / "summary.json", {"target": "kem", "status": 0})
    write_json(run_root / "sig" / "summary.json", {"target": "sig", "status": 0})
    touch(run_root / "kem" / "logs" / "full.log", "log")
    touch(run_root / "kem" / "corpus" / "seed", "seed")
    touch(run_root / "kem" / "artifacts" / "unused", "artifact")
    touch(run_root / "kem" / "crashes" / "crash-a", "crash")
    touch(run_root / "kem" / "crashes" / "timeout-b", "timeout")
    touch(run_root / "kem" / "crashes" / "nested" / "crash-nested", "nested-crash")
    touch(run_root / "kem" / "crashes" / "nested" / "notes.txt", "remove-me")
    touch(run_root / "sig" / "crashes" / "oom-c", "oom")

    run_compactor(workspace, "libFuzzer")

    assert not (root / "targets-build").exists()
    assert not (run_root / "kem" / "corpus").exists()
    assert not (run_root / "kem" / "artifacts").exists()
    assert (run_root / "summary.json").is_file()
    assert (run_root / "kem" / "summary.json").is_file()
    assert (run_root / "kem" / "logs" / "full.log").is_file()
    assert (run_root / "kem" / "crashes" / "crash-a").is_file()
    assert (run_root / "kem" / "crashes" / "timeout-b").is_file()
    assert (run_root / "kem" / "crashes" / "nested" / "crash-nested").is_file()
    assert not (run_root / "kem" / "crashes" / "nested" / "notes.txt").exists()
    assert (run_root / "sig" / "crashes" / "oom-c").is_file()

    manifest = load_manifest(workspace, "libFuzzer")
    assert manifest["status"] == "completed"
    assert manifest["build_retained"] is False
    assert manifest["corpus_retained"] is False
    assert manifest["retained_artifact_counts"]["crash"] == 2
    assert manifest["retained_artifact_counts"]["timeout"] == 1
    assert manifest["retained_artifact_counts"]["oom"] == 1
    assert manifest["retained_artifact_counts_by_target"]["kem"] == {
        "crash": 2,
        "hang": 0,
        "leak": 0,
        "oom": 0,
        "timeout": 1,
    }
    assert manifest["retained_artifact_counts_by_target"]["sig"] == {
        "crash": 0,
        "hang": 0,
        "leak": 0,
        "oom": 1,
        "timeout": 0,
    }

    summary = json.loads((run_root / "summary.json").read_text(encoding="utf-8"))
    assert summary["result_save_mode"] == "compact"
    assert summary["compacted"] is True
    assert summary["retained_artifact_counts"]["crash"] == 2
    kem_summary = json.loads((run_root / "kem" / "summary.json").read_text(encoding="utf-8"))
    sig_summary = json.loads((run_root / "sig" / "summary.json").read_text(encoding="utf-8"))
    assert kem_summary["retained_artifact_counts"]["crash"] == 2
    assert kem_summary["retained_artifact_counts"]["oom"] == 0
    assert sig_summary["retained_artifact_counts"]["crash"] == 0
    assert sig_summary["retained_artifact_counts"]["oom"] == 1


def test_libfuzzer_profile_compaction_keeps_findings_and_profile_counts_separate(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    root = workspace / "libFuzzer"
    run_root = root / "targets-run" / "liboqs-0.14.0"
    kem_root = run_root / "kem"

    semantic = {
        "target": "kem",
        "profile": "semantic",
        "sanitizer_artifacts": ["crashes/semantic/timeout-semantic"],
        "semantic_findings": ["findings/semantic/ML-KEM-512/kem_decaps_c/finding.json"],
        "operation_diagnostics": ["diagnostics/semantic/keypair-error.json"],
    }
    memory_safety = {
        "target": "kem",
        "profile": "memory-safety",
        "sanitizer_artifacts": ["crashes/memory-safety/crash-memory"],
        "semantic_findings": [],
        "operation_diagnostics": [],
    }
    target_index = {"target": "kem", "profiles": {"semantic": semantic, "memory-safety": memory_safety}}
    aggregate_index = {
        "baseline": "libFuzzer",
        "profiles": {"semantic": {"profile": "semantic"}, "memory-safety": {"profile": "memory-safety"}},
    }

    touch(root / "targets-build" / "liboqs-0.14.0" / "object.o")
    write_json(run_root / "summary.json", aggregate_index)
    write_json(run_root / "summary.semantic.json", {"profile": "semantic"})
    write_json(run_root / "summary.memory-safety.json", {"profile": "memory-safety"})
    write_json(kem_root / "summary.json", target_index)
    write_json(kem_root / "summary.semantic.json", semantic)
    write_json(kem_root / "summary.memory-safety.json", memory_safety)
    touch(kem_root / "crashes" / "semantic" / "timeout-semantic")
    touch(kem_root / "crashes" / "memory-safety" / "crash-memory")
    write_json(
        kem_root / "findings" / "semantic" / "ML-KEM-512" / "kem_decaps_c" / "finding.json",
        {"property_id": "kem_decaps_c", "replay_input": "finding.input"},
    )
    touch(kem_root / "findings" / "semantic" / "ML-KEM-512" / "kem_decaps_c" / "finding.input")
    write_json(kem_root / "diagnostics" / "semantic" / "keypair-error.json", {"operation": "keypair"})
    write_json(kem_root / "metadata" / "semantic.json", {"property_ids": ["kem_decaps_c"]})
    touch(kem_root / "corpus" / "semantic" / "seed")
    touch(kem_root / "artifacts" / "memory-safety" / "temporary")

    run_compactor(workspace, "libFuzzer")

    assert (kem_root / "findings" / "semantic" / "ML-KEM-512" / "kem_decaps_c" / "finding.json").is_file()
    assert (kem_root / "findings" / "semantic" / "ML-KEM-512" / "kem_decaps_c" / "finding.input").is_file()
    assert (kem_root / "diagnostics" / "semantic" / "keypair-error.json").is_file()
    assert (kem_root / "metadata" / "semantic.json").is_file()
    assert not (kem_root / "corpus").exists()
    assert not (kem_root / "artifacts").exists()

    semantic_summary = json.loads((kem_root / "summary.semantic.json").read_text(encoding="utf-8"))
    memory_summary = json.loads((kem_root / "summary.memory-safety.json").read_text(encoding="utf-8"))
    target_summary = json.loads((kem_root / "summary.json").read_text(encoding="utf-8"))
    aggregate_summary = json.loads((run_root / "summary.semantic.json").read_text(encoding="utf-8"))
    assert semantic_summary["retained_artifact_counts"]["timeout"] == 1
    assert semantic_summary["retained_artifact_counts"]["crash"] == 0
    assert semantic_summary["retained_semantic_finding_count"] == 1
    assert semantic_summary["retained_operation_diagnostic_count"] == 1
    assert memory_summary["retained_artifact_counts"]["crash"] == 1
    assert memory_summary["retained_semantic_finding_count"] == 0
    assert "retained_artifact_counts" not in target_summary
    assert target_summary["retained_artifact_counts_by_profile"]["semantic"]["timeout"] == 1
    assert target_summary["retained_artifact_counts_by_profile"]["memory-safety"]["crash"] == 1
    assert "retained_artifact_counts" not in aggregate_summary
    assert aggregate_summary["retained_artifact_counts_by_target"]["kem"]["timeout"] == 1

    manifest = load_manifest(workspace, "libFuzzer")
    assert manifest["retained_artifact_counts_by_target_profile"]["kem"]["semantic"]["timeout"] == 1
    assert manifest["retained_artifact_counts_by_target_profile"]["kem"]["memory-safety"]["crash"] == 1
    assert manifest["retained_semantic_finding_counts_by_target_profile"]["kem"]["semantic"] == 1
    assert manifest["retained_artifact_validation"]["targets"]["kem"]["semantic_findings"]["validated"] == 1


def test_libfuzzer_compaction_rejects_unlisted_new_evidence_before_deleting(tmp_path: Path) -> None:
    for evidence in ("sanitizer", "finding"):
        workspace = tmp_path / evidence / "workspace"
        root = workspace / "libFuzzer"
        run_root = root / "targets-run" / "liboqs-0.14.0"
        kem_root = run_root / "kem"
        profile = {
            "target": "kem",
            "profile": "semantic",
            "sanitizer_artifacts": [],
            "semantic_findings": [],
            "operation_diagnostics": [],
        }
        write_json(kem_root / "summary.json", {"target": "kem", "profiles": {"semantic": profile}})
        write_json(kem_root / "summary.semantic.json", profile)
        touch(root / "targets-build" / "liboqs-0.14.0" / "object.o")
        touch(kem_root / "corpus" / "semantic" / "seed")

        if evidence == "sanitizer":
            retained_path = kem_root / "crashes" / "semantic" / "crash-unlisted"
            touch(retained_path)
        else:
            retained_path = kem_root / "findings" / "semantic" / "algorithm" / "property" / "finding.json"
            write_json(retained_path, {"property_id": "property"})

        result = run_compactor(workspace, "libFuzzer", check=False)

        assert result.returncode != 0
        assert retained_path.is_file()
        assert (kem_root / "corpus" / "semantic" / "seed").is_file()
        assert (root / "targets-build" / "liboqs-0.14.0" / "object.o").is_file()
        assert not (root / "compaction_manifest.json").exists()


def test_cryptofuzz_and_clfuzz_compaction_use_single_run_layout(tmp_path: Path) -> None:
    for baseline in ("cryptofuzz", "CLFuzz"):
        workspace = tmp_path / baseline / "workspace"
        root = workspace / baseline
        run_root = root / "targets-run" / "liboqs-0.8.0"

        touch(root / "targets-build" / "liboqs-0.8.0" / "object.o")
        write_json(run_root / "summary.json", {"baseline": baseline, "status": 0})
        touch(run_root / "logs" / "full.log", "log")
        touch(run_root / "corpus" / "seed", "seed")
        touch(run_root / "artifacts" / "unused", "artifact")
        touch(run_root / "crashes" / "leak-a", "leak")

        run_compactor(workspace, baseline, version="0.8.0")

        assert not (root / "targets-build").exists()
        assert not (run_root / "corpus").exists()
        assert not (run_root / "artifacts").exists()
        assert (run_root / "summary.json").is_file()
        assert (run_root / "logs" / "full.log").is_file()
        assert (run_root / "crashes" / "leak-a").is_file()

        manifest = load_manifest(workspace, baseline)
        assert manifest["retained_artifact_counts"]["leak"] == 1
        assert manifest["build_retained"] is False


def test_clfuzz_compaction_requires_three_replays_and_retains_structured_evidence(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    root = workspace / "CLFuzz"
    run_root = root / "targets-run" / "liboqs-0.14.0"
    finding_path = run_root / "findings" / "finding-ov.json"
    diagnostic_path = run_root / "diagnostics" / "diagnostic-keypair.json"
    fixture_contents = b"fixture"
    fixture_sha256 = hashlib.sha256(fixture_contents).hexdigest()
    fixture_relative_path = "replay-inputs/fixture.bin"

    finding = {
        "format_version": 1,
        "baseline": "CLFuzz",
        "classification": "semantic_finding",
        "algorithm": "OV-Is-pkc-skc",
        "property_id": "sig_verify_pk",
        "semantic_relation": "OBSERVED_EQUAL",
        "mutation_effective": True,
        "mutation_operation": "xor",
        "mutation_before_digest": "before",
        "mutation_after_digest": "after",
        "input": {
            "fixture_sha256": fixture_sha256,
            "fixture_path": fixture_relative_path,
        },
        "replay": {
            "required": True,
            "result": "reproduced",
            "attempts_completed": 3,
            "reproduced_count": 3,
            "attempt_results": ["reproduced", "reproduced", "reproduced"],
            "input_sha256": fixture_sha256,
            "input_path": fixture_relative_path,
            "algorithm": "OV-Is-pkc-skc",
            "property_id": "sig_verify_pk",
            "semantic_relation": "OBSERVED_EQUAL",
        },
    }
    diagnostic = {
        "format_version": 1,
        "baseline": "CLFuzz",
        "classification": "operation_diagnostic",
        "algorithm": "OV-Is-pkc-skc",
        "property_id": "sig_roundtrip",
    }
    write_json(
        run_root / "summary.json",
        {
            "baseline": "CLFuzz",
            "target": "liboqs",
            "semantic_finding_count": 1,
            "semantic_findings": ["findings/finding-ov.json"],
            "operation_diagnostic_count": 1,
            "operation_diagnostics": ["diagnostics/diagnostic-keypair.json"],
            "sanitizer_artifact_count": 0,
            "sanitizer_crash_count": 0,
            "hang_count": 0,
        },
    )
    write_json(finding_path, finding)
    write_json(diagnostic_path, diagnostic)
    touch(run_root / "findings" / "replay-inputs" / "fixture.bin", fixture_contents.decode("ascii"))
    touch(run_root / "metadata" / "liboqs-oracle-metadata.json", "{}")
    touch(run_root / "corpus" / "seed", "seed")
    touch(run_root / "artifacts" / "temporary", "temporary")
    touch(root / "targets-build" / "liboqs-0.14.0" / "object.o", "object")

    run_compactor(workspace, "CLFuzz")

    assert finding_path.is_file()
    assert diagnostic_path.is_file()
    assert (run_root / "findings" / "replay-inputs" / "fixture.bin").is_file()
    assert (run_root / "metadata" / "liboqs-oracle-metadata.json").is_file()
    assert not (run_root / "corpus").exists()
    assert not (run_root / "artifacts").exists()
    assert not (root / "targets-build").exists()
    manifest = load_manifest(workspace, "CLFuzz")
    assert manifest["retained_semantic_finding_count"] == 1
    assert manifest["retained_operation_diagnostic_count"] == 1
    assert manifest["retained_artifact_validation"]["targets"]["liboqs"]["replay"]["status"] == "passed"


def test_clfuzz_compaction_rejects_finding_without_three_replays(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    root = workspace / "CLFuzz"
    run_root = root / "targets-run" / "liboqs-0.14.0"
    finding_path = run_root / "findings" / "finding-short-replay.json"
    finding = {
        "format_version": 1,
        "baseline": "CLFuzz",
        "classification": "semantic_finding",
        "algorithm": "OV-Is-pkc-skc",
        "property_id": "sig_verify_pk",
        "semantic_relation": "OBSERVED_EQUAL",
        "replay": {
            "required": True,
            "result": "reproduced",
            "attempts_completed": 1,
            "attempt_results": ["reproduced"],
        },
    }
    write_json(
        run_root / "summary.json",
        {
            "target": "liboqs",
            "semantic_finding_count": 1,
            "semantic_findings": ["findings/finding-short-replay.json"],
            "operation_diagnostic_count": 0,
            "operation_diagnostics": [],
            "sanitizer_artifact_count": 0,
            "sanitizer_crash_count": 0,
            "hang_count": 0,
        },
    )
    write_json(finding_path, finding)
    touch(run_root / "corpus" / "seed", "seed")
    touch(root / "targets-build" / "liboqs-0.14.0" / "object.o", "object")

    result = run_compactor(workspace, "CLFuzz", check=False)

    assert result.returncode != 0
    assert finding_path.is_file()
    assert (run_root / "corpus" / "seed").is_file()
    assert (root / "targets-build" / "liboqs-0.14.0" / "object.o").is_file()
    manifest = load_manifest(workspace, "CLFuzz")
    assert manifest["status"] == "failed"


def test_clfuzz_compaction_rejects_a_nonunanimous_replay_even_with_three_attempts(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    root = workspace / "CLFuzz"
    run_root = root / "targets-run" / "liboqs-0.14.0"
    finding_path = run_root / "findings" / "finding-nonunanimous.json"
    fixture = b"nonunanimous-fixture"
    fixture_sha256 = hashlib.sha256(fixture).hexdigest()
    fixture_path = run_root / "findings" / "replay-inputs" / f"{fixture_sha256}.bin"
    fixture_path.parent.mkdir(parents=True, exist_ok=True)
    fixture_path.write_bytes(fixture)
    finding = {
        "schema_version": 1,
        "classification": "semantic_finding",
        "algorithm": "OV-Is-pkc-skc",
        "property_id": "sig_verify_pk",
        "semantic_relation": "OBSERVED_EQUAL",
        "input": {
            "fixture_sha256": fixture_sha256,
            "fixture_path": f"replay-inputs/{fixture_sha256}.bin",
        },
        "replay": {
            "required": True,
            "result": "reproduced",
            "attempts_completed": 3,
            "reproduced_count": 2,
            "attempt_results": ["reproduced", "unreproduced", "reproduced"],
            "input_sha256": fixture_sha256,
            "input_path": f"replay-inputs/{fixture_sha256}.bin",
        },
    }
    write_json(
        run_root / "summary.json",
        {
            "target": "liboqs",
            "semantic_finding_count": 1,
            "semantic_findings": ["findings/finding-nonunanimous.json"],
            "operation_diagnostic_count": 0,
            "operation_diagnostics": [],
            "sanitizer_artifact_count": 0,
            "sanitizer_crash_count": 0,
            "hang_count": 0,
        },
    )
    write_json(finding_path, finding)
    touch(run_root / "corpus" / "seed", "seed")
    touch(root / "targets-build" / "liboqs-0.14.0" / "object.o", "object")

    result = run_compactor(workspace, "CLFuzz", check=False)

    assert result.returncode != 0
    assert fixture_path.is_file()
    manifest = load_manifest(workspace, "CLFuzz")
    assert manifest["status"] == "failed"
    assert manifest["retained_artifact_validation"]["targets"]["liboqs"]["replay"]["not_reproduced"] == 1


def test_clfuzz_compaction_keeps_profile_scoped_findings_and_fixtures(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    root = workspace / "CLFuzz"
    version_root = root / "targets-run" / "liboqs-0.14.0"

    for profile in ("smoke", "full"):
        run_root = version_root / profile
        fixture = f"fixture-{profile}".encode("ascii")
        fixture_sha256 = hashlib.sha256(fixture).hexdigest()
        fixture_relative_path = f"replay-inputs/{fixture_sha256}.bin"
        fixture_path = run_root / "findings" / fixture_relative_path
        fixture_path.parent.mkdir(parents=True, exist_ok=True)
        fixture_path.write_bytes(fixture)
        finding_name = f"finding-{profile}.json"
        write_json(
            run_root / "findings" / finding_name,
            {
                "schema_version": 1,
                "classification": "semantic_finding",
                "algorithm": "OV-Is-pkc-skc",
                "property_id": "sig_verify_pk",
                "semantic_relation": "OBSERVED_EQUAL",
                "input": {
                    "fixture_sha256": fixture_sha256,
                    "fixture_path": fixture_relative_path,
                },
                "replay": {
                    "required": True,
                    "result": "reproduced",
                    "attempts_completed": 3,
                    "reproduced_count": 3,
                    "attempt_results": ["reproduced", "reproduced", "reproduced"],
                    "input_sha256": fixture_sha256,
                    "input_path": fixture_relative_path,
                },
            },
        )
        write_json(
            run_root / "summary.json",
            {
                "baseline": "CLFuzz",
                "target": "liboqs",
                "profile": profile,
                "semantic_finding_count": 1,
                "semantic_findings": [f"findings/{finding_name}"],
                "operation_diagnostic_count": 0,
                "operation_diagnostics": [],
                "sanitizer_artifact_count": 0,
                "sanitizer_crash_count": 0,
                "hang_count": 0,
            },
        )
        touch(run_root / "corpus" / "seed", "seed")
        touch(run_root / "artifacts" / "temporary", "artifact")

    touch(root / "targets-build" / "liboqs-0.14.0" / "object.o", "object")
    run_compactor(workspace, "CLFuzz")

    for profile in ("smoke", "full"):
        run_root = version_root / profile
        assert (run_root / "summary.json").is_file()
        assert list((run_root / "findings" / "replay-inputs").glob("*.bin"))
        assert not (run_root / "corpus").exists()
        assert not (run_root / "artifacts").exists()
    assert not (root / "targets-build").exists()
    manifest = load_manifest(workspace, "CLFuzz")
    assert manifest["retained_semantic_finding_count"] == 2
    validations = manifest["retained_artifact_validation"]["targets"]
    assert validations["liboqs/smoke"]["replay"]["status"] == "passed"
    assert validations["liboqs/full"]["replay"]["status"] == "passed"


def test_cryptofuzz_compaction_keeps_replayable_findings_and_target_local_counts(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    root = workspace / "cryptofuzz"
    run_root = root / "targets-run" / "liboqs-0.14.0"
    finding_path = run_root / "findings" / "a1b2c3d4-e5f6.json"
    diagnostic_path = run_root / "diagnostics" / "diagnostic-d4c3b2a1.json"

    finding = {
        "format_version": 1,
        "classification": "semantic_finding",
        "algorithm": "ML-KEM-512",
        "property_id": "kem_decaps_mutated_ciphertext",
        "semantic_relation": "accepted_mutation_preserved_shared_secret",
        "input": {"entropy": "00", "mutation": "01"},
        "replay": {
            "required": True,
            "result": "reproduced",
            "algorithm": "ML-KEM-512",
            "property_id": "kem_decaps_mutated_ciphertext",
            "semantic_relation": "accepted_mutation_preserved_shared_secret",
        },
    }
    diagnostic = {
        "format_version": 1,
        "classification": "operation_diagnostic",
        "algorithm": "picnic3_L1",
        "operation": "sign",
        "diagnostic_class": "operation-return",
    }
    write_json(
        run_root / "summary.json",
        {
            "baseline": "cryptofuzz",
            "target": "liboqs",
            "semantic_finding_count": 1,
            "semantic_findings": ["findings/a1b2c3d4-e5f6.json"],
            "operation_diagnostic_count": 1,
            "operation_diagnostics": ["diagnostics/diagnostic-d4c3b2a1.json"],
            "sanitizer_crash_count": 1,
            "sanitizer_crashes": ["crashes/crash-sanitizer"],
            "sanitizer_artifact_count": 2,
            "sanitizer_artifacts": ["crashes/crash-sanitizer", "crashes/timeout-hang"],
            "hang_count": 1,
            "hangs": ["crashes/timeout-hang"],
        },
    )
    write_json(finding_path, finding)
    touch(run_root / "findings" / "a1b2c3d4-e5f6.original-input", "original")
    touch(run_root / "findings" / "a1b2c3d4-e5f6.minimized-input", "minimized")
    touch(run_root / "findings" / "a1b2c3d4-e5f6.stdout.log", "stdout")
    touch(run_root / "findings" / "a1b2c3d4-e5f6.stderr.log", "stderr")
    write_json(diagnostic_path, diagnostic)
    touch(run_root / "diagnostics" / "diagnostic-d4c3b2a1.stderr.log", "diagnostic")
    touch(run_root / "crashes" / "crash-sanitizer", "crash")
    touch(run_root / "crashes" / "timeout-hang", "hang")
    touch(run_root / "logs" / "campaign.log", "log")
    touch(run_root / "corpus" / "seed", "seed")
    touch(run_root / "artifacts" / "temporary", "temporary")
    touch(root / "targets-build" / "liboqs-0.14.0" / "object.o", "object")

    run_compactor(workspace, "cryptofuzz")

    assert finding_path.is_file()
    assert (run_root / "findings" / "a1b2c3d4-e5f6.original-input").read_text(encoding="utf-8") == "original"
    assert (run_root / "findings" / "a1b2c3d4-e5f6.minimized-input").read_text(encoding="utf-8") == "minimized"
    assert (run_root / "findings" / "a1b2c3d4-e5f6.stdout.log").is_file()
    assert (run_root / "findings" / "a1b2c3d4-e5f6.stderr.log").is_file()
    assert diagnostic_path.is_file()
    assert (run_root / "diagnostics" / "diagnostic-d4c3b2a1.stderr.log").is_file()
    assert (run_root / "crashes" / "crash-sanitizer").is_file()
    assert (run_root / "crashes" / "timeout-hang").is_file()
    assert not (run_root / "corpus").exists()
    assert not (run_root / "artifacts").exists()
    assert not (root / "targets-build").exists()

    manifest = load_manifest(workspace, "cryptofuzz")
    assert manifest["retained_artifact_counts"] == {
        "crash": 1,
        "hang": 1,
        "leak": 0,
        "oom": 0,
        "timeout": 1,
    }
    assert manifest["retained_artifact_counts_by_target"]["liboqs"] == manifest[
        "retained_artifact_counts"
    ]
    assert manifest["retained_semantic_finding_count"] == 1
    assert manifest["retained_semantic_finding_counts_by_target"] == {"liboqs": 1}
    assert manifest["retained_operation_diagnostic_count"] == 1
    assert manifest["retained_operation_diagnostic_counts_by_target"] == {"liboqs": 1}
    assert manifest["retained_artifact_validation"]["targets"]["liboqs"]["replay"] == {
        "identity_mismatches": 0,
        "legacy_unverified": 0,
        "not_reproduced": 0,
        "required": 1,
        "status": "passed",
        "verified": 1,
    }

    summary = json.loads((run_root / "summary.json").read_text(encoding="utf-8"))
    assert summary["retained_artifact_counts"] == manifest["retained_artifact_counts"]
    assert summary["retained_semantic_finding_count"] == 1
    assert summary["retained_operation_diagnostic_count"] == 1
    assert summary["compaction_validation"]["replay"]["status"] == "passed"


def test_cryptofuzz_compaction_marks_nonreproduced_finding_without_deleting(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    root = workspace / "cryptofuzz"
    run_root = root / "targets-run" / "liboqs-0.14.0"
    finding_path = run_root / "findings" / "finding-not-reproduced.json"

    write_json(
        run_root / "summary.json",
        {
            "baseline": "cryptofuzz",
            "target": "liboqs",
            "semantic_findings": ["findings/finding-not-reproduced.json"],
            "operation_diagnostics": [],
            "sanitizer_artifacts": [],
        },
    )
    write_json(
        finding_path,
        {
            "schema_version": 1,
            "kind": "semantic_finding",
            "algorithm": "ML-KEM-512",
            "property_id": "kem_decaps_mutated_ciphertext",
            "semantic_relation": "accepted_mutation_preserved_shared_secret",
            "replay": {"required": True, "result": "not-reproduced"},
        },
    )
    touch(run_root / "corpus" / "seed", "seed")
    touch(root / "targets-build" / "liboqs-0.14.0" / "object.o", "object")

    result = run_compactor(workspace, "cryptofuzz", check=False)

    assert result.returncode != 0
    assert finding_path.is_file()
    assert (run_root / "corpus" / "seed").is_file()
    assert (root / "targets-build" / "liboqs-0.14.0" / "object.o").is_file()
    manifest = load_manifest(workspace, "cryptofuzz")
    assert manifest["status"] == "failed"
    assert manifest["compacted"] is False
    assert manifest["retained_semantic_finding_counts_by_target"] == {"liboqs": 1}
    assert manifest["retained_artifact_validation"]["targets"]["liboqs"]["replay"]["status"] == "failed"


def test_shared_liboqs_oracle_module_policy_is_enforced() -> None:
    cryptofuzz_module = ROOT / "baselines" / "cryptofuzz" / "modules" / "liboqs"
    cl_fuzz_module = ROOT / "baselines" / "CLFuzz" / "modules" / "liboqs"

    for name in ("module.cpp", "module.h", "Makefile"):
        assert (cryptofuzz_module / name).read_bytes() == (cl_fuzz_module / name).read_bytes()
    assert (ROOT / "baselines" / "cryptofuzz" / "liboqs_replay_input.h").read_bytes() == (
        ROOT / "baselines" / "CLFuzz" / "liboqs_replay_input.h"
    ).read_bytes()


def test_cryptotesting_compaction_copies_afl_crashes_and_hangs(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    root = workspace / "cryptoTesting"
    build_target = root / "targets-build" / "ches_liboqs"
    run_root = root / "targets-run"

    touch(build_target / "alg1" / "fuzzoutputs" / "default" / "crashes" / "id:000000", "crash")
    touch(build_target / "alg1" / "fuzzoutputs" / "default" / "crashes" / "README.txt", "readme")
    touch(build_target / "alg1" / "fuzzoutputs" / "default" / "hangs" / "id:000001", "hang")
    touch(run_root / "reports" / "crash_report_ches_liboqs_python.xlsx", "report")
    touch(run_root / "logs" / "ches_liboqs.functional.log", "log")

    run_compactor(workspace, "cryptoTesting", version="0.14.0")

    artifact_root = run_root / "artifacts" / "ches_liboqs" / "alg1" / "fuzzoutputs" / "default"
    assert not (root / "targets-build").exists()
    assert (run_root / "reports" / "crash_report_ches_liboqs_python.xlsx").is_file()
    assert (run_root / "logs" / "ches_liboqs.functional.log").is_file()
    assert (artifact_root / "crashes" / "id:000000").read_text(encoding="utf-8") == "crash"
    assert (artifact_root / "hangs" / "id:000001").read_text(encoding="utf-8") == "hang"
    assert not (artifact_root / "crashes" / "README.txt").exists()

    manifest = load_manifest(workspace, "cryptoTesting")
    assert manifest["retained_artifact_counts"]["crash"] == 1
    assert manifest["retained_artifact_counts"]["hang"] == 1

    summary = json.loads((run_root / "summary.json").read_text(encoding="utf-8"))
    assert summary["baseline"] == "cryptoTesting"
    assert summary["target"] == "ches_liboqs"
    assert summary["compacted"] is True


def test_all_mode_leaves_tree_untouched(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    root = workspace / "cryptofuzz"
    touch(root / "targets-build" / "liboqs-0.14.0" / "object.o")
    touch(root / "targets-run" / "liboqs-0.14.0" / "corpus" / "seed")

    run_compactor(workspace, "cryptofuzz", mode="all")

    assert (root / "targets-build" / "liboqs-0.14.0" / "object.o").is_file()
    assert (root / "targets-run" / "liboqs-0.14.0" / "corpus" / "seed").is_file()
    assert not (root / "compaction_manifest.json").exists()


def test_skipped_compaction_writes_non_compacted_manifest_without_deleting(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    root = workspace / "libFuzzer"
    touch(root / "targets-build" / "liboqs-0.14.0" / "object.o")

    run_compactor(workspace, "libFuzzer", skip_reason="campaign did not reach result-producing phase")

    assert (root / "targets-build" / "liboqs-0.14.0" / "object.o").is_file()
    manifest = load_manifest(workspace, "libFuzzer")
    assert manifest["status"] == "skipped"
    assert manifest["compacted"] is False
    assert manifest["reason"] == "campaign did not reach result-producing phase"
    assert manifest["removed_paths"] == []
