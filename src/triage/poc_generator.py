#!/usr/bin/env python3
"""Generate standalone PQCFuzz reproducer scaffolding for a finding."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def generate_poc(artifact_dir: Path, finding: dict[str, Any], job: dict[str, Any]) -> None:
    poc_dir = artifact_dir / "poc"
    poc_dir.mkdir(parents=True, exist_ok=True)
    (poc_dir / "README.md").write_text(
        "\n".join(
            [
                f"# PQCFuzz PoC: {finding['finding_id']}",
                "",
                f"Job: `{finding['job_id']}`",
                f"Pair: `{finding['pair_id']}`",
                f"Algorithm: `{finding['algorithm']}`",
                f"Oracle: `{finding['oracle_id']}`",
                "",
                "This reproducer is intentionally minimal. It rebuilds the PQCFuzz replay oracle",
                "and replays the saved `structured_input.bin` against the generated config.",
                "",
                "Replay command:",
                "",
                f"`{finding.get('replay_command', '')}`",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (poc_dir / "Dockerfile").write_text(
        "\n".join(
            [
                "FROM ubuntu:24.04",
                "RUN apt-get update && apt-get install -y --no-install-recommends build-essential python3 && rm -rf /var/lib/apt/lists/*",
                "WORKDIR /pqcfuzz",
                "COPY . /pqcfuzz",
                "CMD [\"bash\", \"poc/run.sh\"]",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (poc_dir / "build.sh").write_text(
        "\n".join(
            [
                "#!/usr/bin/env bash",
                "set -euo pipefail",
                "c++ -std=c++17 -Isrc src/replay/replay_oracle.cc \\",
                "  src/adapters/status.cc \\",
                "  src/adapters/rng_control.cc \\",
                "  src/adapters/liboqs/rng_control.cc \\",
                "  src/adapters/liboqs/kem_adapter.cc \\",
                "  src/adapters/liboqs/sig_adapter.cc \\",
                "  src/adapters/pqclean/randombytes_override.cc \\",
                "  src/adapters/pqclean/kem_adapter.cc \\",
                "  src/adapters/pqclean/sig_adapter.cc \\",
                "  src/mutators/envelope.cc \\",
                "  src/mutators/maul.cc \\",
                "  src/mutators/ml_kem_layout.cc \\",
                "  src/mutators/ml_kem_mutator.cc \\",
                "  src/mutators/ml_dsa_layout.cc \\",
                "  src/mutators/ml_dsa_mutator.cc \\",
                "  src/mutators/slh_dsa_layout.cc \\",
                "  src/mutators/slh_dsa_mutator.cc \\",
                "  src/oracles/expected_relation.cc \\",
                "  src/oracles/oracle_spec.cc \\",
                "  src/oracles/oracle_spec_loader.cc \\",
                "  src/oracles/oracle_executor.cc \\",
                "  src/oracles/metamorphic_observation.cc \\",
                "  src/oracles/metamorphic_spec.cc \\",
                "  src/oracles/metamorphic_executor.cc \\",
                "  src/runtime/adapter_registry.cc \\",
                "  src/runtime/replay_args.cc \\",
                "  src/triage/finding_writer.cc \\",
                "  -o pqcfuzz_replay_oracle",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (poc_dir / "run.sh").write_text(
        "\n".join(
            [
                "#!/usr/bin/env bash",
                "set -euo pipefail",
                "./poc/build.sh",
                finding.get(
                    "replay_command",
                    "./pqcfuzz_replay_oracle --generated-config generated_config.json --input structured_input.bin --trace oracle_trace.json "
                    "--job-id unknown --pair-id unknown --algorithm ML-KEM-768 --primitive-type kem --oracle-id mlkem_local_roundtrip "
                    "--oracle-suite fips --relation-mode cross-implementation --left-project-id liboqs --left-implementation-id liboqs_mlkem768_wrapper_generic "
                    "--right-project-id pqclean --right-implementation-id pqclean_mlkem768_clean --public-key-exchange 1 --ciphertext-exchange 1 "
                    "--secret-key-exchange 0 --secret-key-format-compatible 0 --signature-exchange 0",
                ),
                "",
            ]
        ),
        encoding="utf-8",
    )
    (poc_dir / "reproduce.cc").write_text(
        "\n".join(
            [
                "#include \"replay/replay_oracle.cc\"",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (poc_dir / "finding_snapshot.json").write_text(json.dumps({"finding": finding, "job": job}, indent=2) + "\n", encoding="utf-8")
