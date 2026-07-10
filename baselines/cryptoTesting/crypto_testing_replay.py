#!/usr/bin/env python3
"""Replay one retained cryptoTesting AFL input and record a normalized result.

This intentionally performs one replay at a time.  It is a diagnostic command
for an already-retained raw artifact, never a replacement for the original
campaign.  The command is embedded in each raw manifest record.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def write_json(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--mode", choices=("functional", "vanilla"), required=True)
    parser.add_argument("--liboqs", required=True)
    parser.add_argument("--property", required=True)
    parser.add_argument("--algorithm-index", type=int, required=True)
    parser.add_argument("--target-timeout", type=int, default=int(os.environ.get("CRYPTO_TESTING_TARGET_TIMEOUT", "5")))
    parser.add_argument(
        "--normal-result",
        choices=("accepted-mutation", "mismatch", "unreproduced"),
        default="unreproduced",
        help="classification for a clean target exit when a property-specific oracle is available",
    )
    args = parser.parse_args(argv)

    artifact = args.artifact.resolve()
    output_root = args.output_root.resolve()
    if not artifact.is_file() or output_root not in artifact.parents:
        parser.error("--artifact must be a file below --output-root")
    if args.target_timeout <= 0:
        parser.error("--target-timeout must be positive")

    source_root = Path("tech/paper_fuzzing")
    if args.mode == "vanilla":
        source_root /= "vanilla"
    testpath = source_root / "liboqs" / args.property
    clone = testpath / str(args.algorithm_index)
    command = (
        f"cd {testpath} && make clone && bash clone.sh {args.algorithm_index} && "
        f"cd {args.algorithm_index} && DIRNAME={args.liboqs} make clean all"
    )
    record = {
        "schema_version": 1,
        "artifact": str(artifact.relative_to(output_root)),
        "artifact_sha256": digest(artifact),
        "mode": args.mode,
        "liboqs": args.liboqs,
        "property": args.property,
        "algorithm_index": args.algorithm_index,
        "target_timeout_seconds": args.target_timeout,
        "setup_command": command,
        "result": "unreproduced",
        "status": "not-reproduced",
        "recorded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    try:
        subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        executable = clone / "bin" / ("Match.afl.out" if args.mode == "functional" else "fuzz_harness.afl.out")
        replay = subprocess.run(
            ["timeout", f"{args.target_timeout}s", str(executable), str(artifact)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        record["exit_code"] = replay.returncode
        if replay.returncode == 124:
            record.update({"result": "target-hang", "status": "reproduced"})
        elif replay.returncode < 0 or replay.returncode >= 128:
            record.update({"result": "crash", "status": "reproduced"})
        elif replay.returncode != 0:
            record.update({"result": "operation-error", "status": "reproduced"})
        else:
            record.update({
                "result": args.normal_result,
                "status": "reproduced" if args.normal_result != "unreproduced" else "not-reproduced",
            })
    except (OSError, subprocess.CalledProcessError) as error:
        record["error"] = str(error)

    replay_path = output_root / "metadata" / "replays" / f"{record['artifact_sha256']}.json"
    write_json(replay_path, record)
    print(replay_path)
    return 0 if record["status"] == "reproduced" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
