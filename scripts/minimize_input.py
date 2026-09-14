#!/usr/bin/env python3
"""Delta-debug a PQCFuzz envelope while a reproducer predicate still holds.

The minimizer shrinks each envelope field independently (seed, msg, mutation,
extra) using ddmin, then writes the smallest input that still satisfies the
predicate command.  This implements the design doc Section 37 requirement to
minimize every failure and rerun it from a clean process.

Usage:
    python3 scripts/minimize_input.py --input crash.bin --output min.bin \
        --command 'python3 src/replay/replay_one.py --job JOB --input {input}'

The command must exit 0 when the reproducer holds.  {input} is substituted with
the candidate file path.
"""

from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from replay.replay_one import encode_binary_envelope, parse_envelope  # noqa: E402

FIELD_NAMES = ("seed", "msg", "mutation", "extra")


def ddmin(items: list[int], holds: Callable[[list[int]], bool]) -> list[int]:
    """Classic ddmin over a byte list.  `holds` must accept the full list."""
    n = 2
    current = list(items)
    while len(current) >= 2:
        chunk_size = (len(current) + n - 1) // n
        reduced = False
        for start in range(0, len(current), chunk_size):
            candidate = current[:start] + current[start + chunk_size :]
            if candidate and holds(candidate):
                current = candidate
                n = max(n - 1, 2)
                reduced = True
                break
        if not reduced:
            if n >= len(current):
                break
            n = min(len(current), n * 2)
    return current


def run_predicate(command: str, data: bytes, timeout: float) -> bool:
    with tempfile.NamedTemporaryFile(prefix="pqcfuzz_min_", suffix=".bin", delete=False) as handle:
        handle.write(data)
        candidate_path = Path(handle.name)
    try:
        rendered = command.replace("{input}", shlex.quote(str(candidate_path)))
        completed = subprocess.run(
            rendered,
            shell=True,
            cwd=REPO_ROOT,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return completed.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    finally:
        candidate_path.unlink(missing_ok=True)


def minimize(input_path: Path, command: str, timeout: float) -> tuple[bytes, dict[str, tuple[int, int]]]:
    raw, envelope = parse_envelope(input_path)
    if not run_predicate(command, raw, timeout):
        raise SystemExit("predicate does not hold for the original input")

    stats: dict[str, tuple[int, int]] = {}
    for field in FIELD_NAMES:
        original = list(envelope[field])
        if len(original) < 2:
            stats[field] = (len(original), len(original))
            continue

        def candidate_bytes(candidate: list[int], field_name: str = field) -> bytes:
            trial = dict(envelope)
            trial[field_name] = bytes(candidate)
            return encode_binary_envelope(trial)

        def holds(candidate: list[int], field_name: str = field) -> bool:
            if not candidate:
                return False
            return run_predicate(command, candidate_bytes(candidate), timeout)

        reduced = ddmin(original, holds)
        envelope[field] = bytes(reduced)
        stats[field] = (len(original), len(reduced))

    return encode_binary_envelope(envelope), stats


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--command", required=True, help="predicate command; {input} is substituted")
    parser.add_argument("--timeout", type=float, default=60.0)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    minimized, stats = minimize(Path(args.input), args.command, args.timeout)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(minimized)
    print(f"wrote {output} ({len(minimized)} bytes)")
    for field, (before, after) in stats.items():
        print(f"  {field}: {before} -> {after}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
