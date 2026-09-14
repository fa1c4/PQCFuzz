from __future__ import annotations

import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from replay.replay_one import encode_binary_envelope, parse_envelope  # noqa: E402


def make_envelope() -> bytes:
    return encode_binary_envelope(
        {
            "magic": "PQCF",
            "version": 1,
            "algorithm": "ML-KEM-768",
            "oracle_id": "mlkem_local_roundtrip",
            "flags": 0,
            "seed": b"AAAA",
            "msg": b"xxNEEDLExx",
            "mutation": b"ZZZZ",
            "extra": b"",
        }
    )


def test_minimizer_shrinks_while_predicate_holds(tmp_path: Path) -> None:
    predicate = tmp_path / "predicate.py"
    predicate.write_text(
        "import sys\n"
        "data = open(sys.argv[1], 'rb').read()\n"
        "sys.exit(0 if b'NEEDLE' in data else 1)\n",
        encoding="utf-8",
    )
    input_path = tmp_path / "input.bin"
    original = make_envelope()
    input_path.write_bytes(original)
    output_path = tmp_path / "minimized.bin"

    result = subprocess.run(
        [
            sys.executable,
            "scripts/minimize_input.py",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--command",
            f"{sys.executable} {predicate} {{input}}",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    minimized = output_path.read_bytes()
    assert b"NEEDLE" in minimized
    assert len(minimized) < len(original)
    _, envelope = parse_envelope(output_path)
    assert envelope["msg"] == b"NEEDLE"


def test_minimizer_rejects_non_reproducing_input(tmp_path: Path) -> None:
    predicate = tmp_path / "predicate.py"
    predicate.write_text("import sys\nsys.exit(1)\n", encoding="utf-8")
    input_path = tmp_path / "input.bin"
    input_path.write_bytes(make_envelope())

    result = subprocess.run(
        [
            sys.executable,
            "scripts/minimize_input.py",
            "--input",
            str(input_path),
            "--output",
            str(tmp_path / "minimized.bin"),
            "--command",
            f"{sys.executable} {predicate} {{input}}",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "predicate does not hold" in result.stderr
