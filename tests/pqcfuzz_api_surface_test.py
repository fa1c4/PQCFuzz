from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_api_surface_report_finds_symbol_and_zeroization(tmp_path: Path) -> None:
    source = tmp_path / "probe.c"
    source.write_text(
        "#include <string.h>\n"
        "void PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(void *pk, void *sk) {\n"
        "  (void)pk;\n"
        "  memset(sk, 0, 32);\n"
        "}\n",
        encoding="utf-8",
    )
    binary = tmp_path / "probe.o"
    subprocess.run(["cc", "-c", str(source), "-o", str(binary)], check=True)

    result = subprocess.run(
        [
            sys.executable,
            "scripts/pqcfuzz_api_surface.py",
            "--binary",
            str(binary),
            "--source",
            str(source),
            "--json",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert "PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair" in report["exported_symbols"]
    assert report["zeroization_sites"]
    assert report["zeroization_sites"][0]["line"] == 4
