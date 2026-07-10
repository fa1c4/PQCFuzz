from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_generic_mutations_record_effectiveness(tmp_path: Path) -> None:
    source = tmp_path / "main.cc"
    binary = tmp_path / "case"
    source.write_text(
        textwrap.dedent(
            """
            #include "mutators/maul.h"
            #include <vector>
            int main() {
              using pqcfuzz::MaulBytes;
              if (!MaulBytes({0}, {1, 0, 0}, "x").record.skipped) return 1;
              if (!MaulBytes({0}, {2, 0, 1}, "x").record.skipped) return 2;
              if (!MaulBytes({0xff}, {3, 0, 1}, "x").record.skipped) return 3;
              if (!MaulBytes({0, 0}, {6, 0, 0}, "x").record.skipped) return 4;
              if (!MaulBytes({1, 2}, {4, 2, 0}, "x").record.skipped) return 5;
              auto flip = MaulBytes({0}, {0, 0, 0}, "x");
              auto append = MaulBytes({0}, {5, 0, 7}, "x");
              return flip.record.effective && append.record.effective &&
                             flip.record.original_length == 1 && append.record.mutated_length == 2 &&
                             flip.record.original_sha256.size() == 64 &&
                             flip.record.original_sha256 != flip.record.mutated_sha256 ? 0 : 6;
            }
            """
        ),
        encoding="utf-8",
    )
    subprocess.run(
        [os.environ.get("CXX", "clang++"), "-std=c++17", "-Isrc", str(source), "src/mutators/maul.cc", "-o", str(binary)],
        cwd=REPO_ROOT,
        check=True,
    )
    subprocess.run([str(binary)], cwd=REPO_ROOT, check=True)
