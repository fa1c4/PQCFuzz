from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def compile_and_run(tmp_path: Path, source: str) -> None:
    main = tmp_path / "main.cc"
    binary = tmp_path / "case"
    main.write_text(textwrap.dedent(source), encoding="utf-8")
    subprocess.run(
        [
            os.environ.get("CXX", "clang++"),
            "-std=c++17",
            "-O0",
            "-g",
            "-Isrc",
            str(main),
            "src/adapters/rng_control.cc",
            "src/adapters/liboqs/rng_control.cc",
            "-o",
            str(binary),
        ],
        cwd=REPO_ROOT,
        check=True,
    )
    subprocess.run([str(binary)], cwd=REPO_ROOT, check=True)


def test_nested_scope_restores_outer_stream_and_system_rng(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include "adapters/rng_control.h"
        #include <cstddef>
        #include <cstdint>

        namespace {
        using RandombytesFn = void (*)(uint8_t *, size_t);
        RandombytesFn callback = nullptr;
        int system_calls = 0;
        }

        extern "C" void OQS_randombytes_custom_algorithm(RandombytesFn value) {
          callback = value;
        }

        extern "C" void OQS_randombytes_system(uint8_t *out, size_t out_len) {
          ++system_calls;
          for (size_t i = 0; i < out_len; ++i) out[i] = static_cast<uint8_t>(0xa0 + i);
        }

        int main() {
          uint8_t outer_tape[2] = {1, 2};
          uint8_t inner_tape[1] = {9};
          uint8_t out[4] = {};
          {
            pqcfuzz::ScopedRngOverride outer({outer_tape, sizeof(outer_tape), false});
            if (!outer.active() || callback == nullptr) return 1;
            if (!pqcfuzz_rng_fill_bytes(out, 1) || out[0] != 1) return 2;
            {
              pqcfuzz::ScopedRngOverride inner({inner_tape, sizeof(inner_tape), false});
              if (!pqcfuzz_rng_fill_bytes(out, 2) || out[0] != 9 || out[1] == 0) return 3;
            }
            if (!pqcfuzz_rng_fill_bytes(out, 1) || out[0] != 2) return 4;
          }
          if (callback == nullptr) return 5;
          callback(out, 2);
          return system_calls == 1 && out[0] == 0xa0 && out[1] == 0xa1 ? 0 : 6;
        }
        """,
    )


def test_non_repeating_stream_has_no_256_byte_cycle(tmp_path: Path) -> None:
    compile_and_run(
        tmp_path,
        """
        #include "adapters/rng_control.h"
        #include <cstddef>
        #include <cstdint>

        int main() {
          uint8_t tape[256];
          for (size_t i = 0; i < sizeof(tape); ++i) tape[i] = static_cast<uint8_t>(i);
          uint8_t out[4096] = {};
          {
            pqcfuzz::ScopedRngOverride rng({tape, sizeof(tape), false});
            if (!pqcfuzz_rng_fill_bytes(out, sizeof(out))) return 1;
          }
          bool second_block_same = true;
          for (size_t i = 0; i < 256; ++i) {
            if (out[i] != out[i + 256]) {
              second_block_same = false;
              break;
            }
          }
          return second_block_same ? 2 : 0;
        }
        """,
    )
