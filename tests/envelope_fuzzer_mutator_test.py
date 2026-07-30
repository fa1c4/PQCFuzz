from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_structured_custom_mutator_keeps_fixed_algorithm_and_allowed_oracles(tmp_path: Path) -> None:
    main = tmp_path / "main.cc"
    binary = tmp_path / "mutator_case"
    main.write_text(
        textwrap.dedent(
            """
            #include <cstddef>
            #include <cstdint>
            #include <set>
            #include <string>
            #include <vector>
            #include "mutators/envelope.h"

            extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *, size_t, size_t, unsigned);

            int main() {
              std::vector<uint8_t> input(512, 0);
              size_t size = 3;  // deliberately not an envelope
              std::set<unsigned> seen;
              for (unsigned seed = 1; seed < 256; ++seed) {
                size = LLVMFuzzerCustomMutator(input.data(), size, input.size(), seed);
                pqcfuzz::Envelope envelope;
                std::string error;
                if (size == 0 || !pqcfuzz::ParseEnvelope(input.data(), size, &envelope, &error)) return 1;
                if (envelope.version != 1 || envelope.algorithm != pqcfuzz::AlgorithmId::kMlKem768) return 2;
                const unsigned oracle = static_cast<unsigned>(envelope.oracle_id);
                if (oracle != 18 && oracle != 19 && oracle != 20) return 3;
                seen.insert(oracle);
              }
              return seen.size() == 3 ? 0 : 4;
            }
            """
        ),
        encoding="utf-8",
    )
    command = [
        os.environ.get("CXX", "clang++"),
        "-std=c++17",
        "-Isrc",
        "-DPQCFUZZ_FIXED_ALGORITHM_ID=2",
        '-DPQCFUZZ_ALLOWED_ORACLE_IDS="18,19,20"',
        str(main),
        "src/mutators/envelope.cc",
        "src/mutators/envelope_fuzzer_mutator.cc",
        "-o",
        str(binary),
    ]
    subprocess.run(command, cwd=REPO_ROOT, check=True)
    subprocess.run([str(binary)], cwd=REPO_ROOT, check=True)


def test_envelope_parser_rejects_unknown_algorithm_and_oracle_enums(tmp_path: Path) -> None:
    main = tmp_path / "main.cc"
    binary = tmp_path / "parser_case"
    main.write_text(
        textwrap.dedent(
            """
            #include <cstdint>
            #include <string>
            #include "mutators/envelope.h"

            bool Parse(const uint8_t algorithm, const uint8_t oracle) {
              const uint8_t data[] = {'P', 'Q', 'C', 'F', 1, algorithm, oracle, 0, 0, 0, 0, 0, 0, 0, 0, 0};
              pqcfuzz::Envelope envelope;
              std::string error;
              return pqcfuzz::ParseEnvelope(data, sizeof(data), &envelope, &error);
            }

            int main() {
              if (Parse(255, 18)) return 1;
              if (Parse(2, 255)) return 2;
              return Parse(2, 18) ? 0 : 3;
            }
            """
        ),
        encoding="utf-8",
    )
    subprocess.run(
        [os.environ.get("CXX", "clang++"), "-std=c++17", "-Isrc", str(main), "src/mutators/envelope.cc", "-o", str(binary)],
        cwd=REPO_ROOT,
        check=True,
    )
    subprocess.run([str(binary)], cwd=REPO_ROOT, check=True)
