#include "triage/finding_writer.h"

#include <filesystem>
#include <fstream>
#include <sstream>

namespace pqcfuzz {
namespace {

std::string JsonEscape(const std::string &value) {
  std::ostringstream out;
  for (char ch : value) {
    switch (ch) {
      case '\\':
        out << "\\\\";
        break;
      case '"':
        out << "\\\"";
        break;
      case '\n':
        out << "\\n";
        break;
      default:
        out << ch;
        break;
    }
  }
  return out.str();
}

uint64_t Fnv1a(const std::vector<uint8_t> &data) {
  uint64_t hash = 1469598103934665603ull;
  for (uint8_t byte : data) {
    hash ^= byte;
    hash *= 1099511628211ull;
  }
  return hash;
}

std::string Hex64(uint64_t value) {
  constexpr char kHex[] = "0123456789abcdef";
  std::string out(16, '0');
  for (int i = 15; i >= 0; --i) {
    out[static_cast<size_t>(i)] = kHex[value & 0xfu];
    value >>= 4;
  }
  return out;
}

std::string FindingClass(const KEMOracleTrace &trace) {
  for (const auto &finding : trace.findings) {
    if (!finding.finding_class.empty()) {
      return finding.finding_class;
    }
  }
  return "confirmed_semantic_bug";
}

std::string FindingSummary(const KEMOracleTrace &trace) {
  for (const auto &finding : trace.findings) {
    if (!finding.summary.empty()) {
      return finding.summary;
    }
  }
  return "semantic mismatch requires manual review";
}

bool WriteText(const std::filesystem::path &path, const std::string &text, std::string *error) {
  std::ofstream out(path);
  if (!out) {
    if (error != nullptr) {
      *error = "failed to open " + path.string();
    }
    return false;
  }
  out << text;
  return true;
}

bool WriteBinary(const std::filesystem::path &path, const std::vector<uint8_t> &data, std::string *error) {
  std::ofstream out(path, std::ios::binary);
  if (!out) {
    if (error != nullptr) {
      *error = "failed to open " + path.string();
    }
    return false;
  }
  out.write(reinterpret_cast<const char *>(data.data()), static_cast<std::streamsize>(data.size()));
  return true;
}

std::string StructuredInputJson(const FindingArtifactInput &input) {
  std::ostringstream out;
  out << "{\n";
  out << "  \"format\": \"pqcfuzz-envelope\",\n";
  out << "  \"size\": " << input.structured_input.size() << "\n";
  out << "}\n";
  return out.str();
}

std::string FindingJson(const FindingArtifactInput &input, const std::string &finding_id, const std::string &artifact_dir) {
  const std::string finding_class = FindingClass(input.trace);
  const std::string summary = FindingSummary(input.trace);
  std::string finding_subclass;
  for (const auto &finding : input.trace.findings) {
    if (!finding.finding_subclass.empty()) {
      finding_subclass = finding.finding_subclass;
      break;
    }
  }
  std::ostringstream out;
  out << "{\n";
  out << "  \"version\": 1,\n";
  out << "  \"finding_id\": \"" << JsonEscape(finding_id) << "\",\n";
  out << "  \"job_id\": \"" << JsonEscape(input.job_id) << "\",\n";
  out << "  \"pair_id\": \"" << JsonEscape(input.pair_id) << "\",\n";
  out << "  \"algorithm\": \"" << JsonEscape(input.algorithm) << "\",\n";
  out << "  \"oracle_suite\": \"" << JsonEscape(input.trace.oracle_suite) << "\",\n";
  out << "  \"relation_mode\": \"" << JsonEscape(input.trace.relation_mode) << "\",\n";
  out << "  \"oracle_id\": \"" << JsonEscape(input.oracle_id) << "\",\n";
  out << "  \"finding_class\": \"" << JsonEscape(finding_class) << "\",\n";
  out << "  \"finding_subclass\": \"" << JsonEscape(finding_subclass) << "\",\n";
  out << "  \"summary\": \"" << JsonEscape(summary) << "\",\n";
  out << "  \"trace_path\": \"" << JsonEscape(artifact_dir + "/oracle_trace.json") << "\",\n";
  out << "  \"artifact_dir\": \"" << JsonEscape(artifact_dir) << "\",\n";
  out << "  \"replay_command\": \"python3 src/replay/replay_one.py --job workspace/jobs/"
      << JsonEscape(input.job_id) << ".json --input " << JsonEscape(artifact_dir)
      << "/structured_input.bin --timeout-seconds 30\"\n";
  out << "}\n";
  return out.str();
}

std::string PocReadme(const FindingArtifactInput &input, const std::string &finding_id) {
  std::ostringstream out;
  out << "# PQCFuzz PoC: " << finding_id << "\n\n";
  out << "Job: `" << input.job_id << "`\n\n";
  out << "Pair: `" << input.pair_id << "`\n\n";
  out << "Algorithm: `" << input.algorithm << "`\n\n";
  out << "Oracle: `" << input.oracle_id << "`\n\n";
  out << "Run `./run.sh` from this directory after copying the repository sources into the container/workspace.\n";
  return out.str();
}

}  // namespace

bool WriteFindingArtifacts(const FindingArtifactInput &input, std::string *artifact_dir, std::string *error) {
  const std::string finding_class = FindingClass(input.trace);
  const std::string finding_id = finding_class + "_" + Hex64(Fnv1a(input.structured_input));
  const std::filesystem::path dir = std::filesystem::path(input.result_dir) / finding_id;
  const std::filesystem::path poc_dir = dir / "poc";
  std::error_code ec;
  std::filesystem::create_directories(poc_dir, ec);
  if (ec) {
    if (error != nullptr) {
      *error = "failed to create finding artifact directory: " + ec.message();
    }
    return false;
  }

  if (!WriteBinary(dir / "structured_input.bin", input.structured_input, error) ||
      !WriteText(dir / "structured_input.json", StructuredInputJson(input), error) ||
      !WriteText(dir / "generated_config.json", input.generated_config_json, error) ||
      !WriteText(dir / "stdout.txt", "", error) ||
      !WriteText(dir / "stderr.txt", "", error) ||
      !WriteText(dir / "exit_code.txt", "70\n", error) ||
      !WriteText(dir / "oracle_trace.json", TraceToJson(input.trace), error) ||
      !WriteBinary(dir / "minimized_seed.bin", input.structured_input, error) ||
      !WriteText(dir / "finding.json", FindingJson(input, finding_id, dir.string()), error) ||
      !WriteText(poc_dir / "README.md", PocReadme(input, finding_id), error) ||
      !WriteText(poc_dir / "Dockerfile",
                 "FROM ubuntu:24.04\nRUN apt-get update && apt-get install -y build-essential\nWORKDIR /pqcfuzz\nCOPY . /pqcfuzz\nCMD [\"bash\", \"run.sh\"]\n",
                 error) ||
      !WriteText(poc_dir / "build.sh",
                 "#!/usr/bin/env bash\nset -euo pipefail\nc++ -std=c++17 -Isrc src/replay/replay_oracle.cc \\\n"
                 "  src/adapters/status.cc \\\n"
                 "  src/adapters/rng_control.cc \\\n"
                 "  src/adapters/liboqs/rng_control.cc \\\n"
                 "  src/adapters/liboqs/kem_adapter.cc \\\n"
                 "  src/adapters/liboqs/sig_adapter.cc \\\n"
                 "  src/adapters/pqclean/randombytes_override.cc \\\n"
                 "  src/adapters/pqclean/kem_adapter.cc \\\n"
                 "  src/adapters/pqclean/sig_adapter.cc \\\n"
                 "  src/mutators/envelope.cc \\\n"
                 "  src/mutators/maul.cc \\\n"
                 "  src/mutators/ml_kem_layout.cc \\\n"
                 "  src/mutators/ml_kem_mutator.cc \\\n"
                 "  src/mutators/ml_dsa_layout.cc \\\n"
                 "  src/mutators/ml_dsa_mutator.cc \\\n"
                 "  src/mutators/slh_dsa_layout.cc \\\n"
                 "  src/mutators/slh_dsa_mutator.cc \\\n"
                 "  src/oracles/expected_relation.cc \\\n"
                 "  src/oracles/oracle_spec.cc \\\n"
                 "  src/oracles/oracle_spec_loader.cc \\\n"
                 "  src/oracles/oracle_executor.cc \\\n"
                 "  src/oracles/metamorphic_observation.cc \\\n"
                 "  src/oracles/metamorphic_spec.cc \\\n"
                 "  src/oracles/metamorphic_executor.cc \\\n"
                 "  src/runtime/adapter_registry.cc \\\n"
                 "  src/runtime/replay_args.cc \\\n"
                 "  src/triage/finding_writer.cc \\\n"
                 "  -o pqcfuzz_replay_oracle\n",
                 error) ||
      !WriteText(poc_dir / "run.sh",
                 "#!/usr/bin/env bash\nset -euo pipefail\npython3 src/replay/replay_one.py --job workspace/jobs/" +
                     input.job_id + ".json --input structured_input.bin --timeout-seconds 30\n",
                 error) ||
      !WriteText(poc_dir / "reproduce.cc", "#include \"replay/replay_oracle.cc\"\n", error)) {
    return false;
  }

  if (artifact_dir != nullptr) {
    *artifact_dir = dir.string();
  }
  return true;
}

}  // namespace pqcfuzz
