#include "triage/finding_writer.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <map>
#include <mutex>
#include <sstream>

namespace pqcfuzz {
namespace {

#ifndef PQCFUZZ_FINDING_SAVE_MODE
#define PQCFUZZ_FINDING_SAVE_MODE "grouped"
#endif

#ifndef PQCFUZZ_MAX_FINDING_EXEMPLARS_PER_GROUP
#define PQCFUZZ_MAX_FINDING_EXEMPLARS_PER_GROUP 1
#endif

constexpr uint64_t kCounterFlushInterval = 1024;

struct CounterRecord {
  std::string result_dir;
  std::string group_key;
  std::string finding_id;
  std::string algorithm;
  std::string primitive;
  std::string oracle_suite;
  std::string relation_mode;
  std::string oracle_id;
  std::string field;
  std::string expected_relation;
  std::string observed_relation;
  std::string finding_class;
  std::string finding_subclass;
  std::string baseline_status;
  std::string mutated_status;
  std::string artifact_dir;
  std::string replay_command;
  uint64_t count = 0;
  uint64_t exemplars = 0;
};

std::mutex &CounterMutex() {
  static auto *mutex = new std::mutex();
  return *mutex;
}

std::map<std::string, CounterRecord> &CounterRecords() {
  static auto *records = new std::map<std::string, CounterRecord>();
  return *records;
}

bool &ExitFlushRegistered() {
  static auto *registered = new bool(false);
  return *registered;
}

std::string JsonEscape(const std::string &value) {
  std::ostringstream out;
  for (unsigned char ch : value) {
    switch (ch) {
      case '\\':
        out << "\\\\";
        break;
      case '"':
        out << "\\\"";
        break;
      case '\b':
        out << "\\b";
        break;
      case '\f':
        out << "\\f";
        break;
      case '\n':
        out << "\\n";
        break;
      case '\r':
        out << "\\r";
        break;
      case '\t':
        out << "\\t";
        break;
      default:
        if (ch < 0x20) {
          out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<unsigned>(ch) << std::dec;
        } else {
          out << static_cast<char>(ch);
        }
        break;
    }
  }
  return out.str();
}

std::string ShellQuote(const std::string &value) {
  std::string out = "'";
  for (char ch : value) {
    if (ch == '\'') {
      out += "'\\''";
    } else {
      out.push_back(ch);
    }
  }
  out.push_back('\'');
  return out;
}

std::string TsvEscape(const std::string &value) {
  std::string out;
  out.reserve(value.size());
  for (char ch : value) {
    switch (ch) {
      case '\t':
      case '\n':
      case '\r':
        out.push_back(' ');
        break;
      default:
        out.push_back(ch);
        break;
    }
  }
  return out;
}

std::string KeyEscape(const std::string &value) {
  std::string out;
  out.reserve(value.size());
  for (char ch : value) {
    if (ch == '\\' || ch == '|') {
      out.push_back('\\');
    }
    out.push_back(ch);
  }
  return out;
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

uint64_t Fnv1aString(const std::string &data) {
  uint64_t hash = 1469598103934665603ull;
  for (unsigned char byte : data) {
    hash ^= byte;
    hash *= 1099511628211ull;
  }
  return hash;
}

std::string FindingClass(const KEMOracleTrace &trace) {
  for (const auto &finding : trace.findings) {
    if (!finding.finding_class.empty()) {
      return finding.finding_class;
    }
  }
  return "";
}

const OracleFindingTrace *FirstSecurityFinding(const KEMOracleTrace &trace) {
  for (const auto &finding : trace.findings) {
    if (!finding.finding_class.empty() && finding.finding_class != "unsupported" &&
        finding.finding_class != "unknown_oracle") {
      return &finding;
    }
  }
  return nullptr;
}

std::string FindingEvidenceKind(const KEMOracleTrace &trace) {
  const OracleFindingTrace *finding = FirstSecurityFinding(trace);
  return finding == nullptr ? "" : EvidenceKindName(finding->evidence_kind);
}

std::string FindingSourcePhase(const KEMOracleTrace &trace) {
  const OracleFindingTrace *finding = FirstSecurityFinding(trace);
  return finding == nullptr ? "fuzz" : finding->source_phase;
}

std::string FindingFingerprint(const KEMOracleTrace &trace) {
  const OracleFindingTrace *finding = FirstSecurityFinding(trace);
  if (finding == nullptr) {
    return "";
  }
  if (!finding->fingerprint.empty()) {
    return finding->fingerprint;
  }
  const std::string material = std::string(EvidenceKindName(finding->evidence_kind)) + "\n" + finding->finding_class +
                               "\n" + finding->finding_subclass + "\n" + finding->summary;
  return "fnv1a64:" + Hex64(Fnv1aString(material));
}

std::string FindingSummary(const KEMOracleTrace &trace) {
  for (const auto &finding : trace.findings) {
    if (!finding.summary.empty()) {
      return finding.summary;
    }
  }
  return "semantic mismatch requires manual review";
}

std::string FindingSubclass(const KEMOracleTrace &trace) {
  if (!trace.finding_subclass.empty()) {
    return trace.finding_subclass;
  }
  for (const auto &finding : trace.findings) {
    if (!finding.finding_subclass.empty()) {
      return finding.finding_subclass;
    }
  }
  return "";
}

std::string Primitive(const FindingArtifactInput &input) {
  if (!input.primitive.empty()) {
    return input.primitive;
  }
  std::filesystem::path result_path(input.result_dir);
  std::string last = result_path.filename().string();
  if (last == "kem" || last == "sig") {
    return last;
  }
  return "";
}

std::string ReplayCommand(const FindingArtifactInput &input, const std::string &artifact_dir) {
  return "python3 src/replay/replay_one.py --job workspace/jobs/" + input.job_id + ".json --input " + artifact_dir +
         "/structured_input.bin --timeout-seconds 30";
}

std::string Field(const KEMOracleTrace &trace) {
  return trace.field.empty() ? trace.mutation_target : trace.field;
}

std::string GroupKey(const FindingArtifactInput &input) {
  const KEMOracleTrace &trace = input.trace;
  const std::string finding_class = FindingClass(trace);
  const std::string finding_subclass = FindingSubclass(trace);
  const MutationRecord *mutation = trace.mutations.empty() ? nullptr : &trace.mutations.front();
  const std::string fields[] = {
      std::to_string(trace.oracle_semantics_version),
      input.algorithm,
      trace.implementation_id,
      Primitive(input),
      trace.oracle_suite,
      trace.relation_mode,
      input.oracle_id.empty() ? trace.oracle_id : input.oracle_id,
      Field(trace),
      trace.expected_relation,
      trace.observed_relation,
      finding_class,
      finding_subclass,
      mutation == nullptr ? "" : mutation->target,
      mutation == nullptr ? "" : mutation->operation,
      pqcfuzz_status_to_string(trace.baseline.status),
      pqcfuzz_status_to_string(trace.mutated.status),
      trace.baseline.output_sha256,
      trace.mutated.output_sha256,
  };
  std::ostringstream out;
  for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
    if (i != 0) {
      out << '|';
    }
    out << KeyEscape(fields[i]);
  }
  return out.str();
}

std::string RecordKey(const std::string &result_dir, const std::string &group_key) {
  return result_dir + "\n" + group_key;
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

bool WriteTextAtomic(const std::filesystem::path &path, const std::string &text, std::string *error) {
  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);
  if (ec) {
    if (error != nullptr) {
      *error = "failed to create " + path.parent_path().string() + ": " + ec.message();
    }
    return false;
  }
  const std::filesystem::path tmp = path.parent_path() / (path.filename().string() + ".tmp");
  if (!WriteText(tmp, text, error)) {
    return false;
  }
  std::filesystem::rename(tmp, path, ec);
  if (ec) {
    if (error != nullptr) {
      *error = "failed to rename " + tmp.string() + " to " + path.string() + ": " + ec.message();
    }
    return false;
  }
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
  const std::string finding_subclass = FindingSubclass(input.trace);
  std::ostringstream out;
  out << "{\n";
  out << "  \"version\": 4,\n";
  out << "  \"oracle_semantics_version\": 4,\n";
  out << "  \"evidence_kind\": \"" << JsonEscape(FindingEvidenceKind(input.trace)) << "\",\n";
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
  out << "  \"source_phase\": \"" << JsonEscape(FindingSourcePhase(input.trace)) << "\",\n";
  out << "  \"fingerprint\": \"" << JsonEscape(FindingFingerprint(input.trace)) << "\",\n";
  out << "  \"trace_path\": \"" << JsonEscape(artifact_dir + "/oracle_trace.json") << "\",\n";
  out << "  \"artifact_dir\": \"" << JsonEscape(artifact_dir) << "\",\n";
  out << "  \"replay_command\": \"" << JsonEscape(ReplayCommand(input, artifact_dir)) << "\",\n";
  out << "  \"validation_state\": \"raw\",\n";
  out << "  \"validated\": false,\n";
  out << "  \"validation_attempts\": 0,\n";
  out << "  \"validation_failure_reason\": \"pending_deterministic_replay\"\n";
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
  out << "Run `./poc/run.sh` from the repository root, or set `PQCFUZZ_REPO_ROOT` to the repository path.\n";
  return out.str();
}

bool WriteArtifactDirectory(
    const FindingArtifactInput &input,
    const std::string &finding_id,
    std::string *artifact_dir,
    std::string *error) {
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
                 "  src/adapters/randombytes_override.cc \\\n"
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
                 "  src/oracles/oracle_result.cc \\\n"
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
                 "#!/usr/bin/env bash\nset -euo pipefail\n"
                 "SCRIPT_DIR=\"$(cd \"$(dirname \"${BASH_SOURCE[0]}\")\" && pwd)\"\n"
                 "ARTIFACT_DIR=\"$(cd \"$SCRIPT_DIR/..\" && pwd)\"\n"
                 "REPO_ROOT=\"${PQCFUZZ_REPO_ROOT:-$(pwd)}\"\n"
                 "cd \"$REPO_ROOT\"\n"
                 "python3 src/replay/replay_one.py --job " +
                     ShellQuote("workspace/jobs/" + input.job_id + ".json") +
                     " --input \"$ARTIFACT_DIR/structured_input.bin\" --timeout-seconds 30\n",
                 error) ||
      !WriteText(poc_dir / "reproduce.cc", "#include \"replay/replay_oracle.cc\"\n", error)) {
    return false;
  }

  if (artifact_dir != nullptr) {
    *artifact_dir = dir.string();
  }
  return true;
}

bool FlushFindingCountsForResultDir(const std::string &result_dir, std::string *error) {
  std::ostringstream out;
  out << "count\tgroup_key\tfinding_id\talgorithm\tprimitive\toracle_suite\trelation_mode\toracle_id\tfield\t"
         "expected_relation\tobserved_relation\tfinding_class\tfinding_subclass\tbaseline_status\tmutated_status\t"
         "exemplar_artifact_path\texemplar_replay_command\n";
  for (const auto &item : CounterRecords()) {
    const CounterRecord &record = item.second;
    if (record.result_dir != result_dir) {
      continue;
    }
    out << record.count << '\t' << TsvEscape(record.group_key) << '\t' << TsvEscape(record.finding_id) << '\t'
        << TsvEscape(record.algorithm) << '\t' << TsvEscape(record.primitive) << '\t'
        << TsvEscape(record.oracle_suite) << '\t' << TsvEscape(record.relation_mode) << '\t'
        << TsvEscape(record.oracle_id) << '\t' << TsvEscape(record.field) << '\t'
        << TsvEscape(record.expected_relation) << '\t' << TsvEscape(record.observed_relation) << '\t'
        << TsvEscape(record.finding_class) << '\t' << TsvEscape(record.finding_subclass) << '\t'
        << TsvEscape(record.baseline_status) << '\t' << TsvEscape(record.mutated_status) << '\t'
        << TsvEscape(record.artifact_dir) << '\t' << TsvEscape(record.replay_command) << '\n';
  }
  return WriteTextAtomic(std::filesystem::path(result_dir) / "finding_counts.tsv", out.str(), error);
}

void FlushAllFindingCounts() {
  std::lock_guard<std::mutex> lock(CounterMutex());
  std::string current;
  for (const auto &item : CounterRecords()) {
    const std::string &result_dir = item.second.result_dir;
    if (result_dir == current) {
      continue;
    }
    FlushFindingCountsForResultDir(result_dir, nullptr);
    current = result_dir;
  }
}

bool SaveModeAll() {
  return std::string(PQCFUZZ_FINDING_SAVE_MODE) == "all";
}

uint64_t MaxExemplarsPerGroup() {
  return PQCFUZZ_MAX_FINDING_EXEMPLARS_PER_GROUP < 0 ? 0 : static_cast<uint64_t>(PQCFUZZ_MAX_FINDING_EXEMPLARS_PER_GROUP);
}

}  // namespace

bool WriteFindingArtifacts(const FindingArtifactInput &input, std::string *artifact_dir, std::string *error) {
  const TraceValidationResult validation = ValidateTraceForPersistence(input.trace);
  if (!validation.persistable) {
    if (error != nullptr) {
      *error = validation.reason;
    }
    return false;
  }
  const std::string finding_class = FindingClass(input.trace);
  if (SaveModeAll()) {
    const std::string finding_id = finding_class + "_" + Hex64(Fnv1a(input.structured_input));
    return WriteArtifactDirectory(input, finding_id, artifact_dir, error);
  }

  std::lock_guard<std::mutex> lock(CounterMutex());
  if (!ExitFlushRegistered()) {
    std::atexit(FlushAllFindingCounts);
    ExitFlushRegistered() = true;
  }

  const std::string group_key = GroupKey(input);
  const std::string key = RecordKey(input.result_dir, group_key);
  CounterRecord &record = CounterRecords()[key];
  if (record.count == 0) {
    record.result_dir = input.result_dir;
    record.group_key = group_key;
    record.algorithm = input.algorithm;
    record.primitive = Primitive(input);
    record.oracle_suite = input.trace.oracle_suite;
    record.relation_mode = input.trace.relation_mode;
    record.oracle_id = input.oracle_id.empty() ? input.trace.oracle_id : input.oracle_id;
    record.field = Field(input.trace);
    record.expected_relation = input.trace.expected_relation;
    record.observed_relation = input.trace.observed_relation;
    record.finding_class = finding_class;
    record.finding_subclass = FindingSubclass(input.trace);
    record.baseline_status = pqcfuzz_status_to_string(input.trace.baseline.status);
    record.mutated_status = pqcfuzz_status_to_string(input.trace.mutated.status);
    record.finding_id = finding_class + "_" + Hex64(Fnv1aString(group_key));
    record.artifact_dir = (std::filesystem::path(input.result_dir) / record.finding_id).string();
    record.replay_command = ReplayCommand(input, record.artifact_dir);
  }

  record.count += 1;
  const bool should_write_exemplar = record.exemplars < MaxExemplarsPerGroup();
  if (should_write_exemplar) {
    std::string exemplar_id = record.finding_id;
    if (record.exemplars > 0) {
      exemplar_id += "_" + Hex64(Fnv1a(input.structured_input));
    }
    if (!WriteArtifactDirectory(input, exemplar_id, artifact_dir, error)) {
      return false;
    }
    record.exemplars += 1;
  } else if (artifact_dir != nullptr) {
    *artifact_dir = record.artifact_dir;
  }

  if (record.count == 1 || record.count % kCounterFlushInterval == 0) {
    if (!FlushFindingCountsForResultDir(input.result_dir, error)) {
      return false;
    }
  }
  return true;
}

}  // namespace pqcfuzz
