#include "triage/oracle_coverage.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>

namespace pqcfuzz {
namespace {

struct Counters {
  uint64_t inputs = 0;
  uint64_t parse_rejected = 0;
  uint64_t parsed = 0;
  uint64_t algorithm_rejected = 0;
  uint64_t routing_rejected = 0;
  uint64_t oracle_invocations = 0;
  uint64_t valid_setup = 0;
  uint64_t relation_evaluable = 0;
  uint64_t intervention_effective = 0;
  uint64_t rng_intervention_observed = 0;
  uint64_t skipped = 0;
  uint64_t unsupported = 0;
  uint64_t finding_records = 0;
};

struct CoverageFile {
  Counters total;
  std::map<std::string, Counters> by_oracle;
};

std::mutex &CoverageMutex() {
  static auto *mutex = new std::mutex();
  return *mutex;
}

std::map<std::string, CoverageFile> &CoverageFiles() {
  static auto *files = new std::map<std::string, CoverageFile>();
  return *files;
}

bool &ExitFlushRegistered() {
  static auto *registered = new bool(false);
  return *registered;
}

std::string JsonEscape(const std::string &value) {
  std::ostringstream out;
  for (unsigned char ch : value) {
    if (ch == '\\') {
      out << "\\\\";
    } else if (ch == '"') {
      out << "\\\"";
    } else if (ch == '\n') {
      out << "\\n";
    } else if (ch == '\r') {
      out << "\\r";
    } else if (ch == '\t') {
      out << "\\t";
    } else if (ch < 0x20) {
      out << "?";
    } else {
      out << static_cast<char>(ch);
    }
  }
  return out.str();
}

void WriteCounters(std::ostringstream *out, const Counters &c) {
  *out << "{\"inputs\":" << c.inputs << ",\"parse_rejected\":" << c.parse_rejected << ",\"parsed\":" << c.parsed
       << ",\"algorithm_rejected\":" << c.algorithm_rejected << ",\"routing_rejected\":" << c.routing_rejected
       << ",\"oracle_invocations\":" << c.oracle_invocations << ",\"valid_setup\":" << c.valid_setup
       << ",\"relation_evaluable\":" << c.relation_evaluable << ",\"intervention_effective\":" << c.intervention_effective
       << ",\"rng_intervention_observed\":" << c.rng_intervention_observed << ",\"skipped\":" << c.skipped
       << ",\"unsupported\":" << c.unsupported << ",\"finding_records\":" << c.finding_records << "}";
}

void FlushAll() {
  std::lock_guard<std::mutex> lock(CoverageMutex());
  for (const auto &item : CoverageFiles()) {
    const std::filesystem::path result_dir(item.first);
    std::error_code ec;
    std::filesystem::create_directories(result_dir, ec);
    if (ec) {
      continue;
    }
    std::ostringstream out;
    out << "{\n  \"schema_version\": 1,\n  \"totals\": ";
    WriteCounters(&out, item.second.total);
    out << ",\n  \"oracles\": {";
    bool first = true;
    for (const auto &oracle : item.second.by_oracle) {
      if (!first) {
        out << ',';
      }
      first = false;
      out << "\n    \"" << JsonEscape(oracle.first) << "\": ";
      WriteCounters(&out, oracle.second);
    }
    if (!item.second.by_oracle.empty()) {
      out << '\n';
    }
    out << "  }\n}\n";
    const std::filesystem::path output = result_dir / "oracle_coverage.json";
    const std::filesystem::path temporary = result_dir / ".oracle_coverage.json.tmp";
    std::ofstream file(temporary, std::ios::binary | std::ios::trunc);
    if (!file) {
      continue;
    }
    file << out.str();
    file.close();
    std::filesystem::rename(temporary, output, ec);
    if (ec) {
      std::filesystem::remove(output, ec);
      ec.clear();
      std::filesystem::rename(temporary, output, ec);
    }
  }
}

CoverageFile &ForResultDir(const std::string &result_dir) {
  if (!ExitFlushRegistered()) {
    std::atexit(FlushAll);
    ExitFlushRegistered() = true;
  }
  return CoverageFiles()[result_dir];
}

void IncrementInput(Counters *c) {
  ++c->inputs;
}

bool HasSkippedSubtest(const KEMOracleTrace &trace) {
  for (const auto &subtest : trace.subtests) {
    if (subtest.skipped) {
      return true;
    }
  }
  return false;
}

bool RngInterventionObserved(const KEMOracleTrace &trace) {
  for (const auto &rng : trace.rng_interventions) {
    if (rng.tapes_distinct && rng.baseline_override_active && rng.mutated_override_active &&
        rng.baseline_bytes_consumed > 0 && rng.mutated_bytes_consumed > 0) {
      return true;
    }
  }
  return false;
}

void RecordTraceCounters(Counters *c, const KEMOracleTrace &trace) {
  ++c->oracle_invocations;
  if (trace.valid_setup) {
    ++c->valid_setup;
  }
  if (trace.relation_evaluable) {
    ++c->relation_evaluable;
  }
  if (trace.intervention_effective) {
    ++c->intervention_effective;
  }
  if (RngInterventionObserved(trace)) {
    ++c->rng_intervention_observed;
  }
  if (HasSkippedSubtest(trace)) {
    ++c->skipped;
  }
  if (trace.finding_class == "unsupported") {
    ++c->unsupported;
  }
  c->finding_records += trace.findings.size();
}

}  // namespace

void RecordEnvelopeParseRejected(const std::string &result_dir) {
  std::lock_guard<std::mutex> lock(CoverageMutex());
  Counters &c = ForResultDir(result_dir).total;
  IncrementInput(&c);
  ++c.parse_rejected;
}

void RecordEnvelopeParsed(const std::string &result_dir) {
  std::lock_guard<std::mutex> lock(CoverageMutex());
  Counters &c = ForResultDir(result_dir).total;
  IncrementInput(&c);
  ++c.parsed;
}

void RecordAlgorithmRejected(const std::string &result_dir) {
  std::lock_guard<std::mutex> lock(CoverageMutex());
  ++ForResultDir(result_dir).total.algorithm_rejected;
}

void RecordRoutingRejected(const std::string &result_dir) {
  std::lock_guard<std::mutex> lock(CoverageMutex());
  ++ForResultDir(result_dir).total.routing_rejected;
}

void RecordOracleTrace(const std::string &result_dir, const KEMOracleTrace &trace) {
  std::lock_guard<std::mutex> lock(CoverageMutex());
  CoverageFile &coverage = ForResultDir(result_dir);
  RecordTraceCounters(&coverage.total, trace);
  RecordTraceCounters(&coverage.by_oracle[trace.oracle_id.empty() ? "unknown" : trace.oracle_id], trace);
}

}  // namespace pqcfuzz
