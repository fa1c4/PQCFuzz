#include "oracles/oracle_spec_loader.h"

#include <algorithm>
#include <fstream>
#include <regex>
#include <sstream>

namespace pqcfuzz {
namespace {

// The loader selects records from the generated registry by the oracle_id
// values declared in the JSON document.  Metadata and execution fields are
// generated from the same JSON files by scripts/generate_oracle_specs.py, so
// this path never invents or repairs a record silently.
std::vector<std::string> OracleIdsInFile(const std::string &text) {
  std::vector<std::string> ids;
  const std::regex id_re("\"oracle_id\"\\s*:\\s*\"([^\"]+)\"");
  for (std::sregex_iterator it(text.begin(), text.end(), id_re), end; it != end; ++it) {
    const std::string oracle_id = (*it)[1].str();
    if (std::find(ids.begin(), ids.end(), oracle_id) == ids.end()) {
      ids.push_back(oracle_id);
    }
  }
  return ids;
}

}  // namespace

std::vector<OracleSpec> LoadOracleSpecs(const std::string &path, std::string *error) {
  std::ifstream input(path);
  if (!input) {
    if (error != nullptr) {
      *error = "oracle spec file not readable; using built-in ML-KEM defaults";
    }
    return DefaultMlKemOracleSpecs();
  }

  std::stringstream buffer;
  buffer << input.rdbuf();
  const std::vector<std::string> ids = OracleIdsInFile(buffer.str());

  std::vector<OracleSpec> loaded;
  std::vector<std::string> unknown;
  for (const std::string &oracle_id : ids) {
    if (const OracleSpec *spec = FindAnyOracleSpec(oracle_id)) {
      loaded.push_back(*spec);
    } else {
      unknown.push_back(oracle_id);
    }
  }

  if (loaded.empty()) {
    if (error != nullptr) {
      *error = "oracle spec contained no known oracle_id entries";
    }
    return {};
  }
  if (!unknown.empty() && error != nullptr) {
    std::ostringstream message;
    message << "oracle spec contains unknown oracle_id entries";
    for (const std::string &oracle_id : unknown) {
      message << ' ' << oracle_id;
    }
    *error = message.str();
  }
  return loaded;
}

}  // namespace pqcfuzz
