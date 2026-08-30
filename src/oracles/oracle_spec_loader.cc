#include "oracles/oracle_spec_loader.h"

#include <fstream>
#include <regex>
#include <sstream>

namespace pqcfuzz {

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
  const std::string text = buffer.str();
  std::vector<OracleSpec> defaults = DefaultMlKemOracleSpecs();
  const auto mldsa_defaults = DefaultMlDsaOracleSpecs();
  defaults.insert(defaults.end(), mldsa_defaults.begin(), mldsa_defaults.end());
  const auto slhdsa_defaults = DefaultSlhDsaOracleSpecs();
  defaults.insert(defaults.end(), slhdsa_defaults.begin(), slhdsa_defaults.end());
  const auto aigisenc_defaults = DefaultAigisEncOracleSpecs();
  defaults.insert(defaults.end(), aigisenc_defaults.begin(), aigisenc_defaults.end());
  const auto aigissig_defaults = DefaultAigisSigOracleSpecs();
  defaults.insert(defaults.end(), aigissig_defaults.begin(), aigissig_defaults.end());
  std::vector<OracleSpec> loaded;

  std::regex id_re("\"oracle_id\"\\s*:\\s*\"([^\"]+)\"");
  for (std::sregex_iterator it(text.begin(), text.end(), id_re), end; it != end; ++it) {
    const std::string oracle_id = (*it)[1].str();
    const OracleSpec *default_spec = FindOracleSpec(defaults, oracle_id);
    if (default_spec != nullptr) {
      loaded.push_back(*default_spec);
    }
  }

  if (loaded.empty()) {
    if (error != nullptr) {
      *error = "oracle spec contained no known ML-KEM oracle_id entries";
    }
    return defaults;
  }
  return loaded;
}

}  // namespace pqcfuzz
