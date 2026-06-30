#ifndef PQCFUZZ_RUNTIME_REPLAY_ARGS_H
#define PQCFUZZ_RUNTIME_REPLAY_ARGS_H

#include <string>

namespace pqcfuzz {

enum class OracleSuite {
  kFips,
  kMetamorphic,
};

enum class RelationMode {
  kSingleTarget,
  kSelfReference,
  kCrossImplementation,
};

struct ReplayArgs {
  std::string generated_config;
  std::string input;
  std::string trace;
  std::string job_id;
  std::string pair_id;
  std::string algorithm;
  std::string primitive_type;
  std::string oracle_id;
  OracleSuite oracle_suite = OracleSuite::kFips;
  RelationMode relation_mode = RelationMode::kCrossImplementation;
  std::string left_project_id;
  std::string left_implementation_id;
  std::string right_project_id;
  std::string right_implementation_id;
  bool public_key_exchange = false;
  bool ciphertext_exchange = false;
  bool secret_key_exchange = false;
  bool secret_key_format_compatible = false;
  bool signature_exchange = false;
};

const char *OracleSuiteName(OracleSuite suite);
const char *RelationModeName(RelationMode mode);
bool ParseOracleSuite(const std::string &text, OracleSuite *suite);
bool ParseRelationMode(const std::string &text, RelationMode *mode);
bool ParseReplayArgs(int argc, char **argv, ReplayArgs *args, std::string *error);
std::string ReplayArgsUsage();

}  // namespace pqcfuzz

#endif
