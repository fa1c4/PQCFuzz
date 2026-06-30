#include "runtime/replay_args.h"

#include <sstream>
#include <unordered_map>

namespace pqcfuzz {
namespace {

bool ParseBool01(const std::string &text, bool *value) {
  if (text == "0") {
    *value = false;
    return true;
  }
  if (text == "1") {
    *value = true;
    return true;
  }
  return false;
}

bool NeedValue(int index, int argc, const std::string &flag, std::string *error) {
  if (index + 1 < argc) {
    return true;
  }
  if (error != nullptr) {
    *error = "missing value for " + flag;
  }
  return false;
}

}  // namespace

const char *OracleSuiteName(OracleSuite suite) {
  switch (suite) {
    case OracleSuite::kFips:
      return "fips";
    case OracleSuite::kMetamorphic:
      return "metamorphic";
  }
  return "fips";
}

const char *RelationModeName(RelationMode mode) {
  switch (mode) {
    case RelationMode::kSingleTarget:
      return "single-target";
    case RelationMode::kSelfReference:
      return "self-reference";
    case RelationMode::kCrossImplementation:
      return "cross-implementation";
  }
  return "cross-implementation";
}

bool ParseOracleSuite(const std::string &text, OracleSuite *suite) {
  if (text == "fips") {
    *suite = OracleSuite::kFips;
    return true;
  }
  if (text == "metamorphic") {
    *suite = OracleSuite::kMetamorphic;
    return true;
  }
  return false;
}

bool ParseRelationMode(const std::string &text, RelationMode *mode) {
  if (text == "single-target" || text == "single-liboqs") {
    *mode = RelationMode::kSingleTarget;
    return true;
  }
  if (text == "self-reference" || text == "self_reference") {
    *mode = RelationMode::kSelfReference;
    return true;
  }
  if (text == "cross-implementation" || text == "liboqs-vs-pqclean") {
    *mode = RelationMode::kCrossImplementation;
    return true;
  }
  return false;
}

std::string ReplayArgsUsage() {
  return "usage: replay_oracle --generated-config <path> --input <structured_input.bin> "
         "--trace <oracle_trace.json> --job-id <job_id> --pair-id <pair_id> "
         "--algorithm <algorithm> --primitive-type kem|sig --oracle-id <oracle_id> "
         "--oracle-suite fips|metamorphic --relation-mode single-target|self-reference|cross-implementation "
         "--left-project-id <id> --left-implementation-id <id> --right-project-id <id> "
         "--right-implementation-id <id> --public-key-exchange 0|1 --ciphertext-exchange 0|1 "
         "--secret-key-exchange 0|1 --secret-key-format-compatible 0|1 --signature-exchange 0|1";
}

bool ParseReplayArgs(int argc, char **argv, ReplayArgs *args, std::string *error) {
  if (args == nullptr) {
    return false;
  }
  ReplayArgs parsed;
  for (int i = 1; i < argc; ++i) {
    const std::string flag = argv[i];
    if (!NeedValue(i, argc, flag, error)) {
      return false;
    }
    const std::string value = argv[++i];
    if (flag == "--generated-config") {
      parsed.generated_config = value;
    } else if (flag == "--input") {
      parsed.input = value;
    } else if (flag == "--trace") {
      parsed.trace = value;
    } else if (flag == "--job-id") {
      parsed.job_id = value;
    } else if (flag == "--pair-id") {
      parsed.pair_id = value;
    } else if (flag == "--algorithm") {
      parsed.algorithm = value;
    } else if (flag == "--primitive-type") {
      parsed.primitive_type = value;
    } else if (flag == "--oracle-id") {
      parsed.oracle_id = value;
    } else if (flag == "--oracle-suite") {
      if (!ParseOracleSuite(value, &parsed.oracle_suite)) {
        if (error != nullptr) {
          *error = "invalid --oracle-suite: " + value;
        }
        return false;
      }
    } else if (flag == "--relation-mode") {
      if (!ParseRelationMode(value, &parsed.relation_mode)) {
        if (error != nullptr) {
          *error = "invalid --relation-mode: " + value;
        }
        return false;
      }
    } else if (flag == "--left-project-id") {
      parsed.left_project_id = value;
    } else if (flag == "--left-implementation-id") {
      parsed.left_implementation_id = value;
    } else if (flag == "--right-project-id") {
      parsed.right_project_id = value;
    } else if (flag == "--right-implementation-id") {
      parsed.right_implementation_id = value;
    } else if (flag == "--public-key-exchange") {
      if (!ParseBool01(value, &parsed.public_key_exchange)) {
        if (error != nullptr) *error = "invalid --public-key-exchange: " + value;
        return false;
      }
    } else if (flag == "--ciphertext-exchange") {
      if (!ParseBool01(value, &parsed.ciphertext_exchange)) {
        if (error != nullptr) *error = "invalid --ciphertext-exchange: " + value;
        return false;
      }
    } else if (flag == "--secret-key-exchange") {
      if (!ParseBool01(value, &parsed.secret_key_exchange)) {
        if (error != nullptr) *error = "invalid --secret-key-exchange: " + value;
        return false;
      }
    } else if (flag == "--secret-key-format-compatible") {
      if (!ParseBool01(value, &parsed.secret_key_format_compatible)) {
        if (error != nullptr) *error = "invalid --secret-key-format-compatible: " + value;
        return false;
      }
    } else if (flag == "--signature-exchange") {
      if (!ParseBool01(value, &parsed.signature_exchange)) {
        if (error != nullptr) *error = "invalid --signature-exchange: " + value;
        return false;
      }
    } else {
      if (error != nullptr) {
        *error = "unknown argument: " + flag;
      }
      return false;
    }
  }

  if (parsed.generated_config.empty() || parsed.input.empty() || parsed.trace.empty() ||
      parsed.job_id.empty() || parsed.pair_id.empty() || parsed.algorithm.empty() ||
      parsed.primitive_type.empty() || parsed.oracle_id.empty() ||
      parsed.left_project_id.empty() || parsed.left_implementation_id.empty()) {
    if (error != nullptr) {
      *error = "missing required replay argument";
    }
    return false;
  }
  if (parsed.primitive_type != "kem" && parsed.primitive_type != "sig") {
    if (error != nullptr) {
      *error = "--primitive-type must be kem or sig";
    }
    return false;
  }

  *args = parsed;
  return true;
}

}  // namespace pqcfuzz
