#include "mutators/envelope.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#ifndef PQCFUZZ_FIXED_ALGORITHM_ID
#define PQCFUZZ_FIXED_ALGORITHM_ID 0
#endif

#ifndef PQCFUZZ_ALLOWED_ORACLE_IDS
#define PQCFUZZ_ALLOWED_ORACLE_IDS ""
#endif

namespace pqcfuzz {
namespace {

uint32_t Next(uint32_t *state) {
  *state = *state * 1664525u + 1013904223u;
  return *state;
}

const std::vector<uint8_t> &AllowedOracleIds() {
  static const std::vector<uint8_t> ids = [] {
    std::vector<uint8_t> out;
    const char *cursor = PQCFUZZ_ALLOWED_ORACLE_IDS;
    while (*cursor != '\0') {
      unsigned value = 0;
      bool have_digit = false;
      while (*cursor >= '0' && *cursor <= '9') {
        have_digit = true;
        value = value * 10u + static_cast<unsigned>(*cursor - '0');
        ++cursor;
      }
      if (have_digit && value > 0 && value <= 255) {
        out.push_back(static_cast<uint8_t>(value));
      }
      while (*cursor != '\0' && (*cursor < '0' || *cursor > '9')) {
        ++cursor;
      }
    }
    if (out.empty()) {
      out.push_back(1);
    }
    return out;
  }();
  return ids;
}

bool IsAllowedOracle(OracleId oracle) {
  const uint8_t value = static_cast<uint8_t>(oracle);
  const auto &allowed = AllowedOracleIds();
  return std::find(allowed.begin(), allowed.end(), value) != allowed.end();
}

void FillDefault(Envelope *envelope, uint32_t *state) {
  envelope->version = 1;
  envelope->algorithm = static_cast<AlgorithmId>(PQCFUZZ_FIXED_ALGORITHM_ID);
  const auto &allowed = AllowedOracleIds();
  envelope->oracle_id = static_cast<OracleId>(allowed[Next(state) % allowed.size()]);
  envelope->flags = 0;
  envelope->seed.resize(32);
  envelope->msg.assign({'P', 'Q', 'C', 'F', 'u', 'z', 'z', ' ', 'e', 'v', 'a', 'l'});
  envelope->mutation = {0, 0, 1, 0, 0, 0, 0, 0};
  envelope->extra.clear();
  for (uint8_t &byte : envelope->seed) {
    byte = static_cast<uint8_t>(Next(state));
  }
}

void LimitField(std::vector<uint8_t> *field, size_t maximum) {
  if (field->size() > maximum) {
    field->resize(maximum);
  }
}

void WriteU16(std::vector<uint8_t> *out, size_t value) {
  out->push_back(static_cast<uint8_t>(value & 0xffu));
  out->push_back(static_cast<uint8_t>((value >> 8u) & 0xffu));
}

bool Encode(const Envelope &envelope, uint8_t *data, size_t max_size) {
  const size_t total = 8 + 2 + envelope.seed.size() + 2 + envelope.msg.size() + 2 + envelope.mutation.size() + 2 +
                       envelope.extra.size();
  // The four field lengths are u16 values.  EnsureMinimumFields bounds every
  // field well below that limit; the only remaining serialization constraint
  // here is libFuzzer's supplied buffer size.
  if (total > max_size) {
    return false;
  }
  std::vector<uint8_t> out;
  out.reserve(total);
  out.insert(out.end(), {'P', 'Q', 'C', 'F'});
  out.push_back(1);
  out.push_back(static_cast<uint8_t>(envelope.algorithm));
  out.push_back(static_cast<uint8_t>(envelope.oracle_id));
  out.push_back(0);
  for (const auto *field : {&envelope.seed, &envelope.msg, &envelope.mutation, &envelope.extra}) {
    WriteU16(&out, field->size());
    out.insert(out.end(), field->begin(), field->end());
  }
  std::memcpy(data, out.data(), out.size());
  return true;
}

void EnsureMinimumFields(Envelope *envelope, uint32_t *state) {
  LimitField(&envelope->seed, 64);
  LimitField(&envelope->msg, 256);
  LimitField(&envelope->mutation, 64);
  LimitField(&envelope->extra, 255);
  if (envelope->seed.empty()) {
    envelope->seed.resize(32);
    for (uint8_t &byte : envelope->seed) {
      byte = static_cast<uint8_t>(Next(state));
    }
  }
  if (envelope->msg.empty()) {
    envelope->msg.assign({'P', 'Q', 'C', 'F', 'u', 'z', 'z'});
  }
  if (envelope->mutation.size() < 4) {
    envelope->mutation.resize(8, 0);
    envelope->mutation[3] = 1;
  }
}

void Mutate(Envelope *envelope, uint32_t *state) {
  const auto &allowed = AllowedOracleIds();
  const uint32_t choice = Next(state) % 9u;
  auto mutate_byte = [state](std::vector<uint8_t> *field) {
    if (field->empty()) {
      field->push_back(static_cast<uint8_t>(Next(state)));
    }
    const size_t offset = Next(state) % field->size();
    (*field)[offset] ^= static_cast<uint8_t>(1u << (Next(state) % 8u));
  };
  switch (choice) {
    case 0:
      envelope->oracle_id = static_cast<OracleId>(allowed[Next(state) % allowed.size()]);
      break;
    case 1:
      mutate_byte(&envelope->seed);
      break;
    case 2:
      mutate_byte(&envelope->msg);
      break;
    case 3:
      mutate_byte(&envelope->extra);
      break;
    case 4:
      envelope->extra.resize(Next(state) % 33u);
      for (uint8_t &byte : envelope->extra) {
        byte = static_cast<uint8_t>(Next(state));
      }
      break;
    case 5:
      envelope->msg.resize(1 + Next(state) % 64u);
      for (uint8_t &byte : envelope->msg) {
        byte = static_cast<uint8_t>(Next(state));
      }
      break;
    default:
      envelope->mutation.resize(8, 0);
      envelope->mutation[0] = static_cast<uint8_t>(Next(state) % 8u);
      envelope->mutation[1] = static_cast<uint8_t>(Next(state));
      envelope->mutation[2] = static_cast<uint8_t>(Next(state));
      envelope->mutation[3] = static_cast<uint8_t>(Next(state) | 1u);
      envelope->mutation[4] = static_cast<uint8_t>(Next(state));
      break;
  }
}

}  // namespace
}  // namespace pqcfuzz

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size, unsigned seed) {
  if (data == nullptr || max_size < 16) {
    return 0;
  }
  uint32_t state = seed == 0 ? 1u : seed;
  pqcfuzz::Envelope envelope;
  std::string error;
  if (!pqcfuzz::ParseEnvelope(data, size, &envelope, &error) ||
      static_cast<uint8_t>(envelope.algorithm) != PQCFUZZ_FIXED_ALGORITHM_ID ||
      !pqcfuzz::IsAllowedOracle(envelope.oracle_id)) {
    pqcfuzz::FillDefault(&envelope, &state);
  }
  envelope.version = 1;
  envelope.algorithm = static_cast<pqcfuzz::AlgorithmId>(PQCFUZZ_FIXED_ALGORITHM_ID);
  pqcfuzz::EnsureMinimumFields(&envelope, &state);
  pqcfuzz::Mutate(&envelope, &state);
  pqcfuzz::EnsureMinimumFields(&envelope, &state);
  while (!pqcfuzz::Encode(envelope, data, max_size)) {
    if (!envelope.extra.empty()) {
      envelope.extra.pop_back();
    } else if (envelope.msg.size() > 1) {
      envelope.msg.pop_back();
    } else if (envelope.seed.size() > 1) {
      envelope.seed.pop_back();
    } else if (envelope.mutation.size() > 3) {
      envelope.mutation.pop_back();
    } else {
      return 0;
    }
  }
  const size_t total = 8 + 2 + envelope.seed.size() + 2 + envelope.msg.size() + 2 + envelope.mutation.size() + 2 +
                       envelope.extra.size();
  return total;
}
