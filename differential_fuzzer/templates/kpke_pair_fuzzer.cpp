#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "differential_fuzzer/adapters/adapter_interface.h"

#ifndef PQCDF_GENERATED_CONFIG_PATH
#define PQCDF_GENERATED_CONFIG_PATH "{{GENERATED_CONFIG_PATH}}"
#endif

static const char *kJobId = "{{JOB_ID}}";
static const char *kPairId = "{{PAIR_ID}}";
static const char *kOracleMode = "{{ORACLE_MODE}}";
static const char *kLeftImplementationId = "{{LEFT_IMPLEMENTATION_ID}}";
static const char *kRightImplementationId = "{{RIGHT_IMPLEMENTATION_ID}}";
static const char *kResultDir = "{{RESULT_DIR}}";
static const char *kCrashDir = "{{CRASH_DIR}}";
static const char *kEnabledSubtests[] = { {{ENABLED_SUBTESTS}} };
static const char *kMismatchLabels[] = { {{MISMATCH_LABELS}} };

static constexpr size_t kLeftPkLen = {{LEFT_PK_LEN}};
static constexpr size_t kLeftSkLen = {{LEFT_SK_LEN}};
static constexpr size_t kLeftCtLen = {{LEFT_CT_LEN}};
static constexpr size_t kLeftMsgLen = {{LEFT_MSG_LEN}};
static constexpr size_t kRightPkLen = {{RIGHT_PK_LEN}};
static constexpr size_t kRightSkLen = {{RIGHT_SK_LEN}};
static constexpr size_t kRightCtLen = {{RIGHT_CT_LEN}};
static constexpr size_t kRightMsgLen = {{RIGHT_MSG_LEN}};

static constexpr bool kPreferSeededKeygen = {{PREFER_SEEDED_KEYGEN}};
static constexpr bool kCrossExchangeAllowed = {{CROSS_EXCHANGE_ALLOWED}};

struct ParsedKpkeInput {
  uint8_t mode;
  uint8_t flags;
  const uint8_t *message;
  size_t message_len;
  const uint8_t *seed;
  size_t seed_len;
  const uint8_t *mutation;
  size_t mutation_len;
  const uint8_t *extra;
  size_t extra_len;
};

extern "C" const pqcdf_kpke_adapter *pqcdf_get_left_kpke_adapter(void);
extern "C" const pqcdf_kpke_adapter *pqcdf_get_right_kpke_adapter(void);

static bool ReadByte(const uint8_t *data, size_t size, size_t *offset, uint8_t *value) {
  if (*offset >= size) {
    return false;
  }
  *value = data[*offset];
  *offset += 1;
  return true;
}

static bool ReadSlice(
    const uint8_t *data,
    size_t size,
    size_t *offset,
    uint8_t length,
    const uint8_t **start,
    size_t *slice_len) {
  if (*offset + length > size) {
    return false;
  }
  *start = data + *offset;
  *slice_len = static_cast<size_t>(length);
  *offset += length;
  return true;
}

static bool ParseKpkeInput(const uint8_t *data, size_t size, ParsedKpkeInput *parsed) {
  size_t offset = 0;
  uint8_t msg_len = 0;
  uint8_t seed_len = 0;
  uint8_t mutation_len = 0;

  if (!ReadByte(data, size, &offset, &parsed->mode) ||
      !ReadByte(data, size, &offset, &parsed->flags) ||
      !ReadByte(data, size, &offset, &msg_len) ||
      !ReadSlice(data, size, &offset, msg_len, &parsed->message, &parsed->message_len) ||
      !ReadByte(data, size, &offset, &seed_len) ||
      !ReadSlice(data, size, &offset, seed_len, &parsed->seed, &parsed->seed_len) ||
      !ReadByte(data, size, &offset, &mutation_len) ||
      !ReadSlice(data, size, &offset, mutation_len, &parsed->mutation, &parsed->mutation_len)) {
    return false;
  }

  parsed->extra = data + offset;
  parsed->extra_len = size - offset;
  return true;
}

static bool HasSubtest(const char *needle) {
  for (const char *candidate : kEnabledSubtests) {
    if (std::strcmp(candidate, needle) == 0) {
      return true;
    }
  }
  return false;
}

static void CopyWithZeroPad(const uint8_t *src, size_t src_len, uint8_t *dst, size_t dst_len) {
  std::memset(dst, 0, dst_len);
  if (src_len == 0 || src == nullptr) {
    return;
  }
  const size_t to_copy = src_len < dst_len ? src_len : dst_len;
  std::memcpy(dst, src, to_copy);
}

static void ApplyMutation(uint8_t *dst, size_t dst_len, const uint8_t *mutation, size_t mutation_len) {
  if (mutation == nullptr || mutation_len == 0) {
    return;
  }
  for (size_t idx = 0; idx < mutation_len; ++idx) {
    dst[idx % dst_len] ^= mutation[idx];
  }
}

static bool BytesEqual(const uint8_t *left, size_t left_len, const uint8_t *right, size_t right_len) {
  return left_len == right_len && std::memcmp(left, right, left_len) == 0;
}

[[noreturn]] static void Fail(const char *label) {
  (void)label;
  __builtin_trap();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  ParsedKpkeInput input = {};
  if (!ParseKpkeInput(data, size, &input)) {
    return -1;
  }

  const pqcdf_kpke_adapter *left = pqcdf_get_left_kpke_adapter();
  const pqcdf_kpke_adapter *right = pqcdf_get_right_kpke_adapter();
  if (left == nullptr || right == nullptr) {
    Fail("missing_adapter");
  }

  if (left->pk_len != kLeftPkLen || left->sk_len != kLeftSkLen || left->ct_len != kLeftCtLen || left->msg_len != kLeftMsgLen) {
    Fail("left_abi_mismatch");
  }
  if (right->pk_len != kRightPkLen || right->sk_len != kRightSkLen || right->ct_len != kRightCtLen || right->msg_len != kRightMsgLen) {
    Fail("right_abi_mismatch");
  }

  if (!kPreferSeededKeygen || !left->supports_keygen_derand || !right->supports_keygen_derand || !kCrossExchangeAllowed) {
    return 0;
  }

  std::array<uint8_t, kLeftMsgLen> message = {};
  std::array<uint8_t, kLeftMsgLen> keygen_seed = {};
  std::array<uint8_t, kLeftMsgLen> encrypt_coins = {};
  CopyWithZeroPad(input.message, input.message_len, message.data(), message.size());
  CopyWithZeroPad(input.seed, input.seed_len, keygen_seed.data(), keygen_seed.size());
  CopyWithZeroPad(input.extra, input.extra_len, encrypt_coins.data(), encrypt_coins.size());

  std::array<uint8_t, kLeftPkLen> left_pk = {};
  std::array<uint8_t, kLeftSkLen> left_sk = {};
  std::array<uint8_t, kRightPkLen> right_pk = {};
  std::array<uint8_t, kRightSkLen> right_sk = {};
  if (left->keygen_derand(left_pk.data(), left_sk.data(), keygen_seed.data(), keygen_seed.size()) != 0) {
    Fail("left_keygen_failed");
  }
  if (right->keygen_derand(right_pk.data(), right_sk.data(), keygen_seed.data(), keygen_seed.size()) != 0) {
    Fail("right_keygen_failed");
  }
  if (HasSubtest("kpke_keygen_consistency") &&
      (!BytesEqual(left_pk.data(), left_pk.size(), right_pk.data(), right_pk.size()) ||
       !BytesEqual(left_sk.data(), left_sk.size(), right_sk.data(), right_sk.size()))) {
    Fail("keygen_mismatch");
  }

  std::array<uint8_t, kLeftCtLen> left_ct = {};
  std::array<uint8_t, kRightCtLen> right_ct = {};
  if (left->encrypt(left_ct.data(), message.data(), left_pk.data(), encrypt_coins.data(), encrypt_coins.size()) != 0) {
    Fail("left_encrypt_failed");
  }
  if (right->encrypt(right_ct.data(), message.data(), left_pk.data(), encrypt_coins.data(), encrypt_coins.size()) != 0) {
    Fail("right_encrypt_failed");
  }
  if (HasSubtest("kpke_encrypt_compare") &&
      !BytesEqual(left_ct.data(), left_ct.size(), right_ct.data(), right_ct.size())) {
    Fail("ciphertext_mismatch");
  }

  if (HasSubtest("kpke_decrypt_roundtrip")) {
    std::array<uint8_t, kLeftMsgLen> left_out = {};
    std::array<uint8_t, kRightMsgLen> right_out = {};
    if (left->decrypt(left_out.data(), left_ct.data(), left_sk.data()) != 0) {
      Fail("left_decrypt_failed");
    }
    if (right->decrypt(right_out.data(), right_ct.data(), right_sk.data()) != 0) {
      Fail("right_decrypt_failed");
    }
    if (!BytesEqual(left_out.data(), left_out.size(), message.data(), message.size()) ||
        !BytesEqual(right_out.data(), right_out.size(), message.data(), message.size()) ||
        !BytesEqual(left_out.data(), left_out.size(), right_out.data(), right_out.size())) {
      Fail("decrypt_mismatch");
    }
  }

  if ((HasSubtest("kpke_corrupt_ciphertext_consistency") ||
       HasSubtest("kpke_corrupt_ciphertext_negative")) &&
      input.mutation_len > 0) {
    std::array<uint8_t, kLeftCtLen> mutated_left_ct = left_ct;
    std::array<uint8_t, kRightCtLen> mutated_right_ct = right_ct;
    std::array<uint8_t, kLeftMsgLen> mutated_left_out = {};
    std::array<uint8_t, kRightMsgLen> mutated_right_out = {};
    ApplyMutation(mutated_left_ct.data(), mutated_left_ct.size(), input.mutation, input.mutation_len);
    ApplyMutation(mutated_right_ct.data(), mutated_right_ct.size(), input.mutation, input.mutation_len);
    if (left->decrypt(mutated_left_out.data(), mutated_left_ct.data(), left_sk.data()) != 0) {
      Fail("left_mutated_decrypt_failed");
    }
    if (right->decrypt(mutated_right_out.data(), mutated_right_ct.data(), right_sk.data()) != 0) {
      Fail("right_mutated_decrypt_failed");
    }
    if (!BytesEqual(mutated_left_out.data(), mutated_left_out.size(), mutated_right_out.data(), mutated_right_out.size())) {
      Fail("mutated_decrypt_mismatch");
    }
  }

  (void)kJobId;
  (void)kPairId;
  (void)kOracleMode;
  (void)kLeftImplementationId;
  (void)kRightImplementationId;
  (void)kResultDir;
  (void)kCrashDir;
  (void)kMismatchLabels;
  (void)input.mode;
  (void)input.flags;
  (void)PQCDF_GENERATED_CONFIG_PATH;
  return 0;
}
