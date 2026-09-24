#include "adapters/falcon/signed_message_adapter.h"

#ifdef PQCFUZZ_HAVE_FALCON

#include <algorithm>
#include <cstring>
#include <vector>

#include "adapters/falcon/falcon_adapter_impl.h"

namespace pqcfuzz {
namespace falcon_internal {
namespace {

constexpr size_t kSaltLen = 40;
constexpr size_t kDetachedPayloadOffset = 41;

pqcfuzz_status SignCompressed(
    unsigned logn,
    const uint8_t *seed,
    size_t seed_len,
    uint8_t *detached,
    size_t *detached_len,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *secret_key) {
  if (logn == 9) {
    if (seed != nullptr) {
      return FalconSignSeededT<9, FALCON_SIG_COMPRESSED>(detached, detached_len, message, message_len, secret_key,
                                                         nullptr, 0, seed, seed_len);
    }
    return FalconSignT<9, FALCON_SIG_COMPRESSED>(detached, detached_len, message, message_len, secret_key, nullptr, 0);
  }
  if (logn == 10) {
    if (seed != nullptr) {
      return FalconSignSeededT<10, FALCON_SIG_COMPRESSED>(detached, detached_len, message, message_len, secret_key,
                                                          nullptr, 0, seed, seed_len);
    }
    return FalconSignT<10, FALCON_SIG_COMPRESSED>(detached, detached_len, message, message_len, secret_key, nullptr, 0);
  }
  return PQCFUZZ_INVALID_INPUT;
}

size_t CompressedCapacity(unsigned logn) {
  return logn == 9 ? FALCON_SIG_COMPRESSED_MAXSIZE(9) : FALCON_SIG_COMPRESSED_MAXSIZE(10);
}

size_t VerifyCapacity(unsigned logn) {
  return logn == 9 ? FALCON_TMPSIZE_VERIFY(9) : FALCON_TMPSIZE_VERIFY(10);
}

}  // namespace

pqcfuzz_status SignAttachedSeeded(
    unsigned logn,
    const uint8_t *seed,
    size_t seed_len,
    uint8_t *signed_message,
    size_t *signed_message_len,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *secret_key) {
  if (signed_message == nullptr || signed_message_len == nullptr || secret_key == nullptr ||
      (message == nullptr && message_len != 0)) {
    return PQCFUZZ_INVALID_INPUT;
  }
  std::vector<uint8_t> detached(CompressedCapacity(logn));
  size_t detached_len = detached.size();
  const pqcfuzz_status status =
      SignCompressed(logn, seed, seed_len, detached.data(), &detached_len, message, message_len, secret_key);
  if (status != PQCFUZZ_OK) {
    return status;
  }
  const size_t compressed_len = detached_len - kDetachedPayloadOffset;
  const size_t sigpart_len = 1 + compressed_len;
  const size_t total = 2 + kSaltLen + message_len + sigpart_len;
  if (sigpart_len > 0xFFFFu || *signed_message_len < total) {
    return PQCFUZZ_INVALID_INPUT;
  }
  signed_message[0] = static_cast<uint8_t>(sigpart_len >> 8);
  signed_message[1] = static_cast<uint8_t>(sigpart_len & 0xFFu);
  std::memcpy(signed_message + 2, detached.data() + 1, kSaltLen);
  std::memcpy(signed_message + 2 + kSaltLen, message, message_len);
  signed_message[2 + kSaltLen + message_len] = static_cast<uint8_t>(0x20 + logn);
  std::memcpy(signed_message + 2 + kSaltLen + message_len + 1, detached.data() + kDetachedPayloadOffset,
              compressed_len);
  *signed_message_len = total;
  return PQCFUZZ_OK;
}

pqcfuzz_status SignAttached(
    unsigned logn,
    uint8_t *signed_message,
    size_t *signed_message_len,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *secret_key) {
  return SignAttachedSeeded(logn, nullptr, 0, signed_message, signed_message_len, message, message_len, secret_key);
}

pqcfuzz_status OpenAttached(
    unsigned logn,
    uint8_t *message,
    size_t *message_len,
    const uint8_t *signed_message,
    size_t signed_message_len,
    const uint8_t *public_key) {
  if (message == nullptr || message_len == nullptr || signed_message == nullptr || public_key == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  if (signed_message_len < 2 + kSaltLen + 1) {
    return PQCFUZZ_REJECT;
  }
  const size_t sigpart_len = (static_cast<size_t>(signed_message[0]) << 8) | signed_message[1];
  if (sigpart_len < 2) {
    return PQCFUZZ_REJECT;
  }
  const size_t compressed_len = sigpart_len - 1;
  // Guard the size_t arithmetic before subtracting: the frame must leave room
  // for the BE16 prefix, the salt, the nonce-less header and the value.
  if (compressed_len > signed_message_len - 2 - kSaltLen - 1) {
    return PQCFUZZ_REJECT;
  }
  const size_t message_off = 2 + kSaltLen;
  const size_t message_frame_len = signed_message_len - 2 - kSaltLen - 1 - compressed_len;
  const uint8_t nonce_less_header = signed_message[message_off + message_frame_len];
  if (nonce_less_header != static_cast<uint8_t>(0x20 + logn)) {
    return PQCFUZZ_REJECT;
  }
  const uint8_t *value = signed_message + message_off + message_frame_len + 1;
  std::vector<uint8_t> detached(1 + kSaltLen + compressed_len);
  detached[0] = static_cast<uint8_t>(0x30 + logn);
  std::memcpy(detached.data() + 1, signed_message + 2, kSaltLen);
  std::memcpy(detached.data() + 1 + kSaltLen, value, compressed_len);

  std::vector<uint8_t> tmp(VerifyCapacity(logn));
  const int rc = falcon_verify(detached.data(), detached.size(), FALCON_SIG_COMPRESSED, public_key,
                               FALCON_PUBKEY_SIZE(logn), signed_message + message_off, message_frame_len, tmp.data(),
                               tmp.size());
  if (rc != 0) {
    return PQCFUZZ_REJECT;
  }
  std::memmove(message, signed_message + message_off, message_frame_len);
  *message_len = message_frame_len;
  return PQCFUZZ_OK;
}

}  // namespace falcon_internal
}  // namespace pqcfuzz

#endif  // PQCFUZZ_HAVE_FALCON
