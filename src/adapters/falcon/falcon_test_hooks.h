#ifndef PQCFUZZ_ADAPTERS_FALCON_TEST_HOOKS_H
#define PQCFUZZ_ADAPTERS_FALCON_TEST_HOOKS_H

#include <cstddef>
#include <cstdint>
#include <vector>

// Test-build-only probes over the pinned Falcon reference internals.  They are
// never linked into the production fuzzers; the Python model lane uses them to
// validate its independent codec, HashToPoint and key-equation implementations
// against the reference for fixed inputs.

namespace pqcfuzz {
namespace falcon_test {

bool HookCompDecode(
    const uint8_t *payload,
    size_t payload_len,
    unsigned logn,
    std::vector<int16_t> *coefficients,
    size_t *consumed_bytes);

bool HookCompEncode(const std::vector<int16_t> &coefficients, unsigned logn, std::vector<uint8_t> *payload);

bool HookTrimDecode(
    const uint8_t *payload,
    size_t payload_len,
    unsigned logn,
    std::vector<int16_t> *coefficients);

bool HookHashToPoint(
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *message,
    size_t message_len,
    unsigned logn,
    std::vector<uint16_t> *coefficients);

bool HookKeygenFromSeed(
    const uint8_t seed[48],
    unsigned logn,
    std::vector<uint8_t> *public_key,
    std::vector<uint8_t> *secret_key);

bool HookSignFromSeed(
    const uint8_t seed[48],
    unsigned logn,
    const uint8_t *secret_key,
    const uint8_t *message,
    size_t message_len,
    int sig_type,
    std::vector<uint8_t> *signature);

bool HookCompletePrivate(
    const uint8_t *secret_key,
    unsigned logn,
    std::vector<int8_t> *f,
    std::vector<int8_t> *g,
    std::vector<int8_t> *F,
    std::vector<int8_t> *G);

bool HookVerify(
    const uint8_t *signature,
    size_t signature_len,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *public_key,
    int sig_type);

}  // namespace falcon_test
}  // namespace pqcfuzz

#endif
