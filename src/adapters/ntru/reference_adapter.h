#ifndef PQCFUZZ_ADAPTERS_NTRU_REFERENCE_ADAPTER_H
#define PQCFUZZ_ADAPTERS_NTRU_REFERENCE_ADAPTER_H

#include <cstddef>
#include <cstdint>
#include <vector>

// Test-build-only hooks over the pinned NTRU reference internals.  They are
// compiled only with PQCFUZZ_HAVE_NTRU_REFERENCE and are never linked into a
// production fuzzer/replay binary.  The Python model lane uses them to
// validate its independent codecs, Lift and DPKE decrypt/fail logic.
namespace pqcfuzz {
namespace ntru_reference {

bool SeedKeypair(
    const uint8_t *seed,
    size_t seed_len,
    std::vector<uint8_t> *public_key,
    std::vector<uint8_t> *secret_key);

bool SeedEncaps(
    const uint8_t *seed,
    size_t seed_len,
    const uint8_t *public_key,
    size_t public_key_len,
    std::vector<uint8_t> *ciphertext,
    std::vector<uint8_t> *shared_secret);

bool SampleRm(
    const uint8_t *seed,
    size_t seed_len,
    std::vector<uint8_t> *r,
    std::vector<uint8_t> *m);

bool DpkeDecryptDetailed(
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *secret_key,
    size_t secret_key_len,
    std::vector<uint8_t> *r,
    std::vector<uint8_t> *m,
    bool *fail,
    bool *fail_padding,
    bool *fail_m,
    bool *fail_r);

bool Pack3(const std::vector<uint8_t> &trits, std::vector<uint8_t> *payload);
bool Unpack3(const uint8_t *payload, size_t payload_len, std::vector<uint8_t> *trits);
bool PackQ(const std::vector<uint16_t> &coefficients, std::vector<uint8_t> *payload);
bool UnpackQ(const uint8_t *payload, size_t payload_len, std::vector<uint16_t> *coefficients);
bool Lift(const std::vector<uint8_t> &trits, std::vector<uint16_t> *coefficients);

bool IsHps();

}  // namespace ntru_reference
}  // namespace pqcfuzz

#endif
