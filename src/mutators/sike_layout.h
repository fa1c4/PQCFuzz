#ifndef PQCFUZZ_MUTATORS_SIKE_LAYOUT_H
#define PQCFUZZ_MUTATORS_SIKE_LAYOUT_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "mutators/ml_kem_layout.h"

namespace pqcfuzz {

// One SIKE uncompressed parameter set from src/config/scheme_profiles/sike.json.
// The field is p = 2^e2 * 3^e3 - 1 with Np = ceil(bitlen(p)/8) little-endian
// octets per Fp element; Fp2 is encoded as real || imag.
struct SikeParams {
  const char *algorithm = "";
  size_t e2 = 0;
  size_t e3 = 0;
  size_t np = 0;       // bytes per Fp element
  size_t nsk2 = 0;     // ceil(e2/8)
  size_t nsk3 = 0;     // ceil(floor(log2(3^e3))/8)
  size_t msg_bytes = 0;
  size_t pk_len = 0;
  size_t sk_len = 0;
  size_t ct_len = 0;
  size_t ss_len = 0;
  // Secret-key segment offsets: sk = s || sk3 || pk3.
  size_t sk_s_off = 0;
  size_t sk_sk3_off = 0;
  size_t sk_pk_off = 0;
  // Ciphertext: ct = c0 || c1.
  size_t c0_len = 0;
  size_t c1_off = 0;
};

// SIDH shares the field/layout primitives with SIKE but has role-specific
// private keys and no ciphertext.
struct SidhParams {
  const char *algorithm = "";
  size_t e2 = 0;
  size_t e3 = 0;
  size_t np = 0;
  size_t nsk2 = 0;
  size_t nsk3 = 0;
  size_t pk_len = 0;
  size_t sk_a_len = 0;
  size_t sk_b_len = 0;
  size_t shared_len = 0;
};

bool GetSikeParams(const std::string &algorithm, SikeParams *params);
bool GetSidhParams(const std::string &algorithm, SidhParams *params);

// ---------------------------------------------------------------------------
// Minimal fixed-precision unsigned integer (768 bits) used for the field
// modulus p = 2^e2 * 3^e3 - 1 and for canonical-range classification.  This
// is intentionally independent of the target's fixed-width Montgomery code.
struct SikeBig {
  static constexpr size_t kLimbs = 12;
  uint64_t limb[kLimbs] = {0};
};

bool ComputeSikeFieldPrime(size_t e2, size_t e3, SikeBig *p);
// floor(log2(3^e3)) without floating point.
bool ComputeSikeBobScalarBits(size_t e3, size_t *sbits);
int SikeBigCompare(const SikeBig &a, const SikeBig &b);
bool SikeBigFromLeBytes(const uint8_t *bytes, size_t len, SikeBig *out);
void SikeBigToLeBytes(const SikeBig &value, uint8_t *out, size_t len);
bool SikeBigToU64(const SikeBig &value, uint64_t *out);

// Canonical little-endian Fp decoding: true when the Np-byte value is in
// [0, p-1].
bool SikeFpCanonical(const uint8_t *bytes, size_t len, const SikeBig &p);

// ---------------------------------------------------------------------------
std::vector<MlKemRegion> SikePublicKeyRegions(const SikeParams &params);
std::vector<MlKemRegion> SikeCiphertextRegions(const SikeParams &params);
std::vector<MlKemRegion> SikeSecretKeyRegions(const SikeParams &params);
std::vector<MlKemRegion> SidhPublicKeyRegions(const SidhParams &params);

// Number of Fp2 coordinates in a public key (3) and in c0 (3).
size_t SikePublicKeyCoordinateCount();
size_t SikeCiphertextCoordinateCount();

// Offset of Fp2 coordinate `coordinate` inside a buffer whose first
// coordinate starts at `base`, or SIZE_MAX when out of range.
size_t SikeCoordinateOffset(size_t base, size_t coordinate, size_t np);

}  // namespace pqcfuzz

#endif
