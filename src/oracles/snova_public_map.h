#ifndef PQCFUZZ_ORACLES_SNOVA_PUBLIC_MAP_H
#define PQCFUZZ_ORACLES_SNOVA_PUBLIC_MAP_H

#include <cstddef>
#include <cstdint>
#include <vector>

#include "mutators/snova_layout.h"

namespace pqcfuzz {

// Independent GF16 implementation of the SNOVA public map and target hash.
// It deliberately does not call the target's evaluation code: the executor
// feeds it the packed expanded public key produced by the adapter and checks
// that the recomputed map agrees with SHAKE256(spublic || digest || salt) for
// exactly the profile nibble count.

// signed_hash = SHAKE256(spublic || digest || salt) squeezed to params.hash_bytes.
bool SnovaTargetHashBytes(
    const SnovaParams &params,
    const uint8_t *spublic,
    size_t spublic_len,
    const uint8_t *digest,
    size_t digest_len,
    const uint8_t *salt,
    size_t salt_len,
    std::vector<uint8_t> *out);

// Direct triple-sum evaluation of Ptilde(U) over the expanded public key.
// `expanded_pk` is the adapter's packed (seed || P22,P11,P12,P21,A,B,Q1,Q2)
// nibble stream; `signature` is the full U || salt buffer.  The output is the
// m*l*l GF16 nibbles of Ptilde(U), low nibble first.
bool SnovaEvaluateExpandedPk(
    const SnovaParams &params,
    const std::vector<uint8_t> &expanded_pk,
    const std::vector<uint8_t> &signature,
    std::vector<uint8_t> *out);

// Compare a byte-packed map result with a squeezed hash, masking the unused
// high nibble of the final byte when the nibble count is odd.
bool SnovaMapBytesEqual(
    const SnovaParams &params,
    const std::vector<uint8_t> &map_bytes,
    const std::vector<uint8_t> &target_hash);

}  // namespace pqcfuzz

#endif
