#ifndef PQCFUZZ_ADAPTERS_KEX_ADAPTER_INTERFACE_H
#define PQCFUZZ_ADAPTERS_KEX_ADAPTER_INTERFACE_H

#include <stddef.h>
#include <stdint.h>

#include "adapters/status.h"

#ifdef __cplusplus
extern "C" {
#endif

// Key-exchange ABI.  Roles are explicit because SIDH uses different secret
// scalar spaces and (potentially) different private-key storage formats per
// role; a single global sk_len must never stand in for both sides.
//
// derive_a(out, peer_pk_b, own_sk_a)  -> Alice's shared value from Bob's pk
// derive_b(out, peer_pk_a, own_sk_b)  -> Bob's shared value from Alice's pk
typedef pqcfuzz_status (*pqcfuzz_kex_keygen_a_fn)(uint8_t *pk_a, uint8_t *sk_a);
typedef pqcfuzz_status (*pqcfuzz_kex_keygen_b_fn)(uint8_t *pk_b, uint8_t *sk_b);
typedef pqcfuzz_status (*pqcfuzz_kex_derive_a_fn)(
    uint8_t *shared,
    const uint8_t *peer_pk_b,
    const uint8_t *own_sk_a);
typedef pqcfuzz_status (*pqcfuzz_kex_derive_b_fn)(
    uint8_t *shared,
    const uint8_t *peer_pk_a,
    const uint8_t *own_sk_b);

// Deterministic scalar hooks: generate the public key from an explicit
// scalar.  Optional; callers must check for nullptr.
typedef pqcfuzz_status (*pqcfuzz_kex_keygen_a_scalar_fn)(uint8_t *pk_a, const uint8_t *scalar_a);
typedef pqcfuzz_status (*pqcfuzz_kex_keygen_b_scalar_fn)(uint8_t *pk_b, const uint8_t *scalar_b);

typedef struct pqcfuzz_kex_adapter {
  const char *project_id;
  const char *implementation_id;
  const char *algorithm;
  size_t pk_len;
  size_t sk_a_len;
  size_t sk_b_len;
  size_t shared_len;
  pqcfuzz_kex_keygen_a_fn keygen_a;
  pqcfuzz_kex_keygen_b_fn keygen_b;
  pqcfuzz_kex_derive_a_fn derive_a;
  pqcfuzz_kex_derive_b_fn derive_b;
  pqcfuzz_kex_keygen_a_scalar_fn keygen_a_scalar;
  pqcfuzz_kex_keygen_b_scalar_fn keygen_b_scalar;
  // Bytes of randomness each role's key generation consumes; 0 when the
  // adapter cannot state it.
  size_t keygen_a_rng_bytes;
  size_t keygen_b_rng_bytes;
  const char *reference_version;
} pqcfuzz_kex_adapter;

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

#include <string>
#include <vector>

namespace pqcfuzz {

enum class KexRole {
  kAlice,
  kBob,
};

inline const char *KexRoleName(KexRole role) {
  return role == KexRole::kAlice ? "alice" : "bob";
}

// A role-tagged private key.  Passing a key under the wrong role is a harness
// error, not a cryptographic rejection: the typed wrappers below refuse to
// route it into the target at all.
struct KexRoleKey {
  KexRole role = KexRole::kAlice;
  std::vector<uint8_t> bytes;
};

inline size_t KexRolePrivateKeyLength(const pqcfuzz_kex_adapter &adapter, KexRole role) {
  return role == KexRole::kAlice ? adapter.sk_a_len : adapter.sk_b_len;
}

inline bool KexRoleKeyMatches(const pqcfuzz_kex_adapter &adapter, const KexRoleKey &key) {
  return key.bytes.size() == KexRolePrivateKeyLength(adapter, key.role);
}

// Typed wrappers: a role mismatch is rejected before the target is entered.
inline pqcfuzz_status KexKeygenTyped(
    const pqcfuzz_kex_adapter *adapter,
    KexRole role,
    uint8_t *pk,
    KexRoleKey *key) {
  if (adapter == nullptr || pk == nullptr || key == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  key->role = role;
  key->bytes.assign(KexRolePrivateKeyLength(*adapter, role), 0);
  if (role == KexRole::kAlice) {
    return adapter->keygen_a != nullptr ? adapter->keygen_a(pk, key->bytes.data()) : PQCFUZZ_API_UNSUPPORTED;
  }
  return adapter->keygen_b != nullptr ? adapter->keygen_b(pk, key->bytes.data()) : PQCFUZZ_API_UNSUPPORTED;
}

inline pqcfuzz_status KexDeriveTyped(
    const pqcfuzz_kex_adapter *adapter,
    KexRole role,
    uint8_t *shared,
    const uint8_t *peer_pk,
    const KexRoleKey &key) {
  if (adapter == nullptr || shared == nullptr || peer_pk == nullptr) {
    return PQCFUZZ_INVALID_INPUT;
  }
  if (!KexRoleKeyMatches(*adapter, key)) {
    // Structurally wrong role/length combination: the harness must not call
    // the target with it.
    return PQCFUZZ_INVALID_INPUT;
  }
  if (role != key.role) {
    return PQCFUZZ_INVALID_INPUT;
  }
  if (role == KexRole::kAlice) {
    return adapter->derive_a != nullptr ? adapter->derive_a(shared, peer_pk, key.bytes.data())
                                        : PQCFUZZ_API_UNSUPPORTED;
  }
  return adapter->derive_b != nullptr ? adapter->derive_b(shared, peer_pk, key.bytes.data())
                                      : PQCFUZZ_API_UNSUPPORTED;
}

}  // namespace pqcfuzz

#endif  // __cplusplus

#endif  // PQCFUZZ_ADAPTERS_KEX_ADAPTER_INTERFACE_H
