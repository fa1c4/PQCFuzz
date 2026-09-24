#include "adapters/falcon/sig_adapter.h"

#ifdef PQCFUZZ_HAVE_FALCON

#include <cstring>

#include "adapters/falcon/falcon_adapter_impl.h"
#include "adapters/falcon/signed_message_adapter.h"
#include "adapters/status.h"

namespace pqcfuzz {
namespace {

template <unsigned LOGN>
pqcfuzz_status FalconSignAttachedT(
    uint8_t *signed_message,
    size_t *signed_message_len,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *secret_key) {
  return falcon_internal::SignAttached(LOGN, signed_message, signed_message_len, message, message_len, secret_key);
}

template <unsigned LOGN>
pqcfuzz_status FalconOpenAttachedT(
    uint8_t *message,
    size_t *message_len,
    const uint8_t *signed_message,
    size_t signed_message_len,
    const uint8_t *public_key) {
  return falcon_internal::OpenAttached(LOGN, message, message_len, signed_message, signed_message_len, public_key);
}

}  // namespace
}  // namespace pqcfuzz

namespace {

using pqcfuzz::FalconKeygenSeededT;
using pqcfuzz::FalconKeygenT;
using pqcfuzz::FalconOpenAttachedT;
using pqcfuzz::FalconSignAttachedT;
using pqcfuzz::FalconSignSeededT;
using pqcfuzz::FalconSignT;
using pqcfuzz::FalconVerifyT;

#define PQCFUZZ_FALCON_ADAPTER(NAME, IMPL, ALG, LOGN, SIGTYPE)                                                     \
  const pqcfuzz_sig_adapter NAME = {                                                                               \
      "falcon",                                                                                                    \
      IMPL,                                                                                                        \
      ALG,                                                                                                         \
      FALCON_PUBKEY_SIZE(LOGN),                                                                                    \
      FALCON_PRIVKEY_SIZE(LOGN),                                                                                   \
      (SIGTYPE) == FALCON_SIG_COMPRESSED                                                                           \
          ? FALCON_SIG_COMPRESSED_MAXSIZE(LOGN)                                                                    \
          : ((SIGTYPE) == FALCON_SIG_PADDED ? FALCON_SIG_PADDED_SIZE(LOGN) : FALCON_SIG_CT_SIZE(LOGN)),            \
      0,                                                                                                           \
      1,                                                                                                           \
      0,                                                                                                           \
      &FalconKeygenT<LOGN>,                                                                                        \
      &FalconSignT<LOGN, SIGTYPE>,                                                                                 \
      &FalconVerifyT<LOGN, SIGTYPE>,                                                                               \
      &FalconSignSeededT<LOGN, SIGTYPE>,                                                                           \
      1,                                                                                                           \
      0,                                                                                                           \
      0,                                                                                                           \
      "Falcon-impl-20211101",                                                                                      \
      &FalconKeygenSeededT<LOGN>,                                                                                  \
      &FalconSignAttachedT<LOGN>,                                                                                  \
      &FalconOpenAttachedT<LOGN>,                                                                                  \
  }

PQCFUZZ_FALCON_ADAPTER(kFalcon512Compressed, "falcon_reference_512_compressed", "FALCON-512-COMPRESSED", 9,
                       FALCON_SIG_COMPRESSED);
PQCFUZZ_FALCON_ADAPTER(kFalcon1024Compressed, "falcon_reference_1024_compressed", "FALCON-1024-COMPRESSED", 10,
                       FALCON_SIG_COMPRESSED);
PQCFUZZ_FALCON_ADAPTER(kFalcon512Padded, "falcon_reference_512_padded", "FALCON-512-PADDED", 9, FALCON_SIG_PADDED);
PQCFUZZ_FALCON_ADAPTER(kFalcon1024Padded, "falcon_reference_1024_padded", "FALCON-1024-PADDED", 10,
                       FALCON_SIG_PADDED);
PQCFUZZ_FALCON_ADAPTER(kFalcon512Ct, "falcon_reference_512_ct", "FALCON-512-CT", 9, FALCON_SIG_CT);
PQCFUZZ_FALCON_ADAPTER(kFalcon1024Ct, "falcon_reference_1024_ct", "FALCON-1024-CT", 10, FALCON_SIG_CT);

#undef PQCFUZZ_FALCON_ADAPTER

const pqcfuzz_sig_adapter *const kFalconAdapters[] = {
    &kFalcon512Compressed, &kFalcon1024Compressed, &kFalcon512Padded,
    &kFalcon1024Padded,    &kFalcon512Ct,          &kFalcon1024Ct,
};

}  // namespace

extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_falcon_sig_adapter(const char *implementation_id) {
  if (implementation_id == nullptr) {
    return nullptr;
  }
  for (const pqcfuzz_sig_adapter *adapter : kFalconAdapters) {
    if (std::strcmp(adapter->implementation_id, implementation_id) == 0) {
      return adapter;
    }
  }
  return nullptr;
}

#else

extern "C" const pqcfuzz_sig_adapter *pqcfuzz_get_falcon_sig_adapter(const char *implementation_id) {
  (void)implementation_id;
  return nullptr;
}

#endif  // PQCFUZZ_HAVE_FALCON
