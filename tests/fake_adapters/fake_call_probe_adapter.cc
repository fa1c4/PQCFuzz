#include "adapters/adapter_interface.h"
#include "runtime/call_probe.h"

#include <cstring>

namespace {

pqcfuzz_status Keygen(uint8_t *pk, uint8_t *sk) {
  pqcfuzz::MarkAdapterEntered();
  pqcfuzz::MarkTargetEntered();
  std::memset(pk, 0x11, 4);
  std::memset(sk, 0x12, 4);
  pqcfuzz::MarkTargetReturned();
  return PQCFUZZ_OK;
}

pqcfuzz_status Encaps(uint8_t *ct, uint8_t *ss, const uint8_t *) {
  pqcfuzz::MarkAdapterEntered();
  pqcfuzz::MarkTargetEntered();
  std::memset(ct, 0x21, 4);
  std::memset(ss, 0x22, 4);
  pqcfuzz::MarkTargetReturned();
  return PQCFUZZ_OK;
}

pqcfuzz_status Decaps(uint8_t *ss, const uint8_t *, const uint8_t *) {
  pqcfuzz::MarkAdapterEntered();
  pqcfuzz::MarkTargetEntered();
  std::memset(ss, 0x22, 4);
  pqcfuzz::MarkTargetReturned();
  return PQCFUZZ_OK;
}

const pqcfuzz_kem_adapter kAdapter = {
    "fake", "fake_call_probe", "ML-KEM-768", 4, 4, 4, 4, Keygen, Encaps, Decaps};

}  // namespace

extern "C" const pqcfuzz_kem_adapter *pqcfuzz_fake_call_probe_adapter() {
  return &kAdapter;
}
