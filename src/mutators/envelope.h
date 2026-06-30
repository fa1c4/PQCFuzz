#ifndef PQCFUZZ_MUTATORS_ENVELOPE_H
#define PQCFUZZ_MUTATORS_ENVELOPE_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pqcfuzz {

enum class AlgorithmId : uint8_t {
  kUnknown = 0,
  kMlKem512 = 1,
  kMlKem768 = 2,
  kMlKem1024 = 3,
  kMlDsa44 = 4,
  kMlDsa65 = 5,
  kMlDsa87 = 6,
  kSlhDsaSha2_128s = 7,
  kSlhDsaShake_128s = 8,
  kSlhDsaSha2_128f = 9,
  kSlhDsaShake_128f = 10,
  kSlhDsaSha2_192s = 11,
  kSlhDsaShake_192s = 12,
  kSlhDsaSha2_192f = 13,
  kSlhDsaShake_192f = 14,
  kSlhDsaSha2_256s = 15,
  kSlhDsaShake_256s = 16,
  kSlhDsaSha2_256f = 17,
  kSlhDsaShake_256f = 18,
};

enum class OracleId : uint8_t {
  kUnknown = 0,
  kMlKemLocalRoundtrip = 1,
  kMlKemCrossExchangeRoundtrip = 2,
  kMlKemTamperedCiphertextImplicitRejection = 3,
  kMlKemBadRandomnessSanity = 4,
  kMlDsaLocalSignVerify = 5,
  kMlDsaCrossVerify = 6,
  kMlDsaMutatedSignatureNegative = 7,
  kMlDsaMutatedMessageNegative = 8,
  kMlDsaMutatedContextNegative = 9,
  kMlDsaOidFieldMutationSanity = 10,
  kMlDsaBadRandomnessSanity = 11,
  kSlhDsaLocalSignVerify = 12,
  kSlhDsaCrossVerify = 13,
  kSlhDsaMutatedSignatureNegative = 14,
  kSlhDsaMutatedMessageNegative = 15,
  kSlhDsaMutatedContextNegative = 16,
  kSlhDsaBadRandomnessSanity = 17,
  kKemDecapsCiphertext = 18,
  kKemDecapsSecretKey = 19,
  kKemEncapsBadRng = 20,
  kKemEncapsZeroPublicKey = 21,
  kKemEncapsPublicKey = 22,
  kKemKeygenBadRng = 23,
  kSigKeygenBadRng = 24,
  kSigSignBadRng = 25,
  kSigSignMessage = 26,
  kSigSignSecretKey = 27,
  kSigVerifyMessage = 28,
  kSigVerifySignature = 29,
  kSigVerifyPublicKey = 30,
};

struct Envelope {
  uint8_t version = 0;
  AlgorithmId algorithm = AlgorithmId::kUnknown;
  OracleId oracle_id = OracleId::kUnknown;
  uint8_t flags = 0;
  std::vector<uint8_t> seed;
  std::vector<uint8_t> msg;
  std::vector<uint8_t> mutation;
  std::vector<uint8_t> extra;
};

const char *AlgorithmName(AlgorithmId algorithm);
const char *OracleName(OracleId oracle_id);
AlgorithmId AlgorithmIdFromName(const std::string &name);
OracleId OracleIdFromName(const std::string &name);
bool ParseEnvelope(const uint8_t *data, size_t size, Envelope *envelope, std::string *error);

}  // namespace pqcfuzz

#endif
