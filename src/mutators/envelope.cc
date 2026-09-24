#include "mutators/envelope.h"

#include <cstring>

namespace pqcfuzz {
namespace {

bool ReadU16(const uint8_t *data, size_t size, size_t *offset, uint16_t *value) {
  if (*offset + 2 > size) {
    return false;
  }
  *value = static_cast<uint16_t>(data[*offset]) | static_cast<uint16_t>(data[*offset + 1] << 8);
  *offset += 2;
  return true;
}

bool ReadSlice(const uint8_t *data, size_t size, size_t *offset, uint16_t length, std::vector<uint8_t> *out) {
  if (*offset + length > size) {
    return false;
  }
  out->assign(data + *offset, data + *offset + length);
  *offset += length;
  return true;
}

bool IsKnownAlgorithmId(AlgorithmId algorithm) {
  switch (algorithm) {
    case AlgorithmId::kMlKem512:
    case AlgorithmId::kMlKem768:
    case AlgorithmId::kMlKem1024:
    case AlgorithmId::kMlDsa44:
    case AlgorithmId::kMlDsa65:
    case AlgorithmId::kMlDsa87:
    case AlgorithmId::kSlhDsaSha2_128s:
    case AlgorithmId::kSlhDsaShake_128s:
    case AlgorithmId::kSlhDsaSha2_128f:
    case AlgorithmId::kSlhDsaShake_128f:
    case AlgorithmId::kSlhDsaSha2_192s:
    case AlgorithmId::kSlhDsaShake_192s:
    case AlgorithmId::kSlhDsaSha2_192f:
    case AlgorithmId::kSlhDsaShake_192f:
    case AlgorithmId::kSlhDsaSha2_256s:
    case AlgorithmId::kSlhDsaShake_256s:
    case AlgorithmId::kSlhDsaSha2_256f:
    case AlgorithmId::kSlhDsaShake_256f:
    case AlgorithmId::kAigisEnc1:
    case AlgorithmId::kAigisEnc2:
    case AlgorithmId::kAigisEnc3:
    case AlgorithmId::kAigisEnc4:
    case AlgorithmId::kAigisSig1:
    case AlgorithmId::kAigisSig2:
    case AlgorithmId::kAigisSig3:
      return true;
    case AlgorithmId::kNtruHps2048509:
    case AlgorithmId::kNtruHps2048677:
    case AlgorithmId::kNtruHps4096821:
    case AlgorithmId::kNtruHrss701:
      return true;
    case AlgorithmId::kFalcon512Compressed:
    case AlgorithmId::kFalcon1024Compressed:
    case AlgorithmId::kFalcon512Padded:
    case AlgorithmId::kFalcon1024Padded:
    case AlgorithmId::kFalcon512Ct:
    case AlgorithmId::kFalcon1024Ct:
      return true;
    case AlgorithmId::kCrossRsdp1Fast:
    case AlgorithmId::kCrossRsdp1Balanced:
    case AlgorithmId::kCrossRsdp1Small:
    case AlgorithmId::kCrossRsdp3Fast:
    case AlgorithmId::kCrossRsdp3Balanced:
    case AlgorithmId::kCrossRsdp3Small:
    case AlgorithmId::kCrossRsdp5Fast:
    case AlgorithmId::kCrossRsdp5Balanced:
    case AlgorithmId::kCrossRsdp5Small:
    case AlgorithmId::kCrossRsdpg1Fast:
    case AlgorithmId::kCrossRsdpg1Balanced:
    case AlgorithmId::kCrossRsdpg1Small:
    case AlgorithmId::kCrossRsdpg3Fast:
    case AlgorithmId::kCrossRsdpg3Balanced:
    case AlgorithmId::kCrossRsdpg3Small:
    case AlgorithmId::kCrossRsdpg5Fast:
    case AlgorithmId::kCrossRsdpg5Balanced:
    case AlgorithmId::kCrossRsdpg5Small:
      return true;
    case AlgorithmId::kUnknown:
      return false;
  }
  return false;
}

bool IsKnownOracleId(OracleId oracle_id) {
  switch (oracle_id) {
    case OracleId::kMlKemLocalRoundtrip:
    case OracleId::kMlKemCrossExchangeRoundtrip:
    case OracleId::kMlKemTamperedCiphertextImplicitRejection:
    case OracleId::kMlKemBadRandomnessSanity:
    case OracleId::kMlDsaLocalSignVerify:
    case OracleId::kMlDsaCrossVerify:
    case OracleId::kMlDsaMutatedSignatureNegative:
    case OracleId::kMlDsaMutatedMessageNegative:
    case OracleId::kMlDsaMutatedContextNegative:
    case OracleId::kMlDsaOidFieldMutationSanity:
    case OracleId::kMlDsaBadRandomnessSanity:
    case OracleId::kSlhDsaLocalSignVerify:
    case OracleId::kSlhDsaCrossVerify:
    case OracleId::kSlhDsaMutatedSignatureNegative:
    case OracleId::kSlhDsaMutatedMessageNegative:
    case OracleId::kSlhDsaMutatedContextNegative:
    case OracleId::kSlhDsaBadRandomnessSanity:
    case OracleId::kKemDecapsCiphertext:
    case OracleId::kKemDecapsSecretKey:
    case OracleId::kKemEncapsBadRng:
    case OracleId::kKemEncapsZeroPublicKey:
    case OracleId::kKemEncapsPublicKey:
    case OracleId::kKemKeygenBadRng:
    case OracleId::kSigKeygenBadRng:
    case OracleId::kSigSignBadRng:
    case OracleId::kSigSignMessage:
    case OracleId::kSigSignSecretKey:
    case OracleId::kSigVerifyMessage:
    case OracleId::kSigVerifySignature:
    case OracleId::kSigVerifyPublicKey:
    case OracleId::kAigisEncLocalRoundtrip:
    case OracleId::kAigisEncCrossExchangeRoundtrip:
    case OracleId::kAigisEncTamperedCiphertextImplicitRejection:
    case OracleId::kAigisEncBadRandomnessSanity:
    case OracleId::kAigisEncSkNoncanonicalCoefficient:
    case OracleId::kAigisSigLocalSignVerify:
    case OracleId::kAigisSigCrossVerify:
    case OracleId::kAigisSigMutatedSignatureNegative:
    case OracleId::kAigisSigMutatedMessageNegative:
    case OracleId::kAigisSigMutatedContextNegative:
    case OracleId::kAigisSigBadRandomnessSanity:
    case OracleId::kAigisSigExactLength:
    case OracleId::kAigisSigUnusedSignBits:
    case OracleId::kAigisSigCtx256FailureState:
    case OracleId::kAigisSigDeterminismProfile:
    case OracleId::kMlKemImplicitRejectionRelations:
    case OracleId::kAigisEncImplicitRejectionRelations:
    case OracleId::kMlDsaVerifyExactLengths:
    case OracleId::kMlDsaCtxBoundaries:
    case OracleId::kSlhDsaVerifyExactLengths:
    case OracleId::kSlhDsaCtxBoundaries:
    case OracleId::kMlKemRawLengthBoundary:
    case OracleId::kMlKemEkCanonicality:
    case OracleId::kMlDsaHintCanonicality:
    case OracleId::kMlDsaZNormBoundary:
    case OracleId::kMlDsaRndDeterminism:
    case OracleId::kMlDsaPurePrehashSeparation:
    case OracleId::kMlDsaPhOidSeparation:
    case OracleId::kSlhDsaPurePrehashSeparation:
    case OracleId::kSlhDsaPhOidSeparation:
    case OracleId::kMlKemRngFailure:
    case OracleId::kMlDsaRngFailure:
    case OracleId::kSlhDsaRngFailure:
      return true;
    case OracleId::kNtruKat:
    case OracleId::kNtruLocalRoundtrip:
    case OracleId::kNtruCrossExchange:
    case OracleId::kNtruDpkeMembership:
    case OracleId::kNtruCtPadding:
    case OracleId::kNtruImplicitRejectionExact:
    case OracleId::kNtruPrfKeySeparation:
    case OracleId::kNtruKeyAlgebra:
    case OracleId::kNtruCodecRoundtrip:
    case OracleId::kNtruSkMalformed:
    case OracleId::kNtruLengths:
    case OracleId::kNtruRngAndReplay:
    case OracleId::kNtruFailureState:
    case OracleId::kNtruDpkeFailureOutput:
    case OracleId::kNtruFaultChecks:
    case OracleId::kNtruTimingResources:
      return true;
    case OracleId::kFalconKat:
    case OracleId::kFalconLocalSignVerify:
    case OracleId::kFalconCrossVerify:
    case OracleId::kFalconMessageSaltBinding:
    case OracleId::kFalconHeaderProfile:
    case OracleId::kFalconPkCoefficients:
    case OracleId::kFalconCompressedCanonicality:
    case OracleId::kFalconFormatLengths:
    case OracleId::kFalconNormEquation:
    case OracleId::kFalconNormBoundaryUnit:
    case OracleId::kFalconHashToPoint:
    case OracleId::kFalconKeyEquation:
    case OracleId::kFalconSkCodec:
    case OracleId::kFalconRngReplay:
    case OracleId::kFalconFailureState:
    case OracleId::kFalconSignedMessageFrame:
    case OracleId::kFalconSamplerArithmetic:
    case OracleId::kFalconFaultChecks:
    case OracleId::kFalconTimingResources:
      return true;
    case OracleId::kCrossKat:
    case OracleId::kCrossLocalSignVerify:
    case OracleId::kCrossCrossVerify:
    case OracleId::kCrossMessageKeyBinding:
    case OracleId::kCrossExactLengths:
    case OracleId::kCrossPackedFieldRange:
    case OracleId::kCrossVectorPadding:
    case OracleId::kCrossChallengeSampling:
    case OracleId::kCrossCommitmentDigests:
    case OracleId::kCrossDomainTranscript:
    case OracleId::kCrossSeedRebuild:
    case OracleId::kCrossMerkleProof:
    case OracleId::kCrossPathProofConsumption:
    case OracleId::kCrossKeyAlgebra:
    case OracleId::kCrossRngReplay:
    case OracleId::kCrossFailureResources:
    case OracleId::kCrossParallelArithmetic:
    case OracleId::kCrossFaultSeedDisclosure:
    case OracleId::kCrossTiming:
      return true;
    case OracleId::kUnknown:
      return false;
  }
  return false;
}

}  // namespace

const char *AlgorithmName(AlgorithmId algorithm) {
  switch (algorithm) {
    case AlgorithmId::kMlKem512:
      return "ML-KEM-512";
    case AlgorithmId::kMlKem768:
      return "ML-KEM-768";
    case AlgorithmId::kMlKem1024:
      return "ML-KEM-1024";
    case AlgorithmId::kMlDsa44:
      return "ML-DSA-44";
    case AlgorithmId::kMlDsa65:
      return "ML-DSA-65";
    case AlgorithmId::kMlDsa87:
      return "ML-DSA-87";
    case AlgorithmId::kSlhDsaSha2_128s:
      return "SLH-DSA-SHA2-128s";
    case AlgorithmId::kSlhDsaShake_128s:
      return "SLH-DSA-SHAKE-128s";
    case AlgorithmId::kSlhDsaSha2_128f:
      return "SLH-DSA-SHA2-128f";
    case AlgorithmId::kSlhDsaShake_128f:
      return "SLH-DSA-SHAKE-128f";
    case AlgorithmId::kSlhDsaSha2_192s:
      return "SLH-DSA-SHA2-192s";
    case AlgorithmId::kSlhDsaShake_192s:
      return "SLH-DSA-SHAKE-192s";
    case AlgorithmId::kSlhDsaSha2_192f:
      return "SLH-DSA-SHA2-192f";
    case AlgorithmId::kSlhDsaShake_192f:
      return "SLH-DSA-SHAKE-192f";
    case AlgorithmId::kSlhDsaSha2_256s:
      return "SLH-DSA-SHA2-256s";
    case AlgorithmId::kSlhDsaShake_256s:
      return "SLH-DSA-SHAKE-256s";
    case AlgorithmId::kSlhDsaSha2_256f:
      return "SLH-DSA-SHA2-256f";
    case AlgorithmId::kSlhDsaShake_256f:
      return "SLH-DSA-SHAKE-256f";
    case AlgorithmId::kAigisEnc1:
      return "AIGIS-ENC-1";
    case AlgorithmId::kAigisEnc2:
      return "AIGIS-ENC-2";
    case AlgorithmId::kAigisEnc3:
      return "AIGIS-ENC-3";
    case AlgorithmId::kAigisEnc4:
      return "AIGIS-ENC-4";
    case AlgorithmId::kAigisSig1:
      return "AIGIS-SIG-1";
    case AlgorithmId::kAigisSig2:
      return "AIGIS-SIG-2";
    case AlgorithmId::kAigisSig3:
      return "AIGIS-SIG-3";
    case AlgorithmId::kNtruHps2048509:
      return "NTRU-HPS-2048-509";
    case AlgorithmId::kNtruHps2048677:
      return "NTRU-HPS-2048-677";
    case AlgorithmId::kNtruHps4096821:
      return "NTRU-HPS-4096-821";
    case AlgorithmId::kNtruHrss701:
      return "NTRU-HRSS-701";
    case AlgorithmId::kFalcon512Compressed:
      return "FALCON-512-COMPRESSED";
    case AlgorithmId::kFalcon1024Compressed:
      return "FALCON-1024-COMPRESSED";
    case AlgorithmId::kFalcon512Padded:
      return "FALCON-512-PADDED";
    case AlgorithmId::kFalcon1024Padded:
      return "FALCON-1024-PADDED";
    case AlgorithmId::kFalcon512Ct:
      return "FALCON-512-CT";
    case AlgorithmId::kFalcon1024Ct:
      return "FALCON-1024-CT";
    case AlgorithmId::kCrossRsdp1Fast:
      return "CROSS-RSDP-1-FAST";
    case AlgorithmId::kCrossRsdp1Balanced:
      return "CROSS-RSDP-1-BALANCED";
    case AlgorithmId::kCrossRsdp1Small:
      return "CROSS-RSDP-1-SMALL";
    case AlgorithmId::kCrossRsdp3Fast:
      return "CROSS-RSDP-3-FAST";
    case AlgorithmId::kCrossRsdp3Balanced:
      return "CROSS-RSDP-3-BALANCED";
    case AlgorithmId::kCrossRsdp3Small:
      return "CROSS-RSDP-3-SMALL";
    case AlgorithmId::kCrossRsdp5Fast:
      return "CROSS-RSDP-5-FAST";
    case AlgorithmId::kCrossRsdp5Balanced:
      return "CROSS-RSDP-5-BALANCED";
    case AlgorithmId::kCrossRsdp5Small:
      return "CROSS-RSDP-5-SMALL";
    case AlgorithmId::kCrossRsdpg1Fast:
      return "CROSS-RSDPG-1-FAST";
    case AlgorithmId::kCrossRsdpg1Balanced:
      return "CROSS-RSDPG-1-BALANCED";
    case AlgorithmId::kCrossRsdpg1Small:
      return "CROSS-RSDPG-1-SMALL";
    case AlgorithmId::kCrossRsdpg3Fast:
      return "CROSS-RSDPG-3-FAST";
    case AlgorithmId::kCrossRsdpg3Balanced:
      return "CROSS-RSDPG-3-BALANCED";
    case AlgorithmId::kCrossRsdpg3Small:
      return "CROSS-RSDPG-3-SMALL";
    case AlgorithmId::kCrossRsdpg5Fast:
      return "CROSS-RSDPG-5-FAST";
    case AlgorithmId::kCrossRsdpg5Balanced:
      return "CROSS-RSDPG-5-BALANCED";
    case AlgorithmId::kCrossRsdpg5Small:
      return "CROSS-RSDPG-5-SMALL";
    case AlgorithmId::kUnknown:
      return "UNKNOWN";
  }
  return "UNKNOWN";
}

const char *OracleName(OracleId oracle_id) {
  switch (oracle_id) {
    case OracleId::kMlKemLocalRoundtrip:
      return "mlkem_local_roundtrip";
    case OracleId::kMlKemCrossExchangeRoundtrip:
      return "mlkem_cross_exchange_roundtrip";
    case OracleId::kMlKemTamperedCiphertextImplicitRejection:
      return "mlkem_tampered_ciphertext_implicit_rejection";
    case OracleId::kMlKemBadRandomnessSanity:
      return "mlkem_bad_randomness_sanity";
    case OracleId::kMlDsaLocalSignVerify:
      return "mldsa_local_sign_verify";
    case OracleId::kMlDsaCrossVerify:
      return "mldsa_cross_verify";
    case OracleId::kMlDsaMutatedSignatureNegative:
      return "mldsa_mutated_signature_negative";
    case OracleId::kMlDsaMutatedMessageNegative:
      return "mldsa_mutated_message_negative";
    case OracleId::kMlDsaMutatedContextNegative:
      return "mldsa_mutated_context_negative";
    case OracleId::kMlDsaOidFieldMutationSanity:
      return "mldsa_oid_field_mutation_sanity";
    case OracleId::kMlDsaBadRandomnessSanity:
      return "mldsa_bad_randomness_sanity";
    case OracleId::kSlhDsaLocalSignVerify:
      return "slhdsa_local_sign_verify";
    case OracleId::kSlhDsaCrossVerify:
      return "slhdsa_cross_verify";
    case OracleId::kSlhDsaMutatedSignatureNegative:
      return "slhdsa_mutated_signature_negative";
    case OracleId::kSlhDsaMutatedMessageNegative:
      return "slhdsa_mutated_message_negative";
    case OracleId::kSlhDsaMutatedContextNegative:
      return "slhdsa_mutated_context_negative";
    case OracleId::kSlhDsaBadRandomnessSanity:
      return "slhdsa_bad_randomness_sanity";
    case OracleId::kKemDecapsCiphertext:
      return "kem_decaps_c";
    case OracleId::kKemDecapsSecretKey:
      return "kem_decaps_sk";
    case OracleId::kKemEncapsBadRng:
      return "kem_encaps_badrng";
    case OracleId::kKemEncapsZeroPublicKey:
      return "kem_encaps_pk_0";
    case OracleId::kKemEncapsPublicKey:
      return "kem_encaps_pk";
    case OracleId::kKemKeygenBadRng:
      return "kem_keygen_badrng";
    case OracleId::kSigKeygenBadRng:
      return "sig_keygen_badrng";
    case OracleId::kSigSignBadRng:
      return "sig_sign_badrng";
    case OracleId::kSigSignMessage:
      return "sig_sign_m";
    case OracleId::kSigSignSecretKey:
      return "sig_sign_sk";
    case OracleId::kSigVerifyMessage:
      return "sig_verify_m";
    case OracleId::kSigVerifySignature:
      return "sig_verify_sig";
    case OracleId::kSigVerifyPublicKey:
      return "sig_verify_pk";
    case OracleId::kAigisEncLocalRoundtrip:
      return "aigisenc_local_roundtrip";
    case OracleId::kAigisEncCrossExchangeRoundtrip:
      return "aigisenc_cross_exchange_roundtrip";
    case OracleId::kAigisEncTamperedCiphertextImplicitRejection:
      return "aigisenc_tampered_ciphertext_implicit_rejection";
    case OracleId::kAigisEncBadRandomnessSanity:
      return "aigisenc_bad_randomness_sanity";
    case OracleId::kAigisEncSkNoncanonicalCoefficient:
      return "aigisenc_sk_noncanonical_coefficient";
    case OracleId::kAigisSigLocalSignVerify:
      return "aigissig_local_sign_verify";
    case OracleId::kAigisSigCrossVerify:
      return "aigissig_cross_verify";
    case OracleId::kAigisSigMutatedSignatureNegative:
      return "aigissig_mutated_signature_negative";
    case OracleId::kAigisSigMutatedMessageNegative:
      return "aigissig_mutated_message_negative";
    case OracleId::kAigisSigMutatedContextNegative:
      return "aigissig_mutated_context_negative";
    case OracleId::kAigisSigBadRandomnessSanity:
      return "aigissig_bad_randomness_sanity";
    case OracleId::kAigisSigExactLength:
      return "aigissig_exact_length";
    case OracleId::kAigisSigUnusedSignBits:
      return "aigissig_unused_sign_bits";
    case OracleId::kAigisSigCtx256FailureState:
      return "aigissig_ctx256_failure_state";
    case OracleId::kAigisSigDeterminismProfile:
      return "aigissig_determinism_profile";
    case OracleId::kMlKemImplicitRejectionRelations:
      return "mlkem_implicit_rejection_relations";
    case OracleId::kAigisEncImplicitRejectionRelations:
      return "aigisenc_implicit_rejection_relations";
    case OracleId::kMlDsaVerifyExactLengths:
      return "mldsa_verify_exact_lengths";
    case OracleId::kMlDsaCtxBoundaries:
      return "mldsa_ctx_boundaries";
    case OracleId::kSlhDsaVerifyExactLengths:
      return "slhdsa_verify_exact_lengths";
    case OracleId::kSlhDsaCtxBoundaries:
      return "slhdsa_ctx_boundaries";
    case OracleId::kMlKemRawLengthBoundary:
      return "mlkem_raw_length_boundary";
    case OracleId::kMlKemEkCanonicality:
      return "mlkem_ek_canonicality";
    case OracleId::kMlDsaHintCanonicality:
      return "mldsa_hint_canonicality";
    case OracleId::kMlDsaZNormBoundary:
      return "mldsa_z_norm_boundary";
    case OracleId::kMlDsaRndDeterminism:
      return "mldsa_rnd_determinism";
    case OracleId::kMlDsaPurePrehashSeparation:
      return "mldsa_pure_prehash_separation";
    case OracleId::kMlDsaPhOidSeparation:
      return "mldsa_ph_oid_separation";
    case OracleId::kSlhDsaPurePrehashSeparation:
      return "slhdsa_pure_prehash_separation";
    case OracleId::kSlhDsaPhOidSeparation:
      return "slhdsa_ph_oid_separation";
    case OracleId::kMlKemRngFailure:
      return "mlkem_rng_failure";
    case OracleId::kMlDsaRngFailure:
      return "mldsa_rng_failure";
    case OracleId::kSlhDsaRngFailure:
      return "slhdsa_rng_failure";
    case OracleId::kNtruKat:
      return "ntru_kat";
    case OracleId::kNtruLocalRoundtrip:
      return "ntru_local_roundtrip";
    case OracleId::kNtruCrossExchange:
      return "ntru_cross_exchange";
    case OracleId::kNtruDpkeMembership:
      return "ntru_dpke_membership";
    case OracleId::kNtruCtPadding:
      return "ntru_ct_padding";
    case OracleId::kNtruImplicitRejectionExact:
      return "ntru_implicit_rejection_exact";
    case OracleId::kNtruPrfKeySeparation:
      return "ntru_prf_key_separation";
    case OracleId::kNtruKeyAlgebra:
      return "ntru_key_algebra";
    case OracleId::kNtruCodecRoundtrip:
      return "ntru_codec_roundtrip";
    case OracleId::kNtruSkMalformed:
      return "ntru_sk_malformed";
    case OracleId::kNtruLengths:
      return "ntru_lengths";
    case OracleId::kNtruRngAndReplay:
      return "ntru_rng_and_replay";
    case OracleId::kNtruFailureState:
      return "ntru_failure_state";
    case OracleId::kNtruDpkeFailureOutput:
      return "ntru_dpke_failure_output";
    case OracleId::kNtruFaultChecks:
      return "ntru_fault_checks";
    case OracleId::kNtruTimingResources:
      return "ntru_timing_resources";
    case OracleId::kFalconKat:
      return "falcon_kat";
    case OracleId::kFalconLocalSignVerify:
      return "falcon_local_sign_verify";
    case OracleId::kFalconCrossVerify:
      return "falcon_cross_verify";
    case OracleId::kFalconMessageSaltBinding:
      return "falcon_message_salt_binding";
    case OracleId::kFalconHeaderProfile:
      return "falcon_header_profile";
    case OracleId::kFalconPkCoefficients:
      return "falcon_pk_coefficients";
    case OracleId::kFalconCompressedCanonicality:
      return "falcon_compressed_canonicality";
    case OracleId::kFalconFormatLengths:
      return "falcon_format_lengths";
    case OracleId::kFalconNormEquation:
      return "falcon_norm_equation";
    case OracleId::kFalconNormBoundaryUnit:
      return "falcon_norm_boundary_unit";
    case OracleId::kFalconHashToPoint:
      return "falcon_hash_to_point";
    case OracleId::kFalconKeyEquation:
      return "falcon_key_equation";
    case OracleId::kFalconSkCodec:
      return "falcon_sk_codec";
    case OracleId::kFalconRngReplay:
      return "falcon_rng_replay";
    case OracleId::kFalconFailureState:
      return "falcon_failure_state";
    case OracleId::kFalconSignedMessageFrame:
      return "falcon_signed_message_frame";
    case OracleId::kFalconSamplerArithmetic:
      return "falcon_sampler_arithmetic";
    case OracleId::kFalconFaultChecks:
      return "falcon_fault_checks";
    case OracleId::kFalconTimingResources:
      return "falcon_timing_resources";
    case OracleId::kCrossKat:
      return "cross_kat";
    case OracleId::kCrossLocalSignVerify:
      return "cross_local_sign_verify";
    case OracleId::kCrossCrossVerify:
      return "cross_cross_verify";
    case OracleId::kCrossMessageKeyBinding:
      return "cross_message_key_binding";
    case OracleId::kCrossExactLengths:
      return "cross_exact_lengths";
    case OracleId::kCrossPackedFieldRange:
      return "cross_packed_field_range";
    case OracleId::kCrossVectorPadding:
      return "cross_vector_padding";
    case OracleId::kCrossChallengeSampling:
      return "cross_challenge_sampling";
    case OracleId::kCrossCommitmentDigests:
      return "cross_commitment_digests";
    case OracleId::kCrossDomainTranscript:
      return "cross_domain_transcript";
    case OracleId::kCrossSeedRebuild:
      return "cross_seed_rebuild";
    case OracleId::kCrossMerkleProof:
      return "cross_merkle_proof";
    case OracleId::kCrossPathProofConsumption:
      return "cross_path_proof_consumption";
    case OracleId::kCrossKeyAlgebra:
      return "cross_key_algebra";
    case OracleId::kCrossRngReplay:
      return "cross_rng_replay";
    case OracleId::kCrossFailureResources:
      return "cross_failure_resources";
    case OracleId::kCrossParallelArithmetic:
      return "cross_parallel_arithmetic";
    case OracleId::kCrossFaultSeedDisclosure:
      return "cross_fault_seed_disclosure";
    case OracleId::kCrossTiming:
      return "cross_timing";
    case OracleId::kUnknown:
      return "unknown";
  }
  return "unknown";
}

AlgorithmId AlgorithmIdFromName(const std::string &name) {
  if (name == "ML-KEM-512") {
    return AlgorithmId::kMlKem512;
  }
  if (name == "ML-KEM-768") {
    return AlgorithmId::kMlKem768;
  }
  if (name == "ML-KEM-1024") {
    return AlgorithmId::kMlKem1024;
  }
  if (name == "ML-DSA-44") {
    return AlgorithmId::kMlDsa44;
  }
  if (name == "ML-DSA-65") {
    return AlgorithmId::kMlDsa65;
  }
  if (name == "ML-DSA-87") {
    return AlgorithmId::kMlDsa87;
  }
  if (name == "SLH-DSA-SHA2-128s") {
    return AlgorithmId::kSlhDsaSha2_128s;
  }
  if (name == "SLH-DSA-SHAKE-128s") {
    return AlgorithmId::kSlhDsaShake_128s;
  }
  if (name == "SLH-DSA-SHA2-128f") {
    return AlgorithmId::kSlhDsaSha2_128f;
  }
  if (name == "SLH-DSA-SHAKE-128f") {
    return AlgorithmId::kSlhDsaShake_128f;
  }
  if (name == "SLH-DSA-SHA2-192s") {
    return AlgorithmId::kSlhDsaSha2_192s;
  }
  if (name == "SLH-DSA-SHAKE-192s") {
    return AlgorithmId::kSlhDsaShake_192s;
  }
  if (name == "SLH-DSA-SHA2-192f") {
    return AlgorithmId::kSlhDsaSha2_192f;
  }
  if (name == "SLH-DSA-SHAKE-192f") {
    return AlgorithmId::kSlhDsaShake_192f;
  }
  if (name == "SLH-DSA-SHA2-256s") {
    return AlgorithmId::kSlhDsaSha2_256s;
  }
  if (name == "SLH-DSA-SHAKE-256s") {
    return AlgorithmId::kSlhDsaShake_256s;
  }
  if (name == "SLH-DSA-SHA2-256f") {
    return AlgorithmId::kSlhDsaSha2_256f;
  }
  if (name == "SLH-DSA-SHAKE-256f") {
    return AlgorithmId::kSlhDsaShake_256f;
  }
  if (name == "AIGIS-ENC-1") {
    return AlgorithmId::kAigisEnc1;
  }
  if (name == "AIGIS-ENC-2") {
    return AlgorithmId::kAigisEnc2;
  }
  if (name == "AIGIS-ENC-3") {
    return AlgorithmId::kAigisEnc3;
  }
  if (name == "AIGIS-ENC-4") {
    return AlgorithmId::kAigisEnc4;
  }
  if (name == "AIGIS-SIG-1") {
    return AlgorithmId::kAigisSig1;
  }
  if (name == "AIGIS-SIG-2") {
    return AlgorithmId::kAigisSig2;
  }
  if (name == "AIGIS-SIG-3") {
    return AlgorithmId::kAigisSig3;
  }
  if (name == "NTRU-HPS-2048-509") {
    return AlgorithmId::kNtruHps2048509;
  }
  if (name == "NTRU-HPS-2048-677") {
    return AlgorithmId::kNtruHps2048677;
  }
  if (name == "NTRU-HPS-4096-821") {
    return AlgorithmId::kNtruHps4096821;
  }
  if (name == "NTRU-HRSS-701") {
    return AlgorithmId::kNtruHrss701;
  }
  if (name == "FALCON-512-COMPRESSED") {
    return AlgorithmId::kFalcon512Compressed;
  }
  if (name == "FALCON-1024-COMPRESSED") {
    return AlgorithmId::kFalcon1024Compressed;
  }
  if (name == "FALCON-512-PADDED") {
    return AlgorithmId::kFalcon512Padded;
  }
  if (name == "FALCON-1024-PADDED") {
    return AlgorithmId::kFalcon1024Padded;
  }
  if (name == "FALCON-512-CT") {
    return AlgorithmId::kFalcon512Ct;
  }
  if (name == "FALCON-1024-CT") {
    return AlgorithmId::kFalcon1024Ct;
  }
  if (name == "CROSS-RSDP-1-FAST") {
    return AlgorithmId::kCrossRsdp1Fast;
  }
  if (name == "CROSS-RSDP-1-BALANCED") {
    return AlgorithmId::kCrossRsdp1Balanced;
  }
  if (name == "CROSS-RSDP-1-SMALL") {
    return AlgorithmId::kCrossRsdp1Small;
  }
  if (name == "CROSS-RSDP-3-FAST") {
    return AlgorithmId::kCrossRsdp3Fast;
  }
  if (name == "CROSS-RSDP-3-BALANCED") {
    return AlgorithmId::kCrossRsdp3Balanced;
  }
  if (name == "CROSS-RSDP-3-SMALL") {
    return AlgorithmId::kCrossRsdp3Small;
  }
  if (name == "CROSS-RSDP-5-FAST") {
    return AlgorithmId::kCrossRsdp5Fast;
  }
  if (name == "CROSS-RSDP-5-BALANCED") {
    return AlgorithmId::kCrossRsdp5Balanced;
  }
  if (name == "CROSS-RSDP-5-SMALL") {
    return AlgorithmId::kCrossRsdp5Small;
  }
  if (name == "CROSS-RSDPG-1-FAST") {
    return AlgorithmId::kCrossRsdpg1Fast;
  }
  if (name == "CROSS-RSDPG-1-BALANCED") {
    return AlgorithmId::kCrossRsdpg1Balanced;
  }
  if (name == "CROSS-RSDPG-1-SMALL") {
    return AlgorithmId::kCrossRsdpg1Small;
  }
  if (name == "CROSS-RSDPG-3-FAST") {
    return AlgorithmId::kCrossRsdpg3Fast;
  }
  if (name == "CROSS-RSDPG-3-BALANCED") {
    return AlgorithmId::kCrossRsdpg3Balanced;
  }
  if (name == "CROSS-RSDPG-3-SMALL") {
    return AlgorithmId::kCrossRsdpg3Small;
  }
  if (name == "CROSS-RSDPG-5-FAST") {
    return AlgorithmId::kCrossRsdpg5Fast;
  }
  if (name == "CROSS-RSDPG-5-BALANCED") {
    return AlgorithmId::kCrossRsdpg5Balanced;
  }
  if (name == "CROSS-RSDPG-5-SMALL") {
    return AlgorithmId::kCrossRsdpg5Small;
  }
  return AlgorithmId::kUnknown;
}

OracleId OracleIdFromName(const std::string &name) {
  if (name == "mlkem_local_roundtrip") {
    return OracleId::kMlKemLocalRoundtrip;
  }
  if (name == "mlkem_cross_exchange_roundtrip") {
    return OracleId::kMlKemCrossExchangeRoundtrip;
  }
  if (name == "mlkem_tampered_ciphertext_implicit_rejection") {
    return OracleId::kMlKemTamperedCiphertextImplicitRejection;
  }
  if (name == "mlkem_bad_randomness_sanity") {
    return OracleId::kMlKemBadRandomnessSanity;
  }
  if (name == "mldsa_local_sign_verify") {
    return OracleId::kMlDsaLocalSignVerify;
  }
  if (name == "mldsa_cross_verify") {
    return OracleId::kMlDsaCrossVerify;
  }
  if (name == "mldsa_mutated_signature_negative") {
    return OracleId::kMlDsaMutatedSignatureNegative;
  }
  if (name == "mldsa_mutated_message_negative") {
    return OracleId::kMlDsaMutatedMessageNegative;
  }
  if (name == "mldsa_mutated_context_negative") {
    return OracleId::kMlDsaMutatedContextNegative;
  }
  if (name == "mldsa_oid_field_mutation_sanity") {
    return OracleId::kMlDsaOidFieldMutationSanity;
  }
  if (name == "mldsa_bad_randomness_sanity") {
    return OracleId::kMlDsaBadRandomnessSanity;
  }
  if (name == "slhdsa_local_sign_verify") {
    return OracleId::kSlhDsaLocalSignVerify;
  }
  if (name == "slhdsa_cross_verify") {
    return OracleId::kSlhDsaCrossVerify;
  }
  if (name == "slhdsa_mutated_signature_negative") {
    return OracleId::kSlhDsaMutatedSignatureNegative;
  }
  if (name == "slhdsa_mutated_message_negative") {
    return OracleId::kSlhDsaMutatedMessageNegative;
  }
  if (name == "slhdsa_mutated_context_negative") {
    return OracleId::kSlhDsaMutatedContextNegative;
  }
  if (name == "slhdsa_bad_randomness_sanity") {
    return OracleId::kSlhDsaBadRandomnessSanity;
  }
  if (name == "kem_decaps_c") {
    return OracleId::kKemDecapsCiphertext;
  }
  if (name == "kem_decaps_sk") {
    return OracleId::kKemDecapsSecretKey;
  }
  if (name == "kem_encaps_badrng") {
    return OracleId::kKemEncapsBadRng;
  }
  if (name == "kem_encaps_pk_0") {
    return OracleId::kKemEncapsZeroPublicKey;
  }
  if (name == "kem_encaps_pk") {
    return OracleId::kKemEncapsPublicKey;
  }
  if (name == "kem_keygen_badrng") {
    return OracleId::kKemKeygenBadRng;
  }
  if (name == "sig_keygen_badrng") {
    return OracleId::kSigKeygenBadRng;
  }
  if (name == "sig_sign_badrng") {
    return OracleId::kSigSignBadRng;
  }
  if (name == "sig_sign_m") {
    return OracleId::kSigSignMessage;
  }
  if (name == "sig_sign_sk") {
    return OracleId::kSigSignSecretKey;
  }
  if (name == "sig_verify_m") {
    return OracleId::kSigVerifyMessage;
  }
  if (name == "sig_verify_sig") {
    return OracleId::kSigVerifySignature;
  }
  if (name == "sig_verify_pk") {
    return OracleId::kSigVerifyPublicKey;
  }
  if (name == "aigisenc_local_roundtrip") {
    return OracleId::kAigisEncLocalRoundtrip;
  }
  if (name == "aigisenc_cross_exchange_roundtrip") {
    return OracleId::kAigisEncCrossExchangeRoundtrip;
  }
  if (name == "aigisenc_tampered_ciphertext_implicit_rejection") {
    return OracleId::kAigisEncTamperedCiphertextImplicitRejection;
  }
  if (name == "aigisenc_bad_randomness_sanity") {
    return OracleId::kAigisEncBadRandomnessSanity;
  }
  if (name == "aigisenc_sk_noncanonical_coefficient") {
    return OracleId::kAigisEncSkNoncanonicalCoefficient;
  }
  if (name == "aigissig_local_sign_verify") {
    return OracleId::kAigisSigLocalSignVerify;
  }
  if (name == "aigissig_cross_verify") {
    return OracleId::kAigisSigCrossVerify;
  }
  if (name == "aigissig_mutated_signature_negative") {
    return OracleId::kAigisSigMutatedSignatureNegative;
  }
  if (name == "aigissig_mutated_message_negative") {
    return OracleId::kAigisSigMutatedMessageNegative;
  }
  if (name == "aigissig_mutated_context_negative") {
    return OracleId::kAigisSigMutatedContextNegative;
  }
  if (name == "aigissig_bad_randomness_sanity") {
    return OracleId::kAigisSigBadRandomnessSanity;
  }
  if (name == "aigissig_exact_length") {
    return OracleId::kAigisSigExactLength;
  }
  if (name == "aigissig_unused_sign_bits") {
    return OracleId::kAigisSigUnusedSignBits;
  }
  if (name == "aigissig_ctx256_failure_state") {
    return OracleId::kAigisSigCtx256FailureState;
  }
  if (name == "aigissig_determinism_profile") {
    return OracleId::kAigisSigDeterminismProfile;
  }
  if (name == "mlkem_implicit_rejection_relations") {
    return OracleId::kMlKemImplicitRejectionRelations;
  }
  if (name == "aigisenc_implicit_rejection_relations") {
    return OracleId::kAigisEncImplicitRejectionRelations;
  }
  if (name == "mldsa_verify_exact_lengths") {
    return OracleId::kMlDsaVerifyExactLengths;
  }
  if (name == "mldsa_ctx_boundaries") {
    return OracleId::kMlDsaCtxBoundaries;
  }
  if (name == "slhdsa_verify_exact_lengths") {
    return OracleId::kSlhDsaVerifyExactLengths;
  }
  if (name == "slhdsa_ctx_boundaries") {
    return OracleId::kSlhDsaCtxBoundaries;
  }
  if (name == "mlkem_raw_length_boundary") {
    return OracleId::kMlKemRawLengthBoundary;
  }
  if (name == "mlkem_ek_canonicality") {
    return OracleId::kMlKemEkCanonicality;
  }
  if (name == "mldsa_hint_canonicality") {
    return OracleId::kMlDsaHintCanonicality;
  }
  if (name == "mldsa_z_norm_boundary") {
    return OracleId::kMlDsaZNormBoundary;
  }
  if (name == "mldsa_rnd_determinism") {
    return OracleId::kMlDsaRndDeterminism;
  }
  if (name == "mldsa_pure_prehash_separation") {
    return OracleId::kMlDsaPurePrehashSeparation;
  }
  if (name == "mldsa_ph_oid_separation") {
    return OracleId::kMlDsaPhOidSeparation;
  }
  if (name == "slhdsa_pure_prehash_separation") {
    return OracleId::kSlhDsaPurePrehashSeparation;
  }
  if (name == "slhdsa_ph_oid_separation") {
    return OracleId::kSlhDsaPhOidSeparation;
  }
  if (name == "mlkem_rng_failure") {
    return OracleId::kMlKemRngFailure;
  }
  if (name == "mldsa_rng_failure") {
    return OracleId::kMlDsaRngFailure;
  }
  if (name == "slhdsa_rng_failure") {
    return OracleId::kSlhDsaRngFailure;
  }
  if (name == "ntru_kat") {
    return OracleId::kNtruKat;
  }
  if (name == "ntru_local_roundtrip") {
    return OracleId::kNtruLocalRoundtrip;
  }
  if (name == "ntru_cross_exchange") {
    return OracleId::kNtruCrossExchange;
  }
  if (name == "ntru_dpke_membership") {
    return OracleId::kNtruDpkeMembership;
  }
  if (name == "ntru_ct_padding") {
    return OracleId::kNtruCtPadding;
  }
  if (name == "ntru_implicit_rejection_exact") {
    return OracleId::kNtruImplicitRejectionExact;
  }
  if (name == "ntru_prf_key_separation") {
    return OracleId::kNtruPrfKeySeparation;
  }
  if (name == "ntru_key_algebra") {
    return OracleId::kNtruKeyAlgebra;
  }
  if (name == "ntru_codec_roundtrip") {
    return OracleId::kNtruCodecRoundtrip;
  }
  if (name == "ntru_sk_malformed") {
    return OracleId::kNtruSkMalformed;
  }
  if (name == "ntru_lengths") {
    return OracleId::kNtruLengths;
  }
  if (name == "ntru_rng_and_replay") {
    return OracleId::kNtruRngAndReplay;
  }
  if (name == "ntru_failure_state") {
    return OracleId::kNtruFailureState;
  }
  if (name == "ntru_dpke_failure_output") {
    return OracleId::kNtruDpkeFailureOutput;
  }
  if (name == "ntru_fault_checks") {
    return OracleId::kNtruFaultChecks;
  }
  if (name == "ntru_timing_resources") {
    return OracleId::kNtruTimingResources;
  }
  if (name == "falcon_kat") {
    return OracleId::kFalconKat;
  }
  if (name == "falcon_local_sign_verify") {
    return OracleId::kFalconLocalSignVerify;
  }
  if (name == "falcon_cross_verify") {
    return OracleId::kFalconCrossVerify;
  }
  if (name == "falcon_message_salt_binding") {
    return OracleId::kFalconMessageSaltBinding;
  }
  if (name == "falcon_header_profile") {
    return OracleId::kFalconHeaderProfile;
  }
  if (name == "falcon_pk_coefficients") {
    return OracleId::kFalconPkCoefficients;
  }
  if (name == "falcon_compressed_canonicality") {
    return OracleId::kFalconCompressedCanonicality;
  }
  if (name == "falcon_format_lengths") {
    return OracleId::kFalconFormatLengths;
  }
  if (name == "falcon_norm_equation") {
    return OracleId::kFalconNormEquation;
  }
  if (name == "falcon_norm_boundary_unit") {
    return OracleId::kFalconNormBoundaryUnit;
  }
  if (name == "falcon_hash_to_point") {
    return OracleId::kFalconHashToPoint;
  }
  if (name == "falcon_key_equation") {
    return OracleId::kFalconKeyEquation;
  }
  if (name == "falcon_sk_codec") {
    return OracleId::kFalconSkCodec;
  }
  if (name == "falcon_rng_replay") {
    return OracleId::kFalconRngReplay;
  }
  if (name == "falcon_failure_state") {
    return OracleId::kFalconFailureState;
  }
  if (name == "falcon_signed_message_frame") {
    return OracleId::kFalconSignedMessageFrame;
  }
  if (name == "falcon_sampler_arithmetic") {
    return OracleId::kFalconSamplerArithmetic;
  }
  if (name == "falcon_fault_checks") {
    return OracleId::kFalconFaultChecks;
  }
  if (name == "falcon_timing_resources") {
    return OracleId::kFalconTimingResources;
  }
  if (name == "cross_kat") {
    return OracleId::kCrossKat;
  }
  if (name == "cross_local_sign_verify") {
    return OracleId::kCrossLocalSignVerify;
  }
  if (name == "cross_cross_verify") {
    return OracleId::kCrossCrossVerify;
  }
  if (name == "cross_message_key_binding") {
    return OracleId::kCrossMessageKeyBinding;
  }
  if (name == "cross_exact_lengths") {
    return OracleId::kCrossExactLengths;
  }
  if (name == "cross_packed_field_range") {
    return OracleId::kCrossPackedFieldRange;
  }
  if (name == "cross_vector_padding") {
    return OracleId::kCrossVectorPadding;
  }
  if (name == "cross_challenge_sampling") {
    return OracleId::kCrossChallengeSampling;
  }
  if (name == "cross_commitment_digests") {
    return OracleId::kCrossCommitmentDigests;
  }
  if (name == "cross_domain_transcript") {
    return OracleId::kCrossDomainTranscript;
  }
  if (name == "cross_seed_rebuild") {
    return OracleId::kCrossSeedRebuild;
  }
  if (name == "cross_merkle_proof") {
    return OracleId::kCrossMerkleProof;
  }
  if (name == "cross_path_proof_consumption") {
    return OracleId::kCrossPathProofConsumption;
  }
  if (name == "cross_key_algebra") {
    return OracleId::kCrossKeyAlgebra;
  }
  if (name == "cross_rng_replay") {
    return OracleId::kCrossRngReplay;
  }
  if (name == "cross_failure_resources") {
    return OracleId::kCrossFailureResources;
  }
  if (name == "cross_parallel_arithmetic") {
    return OracleId::kCrossParallelArithmetic;
  }
  if (name == "cross_fault_seed_disclosure") {
    return OracleId::kCrossFaultSeedDisclosure;
  }
  if (name == "cross_timing") {
    return OracleId::kCrossTiming;
  }
  return OracleId::kUnknown;
}

bool ParseEnvelope(const uint8_t *data, size_t size, Envelope *envelope, std::string *error) {
  if (envelope == nullptr) {
    return false;
  }
  if (size < 8) {
    if (error != nullptr) {
      *error = "input shorter than PQCFuzz envelope header";
    }
    return false;
  }
  if (std::memcmp(data, "PQCF", 4) != 0) {
    if (error != nullptr) {
      *error = "bad PQCFuzz envelope magic";
    }
    return false;
  }

  Envelope parsed;
  parsed.version = data[4];
  parsed.algorithm = static_cast<AlgorithmId>(data[5]);
  parsed.oracle_id = static_cast<OracleId>(data[6]);
  parsed.flags = data[7];
  size_t offset = 8;

  uint16_t seed_len = 0;
  uint16_t msg_len = 0;
  uint16_t mutation_len = 0;
  uint16_t extra_len = 0;
  if (!ReadU16(data, size, &offset, &seed_len) || !ReadSlice(data, size, &offset, seed_len, &parsed.seed) ||
      !ReadU16(data, size, &offset, &msg_len) || !ReadSlice(data, size, &offset, msg_len, &parsed.msg) ||
      !ReadU16(data, size, &offset, &mutation_len) ||
      !ReadSlice(data, size, &offset, mutation_len, &parsed.mutation) ||
      !ReadU16(data, size, &offset, &extra_len) || !ReadSlice(data, size, &offset, extra_len, &parsed.extra)) {
    if (error != nullptr) {
      *error = "truncated PQCFuzz envelope field";
    }
    return false;
  }
  if (offset != size) {
    if (error != nullptr) {
      *error = "trailing bytes after PQCFuzz envelope";
    }
    return false;
  }
  if (parsed.version != 1) {
    if (error != nullptr) {
      *error = "unsupported PQCFuzz envelope version";
    }
    return false;
  }
  if (!IsKnownAlgorithmId(parsed.algorithm) || !IsKnownOracleId(parsed.oracle_id)) {
    if (error != nullptr) {
      *error = "unknown algorithm or oracle enum";
    }
    return false;
  }

  *envelope = std::move(parsed);
  return true;
}

}  // namespace pqcfuzz
