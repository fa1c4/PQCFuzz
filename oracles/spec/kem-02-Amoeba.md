---
status: draft
target: kem-02
algorithm: Amoeba
source_path: third_party/kem-02/source
source_sha256: 51d29d04a85e9b4dd0c34b4b69c49ba7b51dcfe5e2f83b84b2f41a0007b5476e
document_path: third_party/kem-02/specification.pdf
document_sha256: ffca61c5470298f3a173b76a8ead43299a04d990b0bbb913397f910285d4d247
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# Amoeba draft claim extraction

This document covers source-pinned public vector records and public API relations
for the named parameter sets. The algorithm construction and correctness context is
at PDF p. 9 (algorithm context). Original PDF and archived source are authoritative.

## AMOEBA576-K — Amoeba-576 submitted valid-vector consistency

- Source locator: PDF p. 9 (algorithm context); `Test_Vectors/KAT_KEM_Amoeba128.txt`, SHA-256 `b1960b65ca0d4b7cc3f0f5f568a70de405da2f3b48a6e33c813697ec1a319dd6`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `Amoeba-576` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record decapsulates to its recorded shared secret.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## AMOEBA576-KEMENC-C — Amoeba-576 kem_enc public API relation

- Source locator: PDF pp. 7–9; `Implementations/Reference_Implementation/Amoeba-576/src/api/KEM_AlgorithmInstance.h` SHA-256 `adb676a4416c2e34af824ea227304477b0491c6083b8017f3d5b8ad526563909`; `Test_Vectors/KAT_KEM_Amoeba128.txt` SHA-256 `b1960b65ca0d4b7cc3f0f5f568a70de405da2f3b48a6e33c813697ec1a319dd6`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Amoeba-576` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AMOEBA576-KEMGETCTLENBYTES-C — Amoeba-576 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/Amoeba-576/src/api/KEM_AlgorithmInstance.h` SHA-256 `adb676a4416c2e34af824ea227304477b0491c6083b8017f3d5b8ad526563909`; `Test_Vectors/KAT_KEM_Amoeba128.txt` SHA-256 `b1960b65ca0d4b7cc3f0f5f568a70de405da2f3b48a6e33c813697ec1a319dd6`.
- Class: submitted API length/KAT observation.
- Scope: `Amoeba-576` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AMOEBA576-KEMGETPKLENBYTES-C — Amoeba-576 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/Amoeba-576/src/api/KEM_AlgorithmInstance.h` SHA-256 `adb676a4416c2e34af824ea227304477b0491c6083b8017f3d5b8ad526563909`; `Test_Vectors/KAT_KEM_Amoeba128.txt` SHA-256 `b1960b65ca0d4b7cc3f0f5f568a70de405da2f3b48a6e33c813697ec1a319dd6`.
- Class: submitted API length/KAT observation.
- Scope: `Amoeba-576` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AMOEBA576-KEMGETSKLENBYTES-C — Amoeba-576 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/Amoeba-576/src/api/KEM_AlgorithmInstance.h` SHA-256 `adb676a4416c2e34af824ea227304477b0491c6083b8017f3d5b8ad526563909`; `Test_Vectors/KAT_KEM_Amoeba128.txt` SHA-256 `b1960b65ca0d4b7cc3f0f5f568a70de405da2f3b48a6e33c813697ec1a319dd6`.
- Class: submitted API length/KAT observation.
- Scope: `Amoeba-576` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AMOEBA576-KEMGETSSLENBYTES-C — Amoeba-576 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/Amoeba-576/src/api/KEM_AlgorithmInstance.h` SHA-256 `adb676a4416c2e34af824ea227304477b0491c6083b8017f3d5b8ad526563909`; `Test_Vectors/KAT_KEM_Amoeba128.txt` SHA-256 `b1960b65ca0d4b7cc3f0f5f568a70de405da2f3b48a6e33c813697ec1a319dd6`.
- Class: submitted API length/KAT observation.
- Scope: `Amoeba-576` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AMOEBA576-KEMKEYGEN-C — Amoeba-576 kem_keygen public API relation

- Source locator: PDF pp. 7–9; `Implementations/Reference_Implementation/Amoeba-576/src/api/KEM_AlgorithmInstance.h` SHA-256 `adb676a4416c2e34af824ea227304477b0491c6083b8017f3d5b8ad526563909`; `Test_Vectors/KAT_KEM_Amoeba128.txt` SHA-256 `b1960b65ca0d4b7cc3f0f5f568a70de405da2f3b48a6e33c813697ec1a319dd6`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Amoeba-576` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AMOEBA1152-K — Amoeba-1152 submitted valid-vector consistency

- Source locator: PDF pp. 7–9 (algorithm context); `Test_Vectors/KAT_KEM_Amoeba256.txt` SHA-256 `d55cfeec811a99ab16d1cf1f241714329fc30e8ff0013734d130199ac8973e34`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `Amoeba-1152` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## AMOEBA1728-K — Amoeba-1728 submitted valid-vector consistency

- Source locator: PDF pp. 7–9 (algorithm context); `Test_Vectors/KAT_KEM_Amoeba384.txt` SHA-256 `bfa2f968cfe402fbc78ea5ce05d6d425cf4602c2b270bba7abfa2e11d93063ca`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `Amoeba-1728` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## AMOEBA2304-K — Amoeba-2304 submitted valid-vector consistency

- Source locator: PDF pp. 7–9 (algorithm context); `Test_Vectors/KAT_KEM_Amoeba512.txt` SHA-256 `08d4f43a29be52118fc3a5f5b0c495f66c25be031e7f837b8749c4521039dfc6`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `Amoeba-2304` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## AMOEBA864-K — Amoeba-864 submitted valid-vector consistency

- Source locator: PDF pp. 7–9 (algorithm context); `Test_Vectors/KAT_KEM_Amoeba192.txt` SHA-256 `10440a828ae85edbecd129d1a070eb8b2f820cddb37ade5abe4627eaf1183878`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `Amoeba-864` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## AMOEBA1152-KEMENC-C — Amoeba-1152 kem_enc public API relation

- Source locator: PDF pp. 7–9; `Implementations/Reference_Implementation/Amoeba-1152/src/api/KEM_AlgorithmInstance.h` SHA-256 `adb676a4416c2e34af824ea227304477b0491c6083b8017f3d5b8ad526563909`; `Test_Vectors/KAT_KEM_Amoeba256.txt` SHA-256 `d55cfeec811a99ab16d1cf1f241714329fc30e8ff0013734d130199ac8973e34`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Amoeba-1152` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AMOEBA1152-KEMGETCTLENBYTES-C — Amoeba-1152 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/Amoeba-1152/src/api/KEM_AlgorithmInstance.h` SHA-256 `adb676a4416c2e34af824ea227304477b0491c6083b8017f3d5b8ad526563909`; `Test_Vectors/KAT_KEM_Amoeba256.txt` SHA-256 `d55cfeec811a99ab16d1cf1f241714329fc30e8ff0013734d130199ac8973e34`.
- Class: submitted API length/KAT observation.
- Scope: `Amoeba-1152` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AMOEBA1152-KEMGETPKLENBYTES-C — Amoeba-1152 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/Amoeba-1152/src/api/KEM_AlgorithmInstance.h` SHA-256 `adb676a4416c2e34af824ea227304477b0491c6083b8017f3d5b8ad526563909`; `Test_Vectors/KAT_KEM_Amoeba256.txt` SHA-256 `d55cfeec811a99ab16d1cf1f241714329fc30e8ff0013734d130199ac8973e34`.
- Class: submitted API length/KAT observation.
- Scope: `Amoeba-1152` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AMOEBA1152-KEMGETSKLENBYTES-C — Amoeba-1152 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/Amoeba-1152/src/api/KEM_AlgorithmInstance.h` SHA-256 `adb676a4416c2e34af824ea227304477b0491c6083b8017f3d5b8ad526563909`; `Test_Vectors/KAT_KEM_Amoeba256.txt` SHA-256 `d55cfeec811a99ab16d1cf1f241714329fc30e8ff0013734d130199ac8973e34`.
- Class: submitted API length/KAT observation.
- Scope: `Amoeba-1152` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AMOEBA1152-KEMGETSSLENBYTES-C — Amoeba-1152 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/Amoeba-1152/src/api/KEM_AlgorithmInstance.h` SHA-256 `adb676a4416c2e34af824ea227304477b0491c6083b8017f3d5b8ad526563909`; `Test_Vectors/KAT_KEM_Amoeba256.txt` SHA-256 `d55cfeec811a99ab16d1cf1f241714329fc30e8ff0013734d130199ac8973e34`.
- Class: submitted API length/KAT observation.
- Scope: `Amoeba-1152` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AMOEBA1152-KEMKEYGEN-C — Amoeba-1152 kem_keygen public API relation

- Source locator: PDF pp. 7–9; `Implementations/Reference_Implementation/Amoeba-1152/src/api/KEM_AlgorithmInstance.h` SHA-256 `adb676a4416c2e34af824ea227304477b0491c6083b8017f3d5b8ad526563909`; `Test_Vectors/KAT_KEM_Amoeba256.txt` SHA-256 `d55cfeec811a99ab16d1cf1f241714329fc30e8ff0013734d130199ac8973e34`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Amoeba-1152` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AMOEBA1728-KEMENC-C — Amoeba-1728 kem_enc public API relation

- Source locator: PDF pp. 7–9; `Implementations/Reference_Implementation/Amoeba-1728/src/api/KEM_AlgorithmInstance.h` SHA-256 `adb676a4416c2e34af824ea227304477b0491c6083b8017f3d5b8ad526563909`; `Test_Vectors/KAT_KEM_Amoeba384.txt` SHA-256 `bfa2f968cfe402fbc78ea5ce05d6d425cf4602c2b270bba7abfa2e11d93063ca`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Amoeba-1728` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AMOEBA1728-KEMGETCTLENBYTES-C — Amoeba-1728 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/Amoeba-1728/src/api/KEM_AlgorithmInstance.h` SHA-256 `adb676a4416c2e34af824ea227304477b0491c6083b8017f3d5b8ad526563909`; `Test_Vectors/KAT_KEM_Amoeba384.txt` SHA-256 `bfa2f968cfe402fbc78ea5ce05d6d425cf4602c2b270bba7abfa2e11d93063ca`.
- Class: submitted API length/KAT observation.
- Scope: `Amoeba-1728` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AMOEBA1728-KEMGETPKLENBYTES-C — Amoeba-1728 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/Amoeba-1728/src/api/KEM_AlgorithmInstance.h` SHA-256 `adb676a4416c2e34af824ea227304477b0491c6083b8017f3d5b8ad526563909`; `Test_Vectors/KAT_KEM_Amoeba384.txt` SHA-256 `bfa2f968cfe402fbc78ea5ce05d6d425cf4602c2b270bba7abfa2e11d93063ca`.
- Class: submitted API length/KAT observation.
- Scope: `Amoeba-1728` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AMOEBA1728-KEMGETSKLENBYTES-C — Amoeba-1728 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/Amoeba-1728/src/api/KEM_AlgorithmInstance.h` SHA-256 `adb676a4416c2e34af824ea227304477b0491c6083b8017f3d5b8ad526563909`; `Test_Vectors/KAT_KEM_Amoeba384.txt` SHA-256 `bfa2f968cfe402fbc78ea5ce05d6d425cf4602c2b270bba7abfa2e11d93063ca`.
- Class: submitted API length/KAT observation.
- Scope: `Amoeba-1728` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AMOEBA1728-KEMGETSSLENBYTES-C — Amoeba-1728 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/Amoeba-1728/src/api/KEM_AlgorithmInstance.h` SHA-256 `adb676a4416c2e34af824ea227304477b0491c6083b8017f3d5b8ad526563909`; `Test_Vectors/KAT_KEM_Amoeba384.txt` SHA-256 `bfa2f968cfe402fbc78ea5ce05d6d425cf4602c2b270bba7abfa2e11d93063ca`.
- Class: submitted API length/KAT observation.
- Scope: `Amoeba-1728` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AMOEBA1728-KEMKEYGEN-C — Amoeba-1728 kem_keygen public API relation

- Source locator: PDF pp. 7–9; `Implementations/Reference_Implementation/Amoeba-1728/src/api/KEM_AlgorithmInstance.h` SHA-256 `adb676a4416c2e34af824ea227304477b0491c6083b8017f3d5b8ad526563909`; `Test_Vectors/KAT_KEM_Amoeba384.txt` SHA-256 `bfa2f968cfe402fbc78ea5ce05d6d425cf4602c2b270bba7abfa2e11d93063ca`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Amoeba-1728` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AMOEBA2304-KEMENC-C — Amoeba-2304 kem_enc public API relation

- Source locator: PDF pp. 7–9; `Implementations/Reference_Implementation/Amoeba-2304/src/api/KEM_AlgorithmInstance.h` SHA-256 `adb676a4416c2e34af824ea227304477b0491c6083b8017f3d5b8ad526563909`; `Test_Vectors/KAT_KEM_Amoeba512.txt` SHA-256 `08d4f43a29be52118fc3a5f5b0c495f66c25be031e7f837b8749c4521039dfc6`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Amoeba-2304` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AMOEBA2304-KEMGETCTLENBYTES-C — Amoeba-2304 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/Amoeba-2304/src/api/KEM_AlgorithmInstance.h` SHA-256 `adb676a4416c2e34af824ea227304477b0491c6083b8017f3d5b8ad526563909`; `Test_Vectors/KAT_KEM_Amoeba512.txt` SHA-256 `08d4f43a29be52118fc3a5f5b0c495f66c25be031e7f837b8749c4521039dfc6`.
- Class: submitted API length/KAT observation.
- Scope: `Amoeba-2304` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AMOEBA2304-KEMGETPKLENBYTES-C — Amoeba-2304 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/Amoeba-2304/src/api/KEM_AlgorithmInstance.h` SHA-256 `adb676a4416c2e34af824ea227304477b0491c6083b8017f3d5b8ad526563909`; `Test_Vectors/KAT_KEM_Amoeba512.txt` SHA-256 `08d4f43a29be52118fc3a5f5b0c495f66c25be031e7f837b8749c4521039dfc6`.
- Class: submitted API length/KAT observation.
- Scope: `Amoeba-2304` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AMOEBA2304-KEMGETSKLENBYTES-C — Amoeba-2304 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/Amoeba-2304/src/api/KEM_AlgorithmInstance.h` SHA-256 `adb676a4416c2e34af824ea227304477b0491c6083b8017f3d5b8ad526563909`; `Test_Vectors/KAT_KEM_Amoeba512.txt` SHA-256 `08d4f43a29be52118fc3a5f5b0c495f66c25be031e7f837b8749c4521039dfc6`.
- Class: submitted API length/KAT observation.
- Scope: `Amoeba-2304` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AMOEBA2304-KEMGETSSLENBYTES-C — Amoeba-2304 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/Amoeba-2304/src/api/KEM_AlgorithmInstance.h` SHA-256 `adb676a4416c2e34af824ea227304477b0491c6083b8017f3d5b8ad526563909`; `Test_Vectors/KAT_KEM_Amoeba512.txt` SHA-256 `08d4f43a29be52118fc3a5f5b0c495f66c25be031e7f837b8749c4521039dfc6`.
- Class: submitted API length/KAT observation.
- Scope: `Amoeba-2304` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AMOEBA2304-KEMKEYGEN-C — Amoeba-2304 kem_keygen public API relation

- Source locator: PDF pp. 7–9; `Implementations/Reference_Implementation/Amoeba-2304/src/api/KEM_AlgorithmInstance.h` SHA-256 `adb676a4416c2e34af824ea227304477b0491c6083b8017f3d5b8ad526563909`; `Test_Vectors/KAT_KEM_Amoeba512.txt` SHA-256 `08d4f43a29be52118fc3a5f5b0c495f66c25be031e7f837b8749c4521039dfc6`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Amoeba-2304` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AMOEBA864-KEMENC-C — Amoeba-864 kem_enc public API relation

- Source locator: PDF pp. 7–9; `Implementations/Reference_Implementation/Amoeba-864/src/api/KEM_AlgorithmInstance.h` SHA-256 `adb676a4416c2e34af824ea227304477b0491c6083b8017f3d5b8ad526563909`; `Test_Vectors/KAT_KEM_Amoeba192.txt` SHA-256 `10440a828ae85edbecd129d1a070eb8b2f820cddb37ade5abe4627eaf1183878`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Amoeba-864` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AMOEBA864-KEMGETCTLENBYTES-C — Amoeba-864 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/Amoeba-864/src/api/KEM_AlgorithmInstance.h` SHA-256 `adb676a4416c2e34af824ea227304477b0491c6083b8017f3d5b8ad526563909`; `Test_Vectors/KAT_KEM_Amoeba192.txt` SHA-256 `10440a828ae85edbecd129d1a070eb8b2f820cddb37ade5abe4627eaf1183878`.
- Class: submitted API length/KAT observation.
- Scope: `Amoeba-864` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AMOEBA864-KEMGETPKLENBYTES-C — Amoeba-864 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/Amoeba-864/src/api/KEM_AlgorithmInstance.h` SHA-256 `adb676a4416c2e34af824ea227304477b0491c6083b8017f3d5b8ad526563909`; `Test_Vectors/KAT_KEM_Amoeba192.txt` SHA-256 `10440a828ae85edbecd129d1a070eb8b2f820cddb37ade5abe4627eaf1183878`.
- Class: submitted API length/KAT observation.
- Scope: `Amoeba-864` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AMOEBA864-KEMGETSKLENBYTES-C — Amoeba-864 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/Amoeba-864/src/api/KEM_AlgorithmInstance.h` SHA-256 `adb676a4416c2e34af824ea227304477b0491c6083b8017f3d5b8ad526563909`; `Test_Vectors/KAT_KEM_Amoeba192.txt` SHA-256 `10440a828ae85edbecd129d1a070eb8b2f820cddb37ade5abe4627eaf1183878`.
- Class: submitted API length/KAT observation.
- Scope: `Amoeba-864` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AMOEBA864-KEMGETSSLENBYTES-C — Amoeba-864 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/Amoeba-864/src/api/KEM_AlgorithmInstance.h` SHA-256 `adb676a4416c2e34af824ea227304477b0491c6083b8017f3d5b8ad526563909`; `Test_Vectors/KAT_KEM_Amoeba192.txt` SHA-256 `10440a828ae85edbecd129d1a070eb8b2f820cddb37ade5abe4627eaf1183878`.
- Class: submitted API length/KAT observation.
- Scope: `Amoeba-864` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AMOEBA864-KEMKEYGEN-C — Amoeba-864 kem_keygen public API relation

- Source locator: PDF pp. 7–9; `Implementations/Reference_Implementation/Amoeba-864/src/api/KEM_AlgorithmInstance.h` SHA-256 `adb676a4416c2e34af824ea227304477b0491c6083b8017f3d5b8ad526563909`; `Test_Vectors/KAT_KEM_Amoeba192.txt` SHA-256 `10440a828ae85edbecd129d1a070eb8b2f820cddb37ade5abe4627eaf1183878`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Amoeba-864` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.
