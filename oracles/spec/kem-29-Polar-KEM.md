---
status: draft
target: kem-29
algorithm: Polar-KEM
source_path: third_party/kem-29/source
source_sha256: 077191d44b3a7d68df44015cd668e514e9c82389f00f9883f0d8db11c9df5aa9
document_path: third_party/kem-29/specification.pdf
document_sha256: 7234eb7b8e71a38a97d0f6f637aa3e72d6363faad6affde77d574124b8ba6e78
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# Polar-KEM draft claim extraction

This document covers source-pinned public vector records and public API relations
for the named parameter sets. The algorithm construction and correctness context is
at PDF p. 11 (algorithm context). Original PDF and archived source are authoritative.

## POLARKEM128-K — PolarKEM-128 submitted valid-vector consistency

- Source locator: PDF p. 11 (algorithm context); `Submission_Package/Test_Vectors/KAT_KEM_PolarKEM-128.txt`, SHA-256 `00515e6bfc08e039fa170ba5b099ae7d11f3e287c1f8993f67a9e11eba52954b`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `PolarKEM-128` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record decapsulates to its recorded shared secret.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## POLARKEM128-KEMENC-C — PolarKEM-128 kem_enc public API relation

- Source locator: PDF p. 11; `Submission_Package/Implementations/Reference_Implementation/PolarKEM-128/KEM_AlgorithmInstance.h` SHA-256 `035ad0a1b8ed5d0e88860381201f34ee1b7dff2476f0723e09362e525bb583da`; `Submission_Package/Test_Vectors/KAT_KEM_PolarKEM-128.txt` SHA-256 `00515e6bfc08e039fa170ba5b099ae7d11f3e287c1f8993f67a9e11eba52954b`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `PolarKEM-128` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARKEM128-KEMGETCTLENBYTES-C — PolarKEM-128 kem_get_ct_len_bytes public API relation

- Source locator: `Submission_Package/Implementations/Reference_Implementation/PolarKEM-128/KEM_AlgorithmInstance.h` SHA-256 `035ad0a1b8ed5d0e88860381201f34ee1b7dff2476f0723e09362e525bb583da`; `Submission_Package/Test_Vectors/KAT_KEM_PolarKEM-128.txt` SHA-256 `00515e6bfc08e039fa170ba5b099ae7d11f3e287c1f8993f67a9e11eba52954b`.
- Class: submitted API length/KAT observation.
- Scope: `PolarKEM-128` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARKEM128-KEMGETPKLENBYTES-C — PolarKEM-128 kem_get_pk_len_bytes public API relation

- Source locator: `Submission_Package/Implementations/Reference_Implementation/PolarKEM-128/KEM_AlgorithmInstance.h` SHA-256 `035ad0a1b8ed5d0e88860381201f34ee1b7dff2476f0723e09362e525bb583da`; `Submission_Package/Test_Vectors/KAT_KEM_PolarKEM-128.txt` SHA-256 `00515e6bfc08e039fa170ba5b099ae7d11f3e287c1f8993f67a9e11eba52954b`.
- Class: submitted API length/KAT observation.
- Scope: `PolarKEM-128` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARKEM128-KEMGETSKLENBYTES-C — PolarKEM-128 kem_get_sk_len_bytes public API relation

- Source locator: `Submission_Package/Implementations/Reference_Implementation/PolarKEM-128/KEM_AlgorithmInstance.h` SHA-256 `035ad0a1b8ed5d0e88860381201f34ee1b7dff2476f0723e09362e525bb583da`; `Submission_Package/Test_Vectors/KAT_KEM_PolarKEM-128.txt` SHA-256 `00515e6bfc08e039fa170ba5b099ae7d11f3e287c1f8993f67a9e11eba52954b`.
- Class: submitted API length/KAT observation.
- Scope: `PolarKEM-128` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARKEM128-KEMGETSSLENBYTES-C — PolarKEM-128 kem_get_ss_len_bytes public API relation

- Source locator: `Submission_Package/Implementations/Reference_Implementation/PolarKEM-128/KEM_AlgorithmInstance.h` SHA-256 `035ad0a1b8ed5d0e88860381201f34ee1b7dff2476f0723e09362e525bb583da`; `Submission_Package/Test_Vectors/KAT_KEM_PolarKEM-128.txt` SHA-256 `00515e6bfc08e039fa170ba5b099ae7d11f3e287c1f8993f67a9e11eba52954b`.
- Class: submitted API length/KAT observation.
- Scope: `PolarKEM-128` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARKEM128-KEMKEYGEN-C — PolarKEM-128 kem_keygen public API relation

- Source locator: PDF p. 11; `Submission_Package/Implementations/Reference_Implementation/PolarKEM-128/KEM_AlgorithmInstance.h` SHA-256 `035ad0a1b8ed5d0e88860381201f34ee1b7dff2476f0723e09362e525bb583da`; `Submission_Package/Test_Vectors/KAT_KEM_PolarKEM-128.txt` SHA-256 `00515e6bfc08e039fa170ba5b099ae7d11f3e287c1f8993f67a9e11eba52954b`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `PolarKEM-128` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARKEM256-K — PolarKEM-256 submitted valid-vector consistency

- Source locator: PDF p. 11 (algorithm context); `Submission_Package/Test_Vectors/KAT_KEM_PolarKEM-256.txt` SHA-256 `2b0b827c53fa82bf8cef7ceb29868c40f08882b37be8088a7b3d0c820b88195b`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `PolarKEM-256` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## POLARKEM512-K — PolarKEM-512 submitted valid-vector consistency

- Source locator: PDF p. 11 (algorithm context); `Submission_Package/Test_Vectors/KAT_KEM_PolarKEM-512.txt` SHA-256 `4f0aaf3430199e17af2e758b37219f2615bfc7ea810bffa2b8fe5078d1175f47`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `PolarKEM-512` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## POLARKEM256-KEMENC-C — PolarKEM-256 kem_enc public API relation

- Source locator: PDF p. 11; `Submission_Package/Implementations/Reference_Implementation/PolarKEM-256/KEM_AlgorithmInstance.h` SHA-256 `83a9469ee6fb2a2b3c5fe8a7feb5c592ae6f56fe0560e87e26d98eb64585abb9`; `Submission_Package/Test_Vectors/KAT_KEM_PolarKEM-256.txt` SHA-256 `2b0b827c53fa82bf8cef7ceb29868c40f08882b37be8088a7b3d0c820b88195b`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `PolarKEM-256` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARKEM256-KEMGETCTLENBYTES-C — PolarKEM-256 kem_get_ct_len_bytes public API relation

- Source locator: `Submission_Package/Implementations/Reference_Implementation/PolarKEM-256/KEM_AlgorithmInstance.h` SHA-256 `83a9469ee6fb2a2b3c5fe8a7feb5c592ae6f56fe0560e87e26d98eb64585abb9`; `Submission_Package/Test_Vectors/KAT_KEM_PolarKEM-256.txt` SHA-256 `2b0b827c53fa82bf8cef7ceb29868c40f08882b37be8088a7b3d0c820b88195b`.
- Class: submitted API length/KAT observation.
- Scope: `PolarKEM-256` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARKEM256-KEMGETPKLENBYTES-C — PolarKEM-256 kem_get_pk_len_bytes public API relation

- Source locator: `Submission_Package/Implementations/Reference_Implementation/PolarKEM-256/KEM_AlgorithmInstance.h` SHA-256 `83a9469ee6fb2a2b3c5fe8a7feb5c592ae6f56fe0560e87e26d98eb64585abb9`; `Submission_Package/Test_Vectors/KAT_KEM_PolarKEM-256.txt` SHA-256 `2b0b827c53fa82bf8cef7ceb29868c40f08882b37be8088a7b3d0c820b88195b`.
- Class: submitted API length/KAT observation.
- Scope: `PolarKEM-256` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARKEM256-KEMGETSKLENBYTES-C — PolarKEM-256 kem_get_sk_len_bytes public API relation

- Source locator: `Submission_Package/Implementations/Reference_Implementation/PolarKEM-256/KEM_AlgorithmInstance.h` SHA-256 `83a9469ee6fb2a2b3c5fe8a7feb5c592ae6f56fe0560e87e26d98eb64585abb9`; `Submission_Package/Test_Vectors/KAT_KEM_PolarKEM-256.txt` SHA-256 `2b0b827c53fa82bf8cef7ceb29868c40f08882b37be8088a7b3d0c820b88195b`.
- Class: submitted API length/KAT observation.
- Scope: `PolarKEM-256` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARKEM256-KEMGETSSLENBYTES-C — PolarKEM-256 kem_get_ss_len_bytes public API relation

- Source locator: `Submission_Package/Implementations/Reference_Implementation/PolarKEM-256/KEM_AlgorithmInstance.h` SHA-256 `83a9469ee6fb2a2b3c5fe8a7feb5c592ae6f56fe0560e87e26d98eb64585abb9`; `Submission_Package/Test_Vectors/KAT_KEM_PolarKEM-256.txt` SHA-256 `2b0b827c53fa82bf8cef7ceb29868c40f08882b37be8088a7b3d0c820b88195b`.
- Class: submitted API length/KAT observation.
- Scope: `PolarKEM-256` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARKEM256-KEMKEYGEN-C — PolarKEM-256 kem_keygen public API relation

- Source locator: PDF p. 11; `Submission_Package/Implementations/Reference_Implementation/PolarKEM-256/KEM_AlgorithmInstance.h` SHA-256 `83a9469ee6fb2a2b3c5fe8a7feb5c592ae6f56fe0560e87e26d98eb64585abb9`; `Submission_Package/Test_Vectors/KAT_KEM_PolarKEM-256.txt` SHA-256 `2b0b827c53fa82bf8cef7ceb29868c40f08882b37be8088a7b3d0c820b88195b`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `PolarKEM-256` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARKEM512-KEMENC-C — PolarKEM-512 kem_enc public API relation

- Source locator: PDF p. 11; `Submission_Package/Implementations/Reference_Implementation/PolarKEM-512/KEM_AlgorithmInstance.h` SHA-256 `5359792389effa0ef1dde564235b44e814c57cdc45dd755d5e4177a085711a91`; `Submission_Package/Test_Vectors/KAT_KEM_PolarKEM-512.txt` SHA-256 `4f0aaf3430199e17af2e758b37219f2615bfc7ea810bffa2b8fe5078d1175f47`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `PolarKEM-512` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARKEM512-KEMGETCTLENBYTES-C — PolarKEM-512 kem_get_ct_len_bytes public API relation

- Source locator: `Submission_Package/Implementations/Reference_Implementation/PolarKEM-512/KEM_AlgorithmInstance.h` SHA-256 `5359792389effa0ef1dde564235b44e814c57cdc45dd755d5e4177a085711a91`; `Submission_Package/Test_Vectors/KAT_KEM_PolarKEM-512.txt` SHA-256 `4f0aaf3430199e17af2e758b37219f2615bfc7ea810bffa2b8fe5078d1175f47`.
- Class: submitted API length/KAT observation.
- Scope: `PolarKEM-512` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARKEM512-KEMGETPKLENBYTES-C — PolarKEM-512 kem_get_pk_len_bytes public API relation

- Source locator: `Submission_Package/Implementations/Reference_Implementation/PolarKEM-512/KEM_AlgorithmInstance.h` SHA-256 `5359792389effa0ef1dde564235b44e814c57cdc45dd755d5e4177a085711a91`; `Submission_Package/Test_Vectors/KAT_KEM_PolarKEM-512.txt` SHA-256 `4f0aaf3430199e17af2e758b37219f2615bfc7ea810bffa2b8fe5078d1175f47`.
- Class: submitted API length/KAT observation.
- Scope: `PolarKEM-512` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARKEM512-KEMGETSKLENBYTES-C — PolarKEM-512 kem_get_sk_len_bytes public API relation

- Source locator: `Submission_Package/Implementations/Reference_Implementation/PolarKEM-512/KEM_AlgorithmInstance.h` SHA-256 `5359792389effa0ef1dde564235b44e814c57cdc45dd755d5e4177a085711a91`; `Submission_Package/Test_Vectors/KAT_KEM_PolarKEM-512.txt` SHA-256 `4f0aaf3430199e17af2e758b37219f2615bfc7ea810bffa2b8fe5078d1175f47`.
- Class: submitted API length/KAT observation.
- Scope: `PolarKEM-512` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARKEM512-KEMGETSSLENBYTES-C — PolarKEM-512 kem_get_ss_len_bytes public API relation

- Source locator: `Submission_Package/Implementations/Reference_Implementation/PolarKEM-512/KEM_AlgorithmInstance.h` SHA-256 `5359792389effa0ef1dde564235b44e814c57cdc45dd755d5e4177a085711a91`; `Submission_Package/Test_Vectors/KAT_KEM_PolarKEM-512.txt` SHA-256 `4f0aaf3430199e17af2e758b37219f2615bfc7ea810bffa2b8fe5078d1175f47`.
- Class: submitted API length/KAT observation.
- Scope: `PolarKEM-512` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARKEM512-KEMKEYGEN-C — PolarKEM-512 kem_keygen public API relation

- Source locator: PDF p. 11; `Submission_Package/Implementations/Reference_Implementation/PolarKEM-512/KEM_AlgorithmInstance.h` SHA-256 `5359792389effa0ef1dde564235b44e814c57cdc45dd755d5e4177a085711a91`; `Submission_Package/Test_Vectors/KAT_KEM_PolarKEM-512.txt` SHA-256 `4f0aaf3430199e17af2e758b37219f2615bfc7ea810bffa2b8fe5078d1175f47`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `PolarKEM-512` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.
