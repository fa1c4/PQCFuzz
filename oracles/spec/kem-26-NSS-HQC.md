---
status: draft
target: kem-26
algorithm: NSS-HQC
source_path: third_party/kem-26/source
source_sha256: 9f2ad59844277d847497d956a1025f8eed4011ee15f59a325fb7e9c4fd47f806
document_path: third_party/kem-26/specification.pdf
document_sha256: e993a0ad7b87be444a0a2381c98eb8ffe9fa75d53f34e5141add21a1c5ef2dde
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# NSS-HQC draft claim extraction

This document covers source-pinned public vector records and public API relations
for the named parameter sets. The algorithm construction and correctness context is
at PDF p. 25 (algorithm context). Original PDF and archived source are authoritative.

## HQC128-K — HQC-128 submitted valid-vector consistency

- Source locator: PDF p. 25 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-128.txt`, SHA-256 `66a0fe8816a982506b0d799c43fcdd18d0434fc54b12fc1e2cc50c0603af8bfc`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `HQC-128` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record decapsulates to its recorded shared secret.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## HQC128-KEMENC-C — HQC-128 kem_enc public API relation

- Source locator: PDF pp. 22–24; `Implementations and Test_Vectors/Implementations/Reference_Implementation/HQC-128/KEM_AlgorithmInstance.h` SHA-256 `f9a36379e9e72444209b92721e8a1ae14c0f691d38544199029149bbfd2e9b9c`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-128.txt` SHA-256 `66a0fe8816a982506b0d799c43fcdd18d0434fc54b12fc1e2cc50c0603af8bfc`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `HQC-128` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HQC128-KEMGETCTLENBYTES-C — HQC-128 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/HQC-128/KEM_AlgorithmInstance.h` SHA-256 `f9a36379e9e72444209b92721e8a1ae14c0f691d38544199029149bbfd2e9b9c`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-128.txt` SHA-256 `66a0fe8816a982506b0d799c43fcdd18d0434fc54b12fc1e2cc50c0603af8bfc`.
- Class: submitted API length/KAT observation.
- Scope: `HQC-128` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HQC128-KEMGETPKLENBYTES-C — HQC-128 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/HQC-128/KEM_AlgorithmInstance.h` SHA-256 `f9a36379e9e72444209b92721e8a1ae14c0f691d38544199029149bbfd2e9b9c`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-128.txt` SHA-256 `66a0fe8816a982506b0d799c43fcdd18d0434fc54b12fc1e2cc50c0603af8bfc`.
- Class: submitted API length/KAT observation.
- Scope: `HQC-128` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HQC128-KEMGETSKLENBYTES-C — HQC-128 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/HQC-128/KEM_AlgorithmInstance.h` SHA-256 `f9a36379e9e72444209b92721e8a1ae14c0f691d38544199029149bbfd2e9b9c`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-128.txt` SHA-256 `66a0fe8816a982506b0d799c43fcdd18d0434fc54b12fc1e2cc50c0603af8bfc`.
- Class: submitted API length/KAT observation.
- Scope: `HQC-128` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HQC128-KEMGETSSLENBYTES-C — HQC-128 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/HQC-128/KEM_AlgorithmInstance.h` SHA-256 `f9a36379e9e72444209b92721e8a1ae14c0f691d38544199029149bbfd2e9b9c`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-128.txt` SHA-256 `66a0fe8816a982506b0d799c43fcdd18d0434fc54b12fc1e2cc50c0603af8bfc`.
- Class: submitted API length/KAT observation.
- Scope: `HQC-128` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HQC128-KEMKEYGEN-C — HQC-128 kem_keygen public API relation

- Source locator: PDF pp. 22–24; `Implementations and Test_Vectors/Implementations/Reference_Implementation/HQC-128/KEM_AlgorithmInstance.h` SHA-256 `f9a36379e9e72444209b92721e8a1ae14c0f691d38544199029149bbfd2e9b9c`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-128.txt` SHA-256 `66a0fe8816a982506b0d799c43fcdd18d0434fc54b12fc1e2cc50c0603af8bfc`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `HQC-128` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HQC256-K — HQC-256 submitted valid-vector consistency

- Source locator: PDF pp. 22–24 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-256.txt` SHA-256 `8cdfacea8444ed8e1380b9ce3cdb4f1ee270acfd35bcd39bb50ac3c4e00c9454`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `HQC-256` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## HQC384-K — HQC-384 submitted valid-vector consistency

- Source locator: PDF pp. 22–24 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-384.txt` SHA-256 `9ce17ccf09e019ab564a4fe0f5799b52054dc8f865dec790c69aa272188dc8e5`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `HQC-384` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## HQC512-K — HQC-512 submitted valid-vector consistency

- Source locator: PDF pp. 22–24 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-512.txt` SHA-256 `e3d01cb3f70f06c548ab50cdee8028cd53974789572de9604acdb7e5a4a9d3d1`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `HQC-512` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## HQC256-KEMENC-C — HQC-256 kem_enc public API relation

- Source locator: PDF pp. 22–24; `Implementations and Test_Vectors/Implementations/Reference_Implementation/HQC-256/KEM_AlgorithmInstance.h` SHA-256 `f9a36379e9e72444209b92721e8a1ae14c0f691d38544199029149bbfd2e9b9c`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-256.txt` SHA-256 `8cdfacea8444ed8e1380b9ce3cdb4f1ee270acfd35bcd39bb50ac3c4e00c9454`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `HQC-256` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HQC256-KEMGETCTLENBYTES-C — HQC-256 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/HQC-256/KEM_AlgorithmInstance.h` SHA-256 `f9a36379e9e72444209b92721e8a1ae14c0f691d38544199029149bbfd2e9b9c`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-256.txt` SHA-256 `8cdfacea8444ed8e1380b9ce3cdb4f1ee270acfd35bcd39bb50ac3c4e00c9454`.
- Class: submitted API length/KAT observation.
- Scope: `HQC-256` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HQC256-KEMGETPKLENBYTES-C — HQC-256 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/HQC-256/KEM_AlgorithmInstance.h` SHA-256 `f9a36379e9e72444209b92721e8a1ae14c0f691d38544199029149bbfd2e9b9c`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-256.txt` SHA-256 `8cdfacea8444ed8e1380b9ce3cdb4f1ee270acfd35bcd39bb50ac3c4e00c9454`.
- Class: submitted API length/KAT observation.
- Scope: `HQC-256` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HQC256-KEMGETSKLENBYTES-C — HQC-256 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/HQC-256/KEM_AlgorithmInstance.h` SHA-256 `f9a36379e9e72444209b92721e8a1ae14c0f691d38544199029149bbfd2e9b9c`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-256.txt` SHA-256 `8cdfacea8444ed8e1380b9ce3cdb4f1ee270acfd35bcd39bb50ac3c4e00c9454`.
- Class: submitted API length/KAT observation.
- Scope: `HQC-256` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HQC256-KEMGETSSLENBYTES-C — HQC-256 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/HQC-256/KEM_AlgorithmInstance.h` SHA-256 `f9a36379e9e72444209b92721e8a1ae14c0f691d38544199029149bbfd2e9b9c`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-256.txt` SHA-256 `8cdfacea8444ed8e1380b9ce3cdb4f1ee270acfd35bcd39bb50ac3c4e00c9454`.
- Class: submitted API length/KAT observation.
- Scope: `HQC-256` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HQC256-KEMKEYGEN-C — HQC-256 kem_keygen public API relation

- Source locator: PDF pp. 22–24; `Implementations and Test_Vectors/Implementations/Reference_Implementation/HQC-256/KEM_AlgorithmInstance.h` SHA-256 `f9a36379e9e72444209b92721e8a1ae14c0f691d38544199029149bbfd2e9b9c`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-256.txt` SHA-256 `8cdfacea8444ed8e1380b9ce3cdb4f1ee270acfd35bcd39bb50ac3c4e00c9454`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `HQC-256` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HQC384-KEMENC-C — HQC-384 kem_enc public API relation

- Source locator: PDF pp. 22–24; `Implementations and Test_Vectors/Implementations/Reference_Implementation/HQC-384/KEM_AlgorithmInstance.h` SHA-256 `f9a36379e9e72444209b92721e8a1ae14c0f691d38544199029149bbfd2e9b9c`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-384.txt` SHA-256 `9ce17ccf09e019ab564a4fe0f5799b52054dc8f865dec790c69aa272188dc8e5`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `HQC-384` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HQC384-KEMGETCTLENBYTES-C — HQC-384 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/HQC-384/KEM_AlgorithmInstance.h` SHA-256 `f9a36379e9e72444209b92721e8a1ae14c0f691d38544199029149bbfd2e9b9c`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-384.txt` SHA-256 `9ce17ccf09e019ab564a4fe0f5799b52054dc8f865dec790c69aa272188dc8e5`.
- Class: submitted API length/KAT observation.
- Scope: `HQC-384` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HQC384-KEMGETPKLENBYTES-C — HQC-384 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/HQC-384/KEM_AlgorithmInstance.h` SHA-256 `f9a36379e9e72444209b92721e8a1ae14c0f691d38544199029149bbfd2e9b9c`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-384.txt` SHA-256 `9ce17ccf09e019ab564a4fe0f5799b52054dc8f865dec790c69aa272188dc8e5`.
- Class: submitted API length/KAT observation.
- Scope: `HQC-384` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HQC384-KEMGETSKLENBYTES-C — HQC-384 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/HQC-384/KEM_AlgorithmInstance.h` SHA-256 `f9a36379e9e72444209b92721e8a1ae14c0f691d38544199029149bbfd2e9b9c`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-384.txt` SHA-256 `9ce17ccf09e019ab564a4fe0f5799b52054dc8f865dec790c69aa272188dc8e5`.
- Class: submitted API length/KAT observation.
- Scope: `HQC-384` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HQC384-KEMGETSSLENBYTES-C — HQC-384 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/HQC-384/KEM_AlgorithmInstance.h` SHA-256 `f9a36379e9e72444209b92721e8a1ae14c0f691d38544199029149bbfd2e9b9c`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-384.txt` SHA-256 `9ce17ccf09e019ab564a4fe0f5799b52054dc8f865dec790c69aa272188dc8e5`.
- Class: submitted API length/KAT observation.
- Scope: `HQC-384` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HQC384-KEMKEYGEN-C — HQC-384 kem_keygen public API relation

- Source locator: PDF pp. 22–24; `Implementations and Test_Vectors/Implementations/Reference_Implementation/HQC-384/KEM_AlgorithmInstance.h` SHA-256 `f9a36379e9e72444209b92721e8a1ae14c0f691d38544199029149bbfd2e9b9c`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-384.txt` SHA-256 `9ce17ccf09e019ab564a4fe0f5799b52054dc8f865dec790c69aa272188dc8e5`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `HQC-384` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HQC512-KEMENC-C — HQC-512 kem_enc public API relation

- Source locator: PDF pp. 22–24; `Implementations and Test_Vectors/Implementations/Reference_Implementation/HQC-512/KEM_AlgorithmInstance.h` SHA-256 `f9a36379e9e72444209b92721e8a1ae14c0f691d38544199029149bbfd2e9b9c`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-512.txt` SHA-256 `e3d01cb3f70f06c548ab50cdee8028cd53974789572de9604acdb7e5a4a9d3d1`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `HQC-512` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HQC512-KEMGETCTLENBYTES-C — HQC-512 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/HQC-512/KEM_AlgorithmInstance.h` SHA-256 `f9a36379e9e72444209b92721e8a1ae14c0f691d38544199029149bbfd2e9b9c`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-512.txt` SHA-256 `e3d01cb3f70f06c548ab50cdee8028cd53974789572de9604acdb7e5a4a9d3d1`.
- Class: submitted API length/KAT observation.
- Scope: `HQC-512` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HQC512-KEMGETPKLENBYTES-C — HQC-512 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/HQC-512/KEM_AlgorithmInstance.h` SHA-256 `f9a36379e9e72444209b92721e8a1ae14c0f691d38544199029149bbfd2e9b9c`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-512.txt` SHA-256 `e3d01cb3f70f06c548ab50cdee8028cd53974789572de9604acdb7e5a4a9d3d1`.
- Class: submitted API length/KAT observation.
- Scope: `HQC-512` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HQC512-KEMGETSKLENBYTES-C — HQC-512 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/HQC-512/KEM_AlgorithmInstance.h` SHA-256 `f9a36379e9e72444209b92721e8a1ae14c0f691d38544199029149bbfd2e9b9c`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-512.txt` SHA-256 `e3d01cb3f70f06c548ab50cdee8028cd53974789572de9604acdb7e5a4a9d3d1`.
- Class: submitted API length/KAT observation.
- Scope: `HQC-512` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HQC512-KEMGETSSLENBYTES-C — HQC-512 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/HQC-512/KEM_AlgorithmInstance.h` SHA-256 `f9a36379e9e72444209b92721e8a1ae14c0f691d38544199029149bbfd2e9b9c`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-512.txt` SHA-256 `e3d01cb3f70f06c548ab50cdee8028cd53974789572de9604acdb7e5a4a9d3d1`.
- Class: submitted API length/KAT observation.
- Scope: `HQC-512` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HQC512-KEMKEYGEN-C — HQC-512 kem_keygen public API relation

- Source locator: PDF pp. 22–24; `Implementations and Test_Vectors/Implementations/Reference_Implementation/HQC-512/KEM_AlgorithmInstance.h` SHA-256 `f9a36379e9e72444209b92721e8a1ae14c0f691d38544199029149bbfd2e9b9c`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-512.txt` SHA-256 `e3d01cb3f70f06c548ab50cdee8028cd53974789572de9604acdb7e5a4a9d3d1`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `HQC-512` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.
