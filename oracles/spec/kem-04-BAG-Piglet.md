---
status: draft
target: kem-04
algorithm: BAG-Piglet
source_path: third_party/kem-04/source
source_sha256: c4a4949a092b6da97f15dc65b05fc72005b8234059510108adaad3198c951ec0
document_path: third_party/kem-04/specification.pdf
document_sha256: f38c754a6609d5f23024452b505fd85b8a6c05eb2932a42c17b19a98f17b00d6
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# BAG-Piglet draft claim extraction

This document covers source-pinned public vector records and public API relations
for the named parameter sets. The algorithm construction and correctness context is
at PDF p. 7 (algorithm context). Original PDF and archived source are authoritative.

## BAGPIGLET128-K — bag_piglet128 submitted valid-vector consistency

- Source locator: PDF p. 7 (algorithm context); `Test_Vectors/KAT_KEM_bag_piglet_128.txt`, SHA-256 `f3c715a2a06d6a7b467fcccd766c47a7de08fa11cac1a61f1642a7cbe4fb5ece`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `bag_piglet128` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record decapsulates to its recorded shared secret.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## BAGPIGLET128-KEMENC-C — bag_piglet128 kem_enc public API relation

- Source locator: PDF p. 7; `Implementations/Reference_Implementation/bag_piglet128/src/kat/KEM_AlgorithmInstance.h` SHA-256 `e3d8c552da1d5db6037da74304825b0e1d3f69b50c5c508b4bff47f5f786075a`; `Test_Vectors/KAT_KEM_bag_piglet_128.txt` SHA-256 `f3c715a2a06d6a7b467fcccd766c47a7de08fa11cac1a61f1642a7cbe4fb5ece`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `bag_piglet128` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## BAGPIGLET128-KEMGETCTLENBYTES-C — bag_piglet128 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/bag_piglet128/src/kat/KEM_AlgorithmInstance.h` SHA-256 `e3d8c552da1d5db6037da74304825b0e1d3f69b50c5c508b4bff47f5f786075a`; `Test_Vectors/KAT_KEM_bag_piglet_128.txt` SHA-256 `f3c715a2a06d6a7b467fcccd766c47a7de08fa11cac1a61f1642a7cbe4fb5ece`.
- Class: submitted API length/KAT observation.
- Scope: `bag_piglet128` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## BAGPIGLET128-KEMGETPKLENBYTES-C — bag_piglet128 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/bag_piglet128/src/kat/KEM_AlgorithmInstance.h` SHA-256 `e3d8c552da1d5db6037da74304825b0e1d3f69b50c5c508b4bff47f5f786075a`; `Test_Vectors/KAT_KEM_bag_piglet_128.txt` SHA-256 `f3c715a2a06d6a7b467fcccd766c47a7de08fa11cac1a61f1642a7cbe4fb5ece`.
- Class: submitted API length/KAT observation.
- Scope: `bag_piglet128` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## BAGPIGLET128-KEMGETSKLENBYTES-C — bag_piglet128 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/bag_piglet128/src/kat/KEM_AlgorithmInstance.h` SHA-256 `e3d8c552da1d5db6037da74304825b0e1d3f69b50c5c508b4bff47f5f786075a`; `Test_Vectors/KAT_KEM_bag_piglet_128.txt` SHA-256 `f3c715a2a06d6a7b467fcccd766c47a7de08fa11cac1a61f1642a7cbe4fb5ece`.
- Class: submitted API length/KAT observation.
- Scope: `bag_piglet128` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## BAGPIGLET128-KEMGETSSLENBYTES-C — bag_piglet128 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/bag_piglet128/src/kat/KEM_AlgorithmInstance.h` SHA-256 `e3d8c552da1d5db6037da74304825b0e1d3f69b50c5c508b4bff47f5f786075a`; `Test_Vectors/KAT_KEM_bag_piglet_128.txt` SHA-256 `f3c715a2a06d6a7b467fcccd766c47a7de08fa11cac1a61f1642a7cbe4fb5ece`.
- Class: submitted API length/KAT observation.
- Scope: `bag_piglet128` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## BAGPIGLET128-KEMKEYGEN-C — bag_piglet128 kem_keygen public API relation

- Source locator: PDF p. 7; `Implementations/Reference_Implementation/bag_piglet128/src/kat/KEM_AlgorithmInstance.h` SHA-256 `e3d8c552da1d5db6037da74304825b0e1d3f69b50c5c508b4bff47f5f786075a`; `Test_Vectors/KAT_KEM_bag_piglet_128.txt` SHA-256 `f3c715a2a06d6a7b467fcccd766c47a7de08fa11cac1a61f1642a7cbe4fb5ece`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `bag_piglet128` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## BAGPIGLET256-K — bag_piglet256 submitted valid-vector consistency

- Source locator: PDF p. 7 (algorithm context); `Test_Vectors/KAT_KEM_bag_piglet_256.txt` SHA-256 `5a0ee6161e598617226ab976048ce992516eb804a25c3590f2a15ef731cc4952`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `bag_piglet256` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## BAGPIGLET384-K — bag_piglet384 submitted valid-vector consistency

- Source locator: PDF p. 7 (algorithm context); `Test_Vectors/KAT_KEM_bag_piglet_384.txt` SHA-256 `26293e3c85763b06d5bd8cc896fb150fb3032099ebce2bb6d96997793933420b`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `bag_piglet384` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## BAGPIGLET512-K — bag_piglet512 submitted valid-vector consistency

- Source locator: PDF p. 7 (algorithm context); `Test_Vectors/KAT_KEM_bag_piglet_512.txt` SHA-256 `9a4ec3639ac1002b28a879ec31eaf8ac21e945661a7276aa1db184bfe1c9a335`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `bag_piglet512` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## BAGPIGLET256-KEMENC-C — bag_piglet256 kem_enc public API relation

- Source locator: PDF p. 7; `Implementations/Reference_Implementation/bag_piglet256/src/kat/KEM_AlgorithmInstance.h` SHA-256 `929bdb25ac121f8b29d8fe3b3a9337b79f763cb830fe93386bba0e8ef89e1233`; `Test_Vectors/KAT_KEM_bag_piglet_256.txt` SHA-256 `5a0ee6161e598617226ab976048ce992516eb804a25c3590f2a15ef731cc4952`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `bag_piglet256` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## BAGPIGLET256-KEMGETCTLENBYTES-C — bag_piglet256 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/bag_piglet256/src/kat/KEM_AlgorithmInstance.h` SHA-256 `929bdb25ac121f8b29d8fe3b3a9337b79f763cb830fe93386bba0e8ef89e1233`; `Test_Vectors/KAT_KEM_bag_piglet_256.txt` SHA-256 `5a0ee6161e598617226ab976048ce992516eb804a25c3590f2a15ef731cc4952`.
- Class: submitted API length/KAT observation.
- Scope: `bag_piglet256` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## BAGPIGLET256-KEMGETPKLENBYTES-C — bag_piglet256 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/bag_piglet256/src/kat/KEM_AlgorithmInstance.h` SHA-256 `929bdb25ac121f8b29d8fe3b3a9337b79f763cb830fe93386bba0e8ef89e1233`; `Test_Vectors/KAT_KEM_bag_piglet_256.txt` SHA-256 `5a0ee6161e598617226ab976048ce992516eb804a25c3590f2a15ef731cc4952`.
- Class: submitted API length/KAT observation.
- Scope: `bag_piglet256` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## BAGPIGLET256-KEMGETSKLENBYTES-C — bag_piglet256 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/bag_piglet256/src/kat/KEM_AlgorithmInstance.h` SHA-256 `929bdb25ac121f8b29d8fe3b3a9337b79f763cb830fe93386bba0e8ef89e1233`; `Test_Vectors/KAT_KEM_bag_piglet_256.txt` SHA-256 `5a0ee6161e598617226ab976048ce992516eb804a25c3590f2a15ef731cc4952`.
- Class: submitted API length/KAT observation.
- Scope: `bag_piglet256` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## BAGPIGLET256-KEMGETSSLENBYTES-C — bag_piglet256 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/bag_piglet256/src/kat/KEM_AlgorithmInstance.h` SHA-256 `929bdb25ac121f8b29d8fe3b3a9337b79f763cb830fe93386bba0e8ef89e1233`; `Test_Vectors/KAT_KEM_bag_piglet_256.txt` SHA-256 `5a0ee6161e598617226ab976048ce992516eb804a25c3590f2a15ef731cc4952`.
- Class: submitted API length/KAT observation.
- Scope: `bag_piglet256` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## BAGPIGLET256-KEMKEYGEN-C — bag_piglet256 kem_keygen public API relation

- Source locator: PDF p. 7; `Implementations/Reference_Implementation/bag_piglet256/src/kat/KEM_AlgorithmInstance.h` SHA-256 `929bdb25ac121f8b29d8fe3b3a9337b79f763cb830fe93386bba0e8ef89e1233`; `Test_Vectors/KAT_KEM_bag_piglet_256.txt` SHA-256 `5a0ee6161e598617226ab976048ce992516eb804a25c3590f2a15ef731cc4952`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `bag_piglet256` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## BAGPIGLET384-KEMENC-C — bag_piglet384 kem_enc public API relation

- Source locator: PDF p. 7; `Implementations/Reference_Implementation/bag_piglet384/src/kat/KEM_AlgorithmInstance.h` SHA-256 `60593ab900184b42a28674a41a57feac0cadf32df26b6fa464c304481c8017a9`; `Test_Vectors/KAT_KEM_bag_piglet_384.txt` SHA-256 `26293e3c85763b06d5bd8cc896fb150fb3032099ebce2bb6d96997793933420b`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `bag_piglet384` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## BAGPIGLET384-KEMGETCTLENBYTES-C — bag_piglet384 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/bag_piglet384/src/kat/KEM_AlgorithmInstance.h` SHA-256 `60593ab900184b42a28674a41a57feac0cadf32df26b6fa464c304481c8017a9`; `Test_Vectors/KAT_KEM_bag_piglet_384.txt` SHA-256 `26293e3c85763b06d5bd8cc896fb150fb3032099ebce2bb6d96997793933420b`.
- Class: submitted API length/KAT observation.
- Scope: `bag_piglet384` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## BAGPIGLET384-KEMGETPKLENBYTES-C — bag_piglet384 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/bag_piglet384/src/kat/KEM_AlgorithmInstance.h` SHA-256 `60593ab900184b42a28674a41a57feac0cadf32df26b6fa464c304481c8017a9`; `Test_Vectors/KAT_KEM_bag_piglet_384.txt` SHA-256 `26293e3c85763b06d5bd8cc896fb150fb3032099ebce2bb6d96997793933420b`.
- Class: submitted API length/KAT observation.
- Scope: `bag_piglet384` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## BAGPIGLET384-KEMGETSKLENBYTES-C — bag_piglet384 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/bag_piglet384/src/kat/KEM_AlgorithmInstance.h` SHA-256 `60593ab900184b42a28674a41a57feac0cadf32df26b6fa464c304481c8017a9`; `Test_Vectors/KAT_KEM_bag_piglet_384.txt` SHA-256 `26293e3c85763b06d5bd8cc896fb150fb3032099ebce2bb6d96997793933420b`.
- Class: submitted API length/KAT observation.
- Scope: `bag_piglet384` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## BAGPIGLET384-KEMGETSSLENBYTES-C — bag_piglet384 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/bag_piglet384/src/kat/KEM_AlgorithmInstance.h` SHA-256 `60593ab900184b42a28674a41a57feac0cadf32df26b6fa464c304481c8017a9`; `Test_Vectors/KAT_KEM_bag_piglet_384.txt` SHA-256 `26293e3c85763b06d5bd8cc896fb150fb3032099ebce2bb6d96997793933420b`.
- Class: submitted API length/KAT observation.
- Scope: `bag_piglet384` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## BAGPIGLET384-KEMKEYGEN-C — bag_piglet384 kem_keygen public API relation

- Source locator: PDF p. 7; `Implementations/Reference_Implementation/bag_piglet384/src/kat/KEM_AlgorithmInstance.h` SHA-256 `60593ab900184b42a28674a41a57feac0cadf32df26b6fa464c304481c8017a9`; `Test_Vectors/KAT_KEM_bag_piglet_384.txt` SHA-256 `26293e3c85763b06d5bd8cc896fb150fb3032099ebce2bb6d96997793933420b`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `bag_piglet384` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## BAGPIGLET512-KEMENC-C — bag_piglet512 kem_enc public API relation

- Source locator: PDF p. 7; `Implementations/Reference_Implementation/bag_piglet512/src/kat/KEM_AlgorithmInstance.h` SHA-256 `19bca03ef79d2b314d87e19246f7540b362a5053c2c607b50274ea4a9383264b`; `Test_Vectors/KAT_KEM_bag_piglet_512.txt` SHA-256 `9a4ec3639ac1002b28a879ec31eaf8ac21e945661a7276aa1db184bfe1c9a335`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `bag_piglet512` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## BAGPIGLET512-KEMGETCTLENBYTES-C — bag_piglet512 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/bag_piglet512/src/kat/KEM_AlgorithmInstance.h` SHA-256 `19bca03ef79d2b314d87e19246f7540b362a5053c2c607b50274ea4a9383264b`; `Test_Vectors/KAT_KEM_bag_piglet_512.txt` SHA-256 `9a4ec3639ac1002b28a879ec31eaf8ac21e945661a7276aa1db184bfe1c9a335`.
- Class: submitted API length/KAT observation.
- Scope: `bag_piglet512` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## BAGPIGLET512-KEMGETPKLENBYTES-C — bag_piglet512 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/bag_piglet512/src/kat/KEM_AlgorithmInstance.h` SHA-256 `19bca03ef79d2b314d87e19246f7540b362a5053c2c607b50274ea4a9383264b`; `Test_Vectors/KAT_KEM_bag_piglet_512.txt` SHA-256 `9a4ec3639ac1002b28a879ec31eaf8ac21e945661a7276aa1db184bfe1c9a335`.
- Class: submitted API length/KAT observation.
- Scope: `bag_piglet512` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## BAGPIGLET512-KEMGETSKLENBYTES-C — bag_piglet512 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/bag_piglet512/src/kat/KEM_AlgorithmInstance.h` SHA-256 `19bca03ef79d2b314d87e19246f7540b362a5053c2c607b50274ea4a9383264b`; `Test_Vectors/KAT_KEM_bag_piglet_512.txt` SHA-256 `9a4ec3639ac1002b28a879ec31eaf8ac21e945661a7276aa1db184bfe1c9a335`.
- Class: submitted API length/KAT observation.
- Scope: `bag_piglet512` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## BAGPIGLET512-KEMGETSSLENBYTES-C — bag_piglet512 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/bag_piglet512/src/kat/KEM_AlgorithmInstance.h` SHA-256 `19bca03ef79d2b314d87e19246f7540b362a5053c2c607b50274ea4a9383264b`; `Test_Vectors/KAT_KEM_bag_piglet_512.txt` SHA-256 `9a4ec3639ac1002b28a879ec31eaf8ac21e945661a7276aa1db184bfe1c9a335`.
- Class: submitted API length/KAT observation.
- Scope: `bag_piglet512` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## BAGPIGLET512-KEMKEYGEN-C — bag_piglet512 kem_keygen public API relation

- Source locator: PDF p. 7; `Implementations/Reference_Implementation/bag_piglet512/src/kat/KEM_AlgorithmInstance.h` SHA-256 `19bca03ef79d2b314d87e19246f7540b362a5053c2c607b50274ea4a9383264b`; `Test_Vectors/KAT_KEM_bag_piglet_512.txt` SHA-256 `9a4ec3639ac1002b28a879ec31eaf8ac21e945661a7276aa1db184bfe1c9a335`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `bag_piglet512` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.
