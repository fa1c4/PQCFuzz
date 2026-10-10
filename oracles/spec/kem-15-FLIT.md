---
status: draft
target: kem-15
algorithm: FLIT
source_path: third_party/kem-15/source
source_sha256: 9afc9032807ce52433d0b4fe80cfe8bd33d5a07184b6c7447728065996b58ccc
document_path: third_party/kem-15/specification.pdf
document_sha256: 47e1fee04a6e766174245f656ca49ea6b566aacbe2bd7f16daf1942f0400b13b
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# FLIT draft claim extraction

This document covers source-pinned public vector records and public API relations
for the named parameter sets. The algorithm construction and correctness context is
at PDF p. 10 (algorithm context). Original PDF and archived source are authoritative.

## FLIT128-K — FLIT128 submitted valid-vector consistency

- Source locator: PDF p. 10 (algorithm context); `Test_Vectors/KAT_KEM_FLIT128_REF.txt`, SHA-256 `a772deebcc67af946d60d9ebab8014318879617de619692bd59650196b578e69`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `FLIT128` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record decapsulates to its recorded shared secret.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## FLIT128-KEMENC-C — FLIT128 kem_enc public API relation

- Source locator: PDF p. 15; `Implementations/Reference_Implementation/FLIT128/KEM_AlgorithmInstance.h` SHA-256 `0c5c432f8692632a49d039e6018952607eddd04852bf4062e29d9117eaf014a4`; `Test_Vectors/KAT_KEM_FLIT128_REF.txt` SHA-256 `a772deebcc67af946d60d9ebab8014318879617de619692bd59650196b578e69`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `FLIT128` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## FLIT128-KEMGETCTLENBYTES-C — FLIT128 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/FLIT128/KEM_AlgorithmInstance.h` SHA-256 `0c5c432f8692632a49d039e6018952607eddd04852bf4062e29d9117eaf014a4`; `Test_Vectors/KAT_KEM_FLIT128_REF.txt` SHA-256 `a772deebcc67af946d60d9ebab8014318879617de619692bd59650196b578e69`.
- Class: submitted API length/KAT observation.
- Scope: `FLIT128` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## FLIT128-KEMGETPKLENBYTES-C — FLIT128 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/FLIT128/KEM_AlgorithmInstance.h` SHA-256 `0c5c432f8692632a49d039e6018952607eddd04852bf4062e29d9117eaf014a4`; `Test_Vectors/KAT_KEM_FLIT128_REF.txt` SHA-256 `a772deebcc67af946d60d9ebab8014318879617de619692bd59650196b578e69`.
- Class: submitted API length/KAT observation.
- Scope: `FLIT128` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## FLIT128-KEMGETSKLENBYTES-C — FLIT128 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/FLIT128/KEM_AlgorithmInstance.h` SHA-256 `0c5c432f8692632a49d039e6018952607eddd04852bf4062e29d9117eaf014a4`; `Test_Vectors/KAT_KEM_FLIT128_REF.txt` SHA-256 `a772deebcc67af946d60d9ebab8014318879617de619692bd59650196b578e69`.
- Class: submitted API length/KAT observation.
- Scope: `FLIT128` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## FLIT128-KEMGETSSLENBYTES-C — FLIT128 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/FLIT128/KEM_AlgorithmInstance.h` SHA-256 `0c5c432f8692632a49d039e6018952607eddd04852bf4062e29d9117eaf014a4`; `Test_Vectors/KAT_KEM_FLIT128_REF.txt` SHA-256 `a772deebcc67af946d60d9ebab8014318879617de619692bd59650196b578e69`.
- Class: submitted API length/KAT observation.
- Scope: `FLIT128` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## FLIT128-KEMKEYGEN-C — FLIT128 kem_keygen public API relation

- Source locator: PDF p. 15; `Implementations/Reference_Implementation/FLIT128/KEM_AlgorithmInstance.h` SHA-256 `0c5c432f8692632a49d039e6018952607eddd04852bf4062e29d9117eaf014a4`; `Test_Vectors/KAT_KEM_FLIT128_REF.txt` SHA-256 `a772deebcc67af946d60d9ebab8014318879617de619692bd59650196b578e69`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `FLIT128` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## FLIT256-K — FLIT256 submitted valid-vector consistency

- Source locator: PDF p. 15 (algorithm context); `Test_Vectors/KAT_KEM_FLIT256_REF.txt` SHA-256 `0788e13e3a0c0ff0c8ada4defab0ea4213bf7980bcb6099dba1a2e35b05ea618`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `FLIT256` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## FLIT512-K — FLIT512 submitted valid-vector consistency

- Source locator: PDF p. 15 (algorithm context); `Test_Vectors/KAT_KEM_FLIT512_REF.txt` SHA-256 `e4019117230dc2ef5983e8c2c252f08189e8004e3b7db595a66eec3aa8d9820c`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `FLIT512` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## FLIT256-KEMENC-C — FLIT256 kem_enc public API relation

- Source locator: PDF p. 15; `Implementations/Reference_Implementation/FLIT256/KEM_AlgorithmInstance.h` SHA-256 `8a4a7e0fd2cd19925bb423baf6c2a527c071f59b141bcc03ff1c0e7727d72edf`; `Test_Vectors/KAT_KEM_FLIT256_REF.txt` SHA-256 `0788e13e3a0c0ff0c8ada4defab0ea4213bf7980bcb6099dba1a2e35b05ea618`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `FLIT256` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## FLIT256-KEMGETCTLENBYTES-C — FLIT256 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/FLIT256/KEM_AlgorithmInstance.h` SHA-256 `8a4a7e0fd2cd19925bb423baf6c2a527c071f59b141bcc03ff1c0e7727d72edf`; `Test_Vectors/KAT_KEM_FLIT256_REF.txt` SHA-256 `0788e13e3a0c0ff0c8ada4defab0ea4213bf7980bcb6099dba1a2e35b05ea618`.
- Class: submitted API length/KAT observation.
- Scope: `FLIT256` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## FLIT256-KEMGETPKLENBYTES-C — FLIT256 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/FLIT256/KEM_AlgorithmInstance.h` SHA-256 `8a4a7e0fd2cd19925bb423baf6c2a527c071f59b141bcc03ff1c0e7727d72edf`; `Test_Vectors/KAT_KEM_FLIT256_REF.txt` SHA-256 `0788e13e3a0c0ff0c8ada4defab0ea4213bf7980bcb6099dba1a2e35b05ea618`.
- Class: submitted API length/KAT observation.
- Scope: `FLIT256` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## FLIT256-KEMGETSKLENBYTES-C — FLIT256 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/FLIT256/KEM_AlgorithmInstance.h` SHA-256 `8a4a7e0fd2cd19925bb423baf6c2a527c071f59b141bcc03ff1c0e7727d72edf`; `Test_Vectors/KAT_KEM_FLIT256_REF.txt` SHA-256 `0788e13e3a0c0ff0c8ada4defab0ea4213bf7980bcb6099dba1a2e35b05ea618`.
- Class: submitted API length/KAT observation.
- Scope: `FLIT256` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## FLIT256-KEMGETSSLENBYTES-C — FLIT256 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/FLIT256/KEM_AlgorithmInstance.h` SHA-256 `8a4a7e0fd2cd19925bb423baf6c2a527c071f59b141bcc03ff1c0e7727d72edf`; `Test_Vectors/KAT_KEM_FLIT256_REF.txt` SHA-256 `0788e13e3a0c0ff0c8ada4defab0ea4213bf7980bcb6099dba1a2e35b05ea618`.
- Class: submitted API length/KAT observation.
- Scope: `FLIT256` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## FLIT256-KEMKEYGEN-C — FLIT256 kem_keygen public API relation

- Source locator: PDF p. 15; `Implementations/Reference_Implementation/FLIT256/KEM_AlgorithmInstance.h` SHA-256 `8a4a7e0fd2cd19925bb423baf6c2a527c071f59b141bcc03ff1c0e7727d72edf`; `Test_Vectors/KAT_KEM_FLIT256_REF.txt` SHA-256 `0788e13e3a0c0ff0c8ada4defab0ea4213bf7980bcb6099dba1a2e35b05ea618`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `FLIT256` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## FLIT512-KEMENC-C — FLIT512 kem_enc public API relation

- Source locator: PDF p. 15; `Implementations/Reference_Implementation/FLIT512/KEM_AlgorithmInstance.h` SHA-256 `2d5a553d5204933dc45b974323f738242158f2d927e215c0b5f20f06dbe89044`; `Test_Vectors/KAT_KEM_FLIT512_REF.txt` SHA-256 `e4019117230dc2ef5983e8c2c252f08189e8004e3b7db595a66eec3aa8d9820c`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `FLIT512` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## FLIT512-KEMGETCTLENBYTES-C — FLIT512 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/FLIT512/KEM_AlgorithmInstance.h` SHA-256 `2d5a553d5204933dc45b974323f738242158f2d927e215c0b5f20f06dbe89044`; `Test_Vectors/KAT_KEM_FLIT512_REF.txt` SHA-256 `e4019117230dc2ef5983e8c2c252f08189e8004e3b7db595a66eec3aa8d9820c`.
- Class: submitted API length/KAT observation.
- Scope: `FLIT512` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## FLIT512-KEMGETPKLENBYTES-C — FLIT512 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/FLIT512/KEM_AlgorithmInstance.h` SHA-256 `2d5a553d5204933dc45b974323f738242158f2d927e215c0b5f20f06dbe89044`; `Test_Vectors/KAT_KEM_FLIT512_REF.txt` SHA-256 `e4019117230dc2ef5983e8c2c252f08189e8004e3b7db595a66eec3aa8d9820c`.
- Class: submitted API length/KAT observation.
- Scope: `FLIT512` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## FLIT512-KEMGETSKLENBYTES-C — FLIT512 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/FLIT512/KEM_AlgorithmInstance.h` SHA-256 `2d5a553d5204933dc45b974323f738242158f2d927e215c0b5f20f06dbe89044`; `Test_Vectors/KAT_KEM_FLIT512_REF.txt` SHA-256 `e4019117230dc2ef5983e8c2c252f08189e8004e3b7db595a66eec3aa8d9820c`.
- Class: submitted API length/KAT observation.
- Scope: `FLIT512` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## FLIT512-KEMGETSSLENBYTES-C — FLIT512 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/FLIT512/KEM_AlgorithmInstance.h` SHA-256 `2d5a553d5204933dc45b974323f738242158f2d927e215c0b5f20f06dbe89044`; `Test_Vectors/KAT_KEM_FLIT512_REF.txt` SHA-256 `e4019117230dc2ef5983e8c2c252f08189e8004e3b7db595a66eec3aa8d9820c`.
- Class: submitted API length/KAT observation.
- Scope: `FLIT512` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## FLIT512-KEMKEYGEN-C — FLIT512 kem_keygen public API relation

- Source locator: PDF p. 15; `Implementations/Reference_Implementation/FLIT512/KEM_AlgorithmInstance.h` SHA-256 `2d5a553d5204933dc45b974323f738242158f2d927e215c0b5f20f06dbe89044`; `Test_Vectors/KAT_KEM_FLIT512_REF.txt` SHA-256 `e4019117230dc2ef5983e8c2c252f08189e8004e3b7db595a66eec3aa8d9820c`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `FLIT512` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.
