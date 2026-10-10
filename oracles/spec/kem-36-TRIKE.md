---
status: draft
target: kem-36
algorithm: TRIKE
source_path: third_party/kem-36/source
source_sha256: ee111e7d665b2f18f6355c6215aba684b0467ad3c50faabb48fa498a96726868
document_path: third_party/kem-36/specification.pdf
document_sha256: 9258ff7264bb3bb78c02da0bf4b915f7087c8711a8ccd67e1d14a1ac2b32b407
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# TRIKE draft claim extraction

This document covers source-pinned public vector records and public API relations
for the named parameter sets. The algorithm construction and correctness context is
at PDF p. 5 (algorithm context). Original PDF and archived source are authoritative.

## TRIKE2-K — TRIKE-2 submitted valid-vector consistency

- Source locator: PDF p. 5 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_TRIKE-2.txt`, SHA-256 `a239ca65bf612d50c01c9c28777861680d98d6a0416b0737685cb6d40bc8d10f`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `TRIKE-2` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record decapsulates to its recorded shared secret.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## TRIKE2-KEMENC-C — TRIKE-2 kem_enc public API relation

- Source locator: PDF p. 7; `Implementations and Test_Vectors/Implementations/Reference_Implementation/TRIKE-2/src/KEM_AlgorithmInstance.h` SHA-256 `3161975bf7ac0d9f6b141fa0b7b4d351c39bd0f57847118e57afa95e84f0acdc`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_TRIKE-2.txt` SHA-256 `a239ca65bf612d50c01c9c28777861680d98d6a0416b0737685cb6d40bc8d10f`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `TRIKE-2` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TRIKE2-KEMGETCTLENBYTES-C — TRIKE-2 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/TRIKE-2/src/KEM_AlgorithmInstance.h` SHA-256 `3161975bf7ac0d9f6b141fa0b7b4d351c39bd0f57847118e57afa95e84f0acdc`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_TRIKE-2.txt` SHA-256 `a239ca65bf612d50c01c9c28777861680d98d6a0416b0737685cb6d40bc8d10f`.
- Class: submitted API length/KAT observation.
- Scope: `TRIKE-2` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TRIKE2-KEMGETPKLENBYTES-C — TRIKE-2 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/TRIKE-2/src/KEM_AlgorithmInstance.h` SHA-256 `3161975bf7ac0d9f6b141fa0b7b4d351c39bd0f57847118e57afa95e84f0acdc`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_TRIKE-2.txt` SHA-256 `a239ca65bf612d50c01c9c28777861680d98d6a0416b0737685cb6d40bc8d10f`.
- Class: submitted API length/KAT observation.
- Scope: `TRIKE-2` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TRIKE2-KEMGETSKLENBYTES-C — TRIKE-2 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/TRIKE-2/src/KEM_AlgorithmInstance.h` SHA-256 `3161975bf7ac0d9f6b141fa0b7b4d351c39bd0f57847118e57afa95e84f0acdc`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_TRIKE-2.txt` SHA-256 `a239ca65bf612d50c01c9c28777861680d98d6a0416b0737685cb6d40bc8d10f`.
- Class: submitted API length/KAT observation.
- Scope: `TRIKE-2` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TRIKE2-KEMGETSSLENBYTES-C — TRIKE-2 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/TRIKE-2/src/KEM_AlgorithmInstance.h` SHA-256 `3161975bf7ac0d9f6b141fa0b7b4d351c39bd0f57847118e57afa95e84f0acdc`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_TRIKE-2.txt` SHA-256 `a239ca65bf612d50c01c9c28777861680d98d6a0416b0737685cb6d40bc8d10f`.
- Class: submitted API length/KAT observation.
- Scope: `TRIKE-2` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TRIKE2-KEMKEYGEN-C — TRIKE-2 kem_keygen public API relation

- Source locator: PDF p. 7; `Implementations and Test_Vectors/Implementations/Reference_Implementation/TRIKE-2/src/KEM_AlgorithmInstance.h` SHA-256 `3161975bf7ac0d9f6b141fa0b7b4d351c39bd0f57847118e57afa95e84f0acdc`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_TRIKE-2.txt` SHA-256 `a239ca65bf612d50c01c9c28777861680d98d6a0416b0737685cb6d40bc8d10f`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `TRIKE-2` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TRIKE5-K — TRIKE-5 submitted valid-vector consistency

- Source locator: PDF p. 7 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_TRIKE-5.txt` SHA-256 `0322e5244f6f9b6c381561e6519fbf7f30b3658d66693d5832ff596894032362`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `TRIKE-5` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## TRIKE7-K — TRIKE-7 submitted valid-vector consistency

- Source locator: PDF p. 7 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_TRIKE-7.txt` SHA-256 `75e757b60924e0fbd00833172f603f1f960ba2c7ccd843a1deffdf4d2aaf06e1`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `TRIKE-7` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## TRIKE9-K — TRIKE-9 submitted valid-vector consistency

- Source locator: PDF p. 7 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_TRIKE-9.txt` SHA-256 `f1923320f996b8af6b55e7eb55bbb823185b703f967724467067e36ce9abcb70`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `TRIKE-9` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## TRIKE5-KEMENC-C — TRIKE-5 kem_enc public API relation

- Source locator: PDF p. 7; `Implementations and Test_Vectors/Implementations/Reference_Implementation/TRIKE-5/src/KEM_AlgorithmInstance.h` SHA-256 `e90b987c1e45b636001e5f77cd656ed672bf763eb53c1e3a718676a693b2144f`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_TRIKE-5.txt` SHA-256 `0322e5244f6f9b6c381561e6519fbf7f30b3658d66693d5832ff596894032362`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `TRIKE-5` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TRIKE5-KEMGETCTLENBYTES-C — TRIKE-5 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/TRIKE-5/src/KEM_AlgorithmInstance.h` SHA-256 `e90b987c1e45b636001e5f77cd656ed672bf763eb53c1e3a718676a693b2144f`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_TRIKE-5.txt` SHA-256 `0322e5244f6f9b6c381561e6519fbf7f30b3658d66693d5832ff596894032362`.
- Class: submitted API length/KAT observation.
- Scope: `TRIKE-5` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TRIKE5-KEMGETPKLENBYTES-C — TRIKE-5 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/TRIKE-5/src/KEM_AlgorithmInstance.h` SHA-256 `e90b987c1e45b636001e5f77cd656ed672bf763eb53c1e3a718676a693b2144f`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_TRIKE-5.txt` SHA-256 `0322e5244f6f9b6c381561e6519fbf7f30b3658d66693d5832ff596894032362`.
- Class: submitted API length/KAT observation.
- Scope: `TRIKE-5` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TRIKE5-KEMGETSKLENBYTES-C — TRIKE-5 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/TRIKE-5/src/KEM_AlgorithmInstance.h` SHA-256 `e90b987c1e45b636001e5f77cd656ed672bf763eb53c1e3a718676a693b2144f`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_TRIKE-5.txt` SHA-256 `0322e5244f6f9b6c381561e6519fbf7f30b3658d66693d5832ff596894032362`.
- Class: submitted API length/KAT observation.
- Scope: `TRIKE-5` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TRIKE5-KEMGETSSLENBYTES-C — TRIKE-5 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/TRIKE-5/src/KEM_AlgorithmInstance.h` SHA-256 `e90b987c1e45b636001e5f77cd656ed672bf763eb53c1e3a718676a693b2144f`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_TRIKE-5.txt` SHA-256 `0322e5244f6f9b6c381561e6519fbf7f30b3658d66693d5832ff596894032362`.
- Class: submitted API length/KAT observation.
- Scope: `TRIKE-5` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TRIKE5-KEMKEYGEN-C — TRIKE-5 kem_keygen public API relation

- Source locator: PDF p. 7; `Implementations and Test_Vectors/Implementations/Reference_Implementation/TRIKE-5/src/KEM_AlgorithmInstance.h` SHA-256 `e90b987c1e45b636001e5f77cd656ed672bf763eb53c1e3a718676a693b2144f`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_TRIKE-5.txt` SHA-256 `0322e5244f6f9b6c381561e6519fbf7f30b3658d66693d5832ff596894032362`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `TRIKE-5` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TRIKE7-KEMENC-C — TRIKE-7 kem_enc public API relation

- Source locator: PDF p. 7; `Implementations and Test_Vectors/Implementations/Reference_Implementation/TRIKE-7/src/KEM_AlgorithmInstance.h` SHA-256 `1b5f482c37b4659825662d1f4ad86182b0b5cb5a6b23c7b50ddec74db24689cf`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_TRIKE-7.txt` SHA-256 `75e757b60924e0fbd00833172f603f1f960ba2c7ccd843a1deffdf4d2aaf06e1`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `TRIKE-7` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TRIKE7-KEMGETCTLENBYTES-C — TRIKE-7 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/TRIKE-7/src/KEM_AlgorithmInstance.h` SHA-256 `1b5f482c37b4659825662d1f4ad86182b0b5cb5a6b23c7b50ddec74db24689cf`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_TRIKE-7.txt` SHA-256 `75e757b60924e0fbd00833172f603f1f960ba2c7ccd843a1deffdf4d2aaf06e1`.
- Class: submitted API length/KAT observation.
- Scope: `TRIKE-7` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TRIKE7-KEMGETPKLENBYTES-C — TRIKE-7 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/TRIKE-7/src/KEM_AlgorithmInstance.h` SHA-256 `1b5f482c37b4659825662d1f4ad86182b0b5cb5a6b23c7b50ddec74db24689cf`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_TRIKE-7.txt` SHA-256 `75e757b60924e0fbd00833172f603f1f960ba2c7ccd843a1deffdf4d2aaf06e1`.
- Class: submitted API length/KAT observation.
- Scope: `TRIKE-7` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TRIKE7-KEMGETSKLENBYTES-C — TRIKE-7 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/TRIKE-7/src/KEM_AlgorithmInstance.h` SHA-256 `1b5f482c37b4659825662d1f4ad86182b0b5cb5a6b23c7b50ddec74db24689cf`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_TRIKE-7.txt` SHA-256 `75e757b60924e0fbd00833172f603f1f960ba2c7ccd843a1deffdf4d2aaf06e1`.
- Class: submitted API length/KAT observation.
- Scope: `TRIKE-7` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TRIKE7-KEMGETSSLENBYTES-C — TRIKE-7 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/TRIKE-7/src/KEM_AlgorithmInstance.h` SHA-256 `1b5f482c37b4659825662d1f4ad86182b0b5cb5a6b23c7b50ddec74db24689cf`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_TRIKE-7.txt` SHA-256 `75e757b60924e0fbd00833172f603f1f960ba2c7ccd843a1deffdf4d2aaf06e1`.
- Class: submitted API length/KAT observation.
- Scope: `TRIKE-7` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TRIKE7-KEMKEYGEN-C — TRIKE-7 kem_keygen public API relation

- Source locator: PDF p. 7; `Implementations and Test_Vectors/Implementations/Reference_Implementation/TRIKE-7/src/KEM_AlgorithmInstance.h` SHA-256 `1b5f482c37b4659825662d1f4ad86182b0b5cb5a6b23c7b50ddec74db24689cf`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_TRIKE-7.txt` SHA-256 `75e757b60924e0fbd00833172f603f1f960ba2c7ccd843a1deffdf4d2aaf06e1`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `TRIKE-7` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TRIKE9-KEMENC-C — TRIKE-9 kem_enc public API relation

- Source locator: PDF p. 7; `Implementations and Test_Vectors/Implementations/Reference_Implementation/TRIKE-9/src/KEM_AlgorithmInstance.h` SHA-256 `dd2a4a4822e52d30af4164a2f00d8b90c0d2ff01fac5be7f1562bf10629df1d0`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_TRIKE-9.txt` SHA-256 `f1923320f996b8af6b55e7eb55bbb823185b703f967724467067e36ce9abcb70`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `TRIKE-9` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TRIKE9-KEMGETCTLENBYTES-C — TRIKE-9 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/TRIKE-9/src/KEM_AlgorithmInstance.h` SHA-256 `dd2a4a4822e52d30af4164a2f00d8b90c0d2ff01fac5be7f1562bf10629df1d0`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_TRIKE-9.txt` SHA-256 `f1923320f996b8af6b55e7eb55bbb823185b703f967724467067e36ce9abcb70`.
- Class: submitted API length/KAT observation.
- Scope: `TRIKE-9` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TRIKE9-KEMGETPKLENBYTES-C — TRIKE-9 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/TRIKE-9/src/KEM_AlgorithmInstance.h` SHA-256 `dd2a4a4822e52d30af4164a2f00d8b90c0d2ff01fac5be7f1562bf10629df1d0`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_TRIKE-9.txt` SHA-256 `f1923320f996b8af6b55e7eb55bbb823185b703f967724467067e36ce9abcb70`.
- Class: submitted API length/KAT observation.
- Scope: `TRIKE-9` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TRIKE9-KEMGETSKLENBYTES-C — TRIKE-9 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/TRIKE-9/src/KEM_AlgorithmInstance.h` SHA-256 `dd2a4a4822e52d30af4164a2f00d8b90c0d2ff01fac5be7f1562bf10629df1d0`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_TRIKE-9.txt` SHA-256 `f1923320f996b8af6b55e7eb55bbb823185b703f967724467067e36ce9abcb70`.
- Class: submitted API length/KAT observation.
- Scope: `TRIKE-9` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TRIKE9-KEMGETSSLENBYTES-C — TRIKE-9 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/TRIKE-9/src/KEM_AlgorithmInstance.h` SHA-256 `dd2a4a4822e52d30af4164a2f00d8b90c0d2ff01fac5be7f1562bf10629df1d0`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_TRIKE-9.txt` SHA-256 `f1923320f996b8af6b55e7eb55bbb823185b703f967724467067e36ce9abcb70`.
- Class: submitted API length/KAT observation.
- Scope: `TRIKE-9` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TRIKE9-KEMKEYGEN-C — TRIKE-9 kem_keygen public API relation

- Source locator: PDF p. 7; `Implementations and Test_Vectors/Implementations/Reference_Implementation/TRIKE-9/src/KEM_AlgorithmInstance.h` SHA-256 `dd2a4a4822e52d30af4164a2f00d8b90c0d2ff01fac5be7f1562bf10629df1d0`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_TRIKE-9.txt` SHA-256 `f1923320f996b8af6b55e7eb55bbb823185b703f967724467067e36ce9abcb70`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `TRIKE-9` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.
