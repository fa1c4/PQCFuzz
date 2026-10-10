---
status: draft
target: kem-27
algorithm: NTRE Key Encapsulation Mechanism
source_path: third_party/kem-27/source
source_sha256: a4084c8a7b95556fb35b7052c4ad4b43191b0ffcbb7b8d5d862133d932df886b
document_path: third_party/kem-27/specification.pdf
document_sha256: af7a09a5633b494a67347bf518babf1f03ed90786e7d075a25869edd575a0003
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# NTRE Key Encapsulation Mechanism draft claim extraction

This document covers source-pinned public vector records and public API relations
for the named parameter sets. The algorithm construction and correctness context is
at PDF p. 18 (algorithm context). Original PDF and archived source are authoritative.

## NTRE128-K — NTRE-128 submitted valid-vector consistency

- Source locator: PDF p. 18 (algorithm context); `Implementations/Reference_Implementation/NTRE-128/output/KAT_KEM_NTRE-128.txt`, SHA-256 `65cab746a920cf829732bdb6e2c9f2a9caf198d3fa676a48c85f03f897a87af7`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `NTRE-128` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record decapsulates to its recorded shared secret.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## NTRE128-KEMENC-C — NTRE-128 kem_enc public API relation

- Source locator: PDF p. 18; `Implementations/Reference_Implementation/NTRE-128/KEM_AlgorithmInstance.h` SHA-256 `093b78a8d0dbc29a73506622227aa2eee1847f1c8a705f498dc53e4a75a769cc`; `Implementations/Reference_Implementation/NTRE-128/output/KAT_KEM_NTRE-128.txt` SHA-256 `65cab746a920cf829732bdb6e2c9f2a9caf198d3fa676a48c85f03f897a87af7`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `NTRE-128` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## NTRE128-KEMGETCTLENBYTES-C — NTRE-128 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/NTRE-128/KEM_AlgorithmInstance.h` SHA-256 `093b78a8d0dbc29a73506622227aa2eee1847f1c8a705f498dc53e4a75a769cc`; `Implementations/Reference_Implementation/NTRE-128/output/KAT_KEM_NTRE-128.txt` SHA-256 `65cab746a920cf829732bdb6e2c9f2a9caf198d3fa676a48c85f03f897a87af7`.
- Class: submitted API length/KAT observation.
- Scope: `NTRE-128` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## NTRE128-KEMGETPKLENBYTES-C — NTRE-128 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/NTRE-128/KEM_AlgorithmInstance.h` SHA-256 `093b78a8d0dbc29a73506622227aa2eee1847f1c8a705f498dc53e4a75a769cc`; `Implementations/Reference_Implementation/NTRE-128/output/KAT_KEM_NTRE-128.txt` SHA-256 `65cab746a920cf829732bdb6e2c9f2a9caf198d3fa676a48c85f03f897a87af7`.
- Class: submitted API length/KAT observation.
- Scope: `NTRE-128` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## NTRE128-KEMGETSKLENBYTES-C — NTRE-128 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/NTRE-128/KEM_AlgorithmInstance.h` SHA-256 `093b78a8d0dbc29a73506622227aa2eee1847f1c8a705f498dc53e4a75a769cc`; `Implementations/Reference_Implementation/NTRE-128/output/KAT_KEM_NTRE-128.txt` SHA-256 `65cab746a920cf829732bdb6e2c9f2a9caf198d3fa676a48c85f03f897a87af7`.
- Class: submitted API length/KAT observation.
- Scope: `NTRE-128` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## NTRE128-KEMGETSSLENBYTES-C — NTRE-128 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/NTRE-128/KEM_AlgorithmInstance.h` SHA-256 `093b78a8d0dbc29a73506622227aa2eee1847f1c8a705f498dc53e4a75a769cc`; `Implementations/Reference_Implementation/NTRE-128/output/KAT_KEM_NTRE-128.txt` SHA-256 `65cab746a920cf829732bdb6e2c9f2a9caf198d3fa676a48c85f03f897a87af7`.
- Class: submitted API length/KAT observation.
- Scope: `NTRE-128` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## NTRE128-KEMKEYGEN-C — NTRE-128 kem_keygen public API relation

- Source locator: PDF p. 18; `Implementations/Reference_Implementation/NTRE-128/KEM_AlgorithmInstance.h` SHA-256 `093b78a8d0dbc29a73506622227aa2eee1847f1c8a705f498dc53e4a75a769cc`; `Implementations/Reference_Implementation/NTRE-128/output/KAT_KEM_NTRE-128.txt` SHA-256 `65cab746a920cf829732bdb6e2c9f2a9caf198d3fa676a48c85f03f897a87af7`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `NTRE-128` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## NTRE256-K — NTRE-256 submitted valid-vector consistency

- Source locator: PDF p. 18 (algorithm context); `Implementations/Reference_Implementation/NTRE-256/output/KAT_KEM_NTRE-256.txt` SHA-256 `b46885a10bc6931aad20390b23aba3a630991948242f379cc41e72710145157a`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `NTRE-256` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## NTRE512-K — NTRE-512 submitted valid-vector consistency

- Source locator: PDF p. 18 (algorithm context); `Implementations/Reference_Implementation/NTRE-512/output/KAT_KEM_NTRE-512.txt` SHA-256 `b3608ede368d63bf002e4819139f748c1e387e1354d98de93420d5db99e24402`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `NTRE-512` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## NTRE256-KEMENC-C — NTRE-256 kem_enc public API relation

- Source locator: PDF p. 18; `Implementations/Reference_Implementation/NTRE-256/KEM_AlgorithmInstance.h` SHA-256 `3f8938e283f57a2ae92c564d7eb963900d9086c1105ef48333769f33e1b74d6b`; `Implementations/Reference_Implementation/NTRE-256/output/KAT_KEM_NTRE-256.txt` SHA-256 `b46885a10bc6931aad20390b23aba3a630991948242f379cc41e72710145157a`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `NTRE-256` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## NTRE256-KEMGETCTLENBYTES-C — NTRE-256 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/NTRE-256/KEM_AlgorithmInstance.h` SHA-256 `3f8938e283f57a2ae92c564d7eb963900d9086c1105ef48333769f33e1b74d6b`; `Implementations/Reference_Implementation/NTRE-256/output/KAT_KEM_NTRE-256.txt` SHA-256 `b46885a10bc6931aad20390b23aba3a630991948242f379cc41e72710145157a`.
- Class: submitted API length/KAT observation.
- Scope: `NTRE-256` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## NTRE256-KEMGETPKLENBYTES-C — NTRE-256 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/NTRE-256/KEM_AlgorithmInstance.h` SHA-256 `3f8938e283f57a2ae92c564d7eb963900d9086c1105ef48333769f33e1b74d6b`; `Implementations/Reference_Implementation/NTRE-256/output/KAT_KEM_NTRE-256.txt` SHA-256 `b46885a10bc6931aad20390b23aba3a630991948242f379cc41e72710145157a`.
- Class: submitted API length/KAT observation.
- Scope: `NTRE-256` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## NTRE256-KEMGETSKLENBYTES-C — NTRE-256 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/NTRE-256/KEM_AlgorithmInstance.h` SHA-256 `3f8938e283f57a2ae92c564d7eb963900d9086c1105ef48333769f33e1b74d6b`; `Implementations/Reference_Implementation/NTRE-256/output/KAT_KEM_NTRE-256.txt` SHA-256 `b46885a10bc6931aad20390b23aba3a630991948242f379cc41e72710145157a`.
- Class: submitted API length/KAT observation.
- Scope: `NTRE-256` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## NTRE256-KEMGETSSLENBYTES-C — NTRE-256 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/NTRE-256/KEM_AlgorithmInstance.h` SHA-256 `3f8938e283f57a2ae92c564d7eb963900d9086c1105ef48333769f33e1b74d6b`; `Implementations/Reference_Implementation/NTRE-256/output/KAT_KEM_NTRE-256.txt` SHA-256 `b46885a10bc6931aad20390b23aba3a630991948242f379cc41e72710145157a`.
- Class: submitted API length/KAT observation.
- Scope: `NTRE-256` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## NTRE256-KEMKEYGEN-C — NTRE-256 kem_keygen public API relation

- Source locator: PDF p. 18; `Implementations/Reference_Implementation/NTRE-256/KEM_AlgorithmInstance.h` SHA-256 `3f8938e283f57a2ae92c564d7eb963900d9086c1105ef48333769f33e1b74d6b`; `Implementations/Reference_Implementation/NTRE-256/output/KAT_KEM_NTRE-256.txt` SHA-256 `b46885a10bc6931aad20390b23aba3a630991948242f379cc41e72710145157a`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `NTRE-256` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## NTRE512-KEMENC-C — NTRE-512 kem_enc public API relation

- Source locator: PDF p. 18; `Implementations/Reference_Implementation/NTRE-512/KEM_AlgorithmInstance.h` SHA-256 `6d418768fa7ae0af64f3eb1dd00406a24b6c879e6dbacf3dcf06565258ce701d`; `Implementations/Reference_Implementation/NTRE-512/output/KAT_KEM_NTRE-512.txt` SHA-256 `b3608ede368d63bf002e4819139f748c1e387e1354d98de93420d5db99e24402`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `NTRE-512` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## NTRE512-KEMGETCTLENBYTES-C — NTRE-512 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/NTRE-512/KEM_AlgorithmInstance.h` SHA-256 `6d418768fa7ae0af64f3eb1dd00406a24b6c879e6dbacf3dcf06565258ce701d`; `Implementations/Reference_Implementation/NTRE-512/output/KAT_KEM_NTRE-512.txt` SHA-256 `b3608ede368d63bf002e4819139f748c1e387e1354d98de93420d5db99e24402`.
- Class: submitted API length/KAT observation.
- Scope: `NTRE-512` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## NTRE512-KEMGETPKLENBYTES-C — NTRE-512 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/NTRE-512/KEM_AlgorithmInstance.h` SHA-256 `6d418768fa7ae0af64f3eb1dd00406a24b6c879e6dbacf3dcf06565258ce701d`; `Implementations/Reference_Implementation/NTRE-512/output/KAT_KEM_NTRE-512.txt` SHA-256 `b3608ede368d63bf002e4819139f748c1e387e1354d98de93420d5db99e24402`.
- Class: submitted API length/KAT observation.
- Scope: `NTRE-512` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## NTRE512-KEMGETSKLENBYTES-C — NTRE-512 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/NTRE-512/KEM_AlgorithmInstance.h` SHA-256 `6d418768fa7ae0af64f3eb1dd00406a24b6c879e6dbacf3dcf06565258ce701d`; `Implementations/Reference_Implementation/NTRE-512/output/KAT_KEM_NTRE-512.txt` SHA-256 `b3608ede368d63bf002e4819139f748c1e387e1354d98de93420d5db99e24402`.
- Class: submitted API length/KAT observation.
- Scope: `NTRE-512` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## NTRE512-KEMGETSSLENBYTES-C — NTRE-512 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/NTRE-512/KEM_AlgorithmInstance.h` SHA-256 `6d418768fa7ae0af64f3eb1dd00406a24b6c879e6dbacf3dcf06565258ce701d`; `Implementations/Reference_Implementation/NTRE-512/output/KAT_KEM_NTRE-512.txt` SHA-256 `b3608ede368d63bf002e4819139f748c1e387e1354d98de93420d5db99e24402`.
- Class: submitted API length/KAT observation.
- Scope: `NTRE-512` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## NTRE512-KEMKEYGEN-C — NTRE-512 kem_keygen public API relation

- Source locator: PDF p. 18; `Implementations/Reference_Implementation/NTRE-512/KEM_AlgorithmInstance.h` SHA-256 `6d418768fa7ae0af64f3eb1dd00406a24b6c879e6dbacf3dcf06565258ce701d`; `Implementations/Reference_Implementation/NTRE-512/output/KAT_KEM_NTRE-512.txt` SHA-256 `b3608ede368d63bf002e4819139f748c1e387e1354d98de93420d5db99e24402`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `NTRE-512` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.
