---
status: draft
target: kem-30
algorithm: PolarLAC
source_path: third_party/kem-30/source
source_sha256: 9d6d76b5ba96cb24266eef517d2fac3acc64b2f808187529a2210838e9cb6801
document_path: third_party/kem-30/specification.pdf
document_sha256: aba16100f0e5c49d54e1811c672d90c4d837200116e5a312625f8473b6d40eca
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# PolarLAC draft claim extraction

This document covers source-pinned public vector records and public API relations
for the named parameter sets. The algorithm construction and correctness context is
at PDF p. 15 (algorithm context). Original PDF and archived source are authoritative.

## POLARLAC128-K — POLARLAC-128 submitted valid-vector consistency

- Source locator: PDF p. 15 (algorithm context); `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-128.txt`, SHA-256 `116b4096f8aa55d4f57de32ed3e9d426fde6a9d642c390ef008b38cad6b00447`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `POLARLAC-128` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record decapsulates to its recorded shared secret.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## POLARLAC128-KEMENC-C — POLARLAC-128 kem_enc public API relation

- Source locator: PDF pp. 14–16; `Implementations/Reference_Implementation/x86/POLARLAC-128/KEM_AlgorithmInstance.h` SHA-256 `5e6fd2122f14757f8f00699c8e32118565a0fdf4b3c87e6c9d34cd8014703fcb`; `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-128.txt` SHA-256 `116b4096f8aa55d4f57de32ed3e9d426fde6a9d642c390ef008b38cad6b00447`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `POLARLAC-128` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARLAC128-KEMGETCTLENBYTES-C — POLARLAC-128 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/x86/POLARLAC-128/KEM_AlgorithmInstance.h` SHA-256 `5e6fd2122f14757f8f00699c8e32118565a0fdf4b3c87e6c9d34cd8014703fcb`; `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-128.txt` SHA-256 `116b4096f8aa55d4f57de32ed3e9d426fde6a9d642c390ef008b38cad6b00447`.
- Class: submitted API length/KAT observation.
- Scope: `POLARLAC-128` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARLAC128-KEMGETPKLENBYTES-C — POLARLAC-128 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/x86/POLARLAC-128/KEM_AlgorithmInstance.h` SHA-256 `5e6fd2122f14757f8f00699c8e32118565a0fdf4b3c87e6c9d34cd8014703fcb`; `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-128.txt` SHA-256 `116b4096f8aa55d4f57de32ed3e9d426fde6a9d642c390ef008b38cad6b00447`.
- Class: submitted API length/KAT observation.
- Scope: `POLARLAC-128` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARLAC128-KEMGETSKLENBYTES-C — POLARLAC-128 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/x86/POLARLAC-128/KEM_AlgorithmInstance.h` SHA-256 `5e6fd2122f14757f8f00699c8e32118565a0fdf4b3c87e6c9d34cd8014703fcb`; `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-128.txt` SHA-256 `116b4096f8aa55d4f57de32ed3e9d426fde6a9d642c390ef008b38cad6b00447`.
- Class: submitted API length/KAT observation.
- Scope: `POLARLAC-128` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARLAC128-KEMGETSSLENBYTES-C — POLARLAC-128 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/x86/POLARLAC-128/KEM_AlgorithmInstance.h` SHA-256 `5e6fd2122f14757f8f00699c8e32118565a0fdf4b3c87e6c9d34cd8014703fcb`; `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-128.txt` SHA-256 `116b4096f8aa55d4f57de32ed3e9d426fde6a9d642c390ef008b38cad6b00447`.
- Class: submitted API length/KAT observation.
- Scope: `POLARLAC-128` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARLAC128-KEMKEYGEN-C — POLARLAC-128 kem_keygen public API relation

- Source locator: PDF pp. 14–16; `Implementations/Reference_Implementation/x86/POLARLAC-128/KEM_AlgorithmInstance.h` SHA-256 `5e6fd2122f14757f8f00699c8e32118565a0fdf4b3c87e6c9d34cd8014703fcb`; `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-128.txt` SHA-256 `116b4096f8aa55d4f57de32ed3e9d426fde6a9d642c390ef008b38cad6b00447`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `POLARLAC-128` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARLAC256-K — POLARLAC-256 submitted valid-vector consistency

- Source locator: PDF pp. 14–16 (algorithm context); `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-256.txt` SHA-256 `0607ad1d8b26c1be60c72b8ad858b73a5a92d8b4cce2a5167a8eceb157848454`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `POLARLAC-256` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## POLARLAC512-K — POLARLAC-512 submitted valid-vector consistency

- Source locator: PDF pp. 14–16 (algorithm context); `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-512.txt` SHA-256 `1e87de3b3e36f33c2079037a1136787b17cf0b1add59d451516d4eb10d761f2f`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `POLARLAC-512` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## POLARLAC512STAR-K — POLARLAC-512-Star submitted valid-vector consistency

- Source locator: PDF pp. 14–16 (algorithm context); `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-512-Star.txt` SHA-256 `dc15d771b2d5fcf7f03c2a59076edb3352e58749eb9ecd8073aab9f29c0a74b1`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `POLARLAC-512-Star` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## POLARLACLIGHT-K — POLARLAC-Light submitted valid-vector consistency

- Source locator: PDF pp. 14–16 (algorithm context); `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-Light.txt` SHA-256 `58ce4ca2e4822bf6ce99f59a465598b1dd620ffb20b7afcdb974572381c2a849`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `POLARLAC-Light` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## POLARLAC256-KEMENC-C — POLARLAC-256 kem_enc public API relation

- Source locator: PDF pp. 14–16; `Implementations/Reference_Implementation/x86/POLARLAC-256/KEM_AlgorithmInstance.h` SHA-256 `6beadac185c39f1a4663a6cabd2efc5b54cb940239e8ce03b1ee4141ad08c69b`; `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-256.txt` SHA-256 `0607ad1d8b26c1be60c72b8ad858b73a5a92d8b4cce2a5167a8eceb157848454`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `POLARLAC-256` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARLAC256-KEMGETCTLENBYTES-C — POLARLAC-256 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/x86/POLARLAC-256/KEM_AlgorithmInstance.h` SHA-256 `6beadac185c39f1a4663a6cabd2efc5b54cb940239e8ce03b1ee4141ad08c69b`; `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-256.txt` SHA-256 `0607ad1d8b26c1be60c72b8ad858b73a5a92d8b4cce2a5167a8eceb157848454`.
- Class: submitted API length/KAT observation.
- Scope: `POLARLAC-256` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARLAC256-KEMGETPKLENBYTES-C — POLARLAC-256 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/x86/POLARLAC-256/KEM_AlgorithmInstance.h` SHA-256 `6beadac185c39f1a4663a6cabd2efc5b54cb940239e8ce03b1ee4141ad08c69b`; `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-256.txt` SHA-256 `0607ad1d8b26c1be60c72b8ad858b73a5a92d8b4cce2a5167a8eceb157848454`.
- Class: submitted API length/KAT observation.
- Scope: `POLARLAC-256` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARLAC256-KEMGETSKLENBYTES-C — POLARLAC-256 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/x86/POLARLAC-256/KEM_AlgorithmInstance.h` SHA-256 `6beadac185c39f1a4663a6cabd2efc5b54cb940239e8ce03b1ee4141ad08c69b`; `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-256.txt` SHA-256 `0607ad1d8b26c1be60c72b8ad858b73a5a92d8b4cce2a5167a8eceb157848454`.
- Class: submitted API length/KAT observation.
- Scope: `POLARLAC-256` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARLAC256-KEMGETSSLENBYTES-C — POLARLAC-256 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/x86/POLARLAC-256/KEM_AlgorithmInstance.h` SHA-256 `6beadac185c39f1a4663a6cabd2efc5b54cb940239e8ce03b1ee4141ad08c69b`; `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-256.txt` SHA-256 `0607ad1d8b26c1be60c72b8ad858b73a5a92d8b4cce2a5167a8eceb157848454`.
- Class: submitted API length/KAT observation.
- Scope: `POLARLAC-256` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARLAC256-KEMKEYGEN-C — POLARLAC-256 kem_keygen public API relation

- Source locator: PDF pp. 14–16; `Implementations/Reference_Implementation/x86/POLARLAC-256/KEM_AlgorithmInstance.h` SHA-256 `6beadac185c39f1a4663a6cabd2efc5b54cb940239e8ce03b1ee4141ad08c69b`; `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-256.txt` SHA-256 `0607ad1d8b26c1be60c72b8ad858b73a5a92d8b4cce2a5167a8eceb157848454`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `POLARLAC-256` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARLAC512-KEMENC-C — POLARLAC-512 kem_enc public API relation

- Source locator: PDF pp. 14–16; `Implementations/Reference_Implementation/x86/POLARLAC-512/KEM_AlgorithmInstance.h` SHA-256 `57c18958b252eacaad90efa633e83b658e8cd040ce425d895c448fc41843ea73`; `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-512.txt` SHA-256 `1e87de3b3e36f33c2079037a1136787b17cf0b1add59d451516d4eb10d761f2f`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `POLARLAC-512` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARLAC512-KEMGETCTLENBYTES-C — POLARLAC-512 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/x86/POLARLAC-512/KEM_AlgorithmInstance.h` SHA-256 `57c18958b252eacaad90efa633e83b658e8cd040ce425d895c448fc41843ea73`; `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-512.txt` SHA-256 `1e87de3b3e36f33c2079037a1136787b17cf0b1add59d451516d4eb10d761f2f`.
- Class: submitted API length/KAT observation.
- Scope: `POLARLAC-512` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARLAC512-KEMGETPKLENBYTES-C — POLARLAC-512 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/x86/POLARLAC-512/KEM_AlgorithmInstance.h` SHA-256 `57c18958b252eacaad90efa633e83b658e8cd040ce425d895c448fc41843ea73`; `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-512.txt` SHA-256 `1e87de3b3e36f33c2079037a1136787b17cf0b1add59d451516d4eb10d761f2f`.
- Class: submitted API length/KAT observation.
- Scope: `POLARLAC-512` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARLAC512-KEMGETSKLENBYTES-C — POLARLAC-512 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/x86/POLARLAC-512/KEM_AlgorithmInstance.h` SHA-256 `57c18958b252eacaad90efa633e83b658e8cd040ce425d895c448fc41843ea73`; `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-512.txt` SHA-256 `1e87de3b3e36f33c2079037a1136787b17cf0b1add59d451516d4eb10d761f2f`.
- Class: submitted API length/KAT observation.
- Scope: `POLARLAC-512` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARLAC512-KEMGETSSLENBYTES-C — POLARLAC-512 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/x86/POLARLAC-512/KEM_AlgorithmInstance.h` SHA-256 `57c18958b252eacaad90efa633e83b658e8cd040ce425d895c448fc41843ea73`; `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-512.txt` SHA-256 `1e87de3b3e36f33c2079037a1136787b17cf0b1add59d451516d4eb10d761f2f`.
- Class: submitted API length/KAT observation.
- Scope: `POLARLAC-512` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARLAC512-KEMKEYGEN-C — POLARLAC-512 kem_keygen public API relation

- Source locator: PDF pp. 14–16; `Implementations/Reference_Implementation/x86/POLARLAC-512/KEM_AlgorithmInstance.h` SHA-256 `57c18958b252eacaad90efa633e83b658e8cd040ce425d895c448fc41843ea73`; `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-512.txt` SHA-256 `1e87de3b3e36f33c2079037a1136787b17cf0b1add59d451516d4eb10d761f2f`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `POLARLAC-512` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARLAC512STAR-KEMENC-C — POLARLAC-512-Star kem_enc public API relation

- Source locator: PDF pp. 14–16; `Implementations/Reference_Implementation/x86/POLARLAC-512-Star/KEM_AlgorithmInstance.h` SHA-256 `640f2d471c6d78d72d130c25c2ce1b36749a56fd7de93639b73129ee8300baec`; `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-512-Star.txt` SHA-256 `dc15d771b2d5fcf7f03c2a59076edb3352e58749eb9ecd8073aab9f29c0a74b1`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `POLARLAC-512-Star` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARLAC512STAR-KEMGETCTLENBYTES-C — POLARLAC-512-Star kem_get_ct_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/x86/POLARLAC-512-Star/KEM_AlgorithmInstance.h` SHA-256 `640f2d471c6d78d72d130c25c2ce1b36749a56fd7de93639b73129ee8300baec`; `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-512-Star.txt` SHA-256 `dc15d771b2d5fcf7f03c2a59076edb3352e58749eb9ecd8073aab9f29c0a74b1`.
- Class: submitted API length/KAT observation.
- Scope: `POLARLAC-512-Star` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARLAC512STAR-KEMGETPKLENBYTES-C — POLARLAC-512-Star kem_get_pk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/x86/POLARLAC-512-Star/KEM_AlgorithmInstance.h` SHA-256 `640f2d471c6d78d72d130c25c2ce1b36749a56fd7de93639b73129ee8300baec`; `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-512-Star.txt` SHA-256 `dc15d771b2d5fcf7f03c2a59076edb3352e58749eb9ecd8073aab9f29c0a74b1`.
- Class: submitted API length/KAT observation.
- Scope: `POLARLAC-512-Star` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARLAC512STAR-KEMGETSKLENBYTES-C — POLARLAC-512-Star kem_get_sk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/x86/POLARLAC-512-Star/KEM_AlgorithmInstance.h` SHA-256 `640f2d471c6d78d72d130c25c2ce1b36749a56fd7de93639b73129ee8300baec`; `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-512-Star.txt` SHA-256 `dc15d771b2d5fcf7f03c2a59076edb3352e58749eb9ecd8073aab9f29c0a74b1`.
- Class: submitted API length/KAT observation.
- Scope: `POLARLAC-512-Star` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARLAC512STAR-KEMGETSSLENBYTES-C — POLARLAC-512-Star kem_get_ss_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/x86/POLARLAC-512-Star/KEM_AlgorithmInstance.h` SHA-256 `640f2d471c6d78d72d130c25c2ce1b36749a56fd7de93639b73129ee8300baec`; `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-512-Star.txt` SHA-256 `dc15d771b2d5fcf7f03c2a59076edb3352e58749eb9ecd8073aab9f29c0a74b1`.
- Class: submitted API length/KAT observation.
- Scope: `POLARLAC-512-Star` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARLAC512STAR-KEMKEYGEN-C — POLARLAC-512-Star kem_keygen public API relation

- Source locator: PDF pp. 14–16; `Implementations/Reference_Implementation/x86/POLARLAC-512-Star/KEM_AlgorithmInstance.h` SHA-256 `640f2d471c6d78d72d130c25c2ce1b36749a56fd7de93639b73129ee8300baec`; `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-512-Star.txt` SHA-256 `dc15d771b2d5fcf7f03c2a59076edb3352e58749eb9ecd8073aab9f29c0a74b1`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `POLARLAC-512-Star` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARLACLIGHT-KEMENC-C — POLARLAC-Light kem_enc public API relation

- Source locator: PDF pp. 14–16; `Implementations/Reference_Implementation/x86/POLARLAC-Light/KEM_AlgorithmInstance.h` SHA-256 `3077e9413e7b9f13203ec9cd7f863d8e77d2186356176c97f40af03c1b48e29d`; `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-Light.txt` SHA-256 `58ce4ca2e4822bf6ce99f59a465598b1dd620ffb20b7afcdb974572381c2a849`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `POLARLAC-Light` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARLACLIGHT-KEMGETCTLENBYTES-C — POLARLAC-Light kem_get_ct_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/x86/POLARLAC-Light/KEM_AlgorithmInstance.h` SHA-256 `3077e9413e7b9f13203ec9cd7f863d8e77d2186356176c97f40af03c1b48e29d`; `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-Light.txt` SHA-256 `58ce4ca2e4822bf6ce99f59a465598b1dd620ffb20b7afcdb974572381c2a849`.
- Class: submitted API length/KAT observation.
- Scope: `POLARLAC-Light` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARLACLIGHT-KEMGETPKLENBYTES-C — POLARLAC-Light kem_get_pk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/x86/POLARLAC-Light/KEM_AlgorithmInstance.h` SHA-256 `3077e9413e7b9f13203ec9cd7f863d8e77d2186356176c97f40af03c1b48e29d`; `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-Light.txt` SHA-256 `58ce4ca2e4822bf6ce99f59a465598b1dd620ffb20b7afcdb974572381c2a849`.
- Class: submitted API length/KAT observation.
- Scope: `POLARLAC-Light` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARLACLIGHT-KEMGETSKLENBYTES-C — POLARLAC-Light kem_get_sk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/x86/POLARLAC-Light/KEM_AlgorithmInstance.h` SHA-256 `3077e9413e7b9f13203ec9cd7f863d8e77d2186356176c97f40af03c1b48e29d`; `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-Light.txt` SHA-256 `58ce4ca2e4822bf6ce99f59a465598b1dd620ffb20b7afcdb974572381c2a849`.
- Class: submitted API length/KAT observation.
- Scope: `POLARLAC-Light` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARLACLIGHT-KEMGETSSLENBYTES-C — POLARLAC-Light kem_get_ss_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/x86/POLARLAC-Light/KEM_AlgorithmInstance.h` SHA-256 `3077e9413e7b9f13203ec9cd7f863d8e77d2186356176c97f40af03c1b48e29d`; `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-Light.txt` SHA-256 `58ce4ca2e4822bf6ce99f59a465598b1dd620ffb20b7afcdb974572381c2a849`.
- Class: submitted API length/KAT observation.
- Scope: `POLARLAC-Light` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## POLARLACLIGHT-KEMKEYGEN-C — POLARLAC-Light kem_keygen public API relation

- Source locator: PDF pp. 14–16; `Implementations/Reference_Implementation/x86/POLARLAC-Light/KEM_AlgorithmInstance.h` SHA-256 `3077e9413e7b9f13203ec9cd7f863d8e77d2186356176c97f40af03c1b48e29d`; `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-Light.txt` SHA-256 `58ce4ca2e4822bf6ce99f59a465598b1dd620ffb20b7afcdb974572381c2a849`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `POLARLAC-Light` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.
