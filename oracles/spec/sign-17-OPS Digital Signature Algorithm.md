---
status: draft
target: sign-17
algorithm: OPS Digital Signature Algorithm
source_path: third_party/sign-17/source
source_sha256: 3fe57e1c750c03f843a39740bc596615017cf20b8d06b1ccd08a68c898fc4291
document_path: third_party/sign-17/specification.pdf
document_sha256: 1b5dc50ff728b2698bda90928251bae4e6cac4e138c82359f6f263cb6914078f
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# OPS Digital Signature Algorithm draft claim extraction

This document covers source-pinned public vector records and public API relations
for the named parameter sets. The algorithm construction and correctness context is
at PDF p. 6 (algorithm context). Original PDF and archived source are authoritative.

## OPSSIG128-K — OPSsig-128 submitted valid-vector consistency

- Source locator: PDF p. 6 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/reference/OPSsig-128/KAT_SIG_OPSsig-128-reference.txt`, SHA-256 `6eb659eb80e779a9ec58498fe14b70c9299e3b626d2d0fab4a0ce144cf466b79`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `OPSsig-128` `sig_verify` on the ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record is accepted by verification.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## OPSSIG128-SIGGETPKLENBYTES-C — OPSsig-128 sig_get_pk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/OPSsig-128/SIG_AlgorithmInstance.h` SHA-256 `c99c141f50759185280ccfd3315fa39272c9c0c547130edc4be25ebde18f06a4`; `Implementations and Test_Vectors/Test_Vectors/reference/OPSsig-128/KAT_SIG_OPSsig-128-reference.txt` SHA-256 `6eb659eb80e779a9ec58498fe14b70c9299e3b626d2d0fab4a0ce144cf466b79`.
- Class: submitted API length/KAT observation.
- Scope: `OPSsig-128` `sig_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## OPSSIG128-SIGGETSKLENBYTES-C — OPSsig-128 sig_get_sk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/OPSsig-128/SIG_AlgorithmInstance.h` SHA-256 `c99c141f50759185280ccfd3315fa39272c9c0c547130edc4be25ebde18f06a4`; `Implementations and Test_Vectors/Test_Vectors/reference/OPSsig-128/KAT_SIG_OPSsig-128-reference.txt` SHA-256 `6eb659eb80e779a9ec58498fe14b70c9299e3b626d2d0fab4a0ce144cf466b79`.
- Class: submitted API length/KAT observation.
- Scope: `OPSsig-128` `sig_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## OPSSIG128-SIGGETSNLENBYTES-C — OPSsig-128 sig_get_sn_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/OPSsig-128/SIG_AlgorithmInstance.h` SHA-256 `c99c141f50759185280ccfd3315fa39272c9c0c547130edc4be25ebde18f06a4`; `Implementations and Test_Vectors/Test_Vectors/reference/OPSsig-128/KAT_SIG_OPSsig-128-reference.txt` SHA-256 `6eb659eb80e779a9ec58498fe14b70c9299e3b626d2d0fab4a0ce144cf466b79`.
- Class: submitted API length/KAT observation.
- Scope: `OPSsig-128` `sig_get_sn_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## OPSSIG128-SIGKEYGEN-C — OPSsig-128 sig_keygen public API relation

- Source locator: PDF p. 7; `Implementations and Test_Vectors/Implementations/Reference_Implementation/OPSsig-128/SIG_AlgorithmInstance.h` SHA-256 `c99c141f50759185280ccfd3315fa39272c9c0c547130edc4be25ebde18f06a4`; `Implementations and Test_Vectors/Test_Vectors/reference/OPSsig-128/KAT_SIG_OPSsig-128-reference.txt` SHA-256 `6eb659eb80e779a9ec58498fe14b70c9299e3b626d2d0fab4a0ce144cf466b79`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `OPSsig-128` `sig_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## OPSSIG128-SIGSIGN-C — OPSsig-128 sig_sign public API relation

- Source locator: PDF p. 7; `Implementations and Test_Vectors/Implementations/Reference_Implementation/OPSsig-128/SIG_AlgorithmInstance.h` SHA-256 `c99c141f50759185280ccfd3315fa39272c9c0c547130edc4be25ebde18f06a4`; `Implementations and Test_Vectors/Test_Vectors/reference/OPSsig-128/KAT_SIG_OPSsig-128-reference.txt` SHA-256 `6eb659eb80e779a9ec58498fe14b70c9299e3b626d2d0fab4a0ce144cf466b79`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `OPSsig-128` `sig_sign` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## OPSSIG256-K — OPSsig-256 submitted valid-vector consistency

- Source locator: PDF p. 7 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/reference/OPSsig-256/KAT_SIG_OPSsig-256-reference.txt` SHA-256 `61881f46ecea283f08cf7e3ca51da570b856e80064b719209743e4c8a6b25f1c`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `OPSsig-256` `sig_verify` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records are accepted by sig_verify.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## OPSSIG512-K — OPSsig-512 submitted valid-vector consistency

- Source locator: PDF p. 7 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/reference/OPSsig-512/KAT_SIG_OPSsig-512-reference.txt` SHA-256 `2a7f1e29f2b8c2f43cc1bad56220ec936a3de4051e04686e0dbd19826d569263`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `OPSsig-512` `sig_verify` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records are accepted by sig_verify.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## OPSSIG256-SIGGETPKLENBYTES-C — OPSsig-256 sig_get_pk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/OPSsig-256/SIG_AlgorithmInstance.h` SHA-256 `03b221a09a67995cef7449d321519f26227c024de58caa64690f16075eadeb5a`; `Implementations and Test_Vectors/Test_Vectors/reference/OPSsig-256/KAT_SIG_OPSsig-256-reference.txt` SHA-256 `61881f46ecea283f08cf7e3ca51da570b856e80064b719209743e4c8a6b25f1c`.
- Class: submitted API length/KAT observation.
- Scope: `OPSsig-256` `sig_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## OPSSIG256-SIGGETSKLENBYTES-C — OPSsig-256 sig_get_sk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/OPSsig-256/SIG_AlgorithmInstance.h` SHA-256 `03b221a09a67995cef7449d321519f26227c024de58caa64690f16075eadeb5a`; `Implementations and Test_Vectors/Test_Vectors/reference/OPSsig-256/KAT_SIG_OPSsig-256-reference.txt` SHA-256 `61881f46ecea283f08cf7e3ca51da570b856e80064b719209743e4c8a6b25f1c`.
- Class: submitted API length/KAT observation.
- Scope: `OPSsig-256` `sig_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## OPSSIG256-SIGGETSNLENBYTES-C — OPSsig-256 sig_get_sn_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/OPSsig-256/SIG_AlgorithmInstance.h` SHA-256 `03b221a09a67995cef7449d321519f26227c024de58caa64690f16075eadeb5a`; `Implementations and Test_Vectors/Test_Vectors/reference/OPSsig-256/KAT_SIG_OPSsig-256-reference.txt` SHA-256 `61881f46ecea283f08cf7e3ca51da570b856e80064b719209743e4c8a6b25f1c`.
- Class: submitted API length/KAT observation.
- Scope: `OPSsig-256` `sig_get_sn_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## OPSSIG256-SIGKEYGEN-C — OPSsig-256 sig_keygen public API relation

- Source locator: PDF p. 7; `Implementations and Test_Vectors/Implementations/Reference_Implementation/OPSsig-256/SIG_AlgorithmInstance.h` SHA-256 `03b221a09a67995cef7449d321519f26227c024de58caa64690f16075eadeb5a`; `Implementations and Test_Vectors/Test_Vectors/reference/OPSsig-256/KAT_SIG_OPSsig-256-reference.txt` SHA-256 `61881f46ecea283f08cf7e3ca51da570b856e80064b719209743e4c8a6b25f1c`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `OPSsig-256` `sig_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## OPSSIG256-SIGSIGN-C — OPSsig-256 sig_sign public API relation

- Source locator: PDF p. 7; `Implementations and Test_Vectors/Implementations/Reference_Implementation/OPSsig-256/SIG_AlgorithmInstance.h` SHA-256 `03b221a09a67995cef7449d321519f26227c024de58caa64690f16075eadeb5a`; `Implementations and Test_Vectors/Test_Vectors/reference/OPSsig-256/KAT_SIG_OPSsig-256-reference.txt` SHA-256 `61881f46ecea283f08cf7e3ca51da570b856e80064b719209743e4c8a6b25f1c`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `OPSsig-256` `sig_sign` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## OPSSIG512-SIGGETPKLENBYTES-C — OPSsig-512 sig_get_pk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/OPSsig-512/SIG_AlgorithmInstance.h` SHA-256 `fa93fc260c257b0a85da1d418dedfd65bf8da168c8628c64625835b413868778`; `Implementations and Test_Vectors/Test_Vectors/reference/OPSsig-512/KAT_SIG_OPSsig-512-reference.txt` SHA-256 `2a7f1e29f2b8c2f43cc1bad56220ec936a3de4051e04686e0dbd19826d569263`.
- Class: submitted API length/KAT observation.
- Scope: `OPSsig-512` `sig_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## OPSSIG512-SIGGETSKLENBYTES-C — OPSsig-512 sig_get_sk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/OPSsig-512/SIG_AlgorithmInstance.h` SHA-256 `fa93fc260c257b0a85da1d418dedfd65bf8da168c8628c64625835b413868778`; `Implementations and Test_Vectors/Test_Vectors/reference/OPSsig-512/KAT_SIG_OPSsig-512-reference.txt` SHA-256 `2a7f1e29f2b8c2f43cc1bad56220ec936a3de4051e04686e0dbd19826d569263`.
- Class: submitted API length/KAT observation.
- Scope: `OPSsig-512` `sig_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## OPSSIG512-SIGGETSNLENBYTES-C — OPSsig-512 sig_get_sn_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/OPSsig-512/SIG_AlgorithmInstance.h` SHA-256 `fa93fc260c257b0a85da1d418dedfd65bf8da168c8628c64625835b413868778`; `Implementations and Test_Vectors/Test_Vectors/reference/OPSsig-512/KAT_SIG_OPSsig-512-reference.txt` SHA-256 `2a7f1e29f2b8c2f43cc1bad56220ec936a3de4051e04686e0dbd19826d569263`.
- Class: submitted API length/KAT observation.
- Scope: `OPSsig-512` `sig_get_sn_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## OPSSIG512-SIGKEYGEN-C — OPSsig-512 sig_keygen public API relation

- Source locator: PDF p. 7; `Implementations and Test_Vectors/Implementations/Reference_Implementation/OPSsig-512/SIG_AlgorithmInstance.h` SHA-256 `fa93fc260c257b0a85da1d418dedfd65bf8da168c8628c64625835b413868778`; `Implementations and Test_Vectors/Test_Vectors/reference/OPSsig-512/KAT_SIG_OPSsig-512-reference.txt` SHA-256 `2a7f1e29f2b8c2f43cc1bad56220ec936a3de4051e04686e0dbd19826d569263`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `OPSsig-512` `sig_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## OPSSIG512-SIGSIGN-C — OPSsig-512 sig_sign public API relation

- Source locator: PDF p. 7; `Implementations and Test_Vectors/Implementations/Reference_Implementation/OPSsig-512/SIG_AlgorithmInstance.h` SHA-256 `fa93fc260c257b0a85da1d418dedfd65bf8da168c8628c64625835b413868778`; `Implementations and Test_Vectors/Test_Vectors/reference/OPSsig-512/KAT_SIG_OPSsig-512-reference.txt` SHA-256 `2a7f1e29f2b8c2f43cc1bad56220ec936a3de4051e04686e0dbd19826d569263`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `OPSsig-512` `sig_sign` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.
