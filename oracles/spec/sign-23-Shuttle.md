---
status: draft
target: sign-23
algorithm: Shuttle
source_path: third_party/sign-23/source
source_sha256: 2eecc9fd1797f6084634abbd027dacc5a1f2ba29d5abf5cb6bf3b203c2f686d5
document_path: third_party/sign-23/specification.pdf
document_sha256: 881145de9832bc55cc5a27a61fff2a213c625c20c2c1ada60c32825ad8a95893
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# Shuttle draft claim extraction

This document covers source-pinned public vector records and public API relations
for the named parameter sets. The algorithm construction and correctness context is
at PDF p. 16 (algorithm context). Original PDF and archived source are authoritative.

## SHUTTLE128-K — SHUTTLE-128 submitted valid-vector consistency

- Source locator: PDF p. 16 (algorithm context); `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Test_Vectors/KAT_SIG_SHUTTLE-128.txt`, SHA-256 `2c3a69e9a24315af747bae07309a7c4ad02fd29808461f9198aad29a6e0a60b3`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `SHUTTLE-128` `sig_verify` on the ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record is accepted by verification.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## SHUTTLE128-SIGGETPKLENBYTES-C — SHUTTLE-128 sig_get_pk_len_bytes public API relation

- Source locator: `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Implementations/Reference_Implementation/SHUTTLE-128/SIG_AlgorithmInstance.h` SHA-256 `3332e100f237fc349f909f24416b98659b9d769e43c80b6fac98ad40905ac938`; `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Test_Vectors/KAT_SIG_SHUTTLE-128.txt` SHA-256 `2c3a69e9a24315af747bae07309a7c4ad02fd29808461f9198aad29a6e0a60b3`.
- Class: submitted API length/KAT observation.
- Scope: `SHUTTLE-128` `sig_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## SHUTTLE128-SIGGETSKLENBYTES-C — SHUTTLE-128 sig_get_sk_len_bytes public API relation

- Source locator: `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Implementations/Reference_Implementation/SHUTTLE-128/SIG_AlgorithmInstance.h` SHA-256 `3332e100f237fc349f909f24416b98659b9d769e43c80b6fac98ad40905ac938`; `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Test_Vectors/KAT_SIG_SHUTTLE-128.txt` SHA-256 `2c3a69e9a24315af747bae07309a7c4ad02fd29808461f9198aad29a6e0a60b3`.
- Class: submitted API length/KAT observation.
- Scope: `SHUTTLE-128` `sig_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## SHUTTLE128-SIGGETSNLENBYTES-C — SHUTTLE-128 sig_get_sn_len_bytes public API relation

- Source locator: `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Implementations/Reference_Implementation/SHUTTLE-128/SIG_AlgorithmInstance.h` SHA-256 `3332e100f237fc349f909f24416b98659b9d769e43c80b6fac98ad40905ac938`; `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Test_Vectors/KAT_SIG_SHUTTLE-128.txt` SHA-256 `2c3a69e9a24315af747bae07309a7c4ad02fd29808461f9198aad29a6e0a60b3`.
- Class: submitted API length/KAT observation.
- Scope: `SHUTTLE-128` `sig_get_sn_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## SHUTTLE128-SIGKEYGEN-C — SHUTTLE-128 sig_keygen public API relation

- Source locator: PDF p. 10; `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Implementations/Reference_Implementation/SHUTTLE-128/SIG_AlgorithmInstance.h` SHA-256 `3332e100f237fc349f909f24416b98659b9d769e43c80b6fac98ad40905ac938`; `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Test_Vectors/KAT_SIG_SHUTTLE-128.txt` SHA-256 `2c3a69e9a24315af747bae07309a7c4ad02fd29808461f9198aad29a6e0a60b3`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `SHUTTLE-128` `sig_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## SHUTTLE128-SIGSIGN-C — SHUTTLE-128 sig_sign public API relation

- Source locator: PDF p. 10; `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Implementations/Reference_Implementation/SHUTTLE-128/SIG_AlgorithmInstance.h` SHA-256 `3332e100f237fc349f909f24416b98659b9d769e43c80b6fac98ad40905ac938`; `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Test_Vectors/KAT_SIG_SHUTTLE-128.txt` SHA-256 `2c3a69e9a24315af747bae07309a7c4ad02fd29808461f9198aad29a6e0a60b3`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `SHUTTLE-128` `sig_sign` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## SHUTTLE256-K — SHUTTLE-256 submitted valid-vector consistency

- Source locator: PDF p. 10 (algorithm context); `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Test_Vectors/KAT_SIG_SHUTTLE-256.txt` SHA-256 `02b98170db3ec301a019249545bbee9bb2d23a9717cd1bec0bf26724dcc20984`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `SHUTTLE-256` `sig_verify` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records are accepted by sig_verify.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## SHUTTLE512-K — SHUTTLE-512 submitted valid-vector consistency

- Source locator: PDF p. 10 (algorithm context); `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Test_Vectors/KAT_SIG_SHUTTLE-512.txt` SHA-256 `58db9d94375d91b9a941134b5b06a32d430f7866636c081a81725fdfac66a3bb`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `SHUTTLE-512` `sig_verify` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records are accepted by sig_verify.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## SHUTTLE256-SIGGETPKLENBYTES-C — SHUTTLE-256 sig_get_pk_len_bytes public API relation

- Source locator: `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Implementations/Reference_Implementation/SHUTTLE-256/SIG_AlgorithmInstance.h` SHA-256 `3332e100f237fc349f909f24416b98659b9d769e43c80b6fac98ad40905ac938`; `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Test_Vectors/KAT_SIG_SHUTTLE-256.txt` SHA-256 `02b98170db3ec301a019249545bbee9bb2d23a9717cd1bec0bf26724dcc20984`.
- Class: submitted API length/KAT observation.
- Scope: `SHUTTLE-256` `sig_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## SHUTTLE256-SIGGETSKLENBYTES-C — SHUTTLE-256 sig_get_sk_len_bytes public API relation

- Source locator: `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Implementations/Reference_Implementation/SHUTTLE-256/SIG_AlgorithmInstance.h` SHA-256 `3332e100f237fc349f909f24416b98659b9d769e43c80b6fac98ad40905ac938`; `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Test_Vectors/KAT_SIG_SHUTTLE-256.txt` SHA-256 `02b98170db3ec301a019249545bbee9bb2d23a9717cd1bec0bf26724dcc20984`.
- Class: submitted API length/KAT observation.
- Scope: `SHUTTLE-256` `sig_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## SHUTTLE256-SIGGETSNLENBYTES-C — SHUTTLE-256 sig_get_sn_len_bytes public API relation

- Source locator: `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Implementations/Reference_Implementation/SHUTTLE-256/SIG_AlgorithmInstance.h` SHA-256 `3332e100f237fc349f909f24416b98659b9d769e43c80b6fac98ad40905ac938`; `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Test_Vectors/KAT_SIG_SHUTTLE-256.txt` SHA-256 `02b98170db3ec301a019249545bbee9bb2d23a9717cd1bec0bf26724dcc20984`.
- Class: submitted API length/KAT observation.
- Scope: `SHUTTLE-256` `sig_get_sn_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## SHUTTLE256-SIGKEYGEN-C — SHUTTLE-256 sig_keygen public API relation

- Source locator: PDF p. 10; `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Implementations/Reference_Implementation/SHUTTLE-256/SIG_AlgorithmInstance.h` SHA-256 `3332e100f237fc349f909f24416b98659b9d769e43c80b6fac98ad40905ac938`; `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Test_Vectors/KAT_SIG_SHUTTLE-256.txt` SHA-256 `02b98170db3ec301a019249545bbee9bb2d23a9717cd1bec0bf26724dcc20984`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `SHUTTLE-256` `sig_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## SHUTTLE256-SIGSIGN-C — SHUTTLE-256 sig_sign public API relation

- Source locator: PDF p. 10; `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Implementations/Reference_Implementation/SHUTTLE-256/SIG_AlgorithmInstance.h` SHA-256 `3332e100f237fc349f909f24416b98659b9d769e43c80b6fac98ad40905ac938`; `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Test_Vectors/KAT_SIG_SHUTTLE-256.txt` SHA-256 `02b98170db3ec301a019249545bbee9bb2d23a9717cd1bec0bf26724dcc20984`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `SHUTTLE-256` `sig_sign` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## SHUTTLE512-SIGGETPKLENBYTES-C — SHUTTLE-512 sig_get_pk_len_bytes public API relation

- Source locator: `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Implementations/Reference_Implementation/SHUTTLE-512/SIG_AlgorithmInstance.h` SHA-256 `3332e100f237fc349f909f24416b98659b9d769e43c80b6fac98ad40905ac938`; `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Test_Vectors/KAT_SIG_SHUTTLE-512.txt` SHA-256 `58db9d94375d91b9a941134b5b06a32d430f7866636c081a81725fdfac66a3bb`.
- Class: submitted API length/KAT observation.
- Scope: `SHUTTLE-512` `sig_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## SHUTTLE512-SIGGETSKLENBYTES-C — SHUTTLE-512 sig_get_sk_len_bytes public API relation

- Source locator: `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Implementations/Reference_Implementation/SHUTTLE-512/SIG_AlgorithmInstance.h` SHA-256 `3332e100f237fc349f909f24416b98659b9d769e43c80b6fac98ad40905ac938`; `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Test_Vectors/KAT_SIG_SHUTTLE-512.txt` SHA-256 `58db9d94375d91b9a941134b5b06a32d430f7866636c081a81725fdfac66a3bb`.
- Class: submitted API length/KAT observation.
- Scope: `SHUTTLE-512` `sig_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## SHUTTLE512-SIGGETSNLENBYTES-C — SHUTTLE-512 sig_get_sn_len_bytes public API relation

- Source locator: `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Implementations/Reference_Implementation/SHUTTLE-512/SIG_AlgorithmInstance.h` SHA-256 `3332e100f237fc349f909f24416b98659b9d769e43c80b6fac98ad40905ac938`; `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Test_Vectors/KAT_SIG_SHUTTLE-512.txt` SHA-256 `58db9d94375d91b9a941134b5b06a32d430f7866636c081a81725fdfac66a3bb`.
- Class: submitted API length/KAT observation.
- Scope: `SHUTTLE-512` `sig_get_sn_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## SHUTTLE512-SIGKEYGEN-C — SHUTTLE-512 sig_keygen public API relation

- Source locator: PDF p. 10; `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Implementations/Reference_Implementation/SHUTTLE-512/SIG_AlgorithmInstance.h` SHA-256 `3332e100f237fc349f909f24416b98659b9d769e43c80b6fac98ad40905ac938`; `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Test_Vectors/KAT_SIG_SHUTTLE-512.txt` SHA-256 `58db9d94375d91b9a941134b5b06a32d430f7866636c081a81725fdfac66a3bb`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `SHUTTLE-512` `sig_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## SHUTTLE512-SIGSIGN-C — SHUTTLE-512 sig_sign public API relation

- Source locator: PDF p. 10; `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Implementations/Reference_Implementation/SHUTTLE-512/SIG_AlgorithmInstance.h` SHA-256 `3332e100f237fc349f909f24416b98659b9d769e43c80b6fac98ad40905ac938`; `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Test_Vectors/KAT_SIG_SHUTTLE-512.txt` SHA-256 `58db9d94375d91b9a941134b5b06a32d430f7866636c081a81725fdfac66a3bb`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `SHUTTLE-512` `sig_sign` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.
