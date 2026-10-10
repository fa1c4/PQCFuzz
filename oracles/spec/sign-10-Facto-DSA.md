---
status: draft
target: sign-10
algorithm: Facto-DSA
source_path: third_party/sign-10/source
source_sha256: 450bad2020675b19d478c4f51d04988359dd414bc827860620ebca595776a82f
document_path: third_party/sign-10/specification.pdf
document_sha256: 0bb0e5a31bfa29dd2d63bfff56051a50e8126abcf9d92665442077664461762b
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# Facto-DSA draft claim extraction

This document covers source-pinned public vector records and public API relations
for the named parameter sets. The algorithm construction and correctness context is
at PDF p. 6 (algorithm context). Original PDF and archived source are authoritative.

## FACTODSA128-K — Facto-DSA-128 submitted valid-vector consistency

- Source locator: PDF p. 6 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/KAT_SIG_Facto-DSA-128.txt`, SHA-256 `d80c26116d6f0940ad57993af12a4932983bddf052afa07606840db8a73f95a5`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `Facto-DSA-128` `sig_verify` on the ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record is accepted by verification.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## FACTODSA128-SIGGETPKLENBYTES-C — Facto-DSA-128 sig_get_pk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Facto-DSA-128/SIG_AlgorithmInstance.h` SHA-256 `d1ff0df1e12ee725f8c31b0def204745f66f5486c7389e28dd516c8568366431`; `Implementations and Test_Vectors/Test_Vectors/KAT_SIG_Facto-DSA-128.txt` SHA-256 `d80c26116d6f0940ad57993af12a4932983bddf052afa07606840db8a73f95a5`.
- Class: submitted API length/KAT observation.
- Scope: `Facto-DSA-128` `sig_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## FACTODSA128-SIGGETSKLENBYTES-C — Facto-DSA-128 sig_get_sk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Facto-DSA-128/SIG_AlgorithmInstance.h` SHA-256 `d1ff0df1e12ee725f8c31b0def204745f66f5486c7389e28dd516c8568366431`; `Implementations and Test_Vectors/Test_Vectors/KAT_SIG_Facto-DSA-128.txt` SHA-256 `d80c26116d6f0940ad57993af12a4932983bddf052afa07606840db8a73f95a5`.
- Class: submitted API length/KAT observation.
- Scope: `Facto-DSA-128` `sig_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## FACTODSA128-SIGGETSNLENBYTES-C — Facto-DSA-128 sig_get_sn_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Facto-DSA-128/SIG_AlgorithmInstance.h` SHA-256 `d1ff0df1e12ee725f8c31b0def204745f66f5486c7389e28dd516c8568366431`; `Implementations and Test_Vectors/Test_Vectors/KAT_SIG_Facto-DSA-128.txt` SHA-256 `d80c26116d6f0940ad57993af12a4932983bddf052afa07606840db8a73f95a5`.
- Class: submitted API length/KAT observation.
- Scope: `Facto-DSA-128` `sig_get_sn_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## FACTODSA128-SIGKEYGEN-C — Facto-DSA-128 sig_keygen public API relation

- Source locator: PDF p. 7; `Implementations and Test_Vectors/Implementations/Reference_Implementation/Facto-DSA-128/SIG_AlgorithmInstance.h` SHA-256 `d1ff0df1e12ee725f8c31b0def204745f66f5486c7389e28dd516c8568366431`; `Implementations and Test_Vectors/Test_Vectors/KAT_SIG_Facto-DSA-128.txt` SHA-256 `d80c26116d6f0940ad57993af12a4932983bddf052afa07606840db8a73f95a5`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Facto-DSA-128` `sig_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## FACTODSA128-SIGSIGN-C — Facto-DSA-128 sig_sign public API relation

- Source locator: PDF p. 7; `Implementations and Test_Vectors/Implementations/Reference_Implementation/Facto-DSA-128/SIG_AlgorithmInstance.h` SHA-256 `d1ff0df1e12ee725f8c31b0def204745f66f5486c7389e28dd516c8568366431`; `Implementations and Test_Vectors/Test_Vectors/KAT_SIG_Facto-DSA-128.txt` SHA-256 `d80c26116d6f0940ad57993af12a4932983bddf052afa07606840db8a73f95a5`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Facto-DSA-128` `sig_sign` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## FACTODSA256-K — Facto-DSA-256 submitted valid-vector consistency

- Source locator: PDF p. 7 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/KAT_SIG_Facto-DSA-256.txt` SHA-256 `7863c23b59af62b695a0e574209404c75720ab4da41781d5ecb404bb4128a836`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `Facto-DSA-256` `sig_verify` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records are accepted by sig_verify.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## FACTODSA256-SIGGETPKLENBYTES-C — Facto-DSA-256 sig_get_pk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Facto-DSA-256/SIG_AlgorithmInstance.h` SHA-256 `a69af0167ba2dfa4d1b4693541186f8b371429585014077efa0b7d8e3ffe8539`; `Implementations and Test_Vectors/Test_Vectors/KAT_SIG_Facto-DSA-256.txt` SHA-256 `7863c23b59af62b695a0e574209404c75720ab4da41781d5ecb404bb4128a836`.
- Class: submitted API length/KAT observation.
- Scope: `Facto-DSA-256` `sig_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## FACTODSA256-SIGGETSKLENBYTES-C — Facto-DSA-256 sig_get_sk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Facto-DSA-256/SIG_AlgorithmInstance.h` SHA-256 `a69af0167ba2dfa4d1b4693541186f8b371429585014077efa0b7d8e3ffe8539`; `Implementations and Test_Vectors/Test_Vectors/KAT_SIG_Facto-DSA-256.txt` SHA-256 `7863c23b59af62b695a0e574209404c75720ab4da41781d5ecb404bb4128a836`.
- Class: submitted API length/KAT observation.
- Scope: `Facto-DSA-256` `sig_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## FACTODSA256-SIGGETSNLENBYTES-C — Facto-DSA-256 sig_get_sn_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Facto-DSA-256/SIG_AlgorithmInstance.h` SHA-256 `a69af0167ba2dfa4d1b4693541186f8b371429585014077efa0b7d8e3ffe8539`; `Implementations and Test_Vectors/Test_Vectors/KAT_SIG_Facto-DSA-256.txt` SHA-256 `7863c23b59af62b695a0e574209404c75720ab4da41781d5ecb404bb4128a836`.
- Class: submitted API length/KAT observation.
- Scope: `Facto-DSA-256` `sig_get_sn_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## FACTODSA256-SIGKEYGEN-C — Facto-DSA-256 sig_keygen public API relation

- Source locator: PDF p. 7; `Implementations and Test_Vectors/Implementations/Reference_Implementation/Facto-DSA-256/SIG_AlgorithmInstance.h` SHA-256 `a69af0167ba2dfa4d1b4693541186f8b371429585014077efa0b7d8e3ffe8539`; `Implementations and Test_Vectors/Test_Vectors/KAT_SIG_Facto-DSA-256.txt` SHA-256 `7863c23b59af62b695a0e574209404c75720ab4da41781d5ecb404bb4128a836`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Facto-DSA-256` `sig_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## FACTODSA256-SIGSIGN-C — Facto-DSA-256 sig_sign public API relation

- Source locator: PDF p. 7; `Implementations and Test_Vectors/Implementations/Reference_Implementation/Facto-DSA-256/SIG_AlgorithmInstance.h` SHA-256 `a69af0167ba2dfa4d1b4693541186f8b371429585014077efa0b7d8e3ffe8539`; `Implementations and Test_Vectors/Test_Vectors/KAT_SIG_Facto-DSA-256.txt` SHA-256 `7863c23b59af62b695a0e574209404c75720ab4da41781d5ecb404bb4128a836`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Facto-DSA-256` `sig_sign` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## FACTODSA512-K — Facto-DSA-512 locally regenerated KAT-generator valid-vector consistency

- Source locator: PDF p. 7 (algorithm context); locally regenerated with the pinned submitted KAT_SIG.c generator; `generator/output/KAT_SIG_Facto-DSA-512.txt` SHA-256 `192bca21b8e1f83c5a3e31b051eb662853c72709576737daf637e210d58ee5e3`.
- Class: PDF correctness context and locally regenerated KAT-generator vector observation; the latter is not independent normative truth.
- Scope: `Facto-DSA-512` `sig_verify` on ten exact public locally regenerated KAT-generator records, with API lengths and status.
- Claim: Both valid locally regenerated KAT-generator records are accepted by sig_verify.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: locally regenerated KAT-generator vectors share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## FACTODSA512-SIGGETPKLENBYTES-C — Facto-DSA-512 sig_get_pk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Facto-DSA-512/SIG_AlgorithmInstance.h` SHA-256 `847b7485077c7e11ce95fa442be7bf311d5f2f7a6957c238116fbcde2a31b1bb`; `generator/output/KAT_SIG_Facto-DSA-512.txt` SHA-256 `192bca21b8e1f83c5a3e31b051eb662853c72709576737daf637e210d58ee5e3`.
- Class: locally regenerated KAT-generator API length observation.
- Scope: `Facto-DSA-512` `sig_get_pk_len_bytes` in the pinned primary reference implementation and ten public locally regenerated KAT-generator records.
- Claim: Its reported allocation/serialization length equals the exact locally regenerated KAT-generator object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; locally regenerated KAT-generator length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## FACTODSA512-SIGGETSKLENBYTES-C — Facto-DSA-512 sig_get_sk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Facto-DSA-512/SIG_AlgorithmInstance.h` SHA-256 `847b7485077c7e11ce95fa442be7bf311d5f2f7a6957c238116fbcde2a31b1bb`; `generator/output/KAT_SIG_Facto-DSA-512.txt` SHA-256 `192bca21b8e1f83c5a3e31b051eb662853c72709576737daf637e210d58ee5e3`.
- Class: locally regenerated KAT-generator API length observation.
- Scope: `Facto-DSA-512` `sig_get_sk_len_bytes` in the pinned primary reference implementation and ten public locally regenerated KAT-generator records.
- Claim: Its reported allocation/serialization length equals the exact locally regenerated KAT-generator object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; locally regenerated KAT-generator length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## FACTODSA512-SIGGETSNLENBYTES-C — Facto-DSA-512 sig_get_sn_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Facto-DSA-512/SIG_AlgorithmInstance.h` SHA-256 `847b7485077c7e11ce95fa442be7bf311d5f2f7a6957c238116fbcde2a31b1bb`; `generator/output/KAT_SIG_Facto-DSA-512.txt` SHA-256 `192bca21b8e1f83c5a3e31b051eb662853c72709576737daf637e210d58ee5e3`.
- Class: locally regenerated KAT-generator API length observation.
- Scope: `Facto-DSA-512` `sig_get_sn_len_bytes` in the pinned primary reference implementation and ten public locally regenerated KAT-generator records.
- Claim: Its reported allocation/serialization length equals the exact locally regenerated KAT-generator object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; locally regenerated KAT-generator length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## FACTODSA512-SIGKEYGEN-C — Facto-DSA-512 sig_keygen public API relation

- Source locator: PDF p. 7; `Implementations and Test_Vectors/Implementations/Reference_Implementation/Facto-DSA-512/SIG_AlgorithmInstance.h` SHA-256 `847b7485077c7e11ce95fa442be7bf311d5f2f7a6957c238116fbcde2a31b1bb`; `generator/output/KAT_SIG_Facto-DSA-512.txt` SHA-256 `192bca21b8e1f83c5a3e31b051eb662853c72709576737daf637e210d58ee5e3`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Facto-DSA-512` `sig_keygen` in the pinned primary reference implementation and ten public locally regenerated KAT-generator records.
- Claim: For a valid locally regenerated KAT-generator key pair or a freshly generated key pair, the complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and API pairing, while randomness bytes are not expected to match the local vector.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## FACTODSA512-SIGSIGN-C — Facto-DSA-512 sig_sign public API relation

- Source locator: PDF p. 7; `Implementations and Test_Vectors/Implementations/Reference_Implementation/Facto-DSA-512/SIG_AlgorithmInstance.h` SHA-256 `847b7485077c7e11ce95fa442be7bf311d5f2f7a6957c238116fbcde2a31b1bb`; `generator/output/KAT_SIG_Facto-DSA-512.txt` SHA-256 `192bca21b8e1f83c5a3e31b051eb662853c72709576737daf637e210d58ee5e3`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Facto-DSA-512` `sig_sign` in the pinned primary reference implementation and ten public locally regenerated KAT-generator records.
- Claim: For a valid locally regenerated KAT-generator key pair or a freshly generated key pair, the complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and API pairing, while randomness bytes are not expected to match the local vector.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.
