---
status: draft
target: sign-01
algorithm: Aigis-Sig+
source_path: third_party/sign-01/source
source_sha256: 60ef88020ca59d3d4eb29e57ba96787ea25e621fc796d222363456eedbebeef9
document_path: third_party/sign-01/specification.pdf
document_sha256: 6e6d2e07524f2d3bd489ef1e1a0db75cfaf3c9ffb66f048f2e46283e1c3a1781
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# Aigis-Sig+ draft claim extraction

This document covers source-pinned public vector records and public API relations
for the named parameter sets. The algorithm construction and correctness context is
at PDF p. 11 (algorithm context). Original PDF and archived source are authoritative.

## AIGISSIGI-K — Aigis-Sig+-I submitted valid-vector consistency

- Source locator: PDF p. 11 (algorithm context); `Test_Vectors/KAT_SIG_Aigis-sig1.txt`, SHA-256 `5e29fe8057c7193b86567f9ee8ff20998bccb165648931e0b5a9154487b867ef`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `Aigis-Sig+-I` `sig_verify` on the ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record is accepted by verification.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.

The submitted `SIG_AlgorithmInstance.c` returns `SIG_BYTES` from
`sig_get_sn_len_bytes`; its KAT driver allocates that amount before `sig_sign`
updates `Sn_Len`. The archived first record has `Sn_Len = 2009` while the
getter returns 2015 for this build. The adapter therefore treats the getter
as an allocation upper bound and checks the exact submitted record length
separately. This is an API observation, not a new PDF-level normative claim.

## AIGISSIGI-SIGGETPKLENBYTES-C — Aigis-Sig+-I sig_get_pk_len_bytes public API relation

- Source locator: `Implementations/Implementations/Reference_Implementation/Aigis-Sig+-I/SIG_AlgorithmInstance.h` SHA-256 `c96c3319ce27ae9be097f08bad0c944da2d92c42813bdc095270b8be82007e60`; `Test_Vectors/KAT_SIG_Aigis-sig1.txt` SHA-256 `5e29fe8057c7193b86567f9ee8ff20998bccb165648931e0b5a9154487b867ef`.
- Class: submitted API length/KAT observation.
- Scope: `Aigis-Sig+-I` `sig_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AIGISSIGI-SIGGETSKLENBYTES-C — Aigis-Sig+-I sig_get_sk_len_bytes public API relation

- Source locator: `Implementations/Implementations/Reference_Implementation/Aigis-Sig+-I/SIG_AlgorithmInstance.h` SHA-256 `c96c3319ce27ae9be097f08bad0c944da2d92c42813bdc095270b8be82007e60`; `Test_Vectors/KAT_SIG_Aigis-sig1.txt` SHA-256 `5e29fe8057c7193b86567f9ee8ff20998bccb165648931e0b5a9154487b867ef`.
- Class: submitted API length/KAT observation.
- Scope: `Aigis-Sig+-I` `sig_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AIGISSIGI-SIGGETSNLENBYTES-C — Aigis-Sig+-I sig_get_sn_len_bytes public API relation

- Source locator: `Implementations/Implementations/Reference_Implementation/Aigis-Sig+-I/SIG_AlgorithmInstance.h` SHA-256 `c96c3319ce27ae9be097f08bad0c944da2d92c42813bdc095270b8be82007e60`; `Test_Vectors/KAT_SIG_Aigis-sig1.txt` SHA-256 `5e29fe8057c7193b86567f9ee8ff20998bccb165648931e0b5a9154487b867ef`.
- Class: submitted API length/KAT observation.
- Scope: `Aigis-Sig+-I` `sig_get_sn_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AIGISSIGI-SIGKEYGEN-C — Aigis-Sig+-I sig_keygen public API relation

- Source locator: PDF p. 11; `Implementations/Implementations/Reference_Implementation/Aigis-Sig+-I/SIG_AlgorithmInstance.h` SHA-256 `c96c3319ce27ae9be097f08bad0c944da2d92c42813bdc095270b8be82007e60`; `Test_Vectors/KAT_SIG_Aigis-sig1.txt` SHA-256 `5e29fe8057c7193b86567f9ee8ff20998bccb165648931e0b5a9154487b867ef`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Aigis-Sig+-I` `sig_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AIGISSIGI-SIGSIGN-C — Aigis-Sig+-I sig_sign public API relation

- Source locator: PDF p. 11; `Implementations/Implementations/Reference_Implementation/Aigis-Sig+-I/SIG_AlgorithmInstance.h` SHA-256 `c96c3319ce27ae9be097f08bad0c944da2d92c42813bdc095270b8be82007e60`; `Test_Vectors/KAT_SIG_Aigis-sig1.txt` SHA-256 `5e29fe8057c7193b86567f9ee8ff20998bccb165648931e0b5a9154487b867ef`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Aigis-Sig+-I` `sig_sign` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AIGISSIGII-K — Aigis-Sig+-II submitted valid-vector consistency

- Source locator: PDF p. 11 (algorithm context); `Test_Vectors/KAT_SIG_Aigis-sig2.txt` SHA-256 `21e152e13afdac3c1e189f02ad0413159df4477662c2f946bf77d91ce3a5a472`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `Aigis-Sig+-II` `sig_verify` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records are accepted by sig_verify.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## AIGISSIGIII-K — Aigis-Sig+-III submitted valid-vector consistency

- Source locator: PDF p. 11 (algorithm context); `Test_Vectors/KAT_SIG_Aigis-sig3.txt` SHA-256 `c9b942c39a596c0d6457c6186262ae7f98ef047249918b12efdd6cc5f72f6f5c`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `Aigis-Sig+-III` `sig_verify` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records are accepted by sig_verify.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## AIGISSIGII-SIGGETPKLENBYTES-C — Aigis-Sig+-II sig_get_pk_len_bytes public API relation

- Source locator: `Implementations/Implementations/Reference_Implementation/Aigis-Sig+-II/SIG_AlgorithmInstance.h` SHA-256 `c96c3319ce27ae9be097f08bad0c944da2d92c42813bdc095270b8be82007e60`; `Test_Vectors/KAT_SIG_Aigis-sig2.txt` SHA-256 `21e152e13afdac3c1e189f02ad0413159df4477662c2f946bf77d91ce3a5a472`.
- Class: submitted API length/KAT observation.
- Scope: `Aigis-Sig+-II` `sig_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AIGISSIGII-SIGGETSKLENBYTES-C — Aigis-Sig+-II sig_get_sk_len_bytes public API relation

- Source locator: `Implementations/Implementations/Reference_Implementation/Aigis-Sig+-II/SIG_AlgorithmInstance.h` SHA-256 `c96c3319ce27ae9be097f08bad0c944da2d92c42813bdc095270b8be82007e60`; `Test_Vectors/KAT_SIG_Aigis-sig2.txt` SHA-256 `21e152e13afdac3c1e189f02ad0413159df4477662c2f946bf77d91ce3a5a472`.
- Class: submitted API length/KAT observation.
- Scope: `Aigis-Sig+-II` `sig_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AIGISSIGII-SIGGETSNLENBYTES-C — Aigis-Sig+-II sig_get_sn_len_bytes public API relation

- Source locator: `Implementations/Implementations/Reference_Implementation/Aigis-Sig+-II/SIG_AlgorithmInstance.h` SHA-256 `c96c3319ce27ae9be097f08bad0c944da2d92c42813bdc095270b8be82007e60`; `Test_Vectors/KAT_SIG_Aigis-sig2.txt` SHA-256 `21e152e13afdac3c1e189f02ad0413159df4477662c2f946bf77d91ce3a5a472`.
- Class: submitted API length/KAT observation.
- Scope: `Aigis-Sig+-II` `sig_get_sn_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AIGISSIGII-SIGKEYGEN-C — Aigis-Sig+-II sig_keygen public API relation

- Source locator: PDF p. 11; `Implementations/Implementations/Reference_Implementation/Aigis-Sig+-II/SIG_AlgorithmInstance.h` SHA-256 `c96c3319ce27ae9be097f08bad0c944da2d92c42813bdc095270b8be82007e60`; `Test_Vectors/KAT_SIG_Aigis-sig2.txt` SHA-256 `21e152e13afdac3c1e189f02ad0413159df4477662c2f946bf77d91ce3a5a472`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Aigis-Sig+-II` `sig_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AIGISSIGII-SIGSIGN-C — Aigis-Sig+-II sig_sign public API relation

- Source locator: PDF p. 11; `Implementations/Implementations/Reference_Implementation/Aigis-Sig+-II/SIG_AlgorithmInstance.h` SHA-256 `c96c3319ce27ae9be097f08bad0c944da2d92c42813bdc095270b8be82007e60`; `Test_Vectors/KAT_SIG_Aigis-sig2.txt` SHA-256 `21e152e13afdac3c1e189f02ad0413159df4477662c2f946bf77d91ce3a5a472`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Aigis-Sig+-II` `sig_sign` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AIGISSIGIII-SIGGETPKLENBYTES-C — Aigis-Sig+-III sig_get_pk_len_bytes public API relation

- Source locator: `Implementations/Implementations/Reference_Implementation/Aigis-Sig+-III/SIG_AlgorithmInstance.h` SHA-256 `c96c3319ce27ae9be097f08bad0c944da2d92c42813bdc095270b8be82007e60`; `Test_Vectors/KAT_SIG_Aigis-sig3.txt` SHA-256 `c9b942c39a596c0d6457c6186262ae7f98ef047249918b12efdd6cc5f72f6f5c`.
- Class: submitted API length/KAT observation.
- Scope: `Aigis-Sig+-III` `sig_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AIGISSIGIII-SIGGETSKLENBYTES-C — Aigis-Sig+-III sig_get_sk_len_bytes public API relation

- Source locator: `Implementations/Implementations/Reference_Implementation/Aigis-Sig+-III/SIG_AlgorithmInstance.h` SHA-256 `c96c3319ce27ae9be097f08bad0c944da2d92c42813bdc095270b8be82007e60`; `Test_Vectors/KAT_SIG_Aigis-sig3.txt` SHA-256 `c9b942c39a596c0d6457c6186262ae7f98ef047249918b12efdd6cc5f72f6f5c`.
- Class: submitted API length/KAT observation.
- Scope: `Aigis-Sig+-III` `sig_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AIGISSIGIII-SIGGETSNLENBYTES-C — Aigis-Sig+-III sig_get_sn_len_bytes public API relation

- Source locator: `Implementations/Implementations/Reference_Implementation/Aigis-Sig+-III/SIG_AlgorithmInstance.h` SHA-256 `c96c3319ce27ae9be097f08bad0c944da2d92c42813bdc095270b8be82007e60`; `Test_Vectors/KAT_SIG_Aigis-sig3.txt` SHA-256 `c9b942c39a596c0d6457c6186262ae7f98ef047249918b12efdd6cc5f72f6f5c`.
- Class: submitted API length/KAT observation.
- Scope: `Aigis-Sig+-III` `sig_get_sn_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AIGISSIGIII-SIGKEYGEN-C — Aigis-Sig+-III sig_keygen public API relation

- Source locator: PDF p. 11; `Implementations/Implementations/Reference_Implementation/Aigis-Sig+-III/SIG_AlgorithmInstance.h` SHA-256 `c96c3319ce27ae9be097f08bad0c944da2d92c42813bdc095270b8be82007e60`; `Test_Vectors/KAT_SIG_Aigis-sig3.txt` SHA-256 `c9b942c39a596c0d6457c6186262ae7f98ef047249918b12efdd6cc5f72f6f5c`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Aigis-Sig+-III` `sig_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AIGISSIGIII-SIGSIGN-C — Aigis-Sig+-III sig_sign public API relation

- Source locator: PDF p. 11; `Implementations/Implementations/Reference_Implementation/Aigis-Sig+-III/SIG_AlgorithmInstance.h` SHA-256 `c96c3319ce27ae9be097f08bad0c944da2d92c42813bdc095270b8be82007e60`; `Test_Vectors/KAT_SIG_Aigis-sig3.txt` SHA-256 `c9b942c39a596c0d6457c6186262ae7f98ef047249918b12efdd6cc5f72f6f5c`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Aigis-Sig+-III` `sig_sign` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.
