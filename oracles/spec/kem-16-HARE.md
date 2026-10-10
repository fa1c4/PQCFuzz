---
status: draft
target: kem-16
algorithm: HARE
source_path: third_party/kem-16/source
source_sha256: c83cf0c04fc2df7b98858b1dafb22e1020285803ce78d604de3ffff2a5fcea40
document_path: third_party/kem-16/specification.pdf
document_sha256: a2242e0dbfcfbf101629e49f75f7b12866f7a3186384adb3642da7f95e5122a9
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# HARE draft claim extraction

This document covers source-pinned public vector records and public API relations
for the named parameter sets. The algorithm construction and correctness context is
at PDF p. 5 (algorithm context). Original PDF and archived source are authoritative.

## HARE128-K — HARE-128 submitted valid-vector consistency

- Source locator: PDF p. 5 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-128-kr.txt`, SHA-256 `fbb71eee548f838976461c754e4b4d6e3dcb8e22d480ad81f9df00baada38f7f`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `HARE-128` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record decapsulates to its recorded shared secret.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## HARE128-KEMENC-C — HARE-128 kem_enc public API relation

- Source locator: PDF p. 9; `Implementations and Test_Vectors/Implementations/Reference_Implementation/HARE-128/kr/KEM_AlgorithmInstance.h` SHA-256 `27f84e514b3d81a4747b141d53a14f36c228306a8372c7b8c7f760ba2b6e2eea`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-128-kr.txt` SHA-256 `fbb71eee548f838976461c754e4b4d6e3dcb8e22d480ad81f9df00baada38f7f`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `HARE-128` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HARE128-KEMGETCTLENBYTES-C — HARE-128 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/HARE-128/kr/KEM_AlgorithmInstance.h` SHA-256 `27f84e514b3d81a4747b141d53a14f36c228306a8372c7b8c7f760ba2b6e2eea`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-128-kr.txt` SHA-256 `fbb71eee548f838976461c754e4b4d6e3dcb8e22d480ad81f9df00baada38f7f`.
- Class: submitted API length/KAT observation.
- Scope: `HARE-128` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HARE128-KEMGETPKLENBYTES-C — HARE-128 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/HARE-128/kr/KEM_AlgorithmInstance.h` SHA-256 `27f84e514b3d81a4747b141d53a14f36c228306a8372c7b8c7f760ba2b6e2eea`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-128-kr.txt` SHA-256 `fbb71eee548f838976461c754e4b4d6e3dcb8e22d480ad81f9df00baada38f7f`.
- Class: submitted API length/KAT observation.
- Scope: `HARE-128` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HARE128-KEMGETSKLENBYTES-C — HARE-128 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/HARE-128/kr/KEM_AlgorithmInstance.h` SHA-256 `27f84e514b3d81a4747b141d53a14f36c228306a8372c7b8c7f760ba2b6e2eea`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-128-kr.txt` SHA-256 `fbb71eee548f838976461c754e4b4d6e3dcb8e22d480ad81f9df00baada38f7f`.
- Class: submitted API length/KAT observation.
- Scope: `HARE-128` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HARE128-KEMGETSSLENBYTES-C — HARE-128 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/HARE-128/kr/KEM_AlgorithmInstance.h` SHA-256 `27f84e514b3d81a4747b141d53a14f36c228306a8372c7b8c7f760ba2b6e2eea`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-128-kr.txt` SHA-256 `fbb71eee548f838976461c754e4b4d6e3dcb8e22d480ad81f9df00baada38f7f`.
- Class: submitted API length/KAT observation.
- Scope: `HARE-128` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HARE128-KEMKEYGEN-C — HARE-128 kem_keygen public API relation

- Source locator: PDF p. 9; `Implementations and Test_Vectors/Implementations/Reference_Implementation/HARE-128/kr/KEM_AlgorithmInstance.h` SHA-256 `27f84e514b3d81a4747b141d53a14f36c228306a8372c7b8c7f760ba2b6e2eea`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-128-kr.txt` SHA-256 `fbb71eee548f838976461c754e4b4d6e3dcb8e22d480ad81f9df00baada38f7f`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `HARE-128` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HARE256-K — HARE-256 submitted valid-vector consistency

- Source locator: PDF p. 9 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-256-kr.txt` SHA-256 `543e2ac2ec9a9d6267e11125fd0683f53920a0a71a3ab54df1ff198f29716221`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `HARE-256` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## HARE384-K — HARE-384 submitted valid-vector consistency

- Source locator: PDF p. 9 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-384-kr.txt` SHA-256 `9cd639973258bd9269093ffed7ccb1641ca51d74e01bd94094c26c671bb3c230`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `HARE-384` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## HARE512-K — HARE-512 submitted valid-vector consistency

- Source locator: PDF p. 9 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-512-kr.txt` SHA-256 `a5ec74c424e0f0408c31811ec847b1f71f4582ebe0b45fd696ffb3964ed1ddc6`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `HARE-512` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## HARE256-KEMENC-C — HARE-256 kem_enc public API relation

- Source locator: PDF p. 9; `Implementations and Test_Vectors/Implementations/Reference_Implementation/HARE-256/kr/KEM_AlgorithmInstance.h` SHA-256 `298e1624266f2b726455ed8bb961e71a10f8553817b036b0864c3ec07287c060`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-256-kr.txt` SHA-256 `543e2ac2ec9a9d6267e11125fd0683f53920a0a71a3ab54df1ff198f29716221`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `HARE-256` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HARE256-KEMGETCTLENBYTES-C — HARE-256 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/HARE-256/kr/KEM_AlgorithmInstance.h` SHA-256 `298e1624266f2b726455ed8bb961e71a10f8553817b036b0864c3ec07287c060`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-256-kr.txt` SHA-256 `543e2ac2ec9a9d6267e11125fd0683f53920a0a71a3ab54df1ff198f29716221`.
- Class: submitted API length/KAT observation.
- Scope: `HARE-256` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HARE256-KEMGETPKLENBYTES-C — HARE-256 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/HARE-256/kr/KEM_AlgorithmInstance.h` SHA-256 `298e1624266f2b726455ed8bb961e71a10f8553817b036b0864c3ec07287c060`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-256-kr.txt` SHA-256 `543e2ac2ec9a9d6267e11125fd0683f53920a0a71a3ab54df1ff198f29716221`.
- Class: submitted API length/KAT observation.
- Scope: `HARE-256` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HARE256-KEMGETSKLENBYTES-C — HARE-256 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/HARE-256/kr/KEM_AlgorithmInstance.h` SHA-256 `298e1624266f2b726455ed8bb961e71a10f8553817b036b0864c3ec07287c060`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-256-kr.txt` SHA-256 `543e2ac2ec9a9d6267e11125fd0683f53920a0a71a3ab54df1ff198f29716221`.
- Class: submitted API length/KAT observation.
- Scope: `HARE-256` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HARE256-KEMGETSSLENBYTES-C — HARE-256 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/HARE-256/kr/KEM_AlgorithmInstance.h` SHA-256 `298e1624266f2b726455ed8bb961e71a10f8553817b036b0864c3ec07287c060`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-256-kr.txt` SHA-256 `543e2ac2ec9a9d6267e11125fd0683f53920a0a71a3ab54df1ff198f29716221`.
- Class: submitted API length/KAT observation.
- Scope: `HARE-256` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HARE256-KEMKEYGEN-C — HARE-256 kem_keygen public API relation

- Source locator: PDF p. 9; `Implementations and Test_Vectors/Implementations/Reference_Implementation/HARE-256/kr/KEM_AlgorithmInstance.h` SHA-256 `298e1624266f2b726455ed8bb961e71a10f8553817b036b0864c3ec07287c060`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-256-kr.txt` SHA-256 `543e2ac2ec9a9d6267e11125fd0683f53920a0a71a3ab54df1ff198f29716221`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `HARE-256` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HARE384-KEMENC-C — HARE-384 kem_enc public API relation

- Source locator: PDF p. 9; `Implementations and Test_Vectors/Implementations/Reference_Implementation/HARE-384/kr/KEM_AlgorithmInstance.h` SHA-256 `4ae811aeb6bc9f88f6422e979932fdfbbd2311e4206869f94d640488491f7e96`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-384-kr.txt` SHA-256 `9cd639973258bd9269093ffed7ccb1641ca51d74e01bd94094c26c671bb3c230`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `HARE-384` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HARE384-KEMGETCTLENBYTES-C — HARE-384 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/HARE-384/kr/KEM_AlgorithmInstance.h` SHA-256 `4ae811aeb6bc9f88f6422e979932fdfbbd2311e4206869f94d640488491f7e96`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-384-kr.txt` SHA-256 `9cd639973258bd9269093ffed7ccb1641ca51d74e01bd94094c26c671bb3c230`.
- Class: submitted API length/KAT observation.
- Scope: `HARE-384` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HARE384-KEMGETPKLENBYTES-C — HARE-384 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/HARE-384/kr/KEM_AlgorithmInstance.h` SHA-256 `4ae811aeb6bc9f88f6422e979932fdfbbd2311e4206869f94d640488491f7e96`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-384-kr.txt` SHA-256 `9cd639973258bd9269093ffed7ccb1641ca51d74e01bd94094c26c671bb3c230`.
- Class: submitted API length/KAT observation.
- Scope: `HARE-384` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HARE384-KEMGETSKLENBYTES-C — HARE-384 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/HARE-384/kr/KEM_AlgorithmInstance.h` SHA-256 `4ae811aeb6bc9f88f6422e979932fdfbbd2311e4206869f94d640488491f7e96`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-384-kr.txt` SHA-256 `9cd639973258bd9269093ffed7ccb1641ca51d74e01bd94094c26c671bb3c230`.
- Class: submitted API length/KAT observation.
- Scope: `HARE-384` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HARE384-KEMGETSSLENBYTES-C — HARE-384 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/HARE-384/kr/KEM_AlgorithmInstance.h` SHA-256 `4ae811aeb6bc9f88f6422e979932fdfbbd2311e4206869f94d640488491f7e96`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-384-kr.txt` SHA-256 `9cd639973258bd9269093ffed7ccb1641ca51d74e01bd94094c26c671bb3c230`.
- Class: submitted API length/KAT observation.
- Scope: `HARE-384` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HARE384-KEMKEYGEN-C — HARE-384 kem_keygen public API relation

- Source locator: PDF p. 9; `Implementations and Test_Vectors/Implementations/Reference_Implementation/HARE-384/kr/KEM_AlgorithmInstance.h` SHA-256 `4ae811aeb6bc9f88f6422e979932fdfbbd2311e4206869f94d640488491f7e96`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-384-kr.txt` SHA-256 `9cd639973258bd9269093ffed7ccb1641ca51d74e01bd94094c26c671bb3c230`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `HARE-384` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HARE512-KEMENC-C — HARE-512 kem_enc public API relation

- Source locator: PDF p. 9; `Implementations and Test_Vectors/Implementations/Reference_Implementation/HARE-512/kr/KEM_AlgorithmInstance.h` SHA-256 `7dc0ec26a36a531982d31fcb2077cbc67564856f3f06de07eaa6dc61642cac3b`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-512-kr.txt` SHA-256 `a5ec74c424e0f0408c31811ec847b1f71f4582ebe0b45fd696ffb3964ed1ddc6`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `HARE-512` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HARE512-KEMGETCTLENBYTES-C — HARE-512 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/HARE-512/kr/KEM_AlgorithmInstance.h` SHA-256 `7dc0ec26a36a531982d31fcb2077cbc67564856f3f06de07eaa6dc61642cac3b`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-512-kr.txt` SHA-256 `a5ec74c424e0f0408c31811ec847b1f71f4582ebe0b45fd696ffb3964ed1ddc6`.
- Class: submitted API length/KAT observation.
- Scope: `HARE-512` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HARE512-KEMGETPKLENBYTES-C — HARE-512 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/HARE-512/kr/KEM_AlgorithmInstance.h` SHA-256 `7dc0ec26a36a531982d31fcb2077cbc67564856f3f06de07eaa6dc61642cac3b`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-512-kr.txt` SHA-256 `a5ec74c424e0f0408c31811ec847b1f71f4582ebe0b45fd696ffb3964ed1ddc6`.
- Class: submitted API length/KAT observation.
- Scope: `HARE-512` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HARE512-KEMGETSKLENBYTES-C — HARE-512 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/HARE-512/kr/KEM_AlgorithmInstance.h` SHA-256 `7dc0ec26a36a531982d31fcb2077cbc67564856f3f06de07eaa6dc61642cac3b`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-512-kr.txt` SHA-256 `a5ec74c424e0f0408c31811ec847b1f71f4582ebe0b45fd696ffb3964ed1ddc6`.
- Class: submitted API length/KAT observation.
- Scope: `HARE-512` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HARE512-KEMGETSSLENBYTES-C — HARE-512 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/HARE-512/kr/KEM_AlgorithmInstance.h` SHA-256 `7dc0ec26a36a531982d31fcb2077cbc67564856f3f06de07eaa6dc61642cac3b`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-512-kr.txt` SHA-256 `a5ec74c424e0f0408c31811ec847b1f71f4582ebe0b45fd696ffb3964ed1ddc6`.
- Class: submitted API length/KAT observation.
- Scope: `HARE-512` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## HARE512-KEMKEYGEN-C — HARE-512 kem_keygen public API relation

- Source locator: PDF p. 9; `Implementations and Test_Vectors/Implementations/Reference_Implementation/HARE-512/kr/KEM_AlgorithmInstance.h` SHA-256 `7dc0ec26a36a531982d31fcb2077cbc67564856f3f06de07eaa6dc61642cac3b`; `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-512-kr.txt` SHA-256 `a5ec74c424e0f0408c31811ec847b1f71f4582ebe0b45fd696ffb3964ed1ddc6`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `HARE-512` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.
