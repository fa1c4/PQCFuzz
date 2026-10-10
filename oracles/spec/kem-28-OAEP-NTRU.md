---
status: draft
target: kem-28
algorithm: OAEP-NTRU
source_path: third_party/kem-28/source
source_sha256: 545aedbcde743760adb7522a5e8eeca1d40ed4b35c98a713d251831285b92bbd
document_path: third_party/kem-28/specification.pdf
document_sha256: cde9de6e14fad324e5133b196a40e00ef394806d06e4101da42de79f8f0689b6
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# OAEP-NTRU draft claim extraction

This document covers source-pinned public vector records and public API relations
for the named parameter sets. The algorithm construction and correctness context is
at PDF p. 6 (algorithm context). Original PDF and archived source are authoritative.

## OAEPNTRU648-K — OAEP-NTRU-648 submitted valid-vector consistency

- Source locator: PDF p. 6 (algorithm context); `Test_Vectors/KAT_KEM_OAEP-NTRU-648.txt`, SHA-256 `b4733e7c232600120eafc607e2aa04402111d8e9cc9279965ed5cf429321740d`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `OAEP-NTRU-648` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record decapsulates to its recorded shared secret.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## OAEPNTRU648-KEMENC-C — OAEP-NTRU-648 kem_enc public API relation

- Source locator: PDF p. 6; `Implementations/Reference_Implementation/OAEP-NTRU-648/KEM_AlgorithmInstance.h` SHA-256 `8580ca34bff25787dea1e130000962e5c13040ebbb2f7485b180eedd388c0bbf`; `Test_Vectors/KAT_KEM_OAEP-NTRU-648.txt` SHA-256 `b4733e7c232600120eafc607e2aa04402111d8e9cc9279965ed5cf429321740d`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `OAEP-NTRU-648` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## OAEPNTRU648-KEMGETCTLENBYTES-C — OAEP-NTRU-648 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/OAEP-NTRU-648/KEM_AlgorithmInstance.h` SHA-256 `8580ca34bff25787dea1e130000962e5c13040ebbb2f7485b180eedd388c0bbf`; `Test_Vectors/KAT_KEM_OAEP-NTRU-648.txt` SHA-256 `b4733e7c232600120eafc607e2aa04402111d8e9cc9279965ed5cf429321740d`.
- Class: submitted API length/KAT observation.
- Scope: `OAEP-NTRU-648` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## OAEPNTRU648-KEMGETPKLENBYTES-C — OAEP-NTRU-648 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/OAEP-NTRU-648/KEM_AlgorithmInstance.h` SHA-256 `8580ca34bff25787dea1e130000962e5c13040ebbb2f7485b180eedd388c0bbf`; `Test_Vectors/KAT_KEM_OAEP-NTRU-648.txt` SHA-256 `b4733e7c232600120eafc607e2aa04402111d8e9cc9279965ed5cf429321740d`.
- Class: submitted API length/KAT observation.
- Scope: `OAEP-NTRU-648` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## OAEPNTRU648-KEMGETSKLENBYTES-C — OAEP-NTRU-648 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/OAEP-NTRU-648/KEM_AlgorithmInstance.h` SHA-256 `8580ca34bff25787dea1e130000962e5c13040ebbb2f7485b180eedd388c0bbf`; `Test_Vectors/KAT_KEM_OAEP-NTRU-648.txt` SHA-256 `b4733e7c232600120eafc607e2aa04402111d8e9cc9279965ed5cf429321740d`.
- Class: submitted API length/KAT observation.
- Scope: `OAEP-NTRU-648` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## OAEPNTRU648-KEMGETSSLENBYTES-C — OAEP-NTRU-648 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/OAEP-NTRU-648/KEM_AlgorithmInstance.h` SHA-256 `8580ca34bff25787dea1e130000962e5c13040ebbb2f7485b180eedd388c0bbf`; `Test_Vectors/KAT_KEM_OAEP-NTRU-648.txt` SHA-256 `b4733e7c232600120eafc607e2aa04402111d8e9cc9279965ed5cf429321740d`.
- Class: submitted API length/KAT observation.
- Scope: `OAEP-NTRU-648` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## OAEPNTRU648-KEMKEYGEN-C — OAEP-NTRU-648 kem_keygen public API relation

- Source locator: PDF p. 6; `Implementations/Reference_Implementation/OAEP-NTRU-648/KEM_AlgorithmInstance.h` SHA-256 `8580ca34bff25787dea1e130000962e5c13040ebbb2f7485b180eedd388c0bbf`; `Test_Vectors/KAT_KEM_OAEP-NTRU-648.txt` SHA-256 `b4733e7c232600120eafc607e2aa04402111d8e9cc9279965ed5cf429321740d`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `OAEP-NTRU-648` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## OAEPNTRU1296-K — OAEP-NTRU-1296 submitted valid-vector consistency

- Source locator: PDF p. 6 (algorithm context); `Test_Vectors/KAT_KEM_OAEP-NTRU-1296.txt` SHA-256 `1617e724930e407e96069c5280b219b4c189bc02ba992cb6ca688aa118d52dd0`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `OAEP-NTRU-1296` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## OAEPNTRU2592-K — OAEP-NTRU-2592 submitted valid-vector consistency

- Source locator: PDF p. 6 (algorithm context); `Test_Vectors/KAT_KEM_OAEP-NTRU-2592.txt` SHA-256 `4b8026ebc6f901358feafb811211be535b4a862a8e5b062d0a9cda865b0bc034`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `OAEP-NTRU-2592` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## OAEPNTRU1296-KEMENC-C — OAEP-NTRU-1296 kem_enc public API relation

- Source locator: PDF p. 6; `Implementations/Reference_Implementation/OAEP-NTRU-1296/KEM_AlgorithmInstance.h` SHA-256 `2292013b187463cf08cb315f75e67eb823eff41b3bbd20cb233d9c94f3015959`; `Test_Vectors/KAT_KEM_OAEP-NTRU-1296.txt` SHA-256 `1617e724930e407e96069c5280b219b4c189bc02ba992cb6ca688aa118d52dd0`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `OAEP-NTRU-1296` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## OAEPNTRU1296-KEMGETCTLENBYTES-C — OAEP-NTRU-1296 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/OAEP-NTRU-1296/KEM_AlgorithmInstance.h` SHA-256 `2292013b187463cf08cb315f75e67eb823eff41b3bbd20cb233d9c94f3015959`; `Test_Vectors/KAT_KEM_OAEP-NTRU-1296.txt` SHA-256 `1617e724930e407e96069c5280b219b4c189bc02ba992cb6ca688aa118d52dd0`.
- Class: submitted API length/KAT observation.
- Scope: `OAEP-NTRU-1296` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## OAEPNTRU1296-KEMGETPKLENBYTES-C — OAEP-NTRU-1296 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/OAEP-NTRU-1296/KEM_AlgorithmInstance.h` SHA-256 `2292013b187463cf08cb315f75e67eb823eff41b3bbd20cb233d9c94f3015959`; `Test_Vectors/KAT_KEM_OAEP-NTRU-1296.txt` SHA-256 `1617e724930e407e96069c5280b219b4c189bc02ba992cb6ca688aa118d52dd0`.
- Class: submitted API length/KAT observation.
- Scope: `OAEP-NTRU-1296` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## OAEPNTRU1296-KEMGETSKLENBYTES-C — OAEP-NTRU-1296 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/OAEP-NTRU-1296/KEM_AlgorithmInstance.h` SHA-256 `2292013b187463cf08cb315f75e67eb823eff41b3bbd20cb233d9c94f3015959`; `Test_Vectors/KAT_KEM_OAEP-NTRU-1296.txt` SHA-256 `1617e724930e407e96069c5280b219b4c189bc02ba992cb6ca688aa118d52dd0`.
- Class: submitted API length/KAT observation.
- Scope: `OAEP-NTRU-1296` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## OAEPNTRU1296-KEMGETSSLENBYTES-C — OAEP-NTRU-1296 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/OAEP-NTRU-1296/KEM_AlgorithmInstance.h` SHA-256 `2292013b187463cf08cb315f75e67eb823eff41b3bbd20cb233d9c94f3015959`; `Test_Vectors/KAT_KEM_OAEP-NTRU-1296.txt` SHA-256 `1617e724930e407e96069c5280b219b4c189bc02ba992cb6ca688aa118d52dd0`.
- Class: submitted API length/KAT observation.
- Scope: `OAEP-NTRU-1296` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## OAEPNTRU1296-KEMKEYGEN-C — OAEP-NTRU-1296 kem_keygen public API relation

- Source locator: PDF p. 6; `Implementations/Reference_Implementation/OAEP-NTRU-1296/KEM_AlgorithmInstance.h` SHA-256 `2292013b187463cf08cb315f75e67eb823eff41b3bbd20cb233d9c94f3015959`; `Test_Vectors/KAT_KEM_OAEP-NTRU-1296.txt` SHA-256 `1617e724930e407e96069c5280b219b4c189bc02ba992cb6ca688aa118d52dd0`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `OAEP-NTRU-1296` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## OAEPNTRU2592-KEMENC-C — OAEP-NTRU-2592 kem_enc public API relation

- Source locator: PDF p. 6; `Implementations/Reference_Implementation/OAEP-NTRU-2592/KEM_AlgorithmInstance.h` SHA-256 `295bf457a63fe0392b13374002cc71edbf83e832e88ed88083927487948c2b71`; `Test_Vectors/KAT_KEM_OAEP-NTRU-2592.txt` SHA-256 `4b8026ebc6f901358feafb811211be535b4a862a8e5b062d0a9cda865b0bc034`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `OAEP-NTRU-2592` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## OAEPNTRU2592-KEMGETCTLENBYTES-C — OAEP-NTRU-2592 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/OAEP-NTRU-2592/KEM_AlgorithmInstance.h` SHA-256 `295bf457a63fe0392b13374002cc71edbf83e832e88ed88083927487948c2b71`; `Test_Vectors/KAT_KEM_OAEP-NTRU-2592.txt` SHA-256 `4b8026ebc6f901358feafb811211be535b4a862a8e5b062d0a9cda865b0bc034`.
- Class: submitted API length/KAT observation.
- Scope: `OAEP-NTRU-2592` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## OAEPNTRU2592-KEMGETPKLENBYTES-C — OAEP-NTRU-2592 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/OAEP-NTRU-2592/KEM_AlgorithmInstance.h` SHA-256 `295bf457a63fe0392b13374002cc71edbf83e832e88ed88083927487948c2b71`; `Test_Vectors/KAT_KEM_OAEP-NTRU-2592.txt` SHA-256 `4b8026ebc6f901358feafb811211be535b4a862a8e5b062d0a9cda865b0bc034`.
- Class: submitted API length/KAT observation.
- Scope: `OAEP-NTRU-2592` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## OAEPNTRU2592-KEMGETSKLENBYTES-C — OAEP-NTRU-2592 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/OAEP-NTRU-2592/KEM_AlgorithmInstance.h` SHA-256 `295bf457a63fe0392b13374002cc71edbf83e832e88ed88083927487948c2b71`; `Test_Vectors/KAT_KEM_OAEP-NTRU-2592.txt` SHA-256 `4b8026ebc6f901358feafb811211be535b4a862a8e5b062d0a9cda865b0bc034`.
- Class: submitted API length/KAT observation.
- Scope: `OAEP-NTRU-2592` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## OAEPNTRU2592-KEMGETSSLENBYTES-C — OAEP-NTRU-2592 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/OAEP-NTRU-2592/KEM_AlgorithmInstance.h` SHA-256 `295bf457a63fe0392b13374002cc71edbf83e832e88ed88083927487948c2b71`; `Test_Vectors/KAT_KEM_OAEP-NTRU-2592.txt` SHA-256 `4b8026ebc6f901358feafb811211be535b4a862a8e5b062d0a9cda865b0bc034`.
- Class: submitted API length/KAT observation.
- Scope: `OAEP-NTRU-2592` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## OAEPNTRU2592-KEMKEYGEN-C — OAEP-NTRU-2592 kem_keygen public API relation

- Source locator: PDF p. 6; `Implementations/Reference_Implementation/OAEP-NTRU-2592/KEM_AlgorithmInstance.h` SHA-256 `295bf457a63fe0392b13374002cc71edbf83e832e88ed88083927487948c2b71`; `Test_Vectors/KAT_KEM_OAEP-NTRU-2592.txt` SHA-256 `4b8026ebc6f901358feafb811211be535b4a862a8e5b062d0a9cda865b0bc034`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `OAEP-NTRU-2592` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.
