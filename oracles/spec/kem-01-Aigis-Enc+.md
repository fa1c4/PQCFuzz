---
status: draft
target: kem-01
algorithm: Aigis-Enc+
source_path: third_party/kem-01/source
source_sha256: fab1491992307c011506625c7f4e9dfb45a98a01c41a4504ee8ab1ae7926fa22
document_path: third_party/kem-01/specification.pdf
document_sha256: 27e4b81bedaffa1a57cc2e2fe9518f3ddefcbdaa6a883463caf8a88196c43ceb
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# Aigis-Enc+ draft claim extraction

This document covers source-pinned public vector records and public API relations
for the named parameter sets. The algorithm construction and correctness context is
at PDF p. 8 (algorithm context). Original PDF and archived source are authoritative.

## AIGISENCI-K — Aigis-Enc+-I submitted valid-vector consistency

- Source locator: PDF p. 8 (algorithm context); `Test_Vectors/KAT_KEM_Aigis-enc1.txt`, SHA-256 `e15e2b2ad808be3c13a43897971117ea4d2b616aba1f7caa16cd76b844db45fb`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `Aigis-Enc+-I` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record decapsulates to its recorded shared secret.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## AIGISENCI-KEMENC-C — Aigis-Enc+-I kem_enc public API relation

- Source locator: PDF pp. 8–9; `Implementations/Reference_Implementation/Aigis-Enc+-I/kat_test/KEM_AlgorithmInstance.h` SHA-256 `7db27e8c01cd05b05587abb14d3f63be45e7fcdad117eebbf7df04c142dedd0d`; `Test_Vectors/KAT_KEM_Aigis-enc1.txt` SHA-256 `e15e2b2ad808be3c13a43897971117ea4d2b616aba1f7caa16cd76b844db45fb`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Aigis-Enc+-I` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AIGISENCI-KEMGETCTLENBYTES-C — Aigis-Enc+-I kem_get_ct_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/Aigis-Enc+-I/kat_test/KEM_AlgorithmInstance.h` SHA-256 `7db27e8c01cd05b05587abb14d3f63be45e7fcdad117eebbf7df04c142dedd0d`; `Test_Vectors/KAT_KEM_Aigis-enc1.txt` SHA-256 `e15e2b2ad808be3c13a43897971117ea4d2b616aba1f7caa16cd76b844db45fb`.
- Class: submitted API length/KAT observation.
- Scope: `Aigis-Enc+-I` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AIGISENCI-KEMGETPKLENBYTES-C — Aigis-Enc+-I kem_get_pk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/Aigis-Enc+-I/kat_test/KEM_AlgorithmInstance.h` SHA-256 `7db27e8c01cd05b05587abb14d3f63be45e7fcdad117eebbf7df04c142dedd0d`; `Test_Vectors/KAT_KEM_Aigis-enc1.txt` SHA-256 `e15e2b2ad808be3c13a43897971117ea4d2b616aba1f7caa16cd76b844db45fb`.
- Class: submitted API length/KAT observation.
- Scope: `Aigis-Enc+-I` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AIGISENCI-KEMGETSKLENBYTES-C — Aigis-Enc+-I kem_get_sk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/Aigis-Enc+-I/kat_test/KEM_AlgorithmInstance.h` SHA-256 `7db27e8c01cd05b05587abb14d3f63be45e7fcdad117eebbf7df04c142dedd0d`; `Test_Vectors/KAT_KEM_Aigis-enc1.txt` SHA-256 `e15e2b2ad808be3c13a43897971117ea4d2b616aba1f7caa16cd76b844db45fb`.
- Class: submitted API length/KAT observation.
- Scope: `Aigis-Enc+-I` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AIGISENCI-KEMGETSSLENBYTES-C — Aigis-Enc+-I kem_get_ss_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/Aigis-Enc+-I/kat_test/KEM_AlgorithmInstance.h` SHA-256 `7db27e8c01cd05b05587abb14d3f63be45e7fcdad117eebbf7df04c142dedd0d`; `Test_Vectors/KAT_KEM_Aigis-enc1.txt` SHA-256 `e15e2b2ad808be3c13a43897971117ea4d2b616aba1f7caa16cd76b844db45fb`.
- Class: submitted API length/KAT observation.
- Scope: `Aigis-Enc+-I` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AIGISENCI-KEMKEYGEN-C — Aigis-Enc+-I kem_keygen public API relation

- Source locator: PDF pp. 8–9; `Implementations/Reference_Implementation/Aigis-Enc+-I/kat_test/KEM_AlgorithmInstance.h` SHA-256 `7db27e8c01cd05b05587abb14d3f63be45e7fcdad117eebbf7df04c142dedd0d`; `Test_Vectors/KAT_KEM_Aigis-enc1.txt` SHA-256 `e15e2b2ad808be3c13a43897971117ea4d2b616aba1f7caa16cd76b844db45fb`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Aigis-Enc+-I` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AIGISENCII-K — Aigis-Enc+-II submitted valid-vector consistency

- Source locator: PDF pp. 8–9 (algorithm context); `Test_Vectors/KAT_KEM_Aigis-enc2.txt` SHA-256 `f6d8bad8e531512c6feee2a488b00b7e3ccf3d5318462154b9afb7701b06b527`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `Aigis-Enc+-II` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## AIGISENCIII-K — Aigis-Enc+-III submitted valid-vector consistency

- Source locator: PDF pp. 8–9 (algorithm context); `Test_Vectors/KAT_KEM_Aigis-enc3.txt` SHA-256 `1c7be3d27d749b6cb4ae83983799f5f1ea4cc6ca0d386967f9448943ab1c393c`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `Aigis-Enc+-III` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## AIGISENCII-KEMENC-C — Aigis-Enc+-II kem_enc public API relation

- Source locator: PDF pp. 8–9; `Implementations/Reference_Implementation/Aigis-Enc+-II/kat_test/KEM_AlgorithmInstance.h` SHA-256 `7db27e8c01cd05b05587abb14d3f63be45e7fcdad117eebbf7df04c142dedd0d`; `Test_Vectors/KAT_KEM_Aigis-enc2.txt` SHA-256 `f6d8bad8e531512c6feee2a488b00b7e3ccf3d5318462154b9afb7701b06b527`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Aigis-Enc+-II` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AIGISENCII-KEMGETCTLENBYTES-C — Aigis-Enc+-II kem_get_ct_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/Aigis-Enc+-II/kat_test/KEM_AlgorithmInstance.h` SHA-256 `7db27e8c01cd05b05587abb14d3f63be45e7fcdad117eebbf7df04c142dedd0d`; `Test_Vectors/KAT_KEM_Aigis-enc2.txt` SHA-256 `f6d8bad8e531512c6feee2a488b00b7e3ccf3d5318462154b9afb7701b06b527`.
- Class: submitted API length/KAT observation.
- Scope: `Aigis-Enc+-II` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AIGISENCII-KEMGETPKLENBYTES-C — Aigis-Enc+-II kem_get_pk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/Aigis-Enc+-II/kat_test/KEM_AlgorithmInstance.h` SHA-256 `7db27e8c01cd05b05587abb14d3f63be45e7fcdad117eebbf7df04c142dedd0d`; `Test_Vectors/KAT_KEM_Aigis-enc2.txt` SHA-256 `f6d8bad8e531512c6feee2a488b00b7e3ccf3d5318462154b9afb7701b06b527`.
- Class: submitted API length/KAT observation.
- Scope: `Aigis-Enc+-II` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AIGISENCII-KEMGETSKLENBYTES-C — Aigis-Enc+-II kem_get_sk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/Aigis-Enc+-II/kat_test/KEM_AlgorithmInstance.h` SHA-256 `7db27e8c01cd05b05587abb14d3f63be45e7fcdad117eebbf7df04c142dedd0d`; `Test_Vectors/KAT_KEM_Aigis-enc2.txt` SHA-256 `f6d8bad8e531512c6feee2a488b00b7e3ccf3d5318462154b9afb7701b06b527`.
- Class: submitted API length/KAT observation.
- Scope: `Aigis-Enc+-II` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AIGISENCII-KEMGETSSLENBYTES-C — Aigis-Enc+-II kem_get_ss_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/Aigis-Enc+-II/kat_test/KEM_AlgorithmInstance.h` SHA-256 `7db27e8c01cd05b05587abb14d3f63be45e7fcdad117eebbf7df04c142dedd0d`; `Test_Vectors/KAT_KEM_Aigis-enc2.txt` SHA-256 `f6d8bad8e531512c6feee2a488b00b7e3ccf3d5318462154b9afb7701b06b527`.
- Class: submitted API length/KAT observation.
- Scope: `Aigis-Enc+-II` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AIGISENCII-KEMKEYGEN-C — Aigis-Enc+-II kem_keygen public API relation

- Source locator: PDF pp. 8–9; `Implementations/Reference_Implementation/Aigis-Enc+-II/kat_test/KEM_AlgorithmInstance.h` SHA-256 `7db27e8c01cd05b05587abb14d3f63be45e7fcdad117eebbf7df04c142dedd0d`; `Test_Vectors/KAT_KEM_Aigis-enc2.txt` SHA-256 `f6d8bad8e531512c6feee2a488b00b7e3ccf3d5318462154b9afb7701b06b527`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Aigis-Enc+-II` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AIGISENCIII-KEMENC-C — Aigis-Enc+-III kem_enc public API relation

- Source locator: PDF pp. 8–9; `Implementations/Reference_Implementation/Aigis-Enc+-III/kat_test/KEM_AlgorithmInstance.h` SHA-256 `7db27e8c01cd05b05587abb14d3f63be45e7fcdad117eebbf7df04c142dedd0d`; `Test_Vectors/KAT_KEM_Aigis-enc3.txt` SHA-256 `1c7be3d27d749b6cb4ae83983799f5f1ea4cc6ca0d386967f9448943ab1c393c`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Aigis-Enc+-III` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AIGISENCIII-KEMGETCTLENBYTES-C — Aigis-Enc+-III kem_get_ct_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/Aigis-Enc+-III/kat_test/KEM_AlgorithmInstance.h` SHA-256 `7db27e8c01cd05b05587abb14d3f63be45e7fcdad117eebbf7df04c142dedd0d`; `Test_Vectors/KAT_KEM_Aigis-enc3.txt` SHA-256 `1c7be3d27d749b6cb4ae83983799f5f1ea4cc6ca0d386967f9448943ab1c393c`.
- Class: submitted API length/KAT observation.
- Scope: `Aigis-Enc+-III` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AIGISENCIII-KEMGETPKLENBYTES-C — Aigis-Enc+-III kem_get_pk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/Aigis-Enc+-III/kat_test/KEM_AlgorithmInstance.h` SHA-256 `7db27e8c01cd05b05587abb14d3f63be45e7fcdad117eebbf7df04c142dedd0d`; `Test_Vectors/KAT_KEM_Aigis-enc3.txt` SHA-256 `1c7be3d27d749b6cb4ae83983799f5f1ea4cc6ca0d386967f9448943ab1c393c`.
- Class: submitted API length/KAT observation.
- Scope: `Aigis-Enc+-III` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AIGISENCIII-KEMGETSKLENBYTES-C — Aigis-Enc+-III kem_get_sk_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/Aigis-Enc+-III/kat_test/KEM_AlgorithmInstance.h` SHA-256 `7db27e8c01cd05b05587abb14d3f63be45e7fcdad117eebbf7df04c142dedd0d`; `Test_Vectors/KAT_KEM_Aigis-enc3.txt` SHA-256 `1c7be3d27d749b6cb4ae83983799f5f1ea4cc6ca0d386967f9448943ab1c393c`.
- Class: submitted API length/KAT observation.
- Scope: `Aigis-Enc+-III` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AIGISENCIII-KEMGETSSLENBYTES-C — Aigis-Enc+-III kem_get_ss_len_bytes public API relation

- Source locator: `Implementations/Reference_Implementation/Aigis-Enc+-III/kat_test/KEM_AlgorithmInstance.h` SHA-256 `7db27e8c01cd05b05587abb14d3f63be45e7fcdad117eebbf7df04c142dedd0d`; `Test_Vectors/KAT_KEM_Aigis-enc3.txt` SHA-256 `1c7be3d27d749b6cb4ae83983799f5f1ea4cc6ca0d386967f9448943ab1c393c`.
- Class: submitted API length/KAT observation.
- Scope: `Aigis-Enc+-III` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## AIGISENCIII-KEMKEYGEN-C — Aigis-Enc+-III kem_keygen public API relation

- Source locator: PDF pp. 8–9; `Implementations/Reference_Implementation/Aigis-Enc+-III/kat_test/KEM_AlgorithmInstance.h` SHA-256 `7db27e8c01cd05b05587abb14d3f63be45e7fcdad117eebbf7df04c142dedd0d`; `Test_Vectors/KAT_KEM_Aigis-enc3.txt` SHA-256 `1c7be3d27d749b6cb4ae83983799f5f1ea4cc6ca0d386967f9448943ab1c393c`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Aigis-Enc+-III` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.
