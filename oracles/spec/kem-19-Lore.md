---
status: draft
target: kem-19
algorithm: Lore
source_path: third_party/kem-19/source
source_sha256: 565433f6d9d78a50d894453bf0f8bc04d26148cbcc247614ae3f52960ab7563e
document_path: third_party/kem-19/specification.pdf
document_sha256: 185adb545b785ef6805a64aa9c70e1e68aca4dd705aebc8e11c3c302987e0b48
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# Lore draft claim extraction

This document covers source-pinned public vector records and public API relations
for the named parameter sets. The algorithm construction and correctness context is
at PDF p. 11 (algorithm context). Original PDF and archived source are authoritative.

## LOREL1-K — Lore-L1 submitted valid-vector consistency

- Source locator: PDF p. 11 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/Lore-SHAKE/KAT_KEM_Lore-L1.txt`, SHA-256 `993e5a7f3bfc16662ace49b2b306f81473fd777173f6de4e54f31e9ef71df432`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `Lore-L1` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record decapsulates to its recorded shared secret.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## LOREL1-KEMENC-C — Lore-L1 kem_enc public API relation

- Source locator: PDF p. 12; `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SHAKE/Lore-L1/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SHAKE/KAT_KEM_Lore-L1.txt` SHA-256 `993e5a7f3bfc16662ace49b2b306f81473fd777173f6de4e54f31e9ef71df432`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Lore-L1` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LOREL1-KEMGETCTLENBYTES-C — Lore-L1 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SHAKE/Lore-L1/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SHAKE/KAT_KEM_Lore-L1.txt` SHA-256 `993e5a7f3bfc16662ace49b2b306f81473fd777173f6de4e54f31e9ef71df432`.
- Class: submitted API length/KAT observation.
- Scope: `Lore-L1` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LOREL1-KEMGETPKLENBYTES-C — Lore-L1 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SHAKE/Lore-L1/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SHAKE/KAT_KEM_Lore-L1.txt` SHA-256 `993e5a7f3bfc16662ace49b2b306f81473fd777173f6de4e54f31e9ef71df432`.
- Class: submitted API length/KAT observation.
- Scope: `Lore-L1` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LOREL1-KEMGETSKLENBYTES-C — Lore-L1 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SHAKE/Lore-L1/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SHAKE/KAT_KEM_Lore-L1.txt` SHA-256 `993e5a7f3bfc16662ace49b2b306f81473fd777173f6de4e54f31e9ef71df432`.
- Class: submitted API length/KAT observation.
- Scope: `Lore-L1` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LOREL1-KEMGETSSLENBYTES-C — Lore-L1 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SHAKE/Lore-L1/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SHAKE/KAT_KEM_Lore-L1.txt` SHA-256 `993e5a7f3bfc16662ace49b2b306f81473fd777173f6de4e54f31e9ef71df432`.
- Class: submitted API length/KAT observation.
- Scope: `Lore-L1` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LOREL1-KEMKEYGEN-C — Lore-L1 kem_keygen public API relation

- Source locator: PDF p. 12; `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SHAKE/Lore-L1/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SHAKE/KAT_KEM_Lore-L1.txt` SHA-256 `993e5a7f3bfc16662ace49b2b306f81473fd777173f6de4e54f31e9ef71df432`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Lore-L1` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LOREL2-K — Lore-L2 submitted valid-vector consistency

- Source locator: PDF p. 12 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/Lore-SHAKE/KAT_KEM_Lore-L2.txt` SHA-256 `3735ec4f854bd1230b63a0502b03b845fb3c8af04f3fba872455fb92ed961b8a`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `Lore-L2` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## LOREL3-K — Lore-L3 submitted valid-vector consistency

- Source locator: PDF p. 12 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/Lore-SHAKE/KAT_KEM_Lore-L3.txt` SHA-256 `d79252a2fddf5930b617f5f476a18ad460ee9db8f31aa282306a62a4d5feb18d`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `Lore-L3` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## LOREL4-K — Lore-L4 submitted valid-vector consistency

- Source locator: PDF p. 12 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/Lore-SHAKE/KAT_KEM_Lore-L4.txt` SHA-256 `f6d34f27b027a8e8a13ddc537bfd3d3d576d839b3d91a6921c1dc724b2694592`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `Lore-L4` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## LOREL2-KEMENC-C — Lore-L2 kem_enc public API relation

- Source locator: PDF p. 12; `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SHAKE/Lore-L2/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SHAKE/KAT_KEM_Lore-L2.txt` SHA-256 `3735ec4f854bd1230b63a0502b03b845fb3c8af04f3fba872455fb92ed961b8a`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Lore-L2` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LOREL2-KEMGETCTLENBYTES-C — Lore-L2 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SHAKE/Lore-L2/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SHAKE/KAT_KEM_Lore-L2.txt` SHA-256 `3735ec4f854bd1230b63a0502b03b845fb3c8af04f3fba872455fb92ed961b8a`.
- Class: submitted API length/KAT observation.
- Scope: `Lore-L2` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LOREL2-KEMGETPKLENBYTES-C — Lore-L2 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SHAKE/Lore-L2/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SHAKE/KAT_KEM_Lore-L2.txt` SHA-256 `3735ec4f854bd1230b63a0502b03b845fb3c8af04f3fba872455fb92ed961b8a`.
- Class: submitted API length/KAT observation.
- Scope: `Lore-L2` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LOREL2-KEMGETSKLENBYTES-C — Lore-L2 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SHAKE/Lore-L2/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SHAKE/KAT_KEM_Lore-L2.txt` SHA-256 `3735ec4f854bd1230b63a0502b03b845fb3c8af04f3fba872455fb92ed961b8a`.
- Class: submitted API length/KAT observation.
- Scope: `Lore-L2` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LOREL2-KEMGETSSLENBYTES-C — Lore-L2 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SHAKE/Lore-L2/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SHAKE/KAT_KEM_Lore-L2.txt` SHA-256 `3735ec4f854bd1230b63a0502b03b845fb3c8af04f3fba872455fb92ed961b8a`.
- Class: submitted API length/KAT observation.
- Scope: `Lore-L2` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LOREL2-KEMKEYGEN-C — Lore-L2 kem_keygen public API relation

- Source locator: PDF p. 12; `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SHAKE/Lore-L2/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SHAKE/KAT_KEM_Lore-L2.txt` SHA-256 `3735ec4f854bd1230b63a0502b03b845fb3c8af04f3fba872455fb92ed961b8a`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Lore-L2` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LOREL3-KEMENC-C — Lore-L3 kem_enc public API relation

- Source locator: PDF p. 12; `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SHAKE/Lore-L3/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SHAKE/KAT_KEM_Lore-L3.txt` SHA-256 `d79252a2fddf5930b617f5f476a18ad460ee9db8f31aa282306a62a4d5feb18d`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Lore-L3` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LOREL3-KEMGETCTLENBYTES-C — Lore-L3 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SHAKE/Lore-L3/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SHAKE/KAT_KEM_Lore-L3.txt` SHA-256 `d79252a2fddf5930b617f5f476a18ad460ee9db8f31aa282306a62a4d5feb18d`.
- Class: submitted API length/KAT observation.
- Scope: `Lore-L3` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LOREL3-KEMGETPKLENBYTES-C — Lore-L3 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SHAKE/Lore-L3/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SHAKE/KAT_KEM_Lore-L3.txt` SHA-256 `d79252a2fddf5930b617f5f476a18ad460ee9db8f31aa282306a62a4d5feb18d`.
- Class: submitted API length/KAT observation.
- Scope: `Lore-L3` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LOREL3-KEMGETSKLENBYTES-C — Lore-L3 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SHAKE/Lore-L3/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SHAKE/KAT_KEM_Lore-L3.txt` SHA-256 `d79252a2fddf5930b617f5f476a18ad460ee9db8f31aa282306a62a4d5feb18d`.
- Class: submitted API length/KAT observation.
- Scope: `Lore-L3` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LOREL3-KEMGETSSLENBYTES-C — Lore-L3 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SHAKE/Lore-L3/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SHAKE/KAT_KEM_Lore-L3.txt` SHA-256 `d79252a2fddf5930b617f5f476a18ad460ee9db8f31aa282306a62a4d5feb18d`.
- Class: submitted API length/KAT observation.
- Scope: `Lore-L3` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LOREL3-KEMKEYGEN-C — Lore-L3 kem_keygen public API relation

- Source locator: PDF p. 12; `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SHAKE/Lore-L3/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SHAKE/KAT_KEM_Lore-L3.txt` SHA-256 `d79252a2fddf5930b617f5f476a18ad460ee9db8f31aa282306a62a4d5feb18d`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Lore-L3` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LOREL4-KEMENC-C — Lore-L4 kem_enc public API relation

- Source locator: PDF p. 12; `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SHAKE/Lore-L4/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SHAKE/KAT_KEM_Lore-L4.txt` SHA-256 `f6d34f27b027a8e8a13ddc537bfd3d3d576d839b3d91a6921c1dc724b2694592`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Lore-L4` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LOREL4-KEMGETCTLENBYTES-C — Lore-L4 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SHAKE/Lore-L4/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SHAKE/KAT_KEM_Lore-L4.txt` SHA-256 `f6d34f27b027a8e8a13ddc537bfd3d3d576d839b3d91a6921c1dc724b2694592`.
- Class: submitted API length/KAT observation.
- Scope: `Lore-L4` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LOREL4-KEMGETPKLENBYTES-C — Lore-L4 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SHAKE/Lore-L4/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SHAKE/KAT_KEM_Lore-L4.txt` SHA-256 `f6d34f27b027a8e8a13ddc537bfd3d3d576d839b3d91a6921c1dc724b2694592`.
- Class: submitted API length/KAT observation.
- Scope: `Lore-L4` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LOREL4-KEMGETSKLENBYTES-C — Lore-L4 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SHAKE/Lore-L4/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SHAKE/KAT_KEM_Lore-L4.txt` SHA-256 `f6d34f27b027a8e8a13ddc537bfd3d3d576d839b3d91a6921c1dc724b2694592`.
- Class: submitted API length/KAT observation.
- Scope: `Lore-L4` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LOREL4-KEMGETSSLENBYTES-C — Lore-L4 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SHAKE/Lore-L4/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SHAKE/KAT_KEM_Lore-L4.txt` SHA-256 `f6d34f27b027a8e8a13ddc537bfd3d3d576d839b3d91a6921c1dc724b2694592`.
- Class: submitted API length/KAT observation.
- Scope: `Lore-L4` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LOREL4-KEMKEYGEN-C — Lore-L4 kem_keygen public API relation

- Source locator: PDF p. 12; `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SHAKE/Lore-L4/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SHAKE/KAT_KEM_Lore-L4.txt` SHA-256 `f6d34f27b027a8e8a13ddc537bfd3d3d576d839b3d91a6921c1dc724b2694592`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Lore-L4` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LORESM3L1-K — Lore-SM3-L1 submitted valid-vector consistency

- Source locator: PDF p. 12 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/Lore-SM3/KAT_KEM_Lore-L1.txt` SHA-256 `74bdbeda5c9e37a7d1347cf51fd31424be457d2fee9a68b3e303b6fcc6afd95e`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `Lore-SM3-L1` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## LORESM3L2-K — Lore-SM3-L2 submitted valid-vector consistency

- Source locator: PDF p. 12 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/Lore-SM3/KAT_KEM_Lore-L2.txt` SHA-256 `fda1ee46e86b1c487a5b0c60f49707471c6eda0d7f89e5903e2e6d1ebd1e7e61`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `Lore-SM3-L2` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## LORESM3L3-K — Lore-SM3-L3 submitted valid-vector consistency

- Source locator: PDF p. 12 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/Lore-SM3/KAT_KEM_Lore-L3.txt` SHA-256 `aebe78f3a3c48c56bf925626cd133a43bacfa23cdcf28666f36efce1abe11d93`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `Lore-SM3-L3` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## LORESM3L4-K — Lore-SM3-L4 submitted valid-vector consistency

- Source locator: PDF p. 12 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/Lore-SM3/KAT_KEM_Lore-L4.txt` SHA-256 `924e2d5d0b8109a08c5ea99f4879cc345b649b61b7a212e60454794dd3850fd3`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `Lore-SM3-L4` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records decapsulate to their own archived shared secrets.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## LORESM3L1-KEMENC-C — Lore-SM3-L1 kem_enc public API relation

- Source locator: PDF p. 12; `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SM3/Lore-L1/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SM3/KAT_KEM_Lore-L1.txt` SHA-256 `74bdbeda5c9e37a7d1347cf51fd31424be457d2fee9a68b3e303b6fcc6afd95e`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Lore-SM3-L1` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LORESM3L1-KEMGETCTLENBYTES-C — Lore-SM3-L1 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SM3/Lore-L1/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SM3/KAT_KEM_Lore-L1.txt` SHA-256 `74bdbeda5c9e37a7d1347cf51fd31424be457d2fee9a68b3e303b6fcc6afd95e`.
- Class: submitted API length/KAT observation.
- Scope: `Lore-SM3-L1` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LORESM3L1-KEMGETPKLENBYTES-C — Lore-SM3-L1 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SM3/Lore-L1/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SM3/KAT_KEM_Lore-L1.txt` SHA-256 `74bdbeda5c9e37a7d1347cf51fd31424be457d2fee9a68b3e303b6fcc6afd95e`.
- Class: submitted API length/KAT observation.
- Scope: `Lore-SM3-L1` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LORESM3L1-KEMGETSKLENBYTES-C — Lore-SM3-L1 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SM3/Lore-L1/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SM3/KAT_KEM_Lore-L1.txt` SHA-256 `74bdbeda5c9e37a7d1347cf51fd31424be457d2fee9a68b3e303b6fcc6afd95e`.
- Class: submitted API length/KAT observation.
- Scope: `Lore-SM3-L1` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LORESM3L1-KEMGETSSLENBYTES-C — Lore-SM3-L1 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SM3/Lore-L1/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SM3/KAT_KEM_Lore-L1.txt` SHA-256 `74bdbeda5c9e37a7d1347cf51fd31424be457d2fee9a68b3e303b6fcc6afd95e`.
- Class: submitted API length/KAT observation.
- Scope: `Lore-SM3-L1` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LORESM3L1-KEMKEYGEN-C — Lore-SM3-L1 kem_keygen public API relation

- Source locator: PDF p. 12; `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SM3/Lore-L1/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SM3/KAT_KEM_Lore-L1.txt` SHA-256 `74bdbeda5c9e37a7d1347cf51fd31424be457d2fee9a68b3e303b6fcc6afd95e`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Lore-SM3-L1` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LORESM3L2-KEMENC-C — Lore-SM3-L2 kem_enc public API relation

- Source locator: PDF p. 12; `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SM3/Lore-L2/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SM3/KAT_KEM_Lore-L2.txt` SHA-256 `fda1ee46e86b1c487a5b0c60f49707471c6eda0d7f89e5903e2e6d1ebd1e7e61`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Lore-SM3-L2` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LORESM3L2-KEMGETCTLENBYTES-C — Lore-SM3-L2 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SM3/Lore-L2/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SM3/KAT_KEM_Lore-L2.txt` SHA-256 `fda1ee46e86b1c487a5b0c60f49707471c6eda0d7f89e5903e2e6d1ebd1e7e61`.
- Class: submitted API length/KAT observation.
- Scope: `Lore-SM3-L2` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LORESM3L2-KEMGETPKLENBYTES-C — Lore-SM3-L2 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SM3/Lore-L2/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SM3/KAT_KEM_Lore-L2.txt` SHA-256 `fda1ee46e86b1c487a5b0c60f49707471c6eda0d7f89e5903e2e6d1ebd1e7e61`.
- Class: submitted API length/KAT observation.
- Scope: `Lore-SM3-L2` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LORESM3L2-KEMGETSKLENBYTES-C — Lore-SM3-L2 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SM3/Lore-L2/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SM3/KAT_KEM_Lore-L2.txt` SHA-256 `fda1ee46e86b1c487a5b0c60f49707471c6eda0d7f89e5903e2e6d1ebd1e7e61`.
- Class: submitted API length/KAT observation.
- Scope: `Lore-SM3-L2` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LORESM3L2-KEMGETSSLENBYTES-C — Lore-SM3-L2 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SM3/Lore-L2/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SM3/KAT_KEM_Lore-L2.txt` SHA-256 `fda1ee46e86b1c487a5b0c60f49707471c6eda0d7f89e5903e2e6d1ebd1e7e61`.
- Class: submitted API length/KAT observation.
- Scope: `Lore-SM3-L2` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LORESM3L2-KEMKEYGEN-C — Lore-SM3-L2 kem_keygen public API relation

- Source locator: PDF p. 12; `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SM3/Lore-L2/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SM3/KAT_KEM_Lore-L2.txt` SHA-256 `fda1ee46e86b1c487a5b0c60f49707471c6eda0d7f89e5903e2e6d1ebd1e7e61`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Lore-SM3-L2` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LORESM3L3-KEMENC-C — Lore-SM3-L3 kem_enc public API relation

- Source locator: PDF p. 12; `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SM3/Lore-L3/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SM3/KAT_KEM_Lore-L3.txt` SHA-256 `aebe78f3a3c48c56bf925626cd133a43bacfa23cdcf28666f36efce1abe11d93`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Lore-SM3-L3` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LORESM3L3-KEMGETCTLENBYTES-C — Lore-SM3-L3 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SM3/Lore-L3/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SM3/KAT_KEM_Lore-L3.txt` SHA-256 `aebe78f3a3c48c56bf925626cd133a43bacfa23cdcf28666f36efce1abe11d93`.
- Class: submitted API length/KAT observation.
- Scope: `Lore-SM3-L3` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LORESM3L3-KEMGETPKLENBYTES-C — Lore-SM3-L3 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SM3/Lore-L3/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SM3/KAT_KEM_Lore-L3.txt` SHA-256 `aebe78f3a3c48c56bf925626cd133a43bacfa23cdcf28666f36efce1abe11d93`.
- Class: submitted API length/KAT observation.
- Scope: `Lore-SM3-L3` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LORESM3L3-KEMGETSKLENBYTES-C — Lore-SM3-L3 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SM3/Lore-L3/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SM3/KAT_KEM_Lore-L3.txt` SHA-256 `aebe78f3a3c48c56bf925626cd133a43bacfa23cdcf28666f36efce1abe11d93`.
- Class: submitted API length/KAT observation.
- Scope: `Lore-SM3-L3` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LORESM3L3-KEMGETSSLENBYTES-C — Lore-SM3-L3 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SM3/Lore-L3/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SM3/KAT_KEM_Lore-L3.txt` SHA-256 `aebe78f3a3c48c56bf925626cd133a43bacfa23cdcf28666f36efce1abe11d93`.
- Class: submitted API length/KAT observation.
- Scope: `Lore-SM3-L3` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LORESM3L3-KEMKEYGEN-C — Lore-SM3-L3 kem_keygen public API relation

- Source locator: PDF p. 12; `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SM3/Lore-L3/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SM3/KAT_KEM_Lore-L3.txt` SHA-256 `aebe78f3a3c48c56bf925626cd133a43bacfa23cdcf28666f36efce1abe11d93`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Lore-SM3-L3` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LORESM3L4-KEMENC-C — Lore-SM3-L4 kem_enc public API relation

- Source locator: PDF p. 12; `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SM3/Lore-L4/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SM3/KAT_KEM_Lore-L4.txt` SHA-256 `924e2d5d0b8109a08c5ea99f4879cc345b649b61b7a212e60454794dd3850fd3`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Lore-SM3-L4` `kem_enc` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LORESM3L4-KEMGETCTLENBYTES-C — Lore-SM3-L4 kem_get_ct_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SM3/Lore-L4/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SM3/KAT_KEM_Lore-L4.txt` SHA-256 `924e2d5d0b8109a08c5ea99f4879cc345b649b61b7a212e60454794dd3850fd3`.
- Class: submitted API length/KAT observation.
- Scope: `Lore-SM3-L4` `kem_get_ct_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LORESM3L4-KEMGETPKLENBYTES-C — Lore-SM3-L4 kem_get_pk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SM3/Lore-L4/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SM3/KAT_KEM_Lore-L4.txt` SHA-256 `924e2d5d0b8109a08c5ea99f4879cc345b649b61b7a212e60454794dd3850fd3`.
- Class: submitted API length/KAT observation.
- Scope: `Lore-SM3-L4` `kem_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LORESM3L4-KEMGETSKLENBYTES-C — Lore-SM3-L4 kem_get_sk_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SM3/Lore-L4/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SM3/KAT_KEM_Lore-L4.txt` SHA-256 `924e2d5d0b8109a08c5ea99f4879cc345b649b61b7a212e60454794dd3850fd3`.
- Class: submitted API length/KAT observation.
- Scope: `Lore-SM3-L4` `kem_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LORESM3L4-KEMGETSSLENBYTES-C — Lore-SM3-L4 kem_get_ss_len_bytes public API relation

- Source locator: `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SM3/Lore-L4/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SM3/KAT_KEM_Lore-L4.txt` SHA-256 `924e2d5d0b8109a08c5ea99f4879cc345b649b61b7a212e60454794dd3850fd3`.
- Class: submitted API length/KAT observation.
- Scope: `Lore-SM3-L4` `kem_get_ss_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## LORESM3L4-KEMKEYGEN-C — Lore-SM3-L4 kem_keygen public API relation

- Source locator: PDF p. 12; `Implementations and Test_Vectors/Implementations/Reference_Implementation/Lore-SM3/Lore-L4/KEM_AlgorithmInstance.h` SHA-256 `cf58bca2da25d05accfe1ded749c550d5b836b5e94abb9490b56358b92cff963`; `Implementations and Test_Vectors/Test_Vectors/Lore-SM3/KAT_KEM_Lore-L4.txt` SHA-256 `924e2d5d0b8109a08c5ea99f4879cc345b649b61b7a212e60454794dd3850fd3`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `Lore-SM3-L4` `kem_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.
