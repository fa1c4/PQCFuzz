---
status: draft
target: kem-17
algorithm: HEP-QC
source_path: third_party/kem-17/source
source_sha256: 34e59ad664bc6a68da3af7288b6c84519fa0a68372544e4d96095cdc797d0654
document_path: third_party/kem-17/specification.pdf
document_sha256: ebfdf7a5e695d3320b521bf4aa7149bb79ba9c6e25e860f431b90c67b02823f8
source_version: NGCC Round 1 submitted archive
extract_version: 1
---

# HEP-QC draft claim extraction

This document covers public submitted KAT records only, under the exact
`kem_dec` API. The algorithm construction and correctness context is
at PDF pp. 16–18 §3.7 Algorithms 4–6 and Table 4.1. Original PDF and archived source are authoritative.

## HEPQC1-K — hep-qc-1 submitted valid-vector consistency

- Source locator: PDF pp. 16–18 §3.7 Algorithms 4–6 and Table 4.1; `Test_Vectors/hep-qc-1/KAT_KEM_AlgorithmInstance.txt`, SHA-256 `6a84260e1bf7a1633e830e1556a8f0fe56b8ea4232769589594f555535dd769c`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `hep-qc-1` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record decapsulates to its recorded shared secret.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## HEPQC3-K — hep-qc-3 submitted valid-vector consistency

- Source locator: PDF pp. 16–18 §3.7 Algorithms 4–6 and Table 4.1; `Test_Vectors/hep-qc-3/KAT_KEM_AlgorithmInstance.txt`, SHA-256 `c6a328b7a52ef3b3d435b4134a8c186c5f630fbd5bbd7af68891fe1ef9c8583c`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `hep-qc-3` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record decapsulates to its recorded shared secret.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## HEPQC5-K — hep-qc-5 submitted valid-vector consistency

- Source locator: PDF pp. 16–18 §3.7 Algorithms 4–6 and Table 4.1; `Test_Vectors/hep-qc-5/KAT_KEM_AlgorithmInstance.txt`, SHA-256 `93dd8f9012e614dfda669b68e0ea54a6c51dc3dde31da0ac55b730ed171a17ca`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `hep-qc-5` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record decapsulates to its recorded shared secret.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## HEPQC7-K — hep-qc-7 submitted valid-vector consistency

- Source locator: PDF pp. 16–18 §3.7 Algorithms 4–6 and Table 4.1; `Test_Vectors/hep-qc-7/KAT_KEM_AlgorithmInstance.txt`, SHA-256 `089c1388bc7feb08c123ff3c9260410776f31dd090ceb69857b00b3a5b546841`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `hep-qc-7` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record decapsulates to its recorded shared secret.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## HEPQC1-R — hep-qc-1 honest KEM round trip

- Source locator: `third_party/kem-17/specification.pdf`, PDF pp. 16–18 §3.7 Algorithms 4–6; submitted `Test_Vectors/hep-qc-1/KAT_KEM_AlgorithmInstance.txt` supplies public seed indices.
- Class: algorithm correctness relation from the PDF; test seeds are public input controls, not independent normative expected outputs.
- Scope: `hep-qc-1` exact submitted `kem_keygen`, `kem_enc`, `kem_dec` API calls in one run-local build.
- Claim: For honestly generated keypairs and ciphertexts, decapsulation returns the encapsulated shared secret.
- Preconditions: Exact source/PDF/KAT identity, one indexed public seed, explicit `prng_init` before keygen, matching API lengths and success statuses.
- Extraction inference/ambiguity: The archived KAT driver initializes a different DRNG context while this implementation's KEM calls use `prng_get_bytes`; these P2 outputs are not asserted to equal archived KAT bytes.
- Limitations: Finite honest executions do not establish zero failure probability, IND-CCA security or malformed-ciphertext behavior.

## HEPQC3-R — hep-qc-3 honest KEM round trip

- Source locator: `third_party/kem-17/specification.pdf`, PDF pp. 16–18 §3.7 Algorithms 4–6; submitted `Test_Vectors/hep-qc-3/KAT_KEM_AlgorithmInstance.txt` supplies public seed indices.
- Class: algorithm correctness relation from the PDF; test seeds are public input controls, not independent normative expected outputs.
- Scope: `hep-qc-3` exact submitted `kem_keygen`, `kem_enc`, `kem_dec` API calls in one run-local build.
- Claim: For honestly generated keypairs and ciphertexts, decapsulation returns the encapsulated shared secret.
- Preconditions: Exact source/PDF/KAT identity, one indexed public seed, explicit `prng_init` before keygen, matching API lengths and success statuses.
- Extraction inference/ambiguity: The archived KAT driver initializes a different DRNG context while this implementation's KEM calls use `prng_get_bytes`; these P2 outputs are not asserted to equal archived KAT bytes.
- Limitations: Finite honest executions do not establish zero failure probability, IND-CCA security or malformed-ciphertext behavior.

## HEPQC5-R — hep-qc-5 honest KEM round trip

- Source locator: `third_party/kem-17/specification.pdf`, PDF pp. 16–18 §3.7 Algorithms 4–6; submitted `Test_Vectors/hep-qc-5/KAT_KEM_AlgorithmInstance.txt` supplies public seed indices.
- Class: algorithm correctness relation from the PDF; test seeds are public input controls, not independent normative expected outputs.
- Scope: `hep-qc-5` exact submitted `kem_keygen`, `kem_enc`, `kem_dec` API calls in one run-local build.
- Claim: For honestly generated keypairs and ciphertexts, decapsulation returns the encapsulated shared secret.
- Preconditions: Exact source/PDF/KAT identity, one indexed public seed, explicit `prng_init` before keygen, matching API lengths and success statuses.
- Extraction inference/ambiguity: The archived KAT driver initializes a different DRNG context while this implementation's KEM calls use `prng_get_bytes`; these P2 outputs are not asserted to equal archived KAT bytes.
- Limitations: Finite honest executions do not establish zero failure probability, IND-CCA security or malformed-ciphertext behavior.

## HEPQC7-R — hep-qc-7 honest KEM round trip

- Source locator: `third_party/kem-17/specification.pdf`, PDF pp. 16–18 §3.7 Algorithms 4–6; submitted `Test_Vectors/hep-qc-7/KAT_KEM_AlgorithmInstance.txt` supplies public seed indices.
- Class: algorithm correctness relation from the PDF; test seeds are public input controls, not independent normative expected outputs.
- Scope: `hep-qc-7` exact submitted `kem_keygen`, `kem_enc`, `kem_dec` API calls in one run-local build.
- Claim: For honestly generated keypairs and ciphertexts, decapsulation returns the encapsulated shared secret.
- Preconditions: Exact source/PDF/KAT identity, one indexed public seed, explicit `prng_init` before keygen, matching API lengths and success statuses.
- Extraction inference/ambiguity: The archived KAT driver initializes a different DRNG context while this implementation's KEM calls use `prng_get_bytes`; these P2 outputs are not asserted to equal archived KAT bytes.
- Limitations: Finite honest executions do not establish zero failure probability, IND-CCA security or malformed-ciphertext behavior.
