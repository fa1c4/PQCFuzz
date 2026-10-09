---
status: draft
target: kem-15
algorithm: FLIT
source_path: third_party/kem-15/source
source_sha256: 9afc9032807ce52433d0b4fe80cfe8bd33d5a07184b6c7447728065996b58ccc
document_path: third_party/kem-15/specification.pdf
document_sha256: 47e1fee04a6e766174245f656ca49ea6b566aacbe2bd7f16daf1942f0400b13b
source_version: NGCC Round 1 submitted archive
extract_version: 1
---

# FLIT draft claim extraction

This document covers public submitted KAT records only, under the exact
`kem_dec` API. The algorithm construction and correctness context is
at PDF p. 10 (algorithm context). Original PDF and archived source are authoritative.

## FLIT128-K — FLIT128 submitted valid-vector consistency

- Source locator: PDF p. 10 (algorithm context); `Test_Vectors/KAT_KEM_FLIT128_REF.txt`, SHA-256 `a772deebcc67af946d60d9ebab8014318879617de619692bd59650196b578e69`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `FLIT128` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record decapsulates to its recorded shared secret.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.
