---
status: draft
target: kem-26
algorithm: NSS-HQC
source_path: third_party/kem-26/source
source_sha256: 9f2ad59844277d847497d956a1025f8eed4011ee15f59a325fb7e9c4fd47f806
document_path: third_party/kem-26/specification.pdf
document_sha256: e993a0ad7b87be444a0a2381c98eb8ffe9fa75d53f34e5141add21a1c5ef2dde
source_version: NGCC Round 1 submitted archive
extract_version: 1
---

# NSS-HQC draft claim extraction

This document covers public submitted KAT records only, under the exact
`kem_dec` API. The algorithm construction and correctness context is
at PDF p. 25 (algorithm context). Original PDF and archived source are authoritative.

## HQC128-K — HQC-128 submitted valid-vector consistency

- Source locator: PDF p. 25 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HQC-128.txt`, SHA-256 `66a0fe8816a982506b0d799c43fcdd18d0434fc54b12fc1e2cc50c0603af8bfc`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `HQC-128` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record decapsulates to its recorded shared secret.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.
