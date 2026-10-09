---
status: draft
target: kem-29
algorithm: Polar-KEM
source_path: third_party/kem-29/source
source_sha256: 077191d44b3a7d68df44015cd668e514e9c82389f00f9883f0d8db11c9df5aa9
document_path: third_party/kem-29/specification.pdf
document_sha256: 7234eb7b8e71a38a97d0f6f637aa3e72d6363faad6affde77d574124b8ba6e78
source_version: NGCC Round 1 submitted archive
extract_version: 1
---

# Polar-KEM draft claim extraction

This document covers public submitted KAT records only, under the exact
`kem_dec` API. The algorithm construction and correctness context is
at PDF p. 11 (algorithm context). Original PDF and archived source are authoritative.

## POLARKEM128-K — PolarKEM-128 submitted valid-vector consistency

- Source locator: PDF p. 11 (algorithm context); `Submission_Package/Test_Vectors/KAT_KEM_PolarKEM-128.txt`, SHA-256 `00515e6bfc08e039fa170ba5b099ae7d11f3e287c1f8993f67a9e11eba52954b`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `PolarKEM-128` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record decapsulates to its recorded shared secret.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.
