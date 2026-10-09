---
status: draft
target: kem-02
algorithm: Amoeba
source_path: third_party/kem-02/source
source_sha256: 51d29d04a85e9b4dd0c34b4b69c49ba7b51dcfe5e2f83b84b2f41a0007b5476e
document_path: third_party/kem-02/specification.pdf
document_sha256: ffca61c5470298f3a173b76a8ead43299a04d990b0bbb913397f910285d4d247
source_version: NGCC Round 1 submitted archive
extract_version: 1
---

# Amoeba draft claim extraction

This document covers public submitted KAT records only, under the exact
`kem_dec` API. The algorithm construction and correctness context is
at PDF p. 9 (algorithm context). Original PDF and archived source are authoritative.

## AMOEBA576-K — Amoeba-576 submitted valid-vector consistency

- Source locator: PDF p. 9 (algorithm context); `Test_Vectors/KAT_KEM_Amoeba128.txt`, SHA-256 `b1960b65ca0d4b7cc3f0f5f568a70de405da2f3b48a6e33c813697ec1a319dd6`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `Amoeba-576` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record decapsulates to its recorded shared secret.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.
