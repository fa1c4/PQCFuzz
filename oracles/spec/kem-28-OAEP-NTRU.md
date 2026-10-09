---
status: draft
target: kem-28
algorithm: OAEP-NTRU
source_path: third_party/kem-28/source
source_sha256: 545aedbcde743760adb7522a5e8eeca1d40ed4b35c98a713d251831285b92bbd
document_path: third_party/kem-28/specification.pdf
document_sha256: cde9de6e14fad324e5133b196a40e00ef394806d06e4101da42de79f8f0689b6
source_version: NGCC Round 1 submitted archive
extract_version: 1
---

# OAEP-NTRU draft claim extraction

This document covers public submitted KAT records only, under the exact
`kem_dec` API. The algorithm construction and correctness context is
at PDF p. 6 (algorithm context). Original PDF and archived source are authoritative.

## OAEPNTRU648-K — OAEP-NTRU-648 submitted valid-vector consistency

- Source locator: PDF p. 6 (algorithm context); `Test_Vectors/KAT_KEM_OAEP-NTRU-648.txt`, SHA-256 `b4733e7c232600120eafc607e2aa04402111d8e9cc9279965ed5cf429321740d`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `OAEP-NTRU-648` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record decapsulates to its recorded shared secret.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.
