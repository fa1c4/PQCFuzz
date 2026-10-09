---
status: draft
target: kem-16
algorithm: HARE
source_path: third_party/kem-16/source
source_sha256: c83cf0c04fc2df7b98858b1dafb22e1020285803ce78d604de3ffff2a5fcea40
document_path: third_party/kem-16/specification.pdf
document_sha256: a2242e0dbfcfbf101629e49f75f7b12866f7a3186384adb3642da7f95e5122a9
source_version: NGCC Round 1 submitted archive
extract_version: 1
---

# HARE draft claim extraction

This document covers public submitted KAT records only, under the exact
`kem_dec` API. The algorithm construction and correctness context is
at PDF p. 5 (algorithm context). Original PDF and archived source are authoritative.

## HARE128-K — HARE-128 submitted valid-vector consistency

- Source locator: PDF p. 5 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_HARE-128-kr.txt`, SHA-256 `fbb71eee548f838976461c754e4b4d6e3dcb8e22d480ad81f9df00baada38f7f`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `HARE-128` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record decapsulates to its recorded shared secret.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.
