---
status: draft
target: kem-19
algorithm: Lore
source_path: third_party/kem-19/source
source_sha256: 565433f6d9d78a50d894453bf0f8bc04d26148cbcc247614ae3f52960ab7563e
document_path: third_party/kem-19/specification.pdf
document_sha256: 185adb545b785ef6805a64aa9c70e1e68aca4dd705aebc8e11c3c302987e0b48
source_version: NGCC Round 1 submitted archive
extract_version: 1
---

# Lore draft claim extraction

This document covers public submitted KAT records only, under the exact
`kem_dec` API. The algorithm construction and correctness context is
at PDF p. 11 (algorithm context). Original PDF and archived source are authoritative.

## LOREL1-K — Lore-L1 submitted valid-vector consistency

- Source locator: PDF p. 11 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/Lore-SHAKE/KAT_KEM_Lore-L1.txt`, SHA-256 `993e5a7f3bfc16662ace49b2b306f81473fd777173f6de4e54f31e9ef71df432`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `Lore-L1` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record decapsulates to its recorded shared secret.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.
