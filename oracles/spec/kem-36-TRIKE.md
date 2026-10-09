---
status: draft
target: kem-36
algorithm: TRIKE
source_path: third_party/kem-36/source
source_sha256: ee111e7d665b2f18f6355c6215aba684b0467ad3c50faabb48fa498a96726868
document_path: third_party/kem-36/specification.pdf
document_sha256: 9258ff7264bb3bb78c02da0bf4b915f7087c8711a8ccd67e1d14a1ac2b32b407
source_version: NGCC Round 1 submitted archive
extract_version: 1
---

# TRIKE draft claim extraction

This document covers public submitted KAT records only, under the exact
`kem_dec` API. The algorithm construction and correctness context is
at PDF p. 5 (algorithm context). Original PDF and archived source are authoritative.

## TRIKE2-K — TRIKE-2 submitted valid-vector consistency

- Source locator: PDF p. 5 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/KAT_KEM_TRIKE-2.txt`, SHA-256 `a239ca65bf612d50c01c9c28777861680d98d6a0416b0737685cb6d40bc8d10f`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `TRIKE-2` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record decapsulates to its recorded shared secret.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.
