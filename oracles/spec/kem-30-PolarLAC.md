---
status: draft
target: kem-30
algorithm: PolarLAC
source_path: third_party/kem-30/source
source_sha256: 9d6d76b5ba96cb24266eef517d2fac3acc64b2f808187529a2210838e9cb6801
document_path: third_party/kem-30/specification.pdf
document_sha256: aba16100f0e5c49d54e1811c672d90c4d837200116e5a312625f8473b6d40eca
source_version: NGCC Round 1 submitted archive
extract_version: 1
---

# PolarLAC draft claim extraction

This document covers public submitted KAT records only, under the exact
`kem_dec` API. The algorithm construction and correctness context is
at PDF p. 15 (algorithm context). Original PDF and archived source are authoritative.

## POLARLAC128-K — POLARLAC-128 submitted valid-vector consistency

- Source locator: PDF p. 15 (algorithm context); `Test_Vectors/Reference_Implementation/x86/KAT_KEM_POLARLAC-128.txt`, SHA-256 `116b4096f8aa55d4f57de32ed3e9d426fde6a9d642c390ef008b38cad6b00447`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `POLARLAC-128` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record decapsulates to its recorded shared secret.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.
