---
status: draft
target: kem-01
algorithm: Aigis-Enc+
source_path: third_party/kem-01/source
source_sha256: fab1491992307c011506625c7f4e9dfb45a98a01c41a4504ee8ab1ae7926fa22
document_path: third_party/kem-01/specification.pdf
document_sha256: 27e4b81bedaffa1a57cc2e2fe9518f3ddefcbdaa6a883463caf8a88196c43ceb
source_version: NGCC Round 1 submitted archive
extract_version: 1
---

# Aigis-Enc+ draft claim extraction

This document covers public submitted KAT records only, under the exact
`kem_dec` API. The algorithm construction and correctness context is
at PDF p. 8 (algorithm context). Original PDF and archived source are authoritative.

## AIGISENCI-K — Aigis-Enc+-I submitted valid-vector consistency

- Source locator: PDF p. 8 (algorithm context); `Test_Vectors/KAT_KEM_Aigis-enc1.txt`, SHA-256 `e15e2b2ad808be3c13a43897971117ea4d2b616aba1f7caa16cd76b844db45fb`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `Aigis-Enc+-I` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record decapsulates to its recorded shared secret.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.
