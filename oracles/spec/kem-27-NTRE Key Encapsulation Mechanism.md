---
status: draft
target: kem-27
algorithm: NTRE Key Encapsulation Mechanism
source_path: third_party/kem-27/source
source_sha256: a4084c8a7b95556fb35b7052c4ad4b43191b0ffcbb7b8d5d862133d932df886b
document_path: third_party/kem-27/specification.pdf
document_sha256: af7a09a5633b494a67347bf518babf1f03ed90786e7d075a25869edd575a0003
source_version: NGCC Round 1 submitted archive
extract_version: 1
---

# NTRE Key Encapsulation Mechanism draft claim extraction

This document covers public submitted KAT records only, under the exact
`kem_dec` API. The algorithm construction and correctness context is
at PDF p. 18 (algorithm context). Original PDF and archived source are authoritative.

## NTRE128-K — NTRE-128 submitted valid-vector consistency

- Source locator: PDF p. 18 (algorithm context); `Implementations/Reference_Implementation/NTRE-128/output/KAT_KEM_NTRE-128.txt`, SHA-256 `65cab746a920cf829732bdb6e2c9f2a9caf198d3fa676a48c85f03f897a87af7`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `NTRE-128` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record decapsulates to its recorded shared secret.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.
