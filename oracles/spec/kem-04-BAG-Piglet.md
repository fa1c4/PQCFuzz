---
status: draft
target: kem-04
algorithm: BAG-Piglet
source_path: third_party/kem-04/source
source_sha256: c4a4949a092b6da97f15dc65b05fc72005b8234059510108adaad3198c951ec0
document_path: third_party/kem-04/specification.pdf
document_sha256: f38c754a6609d5f23024452b505fd85b8a6c05eb2932a42c17b19a98f17b00d6
source_version: NGCC Round 1 submitted archive
extract_version: 1
---

# BAG-Piglet draft claim extraction

This document covers public submitted KAT records only, under the exact
`kem_dec` API. The algorithm construction and correctness context is
at PDF p. 7 (algorithm context). Original PDF and archived source are authoritative.

## BAGPIGLET128-K — bag_piglet128 submitted valid-vector consistency

- Source locator: PDF p. 7 (algorithm context); `Test_Vectors/KAT_KEM_bag_piglet_128.txt`, SHA-256 `f3c715a2a06d6a7b467fcccd766c47a7de08fa11cac1a61f1642a7cbe4fb5ece`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `bag_piglet128` `kem_dec` on ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record decapsulates to its recorded shared secret.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.
