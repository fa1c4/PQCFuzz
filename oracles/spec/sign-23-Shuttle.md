---
status: draft
target: sign-23
algorithm: Shuttle
source_path: third_party/sign-23/source
source_sha256: 2eecc9fd1797f6084634abbd027dacc5a1f2ba29d5abf5cb6bf3b203c2f686d5
document_path: third_party/sign-23/specification.pdf
document_sha256: 881145de9832bc55cc5a27a61fff2a213c625c20c2c1ada60c32825ad8a95893
source_version: NGCC Round 1 submitted archive
extract_version: 1
---

# Shuttle draft claim extraction

This document covers public submitted KAT records only, under the exact
`sig_verify` API. The algorithm construction and correctness context is
at PDF p. 16 (algorithm context). Original PDF and archived source are authoritative.

## SHUTTLE128-K — SHUTTLE-128 submitted valid-vector consistency

- Source locator: PDF p. 16 (algorithm context); `Implementation codes and test vectors/Shuttle 算法实现源代码及测试向量/Test_Vectors/KAT_SIG_SHUTTLE-128.txt`, SHA-256 `2c3a69e9a24315af747bae07309a7c4ad02fd29808461f9198aad29a6e0a60b3`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `SHUTTLE-128` `sig_verify` on the ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record is accepted by verification.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.
