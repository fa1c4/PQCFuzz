---
status: draft
target: sign-10
algorithm: Facto-DSA
source_path: third_party/sign-10/source
source_sha256: 450bad2020675b19d478c4f51d04988359dd414bc827860620ebca595776a82f
document_path: third_party/sign-10/specification.pdf
document_sha256: 0bb0e5a31bfa29dd2d63bfff56051a50e8126abcf9d92665442077664461762b
source_version: NGCC Round 1 submitted archive
extract_version: 1
---

# Facto-DSA draft claim extraction

This document covers public submitted KAT records only, under the exact
`sig_verify` API. The algorithm construction and correctness context is
at PDF p. 6 (algorithm context). Original PDF and archived source are authoritative.

## FACTODSA128-K — Facto-DSA-128 submitted valid-vector consistency

- Source locator: PDF p. 6 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/KAT_SIG_Facto-DSA-128.txt`, SHA-256 `d80c26116d6f0940ad57993af12a4932983bddf052afa07606840db8a73f95a5`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `Facto-DSA-128` `sig_verify` on the ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record is accepted by verification.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.
