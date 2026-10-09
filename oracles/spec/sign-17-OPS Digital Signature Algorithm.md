---
status: draft
target: sign-17
algorithm: OPS Digital Signature Algorithm
source_path: third_party/sign-17/source
source_sha256: 3fe57e1c750c03f843a39740bc596615017cf20b8d06b1ccd08a68c898fc4291
document_path: third_party/sign-17/specification.pdf
document_sha256: 1b5dc50ff728b2698bda90928251bae4e6cac4e138c82359f6f263cb6914078f
source_version: NGCC Round 1 submitted archive
extract_version: 1
---

# OPS Digital Signature Algorithm draft claim extraction

This document covers public submitted KAT records only, under the exact
`sig_verify` API. The algorithm construction and correctness context is
at PDF p. 6 (algorithm context). Original PDF and archived source are authoritative.

## OPSSIG128-K — OPSsig-128 submitted valid-vector consistency

- Source locator: PDF p. 6 (algorithm context); `Implementations and Test_Vectors/Test_Vectors/reference/OPSsig-128/KAT_SIG_OPSsig-128-reference.txt`, SHA-256 `6eb659eb80e779a9ec58498fe14b70c9299e3b626d2d0fab4a0ce144cf466b79`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `OPSsig-128` `sig_verify` on the ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record is accepted by verification.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.
