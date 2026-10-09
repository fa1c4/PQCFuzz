---
status: draft
target: sign-31
algorithm: TSUOV
source_path: third_party/sign-31/source
source_sha256: c970311c547b4ce2436dd4d7f6e3d25da99439299574b30d94bc40fd75bd9c58
document_path: third_party/sign-31/specification.pdf
document_sha256: 17b2cb0d43a3f45c59fe79f2819bb6dcdc988fdc1a9776a40054d27761f5697a
source_version: NGCC Round 1 submitted archive
extract_version: 1
---

# TSUOV draft claim extraction

This document covers public submitted KAT records only, under the exact
`sig_verify` API. The algorithm construction and correctness context is
at PDF p. 4 (algorithm context). Original PDF and archived source are authoritative.

## TSUOV128-K — TSUOV_128 submitted valid-vector consistency

- Source locator: PDF p. 4 (algorithm context); `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Test_Vector/KAT_SIG_TSUOV_128.txt`, SHA-256 `f880573499a298ace2e834a9ea21be65e8aca4e9cd2543d48b273140618cd34c`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `TSUOV_128` `sig_verify` on the ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record is accepted by verification.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.
