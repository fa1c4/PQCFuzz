---
status: draft
target: sign-01
algorithm: Aigis-Sig+
source_path: third_party/sign-01/source
source_sha256: 60ef88020ca59d3d4eb29e57ba96787ea25e621fc796d222363456eedbebeef9
document_path: third_party/sign-01/specification.pdf
document_sha256: 6e6d2e07524f2d3bd489ef1e1a0db75cfaf3c9ffb66f048f2e46283e1c3a1781
source_version: NGCC Round 1 submitted archive
extract_version: 1
---

# Aigis-Sig+ draft claim extraction

This document covers public submitted KAT records only, under the exact
`sig_verify` API. The algorithm construction and correctness context is
at PDF p. 11 (algorithm context). Original PDF and archived source are authoritative.

## AIGISSIGI-K — Aigis-Sig+-I submitted valid-vector consistency

- Source locator: PDF p. 11 (algorithm context); `Test_Vectors/KAT_SIG_Aigis-sig1.txt`, SHA-256 `5e29fe8057c7193b86567f9ee8ff20998bccb165648931e0b5a9154487b867ef`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `Aigis-Sig+-I` `sig_verify` on the ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record is accepted by verification.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.

The submitted `SIG_AlgorithmInstance.c` returns `SIG_BYTES` from
`sig_get_sn_len_bytes`; its KAT driver allocates that amount before `sig_sign`
updates `Sn_Len`. The archived first record has `Sn_Len = 2009` while the
getter returns 2015 for this build. The adapter therefore treats the getter
as an allocation upper bound and checks the exact submitted record length
separately. This is an API observation, not a new PDF-level normative claim.
