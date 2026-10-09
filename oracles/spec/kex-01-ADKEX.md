---
status: draft
target: kex-01
algorithm: ADKEX
source_path: third_party/kex-01/source
source_sha256: a3062aa4b414eff6f319c661037cdf9331ff8479dfc348130aeb37cbc3c144e7
document_path: third_party/kex-01/specification.pdf
document_sha256: ab64a177d72a862713835b8f14c72fad1dbde6082b514198d9d684e68605344e
source_version: NGCC Round 1 submitted archive
extract_version: 1
---

# ADKEX draft matching-session extraction

The original specification's matching-session correctness relation is at
PDF pp. 32–33 matching-session correctness. This extract covers only final role derivation from exact public
submitted transcripts. It does not test full handshake generation, authentication,
replay resistance or forward secrecy; those require separate source-backed oracles.

## ADKEX128-C — ADKEX-128 final matching-session role agreement

- Source locator: `third_party/kex-01/specification.pdf`, PDF pp. 32–33 matching-session correctness; `Test_Vectors/KAT_KEX_ADKEX-128.txt`, SHA-256 `96faa56746d153206e12f3796bfdc6f24e3721d59f72d93f078a617d2b97df3d`.
- Class: proposed matching-session correctness relation and submitted-vector observation.
- Scope: `ADKEX-128` final `kex_derive_ss_a/b` calls on the ten exact public submitted transcripts, with 2 passes.
- Claim: Both honest matching roles derive the same submitted session key for an exact valid transcript.
- Preconditions: Identical session record index/source hash, exact role keys, final messages and states, successful API calls and output lengths.
- Extraction inference/ambiguity: These vectors are same-lineage controls; matching keys on archived transcripts do not imply authentication or freshness.
- Limitations: Probabilistic protocol correctness and cryptographic AKE security cannot be proven by finite vectors; full handshake paths are outside this slice.

## ADKEX256-C — ADKEX-256 final matching-session role agreement

- Source locator: `third_party/kex-01/specification.pdf`, PDF pp. 32–33 matching-session correctness; `Test_Vectors/KAT_KEX_ADKEX-256.txt`, SHA-256 `f382145642d9e4453d3cef87091fcaee75800e1ff065407cb0daf3d7f402c6cd`.
- Class: proposed matching-session correctness relation and submitted-vector observation.
- Scope: `ADKEX-256` final `kex_derive_ss_a/b` calls on the ten exact public submitted transcripts, with 2 passes.
- Claim: Both honest matching roles derive the same submitted session key for an exact valid transcript.
- Preconditions: Identical session record index/source hash, exact role keys, final messages and states, successful API calls and output lengths.
- Extraction inference/ambiguity: These vectors are same-lineage controls; matching keys on archived transcripts do not imply authentication or freshness.
- Limitations: Probabilistic protocol correctness and cryptographic AKE security cannot be proven by finite vectors; full handshake paths are outside this slice.

## ADKEX512-C — ADKEX-512 final matching-session role agreement

- Source locator: `third_party/kex-01/specification.pdf`, PDF pp. 32–33 matching-session correctness; `Test_Vectors/KAT_KEX_ADKEX-512.txt`, SHA-256 `95eda58014c5d2e9aed00eb61e6e237be90e67b2913f1e3401d1fc3cbceb312a`.
- Class: proposed matching-session correctness relation and submitted-vector observation.
- Scope: `ADKEX-512` final `kex_derive_ss_a/b` calls on the ten exact public submitted transcripts, with 2 passes.
- Claim: Both honest matching roles derive the same submitted session key for an exact valid transcript.
- Preconditions: Identical session record index/source hash, exact role keys, final messages and states, successful API calls and output lengths.
- Extraction inference/ambiguity: These vectors are same-lineage controls; matching keys on archived transcripts do not imply authentication or freshness.
- Limitations: Probabilistic protocol correctness and cryptographic AKE security cannot be proven by finite vectors; full handshake paths are outside this slice.
