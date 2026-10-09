---
status: draft
target: kex-04
algorithm: DKEX
source_path: third_party/kex-04/source
source_sha256: cd43c760f309c9f4f2eb9dec6034d784edc0d84c9e48e697003754b207f2b70d
document_path: third_party/kex-04/specification.pdf
document_sha256: 3de5d1db42cfb2af59e317729489b9f5a117763fca84fcaab51538ffd53a6de5
source_version: NGCC Round 1 submitted archive
extract_version: 1
---

# DKEX draft matching-session extraction

The original specification's matching-session correctness relation is at
PDF pp. 27–28 matching-session correctness. This extract covers only final role derivation from exact public
submitted transcripts. It does not test full handshake generation, authentication,
replay resistance or forward secrecy; those require separate source-backed oracles.

## DKEX128-C — DKEX-128 final matching-session role agreement

- Source locator: `third_party/kex-04/specification.pdf`, PDF pp. 27–28 matching-session correctness; `Test_Vectors/KAT_KEX_DKEX-128.txt`, SHA-256 `298ccd2e7805c743b0cd633a226239ffe64e136bea828c8e9e10a7385c1f38a5`.
- Class: proposed matching-session correctness relation and submitted-vector observation.
- Scope: `DKEX-128` final `kex_derive_ss_a/b` calls on the ten exact public submitted transcripts, with 3 passes.
- Claim: Both honest matching roles derive the same submitted session key for an exact valid transcript.
- Preconditions: Identical session record index/source hash, exact role keys, final messages and states, successful API calls and output lengths.
- Extraction inference/ambiguity: These vectors are same-lineage controls; matching keys on archived transcripts do not imply authentication or freshness.
- Limitations: Probabilistic protocol correctness and cryptographic AKE security cannot be proven by finite vectors; full handshake paths are outside this slice.

## DKEX256-C — DKEX-256 final matching-session role agreement

- Source locator: `third_party/kex-04/specification.pdf`, PDF pp. 27–28 matching-session correctness; `Test_Vectors/KAT_KEX_DKEX-256.txt`, SHA-256 `1a87393635e9e0954fb174742ac4229923d3df0c8f692689e0f03de77fe9e2d3`.
- Class: proposed matching-session correctness relation and submitted-vector observation.
- Scope: `DKEX-256` final `kex_derive_ss_a/b` calls on the ten exact public submitted transcripts, with 3 passes.
- Claim: Both honest matching roles derive the same submitted session key for an exact valid transcript.
- Preconditions: Identical session record index/source hash, exact role keys, final messages and states, successful API calls and output lengths.
- Extraction inference/ambiguity: These vectors are same-lineage controls; matching keys on archived transcripts do not imply authentication or freshness.
- Limitations: Probabilistic protocol correctness and cryptographic AKE security cannot be proven by finite vectors; full handshake paths are outside this slice.

## DKEX512-C — DKEX-512 final matching-session role agreement

- Source locator: `third_party/kex-04/specification.pdf`, PDF pp. 27–28 matching-session correctness; `Test_Vectors/KAT_KEX_DKEX-512.txt`, SHA-256 `01037a2ad50d94fe93f0fa7367b14fca08ceeb1f7bccdab4b2590d756148526d`.
- Class: proposed matching-session correctness relation and submitted-vector observation.
- Scope: `DKEX-512` final `kex_derive_ss_a/b` calls on the ten exact public submitted transcripts, with 3 passes.
- Claim: Both honest matching roles derive the same submitted session key for an exact valid transcript.
- Preconditions: Identical session record index/source hash, exact role keys, final messages and states, successful API calls and output lengths.
- Extraction inference/ambiguity: These vectors are same-lineage controls; matching keys on archived transcripts do not imply authentication or freshness.
- Limitations: Probabilistic protocol correctness and cryptographic AKE security cannot be proven by finite vectors; full handshake paths are outside this slice.
