---
status: draft
target: hash-22
algorithm: Pavelor
source_path: third_party/hash-22/source
source_sha256: e273037bc8cbed81bd9812982c94c00f5c0ff8bc32b31f5d16fc433ec7dce2ef
document_path: third_party/hash-22/specification.pdf
document_sha256: 08c532b9241dd85ab4b5d5b8c4b020a5baf412738457431c895e17f0434abcb0
source_version: NGCC Round 1 submitted archive
extract_version: 1
---

# Pavelor draft claim extraction

The original PDF pp. 5–8 §1.2, Algorithms 1–4 defines the three fixed-output
Pavelor instances, their rate/capacity choices, padding and digest generation.
Only the submitted `CryptHash` interface is in scope here. The PDF's collision
and preimage complexity claims are outside finite SOP conformance testing.

## PAVELOR512-D — Pavelor-512 submitted backend agreement

- Source locator: `third_party/hash-22/specification.pdf`, PDF pp. 5–8 §1.2, Algorithms 1–4; submitted `Pavelor-512` reference and optimized `CryptHash_AlgorithmInstance.h` paths.
- Class: deterministic construction and submitted API identity; backend equality is an extraction inference, not a PDF statement about software.
- Scope: exact `Pavelor-512` fixed-output `CryptHash` call with canonical message bitstring, successful calls and identical output length.
- Claim: Both submitted paths for one named instance should produce equal `512`-bit digests for the same input.
- Preconditions: Identical message bytes/bit length, exact output length, compatible profiles and pinned source.
- Extraction inference/ambiguity: Backend equality follows from common deterministic instance identity, not a PDF software statement.
- Limitations: Shared lineage can hide defects; difference alone does not identify which path is faulty. Finite comparisons do not prove computational security.

## PAVELOR512-K — Pavelor-512 submitted KAT consistency

- Source locator: `Pavelor/Implementations and Test_Vectors/API_CryptHash/Test_Vector/KAT_2_12_Pavelor-512.txt`, SHA-256 `53efe99d570575ebe6626fa0ca4bf7ee9f1c0af168b9816fab094886fa6fe949`, fields `Msg_Len`, `Msg`, `Dst_Len`, `Dst`.
- Class: submitted vector observation, not independent normative truth.
- Scope: exact indexed rows and `Pavelor-512` `CryptHash` backends.
- Claim: Each recorded input reproduces its own submitted `512`-bit digest.
- Preconditions: Exact bytes, bit length, output length, record index, KAT hash and source version.
- Extraction inference/ambiguity: Vector generation may share implementation lineage.
- Limitations: Mismatch remains candidate-only and finite samples prove no security property.

## PAVELOR768-D — Pavelor-768 submitted backend agreement

- Source locator: `third_party/hash-22/specification.pdf`, PDF pp. 5–8 §1.2, Algorithms 1–4; submitted `Pavelor-768` reference and optimized `CryptHash_AlgorithmInstance.h` paths.
- Class: deterministic construction and submitted API identity; backend equality is an extraction inference, not a PDF statement about software.
- Scope: exact `Pavelor-768` fixed-output `CryptHash` call with canonical message bitstring, successful calls and identical output length.
- Claim: Both submitted paths for one named instance should produce equal `768`-bit digests for the same input.
- Preconditions: Identical message bytes/bit length, exact output length, compatible profiles and pinned source.
- Extraction inference/ambiguity: Backend equality follows from common deterministic instance identity, not a PDF software statement.
- Limitations: Shared lineage can hide defects; difference alone does not identify which path is faulty. Finite comparisons do not prove computational security.

## PAVELOR768-K — Pavelor-768 submitted KAT consistency

- Source locator: `Pavelor/Implementations and Test_Vectors/API_CryptHash/Test_Vector/KAT_2_12_Pavelor-768.txt`, SHA-256 `3f7aec5fc63f96ff51394887c6379959b5cd5a63b7c970011d015065be2b2859`, fields `Msg_Len`, `Msg`, `Dst_Len`, `Dst`.
- Class: submitted vector observation, not independent normative truth.
- Scope: exact indexed rows and `Pavelor-768` `CryptHash` backends.
- Claim: Each recorded input reproduces its own submitted `768`-bit digest.
- Preconditions: Exact bytes, bit length, output length, record index, KAT hash and source version.
- Extraction inference/ambiguity: Vector generation may share implementation lineage.
- Limitations: Mismatch remains candidate-only and finite samples prove no security property.

## PAVELOR1024-D — Pavelor-1024 submitted backend agreement

- Source locator: `third_party/hash-22/specification.pdf`, PDF pp. 5–8 §1.2, Algorithms 1–4; submitted `Pavelor-1024` reference and optimized `CryptHash_AlgorithmInstance.h` paths.
- Class: deterministic construction and submitted API identity; backend equality is an extraction inference, not a PDF statement about software.
- Scope: exact `Pavelor-1024` fixed-output `CryptHash` call with canonical message bitstring, successful calls and identical output length.
- Claim: Both submitted paths for one named instance should produce equal `1024`-bit digests for the same input.
- Preconditions: Identical message bytes/bit length, exact output length, compatible profiles and pinned source.
- Extraction inference/ambiguity: Backend equality follows from common deterministic instance identity, not a PDF software statement.
- Limitations: Shared lineage can hide defects; difference alone does not identify which path is faulty. Finite comparisons do not prove computational security.

## PAVELOR1024-K — Pavelor-1024 submitted KAT consistency

- Source locator: `Pavelor/Implementations and Test_Vectors/API_CryptHash/Test_Vector/KAT_2_12_Pavelor-1024.txt`, SHA-256 `c8d1909e7b7388896a17cf8a3391dc0e929b5d45752702a87e5a799f03a9c266`, fields `Msg_Len`, `Msg`, `Dst_Len`, `Dst`.
- Class: submitted vector observation, not independent normative truth.
- Scope: exact indexed rows and `Pavelor-1024` `CryptHash` backends.
- Claim: Each recorded input reproduces its own submitted `1024`-bit digest.
- Preconditions: Exact bytes, bit length, output length, record index, KAT hash and source version.
- Extraction inference/ambiguity: Vector generation may share implementation lineage.
- Limitations: Mismatch remains candidate-only and finite samples prove no security property.
