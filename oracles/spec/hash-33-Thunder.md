---
status: draft
target: hash-33
algorithm: Thunder
source_path: third_party/hash-33/source
source_sha256: 1487f10a48121b250d6320d0c4b7e8628e1d8e716b33fcc0f93ece5ce379ed89
document_path: third_party/hash-33/specification.pdf
document_sha256: f6fafe152124757787f54db3869bb7ef7d8106e8a7293ee341d511ec279e7d36
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# Thunder-512 draft claim extraction

The original source and PDF are pinned above. This extract covers only the
`Thunder-512` submitted `CryptHash` API. The cited construction and parameter
discussion is on PDF pp. 7–8; the exact source and PDF files are authoritative.

## S1 — Same-instance deterministic digest agreement

- Source locator: `third_party/hash-33/specification.pdf`, PDF pp. 7–8; submitted `Thunder/Implementations and Test_vector/Thunder-X86/Implementations/Reference_Implementation/Thunder-512/CryptHash_AlgorithmInstance.h` and the corresponding optimized implementation listed in `data/build_sources.json`.
- Class: submitted construction/API identity; backend agreement is an extraction inference.
- Scope: `Thunder-512`, 512-bit digest, `CryptHash`, canonical public bitstrings, reference and optimized submitted paths in this pinned source tree.
- Claim: For the same valid bitstring and 512-bit output profile, both submitted implementations of this named hash instance should return the same digest.
- Preconditions: Identical message bytes and exact bit length, both calls succeed, same source snapshot and fixed instance.
- Extraction inference/ambiguity: The PDF defines the named hash construction; equality across software paths follows from their shared instance identity, not an explicit PDF statement about backends. This is draft until human review.
- Limitations: Shared code may hide common errors; agreement proves neither independent conformance nor collision/preimage security. A mismatch does not identify the faulty path.

## S2 — Submitted KAT consistency

- Source locator: `Thunder/Implementations and Test_vector/Thunder-ARM/Test_Vector/KAT_2_12_Thunder-512.txt`, SHA-256 `51aa1cdcbd48991d708298ee3e25b857d8d5e74635ae200ae54f6f42e08a1751`, fields `Msg_Len`, `Msg`, `Dst_Len`, `Dst`.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact pinned 512-bit KAT records and the two submitted `Thunder-512` `CryptHash` paths.
- Claim: The exact recorded message and bit length should reproduce its corresponding submitted digest on each backend.
- Preconditions: Exact record index, bytes, bit length, output length and KAT-file digest are bound in the case.
- Extraction inference/ambiguity: Vector provenance is the archive itself; the vector generator may share implementation lineage.
- Limitations: A mismatch is candidate consistency evidence requiring review. Finite KAT sampling proves no computational security property.

## THUNDER1024-K — Thunder-1024 submitted CryptHash known-answer relation

- Source locator: PDF pp. 7–8; `Thunder/Implementations and Test_vector/Thunder-ARM/Implementations/Reference_Implementation/Thunder-1024/CryptHash_AlgorithmInstance.h` SHA-256 `6492838db1d4e1520325c1a642712f9479d0015c31ccfae2684a63a4b79facad`; `Thunder/Implementations and Test_vector/Thunder-ARM/Test_Vector/KAT_2_12_Thunder-1024.txt` SHA-256 `c7a6875584c99d98e9bbc591a6844945020ce2304b325215da4925b53b2fb6cf`.
- Class: submitted vector observation with PDF algorithm context; vectors are not independent normative truth.
- Scope: `Thunder-1024` reference `CryptHash` at exactly 1024 output bits, with eighteen pinned public KAT records.
- Claim: Each recorded input bitstring yields its own submitted digest through the selected public API.
- Preconditions: Exact source/KAT digests, requested output length, canonical message storage, successful public call and intact output guard.
- Extraction inference/ambiguity: KAT generator and reference implementation may share code lineage.
- Limitations: Candidate-only; no claim about collision/preimage security or other backends.

## THUNDER768-K — Thunder-768 submitted CryptHash known-answer relation

- Source locator: PDF pp. 7–8; `Thunder/Implementations and Test_vector/Thunder-ARM/Implementations/Reference_Implementation/Thunder-768/CryptHash_AlgorithmInstance.h` SHA-256 `766e1c51851d289d0b0f595fb7002d68c7770a942bb68f95f9b7da7b7588f62f`; `Thunder/Implementations and Test_vector/Thunder-ARM/Test_Vector/KAT_2_12_Thunder-768.txt` SHA-256 `815e70e81ce3820a5429e6e73e6e82ce6eefe6040170994f48acb9c5a80ddc9d`.
- Class: submitted vector observation with PDF algorithm context; vectors are not independent normative truth.
- Scope: `Thunder-768` reference `CryptHash` at exactly 768 output bits, with eighteen pinned public KAT records.
- Claim: Each recorded input bitstring yields its own submitted digest through the selected public API.
- Preconditions: Exact source/KAT digests, requested output length, canonical message storage, successful public call and intact output guard.
- Extraction inference/ambiguity: KAT generator and reference implementation may share code lineage.
- Limitations: Candidate-only; no claim about collision/preimage security or other backends.

## THUNDERXOF256-K — Thunder-XOF-256 submitted CryptHash known-answer relation

- Source locator: PDF pp. 7–8; `Thunder/Implementations and Test_vector/Thunder-ARM/Implementations/Reference_Implementation/Thunder-XOF-256/CryptHash_AlgorithmInstance.h` SHA-256 `c1b93ca286c43902f92849bbf6e31446884c074be443944832f8b85788c234bd`; `Thunder/Implementations and Test_vector/Thunder-ARM/Test_Vector/KAT_2_12_Thunder-XOF-256.txt` SHA-256 `bf800da64fb07f77b508784bcbe6a0ea6513688ab7930d12f2925a12ade7e512`.
- Class: submitted vector observation with PDF algorithm context; vectors are not independent normative truth.
- Scope: `Thunder-XOF-256` reference `CryptHash` at exactly 1280 output bits, with eighteen pinned public KAT records.
- Claim: Each recorded input bitstring yields its own submitted digest through the selected public API.
- Preconditions: Exact source/KAT digests, requested output length, canonical message storage, successful public call and intact output guard.
- Extraction inference/ambiguity: KAT generator and reference implementation may share code lineage.
- Limitations: Candidate-only; no claim about collision/preimage security or other backends.

## THUNDERXOF384-K — Thunder-XOF-384 submitted CryptHash known-answer relation

- Source locator: PDF pp. 7–8; `Thunder/Implementations and Test_vector/Thunder-ARM/Implementations/Reference_Implementation/Thunder-XOF-384/CryptHash_AlgorithmInstance.h` SHA-256 `2eb6a22d73cb05e27237b53701d53fb66d8d4f0f13599e952cd281d9a6bff301`; `Thunder/Implementations and Test_vector/Thunder-ARM/Test_Vector/KAT_2_12_Thunder-XOF-384.txt` SHA-256 `07c3a5ad56c2c1e52259d1f78c68d867910c77b435c00bb0be3473ff89b9dc85`.
- Class: submitted vector observation with PDF algorithm context; vectors are not independent normative truth.
- Scope: `Thunder-XOF-384` reference `CryptHash` at exactly 1152 output bits, with eighteen pinned public KAT records.
- Claim: Each recorded input bitstring yields its own submitted digest through the selected public API.
- Preconditions: Exact source/KAT digests, requested output length, canonical message storage, successful public call and intact output guard.
- Extraction inference/ambiguity: KAT generator and reference implementation may share code lineage.
- Limitations: Candidate-only; no claim about collision/preimage security or other backends.

## THUNDERXOF512-K — Thunder-XOF-512 submitted CryptHash known-answer relation

- Source locator: PDF pp. 7–8; `Thunder/Implementations and Test_vector/Thunder-ARM/Implementations/Reference_Implementation/Thunder-XOF-512/CryptHash_AlgorithmInstance.h` SHA-256 `bf3a197f010de106a7e324d23b71dcf41400b03830ba66ca405ee722e03028f3`; `Thunder/Implementations and Test_vector/Thunder-ARM/Test_Vector/KAT_2_12_Thunder-XOF-512.txt` SHA-256 `9a86aa91faf0a622b456a0968f821c68661d59fe39a83289f23ea963b7f3ca20`.
- Class: submitted vector observation with PDF algorithm context; vectors are not independent normative truth.
- Scope: `Thunder-XOF-512` reference `CryptHash` at exactly 1024 output bits, with eighteen pinned public KAT records.
- Claim: Each recorded input bitstring yields its own submitted digest through the selected public API.
- Preconditions: Exact source/KAT digests, requested output length, canonical message storage, successful public call and intact output guard.
- Extraction inference/ambiguity: KAT generator and reference implementation may share code lineage.
- Limitations: Candidate-only; no claim about collision/preimage security or other backends.
