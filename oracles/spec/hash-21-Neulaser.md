---
status: draft
target: hash-21
algorithm: Neulaser
source_path: third_party/hash-21/source
source_sha256: d4d56d11e7729f4198f896a436846ae0e28772a3ca78fc5b3c0b96f944b257f1
document_path: third_party/hash-21/specification.pdf
document_sha256: 7f26bdea076d5c2c06469a764118ef6c323ba7844df018810de67a88215610db
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# Neulaser-512 draft claim extraction

The original source and PDF are pinned above. This extract covers only the
`Neulaser-512` submitted `CryptHash` API. The cited construction and parameter
discussion is on PDF p. 5; the exact source and PDF files are authoritative.

## S1 — Same-instance deterministic digest agreement

- Source locator: `third_party/hash-21/specification.pdf`, PDF p. 5; submitted `Neulaser/Implementations and Test_Vectors/API_CryptHash/Implementations/Reference_Implementation/Neulaser-512/CryptHash_AlgorithmInstance.h` and the corresponding optimized implementation listed in `data/build_sources.json`.
- Class: submitted construction/API identity; backend agreement is an extraction inference.
- Scope: `Neulaser-512`, 512-bit digest, `CryptHash`, canonical public bitstrings, reference and optimized submitted paths in this pinned source tree.
- Claim: For the same valid bitstring and 512-bit output profile, both submitted implementations of this named hash instance should return the same digest.
- Preconditions: Identical message bytes and exact bit length, both calls succeed, same source snapshot and fixed instance.
- Extraction inference/ambiguity: The PDF defines the named hash construction; equality across software paths follows from their shared instance identity, not an explicit PDF statement about backends. This is draft until human review.
- Limitations: Shared code may hide common errors; agreement proves neither independent conformance nor collision/preimage security. A mismatch does not identify the faulty path.

## S2 — Submitted KAT consistency

- Source locator: `Neulaser/Implementations and Test_Vectors/API_CryptHash/Test_Vector/KAT_2_12_Neulaser-512.txt`, SHA-256 `e83329d96202be38c3b26f35396b13579169988e042ba5613cc734b64f73abf4`, fields `Msg_Len`, `Msg`, `Dst_Len`, `Dst`.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact pinned 512-bit KAT records and the two submitted `Neulaser-512` `CryptHash` paths.
- Claim: The exact recorded message and bit length should reproduce its corresponding submitted digest on each backend.
- Preconditions: Exact record index, bytes, bit length, output length and KAT-file digest are bound in the case.
- Extraction inference/ambiguity: Vector provenance is the archive itself; the vector generator may share implementation lineage.
- Limitations: A mismatch is candidate consistency evidence requiring review. Finite KAT sampling proves no computational security property.

## NEULASER1024-K — Neulaser-1024 submitted CryptHash known-answer relation

- Source locator: PDF p. 5; `Neulaser/Implementations and Test_Vectors/API_CryptHash/Implementations/Reference_Implementation/Neulaser-1024/CryptHash_AlgorithmInstance.h` SHA-256 `7650b1fe33b1e6dcf58ee84afc02e7b1cae2ad8393e5d83f6b9e805b17d19e95`; `Neulaser/Implementations and Test_Vectors/API_CryptHash/Test_Vector/KAT_2_12_Neulaser-1024.txt` SHA-256 `0059202e68c267fc76ec6ffff4c607ef2b02a2d757fb0934960d01acab75ab89`.
- Class: submitted vector observation with PDF algorithm context; vectors are not independent normative truth.
- Scope: `Neulaser-1024` reference `CryptHash` at exactly 1024 output bits, with eighteen pinned public KAT records.
- Claim: Each recorded input bitstring yields its own submitted digest through the selected public API.
- Preconditions: Exact source/KAT digests, requested output length, canonical message storage, successful public call and intact output guard.
- Extraction inference/ambiguity: KAT generator and reference implementation may share code lineage.
- Limitations: Candidate-only; no claim about collision/preimage security or other backends.

## NEULASER768-K — Neulaser-768 submitted CryptHash known-answer relation

- Source locator: PDF p. 5; `Neulaser/Implementations and Test_Vectors/API_CryptHash/Implementations/Reference_Implementation/Neulaser-768/CryptHash_AlgorithmInstance.h` SHA-256 `e3c9b136eff6e07b3ca83d6bc451e77cefa327509419ab116c4c0f824c9ba13e`; `Neulaser/Implementations and Test_Vectors/API_CryptHash/Test_Vector/KAT_2_12_Neulaser-768.txt` SHA-256 `46b89e05bfc95dc5ce8bacbb8e8b366aea921d46970614e9af0dc891b0eec4f6`.
- Class: submitted vector observation with PDF algorithm context; vectors are not independent normative truth.
- Scope: `Neulaser-768` reference `CryptHash` at exactly 768 output bits, with eighteen pinned public KAT records.
- Claim: Each recorded input bitstring yields its own submitted digest through the selected public API.
- Preconditions: Exact source/KAT digests, requested output length, canonical message storage, successful public call and intact output guard.
- Extraction inference/ambiguity: KAT generator and reference implementation may share code lineage.
- Limitations: Candidate-only; no claim about collision/preimage security or other backends.
