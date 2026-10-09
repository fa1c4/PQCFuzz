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
