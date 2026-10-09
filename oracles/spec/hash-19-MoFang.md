---
status: draft
target: hash-19
algorithm: MoFang
source_path: third_party/hash-19/source
source_sha256: 76323d30f5f0859bea6f917567f2d05393f6575257158d5c2cc42844c366ec19
document_path: third_party/hash-19/specification.pdf
document_sha256: 3be6697d885dcb3ec93999c8dfae2c78a15abf6ac0bfe5e89b08de5eab6ff81c
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# MoFang_512 draft claim extraction

The original source and PDF are pinned above. This extract covers only the
`MoFang_512` submitted `CryptHash` API. The cited construction and parameter
discussion is on PDF pp. 4–5; the exact source and PDF files are authoritative.

## S1 — Same-instance deterministic digest agreement

- Source locator: `third_party/hash-19/specification.pdf`, PDF pp. 4–5; submitted `MoFang/Implementations/Reference_Implementation/MoFang-512/CryptHash_AlgorithmInstance.h` and the corresponding optimized implementation listed in `data/build_sources.json`.
- Class: submitted construction/API identity; backend agreement is an extraction inference.
- Scope: `MoFang_512`, 512-bit digest, `CryptHash`, canonical public bitstrings, reference and optimized submitted paths in this pinned source tree.
- Claim: For the same valid bitstring and 512-bit output profile, both submitted implementations of this named hash instance should return the same digest.
- Preconditions: Identical message bytes and exact bit length, both calls succeed, same source snapshot and fixed instance.
- Extraction inference/ambiguity: The PDF defines the named hash construction; equality across software paths follows from their shared instance identity, not an explicit PDF statement about backends. This is draft until human review.
- Limitations: Shared code may hide common errors; agreement proves neither independent conformance nor collision/preimage security. A mismatch does not identify the faulty path.

## S2 — Submitted KAT consistency

- Source locator: `MoFang/Test_Vectors/Test_Vector/KAT_2_12_MoFang_512.txt`, SHA-256 `095b80ebe7a6642e82cf437a5e0f8da7a0e2dfc2c80d0ca57bbc861c8cf26c8e`, fields `Msg_Len`, `Msg`, `Dst_Len`, `Dst`.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact pinned 512-bit KAT records and the two submitted `MoFang_512` `CryptHash` paths.
- Claim: The exact recorded message and bit length should reproduce its corresponding submitted digest on each backend.
- Preconditions: Exact record index, bytes, bit length, output length and KAT-file digest are bound in the case.
- Extraction inference/ambiguity: Vector provenance is the archive itself; the vector generator may share implementation lineage.
- Limitations: A mismatch is candidate consistency evidence requiring review. Finite KAT sampling proves no computational security property.
