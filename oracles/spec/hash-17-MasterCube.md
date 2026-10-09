---
status: draft
target: hash-17
algorithm: MasterCube
source_path: third_party/hash-17/source
source_sha256: 0198b80f2c280ae85223f6b60a617f39b7a9a40a5dd195bbd39eeb82a15634ea
document_path: third_party/hash-17/specification.pdf
document_sha256: cc5b51b21af90a1331f83ebc03ac1a0452c60dd5f7e5661b84266beb7c9c21e9
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# MasterCube-512 draft claim extraction

The original source and PDF are pinned above. This extract covers only the
`MasterCube-512` submitted `CryptHash` API. The cited construction and parameter
discussion is on PDF pp. 4, 10; the exact source and PDF files are authoritative.

## S1 — Same-instance deterministic digest agreement

- Source locator: `third_party/hash-17/specification.pdf`, PDF pp. 4, 10; submitted `MasterCube/Implementations/Reference_Implementation/MasterCube-512/CryptHash_AlgorithmInstance.h` and the corresponding optimized implementation listed in `data/build_sources.json`.
- Class: submitted construction/API identity; backend agreement is an extraction inference.
- Scope: `MasterCube-512`, 512-bit digest, `CryptHash`, canonical public bitstrings, reference and optimized submitted paths in this pinned source tree.
- Claim: For the same valid bitstring and 512-bit output profile, both submitted implementations of this named hash instance should return the same digest.
- Preconditions: Identical message bytes and exact bit length, both calls succeed, same source snapshot and fixed instance.
- Extraction inference/ambiguity: The PDF defines the named hash construction; equality across software paths follows from their shared instance identity, not an explicit PDF statement about backends. This is draft until human review.
- Limitations: Shared code may hide common errors; agreement proves neither independent conformance nor collision/preimage security. A mismatch does not identify the faulty path.

## S2 — Submitted KAT consistency

- Source locator: `MasterCube/Test_Vectors/KAT_2_12_MasterCube-512.txt`, SHA-256 `11d97ca2107e2221d4bbb10a84f480561b77074311979106508b3a3b0cfe4623`, fields `Msg_Len`, `Msg`, `Dst_Len`, `Dst`.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact pinned 512-bit KAT records and the two submitted `MasterCube-512` `CryptHash` paths.
- Claim: The exact recorded message and bit length should reproduce its corresponding submitted digest on each backend.
- Preconditions: Exact record index, bytes, bit length, output length and KAT-file digest are bound in the case.
- Extraction inference/ambiguity: Vector provenance is the archive itself; the vector generator may share implementation lineage.
- Limitations: A mismatch is candidate consistency evidence requiring review. Finite KAT sampling proves no computational security property.
