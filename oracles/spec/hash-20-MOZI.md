---
status: draft
target: hash-20
algorithm: MOZI
source_path: third_party/hash-20/source
source_sha256: ff063e83c4ad48cfbc1e559c1d0e97bf2b0c8ac4d0eb1ec01abeb8c117fb04e5
document_path: third_party/hash-20/specification.pdf
document_sha256: 1c611656c47a7d708dc47449c5fdf2aa4f524e53362b08242daedc57932dbb86
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# MOZI-512 draft claim extraction

The original source and PDF are pinned above. This extract covers only the
`MOZI-512` submitted `CryptHash` API. The cited construction and parameter
discussion is on PDF pp. 3–4; the exact source and PDF files are authoritative.

## S1 — Same-instance deterministic digest agreement

- Source locator: `third_party/hash-20/specification.pdf`, PDF pp. 3–4; submitted `Mozi/Implementations/Reference_Implementation/MOZI-512/CryptHash_AlgorithmInstance.h` and the corresponding optimized implementation listed in `data/build_sources.json`.
- Class: submitted construction/API identity; backend agreement is an extraction inference.
- Scope: `MOZI-512`, 512-bit digest, `CryptHash`, canonical public bitstrings, reference and optimized submitted paths in this pinned source tree.
- Claim: For the same valid bitstring and 512-bit output profile, both submitted implementations of this named hash instance should return the same digest.
- Preconditions: Identical message bytes and exact bit length, both calls succeed, same source snapshot and fixed instance.
- Extraction inference/ambiguity: The PDF defines the named hash construction; equality across software paths follows from their shared instance identity, not an explicit PDF statement about backends. This is draft until human review.
- Limitations: Shared code may hide common errors; agreement proves neither independent conformance nor collision/preimage security. A mismatch does not identify the faulty path.

## S2 — Submitted KAT consistency

- Source locator: `Mozi/Test_Vectors/Test_Vector/KAT_2_12_MOZI-512.txt`, SHA-256 `aab9c381c6e74ab9fa3ffdf5f91a29a6515627580f3e7befd29c2bd5408df6a3`, fields `Msg_Len`, `Msg`, `Dst_Len`, `Dst`.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact pinned 512-bit KAT records and the two submitted `MOZI-512` `CryptHash` paths.
- Claim: The exact recorded message and bit length should reproduce its corresponding submitted digest on each backend.
- Preconditions: Exact record index, bytes, bit length, output length and KAT-file digest are bound in the case.
- Extraction inference/ambiguity: Vector provenance is the archive itself; the vector generator may share implementation lineage.
- Limitations: A mismatch is candidate consistency evidence requiring review. Finite KAT sampling proves no computational security property.
