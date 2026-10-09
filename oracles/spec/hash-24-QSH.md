---
status: draft
target: hash-24
algorithm: QSH
source_path: third_party/hash-24/source
source_sha256: 4fd5bcd2bceb7745ebe43568cfdc13645aaec7e8db6e9947333773eaa8ab4f82
document_path: third_party/hash-24/specification.pdf
document_sha256: 5e822a570ad6cc2f07a2c72d6bb9997e658ee01aa2e8264b9dcc0f2cc8dab6b1
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# QSH-512 draft claim extraction

The original source and PDF are pinned above. This extract covers only the
`QSH-512` submitted `CryptHash` API. The cited construction and parameter
discussion is on PDF pp. 4–5, 15; the exact source and PDF files are authoritative.

## S1 — Same-instance deterministic digest agreement

- Source locator: `third_party/hash-24/specification.pdf`, PDF pp. 4–5, 15; submitted `QSH/Implementations/03_Implementations/1_Reference_Implementation/QSH-512/CryptHash_AlgorithmInstance.h` and the corresponding optimized implementation listed in `data/build_sources.json`.
- Class: submitted construction/API identity; backend agreement is an extraction inference.
- Scope: `QSH-512`, 512-bit digest, `CryptHash`, canonical public bitstrings, reference and optimized submitted paths in this pinned source tree.
- Claim: For the same valid bitstring and 512-bit output profile, both submitted implementations of this named hash instance should return the same digest.
- Preconditions: Identical message bytes and exact bit length, both calls succeed, same source snapshot and fixed instance.
- Extraction inference/ambiguity: The PDF defines the named hash construction; equality across software paths follows from their shared instance identity, not an explicit PDF statement about backends. This is draft until human review.
- Limitations: Shared code may hide common errors; agreement proves neither independent conformance nor collision/preimage security. A mismatch does not identify the faulty path.

## S2 — Submitted KAT consistency

- Source locator: `QSH/Test_Vectors/04_TestVectors/KAT_2_12_QSH-512.txt`, SHA-256 `edb3aa74b0592267a416e565effae994e5baf343c2d91b9aee0dc564fd6621da`, fields `Msg_Len`, `Msg`, `Dst_Len`, `Dst`.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact pinned 512-bit KAT records and the two submitted `QSH-512` `CryptHash` paths.
- Claim: The exact recorded message and bit length should reproduce its corresponding submitted digest on each backend.
- Preconditions: Exact record index, bytes, bit length, output length and KAT-file digest are bound in the case.
- Extraction inference/ambiguity: Vector provenance is the archive itself; the vector generator may share implementation lineage.
- Limitations: A mismatch is candidate consistency evidence requiring review. Finite KAT sampling proves no computational security property.
