---
status: draft
target: hash-10
algorithm: FEILIAN
source_path: third_party/hash-10/source
source_sha256: b4eebbfea01a396a752506e998a0701c2080cdbe63d2394b4700242f1009add3
document_path: third_party/hash-10/specification.pdf
document_sha256: 8e3a9a109f3188ab57cbd0156c243f80a6453051cf98006dfef11d66bdeb5fa8
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# FEILIAN512 draft claim extraction

The original source and PDF are pinned above. This extract covers only the
`FEILIAN512` submitted `CryptHash` API. The cited construction and parameter
discussion is on PDF pp. 4–6; the exact source and PDF files are authoritative.

## S1 — Same-instance deterministic digest agreement

- Source locator: `third_party/hash-10/specification.pdf`, PDF pp. 4–6; submitted `FEILIAN/Implementations/Reference_Implementation/FEILIAN512/CryptHash_AlgorithmInstance.h` and the corresponding optimized implementation listed in `data/build_sources.json`.
- Class: submitted construction/API identity; backend agreement is an extraction inference.
- Scope: `FEILIAN512`, 512-bit digest, `CryptHash`, canonical public bitstrings, reference and optimized submitted paths in this pinned source tree.
- Claim: For the same valid bitstring and 512-bit output profile, both submitted implementations of this named hash instance should return the same digest.
- Preconditions: Identical message bytes and exact bit length, both calls succeed, same source snapshot and fixed instance.
- Extraction inference/ambiguity: The PDF defines the named hash construction; equality across software paths follows from their shared instance identity, not an explicit PDF statement about backends. This is draft until human review.
- Limitations: Shared code may hide common errors; agreement proves neither independent conformance nor collision/preimage security. A mismatch does not identify the faulty path.

## S2 — Submitted KAT consistency

- Source locator: `FEILIAN/Test_Vectors/KAT_2_12_FEILIAN512.txt`, SHA-256 `081f5e0640f66c15747dc53bf91cd6206fa8e1151f4d598c50edc2fd43db83ef`, fields `Msg_Len`, `Msg`, `Dst_Len`, `Dst`.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact pinned 512-bit KAT records and the two submitted `FEILIAN512` `CryptHash` paths.
- Claim: The exact recorded message and bit length should reproduce its corresponding submitted digest on each backend.
- Preconditions: Exact record index, bytes, bit length, output length and KAT-file digest are bound in the case.
- Extraction inference/ambiguity: Vector provenance is the archive itself; the vector generator may share implementation lineage.
- Limitations: A mismatch is candidate consistency evidence requiring review. Finite KAT sampling proves no computational security property.
