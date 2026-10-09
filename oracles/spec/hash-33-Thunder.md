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
