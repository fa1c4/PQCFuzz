---
status: draft
target: hash-27
algorithm: Vedak
source_path: third_party/hash-27/source
source_sha256: 75b62697ed3708a665cce719b0fc213aa47e2a9c77922be82c03de836495865a
document_path: third_party/hash-27/specification.pdf
document_sha256: d56d73291912a08ba506d969605a0c771851fa5472d77db859aef299e6bffda2
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# Vedak-512 draft claim extraction

The original source and PDF are pinned above. This extract covers only the
`Vedak-512` submitted `CryptHash` API. The cited construction and parameter
discussion is on PDF pp. 4–5; the exact source and PDF files are authoritative.

## S1 — Same-instance deterministic digest agreement

- Source locator: `third_party/hash-27/specification.pdf`, PDF pp. 4–5; submitted `Vedak/Implementations/Reference_Implementation/Vedak-512/CryptHash_AlgorithmInstance.h` and the corresponding optimized implementation listed in `data/build_sources.json`.
- Class: submitted construction/API identity; backend agreement is an extraction inference.
- Scope: `Vedak-512`, 512-bit digest, `CryptHash`, canonical public bitstrings, reference and optimized submitted paths in this pinned source tree.
- Claim: For the same valid bitstring and 512-bit output profile, both submitted implementations of this named hash instance should return the same digest.
- Preconditions: Identical message bytes and exact bit length, both calls succeed, same source snapshot and fixed instance.
- Extraction inference/ambiguity: The PDF defines the named hash construction; equality across software paths follows from their shared instance identity, not an explicit PDF statement about backends. This is draft until human review.
- Limitations: Shared code may hide common errors; agreement proves neither independent conformance nor collision/preimage security. A mismatch does not identify the faulty path.

## S2 — Submitted KAT consistency

- Source locator: `Vedak/Test_Vectors/KAT_2_12_Vedak-512.txt`, SHA-256 `6fd3775717bb2ecd7cdee333b997e8162906263c3f2f719f7ac41f5d40ac3b06`, fields `Msg_Len`, `Msg`, `Dst_Len`, `Dst`.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact pinned 512-bit KAT records and the two submitted `Vedak-512` `CryptHash` paths.
- Claim: The exact recorded message and bit length should reproduce its corresponding submitted digest on each backend.
- Preconditions: Exact record index, bytes, bit length, output length and KAT-file digest are bound in the case.
- Extraction inference/ambiguity: Vector provenance is the archive itself; the vector generator may share implementation lineage.
- Limitations: A mismatch is candidate consistency evidence requiring review. Finite KAT sampling proves no computational security property.
