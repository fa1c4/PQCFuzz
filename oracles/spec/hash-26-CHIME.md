---
status: draft
target: hash-26
algorithm: CHIME
source_path: third_party/hash-26/source
source_sha256: 6a9e9f1d7432185271236c7b9576a22ff5b6c4948655eaf867e0f7c61bcb2f95
document_path: third_party/hash-26/specification.pdf
document_sha256: b8358601c531d49ecc3a7843771b403d44504aad6a0aac07dc4e20eb397a2a5c
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# CHIME-512 draft claim extraction

The original source and PDF are pinned above. This extract covers only the
`CHIME-512` submitted `CryptHash` API. The cited construction and parameter
discussion is on PDF p. 4; the exact source and PDF files are authoritative.

## S1 — Same-instance deterministic digest agreement

- Source locator: `third_party/hash-26/specification.pdf`, PDF p. 4; submitted `CHIME/Implementations/Reference_Implementation/CHIME-512/CryptHash_AlgorithmInstance.h` and the corresponding optimized implementation listed in `data/build_sources.json`.
- Class: submitted construction/API identity; backend agreement is an extraction inference.
- Scope: `CHIME-512`, 512-bit digest, `CryptHash`, canonical public bitstrings, reference and optimized submitted paths in this pinned source tree.
- Claim: For the same valid bitstring and 512-bit output profile, both submitted implementations of this named hash instance should return the same digest.
- Preconditions: Identical message bytes and exact bit length, both calls succeed, same source snapshot and fixed instance.
- Extraction inference/ambiguity: The PDF defines the named hash construction; equality across software paths follows from their shared instance identity, not an explicit PDF statement about backends. This is draft until human review.
- Limitations: Shared code may hide common errors; agreement proves neither independent conformance nor collision/preimage security. A mismatch does not identify the faulty path.

## S2 — Submitted KAT consistency

- Source locator: `CHIME/Test_Vectors/Test_Vector/KAT_2_12_CHIME-512.txt`, SHA-256 `5435ee6e6417b38d00af17e811f3e678598c6cef1cb5c5f905c4f2a807a026ae`, fields `Msg_Len`, `Msg`, `Dst_Len`, `Dst`.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact pinned 512-bit KAT records and the two submitted `CHIME-512` `CryptHash` paths.
- Claim: The exact recorded message and bit length should reproduce its corresponding submitted digest on each backend.
- Preconditions: Exact record index, bytes, bit length, output length and KAT-file digest are bound in the case.
- Extraction inference/ambiguity: Vector provenance is the archive itself; the vector generator may share implementation lineage.
- Limitations: A mismatch is candidate consistency evidence requiring review. Finite KAT sampling proves no computational security property.
