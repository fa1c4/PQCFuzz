---
status: draft
target: hash-02
algorithm: AXIS
source_path: third_party/hash-02/source
source_sha256: 74a75b1b73470d1a76ad56a3b6f60d496d461febec5947ca5f09a26ea2f89e30
document_path: third_party/hash-02/specification.pdf
document_sha256: 2b99ad1648ee8f13432623c96bcef3a76a0837e1913b28613f7f94408dee4b37
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# AXIS-512 draft claim extraction

The original source and PDF are pinned above. This extract covers only the
`AXIS-512` submitted `CryptHash` API. The cited construction and parameter
discussion is on PDF pp. 4, 10; the exact source and PDF files are authoritative.

## S1 — Same-instance deterministic digest agreement

- Source locator: `third_party/hash-02/specification.pdf`, PDF pp. 4, 10; submitted `AXIS/Implementations/Reference_Implementation/AXIS-512/CryptHash_AlgorithmInstance.h` and the corresponding optimized implementation listed in `data/build_sources.json`.
- Class: submitted construction/API identity; backend agreement is an extraction inference.
- Scope: `AXIS-512`, 512-bit digest, `CryptHash`, canonical public bitstrings, reference and optimized submitted paths in this pinned source tree.
- Claim: For the same valid bitstring and 512-bit output profile, both submitted implementations of this named hash instance should return the same digest.
- Preconditions: Identical message bytes and exact bit length, both calls succeed, same source snapshot and fixed instance.
- Extraction inference/ambiguity: The PDF defines the named hash construction; equality across software paths follows from their shared instance identity, not an explicit PDF statement about backends. This is draft until human review.
- Limitations: Shared code may hide common errors; agreement proves neither independent conformance nor collision/preimage security. A mismatch does not identify the faulty path.

## S2 — Submitted KAT consistency

- Source locator: `AXIS/Test_Vectors/KAT_2_12_AXIS-512.txt`, SHA-256 `19a96229c29df5d3c5fc3d11c5be2817e54481ef8eddc7b4472df8654cefc9fc`, fields `Msg_Len`, `Msg`, `Dst_Len`, `Dst`.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact pinned 512-bit KAT records and the two submitted `AXIS-512` `CryptHash` paths.
- Claim: The exact recorded message and bit length should reproduce its corresponding submitted digest on each backend.
- Preconditions: Exact record index, bytes, bit length, output length and KAT-file digest are bound in the case.
- Extraction inference/ambiguity: Vector provenance is the archive itself; the vector generator may share implementation lineage.
- Limitations: A mismatch is candidate consistency evidence requiring review. Finite KAT sampling proves no computational security property.
