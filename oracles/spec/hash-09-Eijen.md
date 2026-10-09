---
status: draft
target: hash-09
algorithm: Eijen
source_path: third_party/hash-09/source
source_sha256: 090fd624a5439064555d3640ee935821cba9ea1b798ba70666d3696eaf99a486
document_path: third_party/hash-09/specification.pdf
document_sha256: d4282aa1f7395125766fa3f8b819252d61153d595275f454576086d7211f587f
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# Eijen-512 draft claim extraction

The original source and PDF are pinned above. This extract covers only the
`Eijen-512` submitted `CryptHash` API. The cited construction and parameter
discussion is on PDF pp. 5, 10; the exact source and PDF files are authoritative.

## S1 — Same-instance deterministic digest agreement

- Source locator: `third_party/hash-09/specification.pdf`, PDF pp. 5, 10; submitted `Eijen/Implementations/Reference_Implementation/Eijen-512/CryptHash_AlgorithmInstance.h` and the corresponding optimized implementation listed in `data/build_sources.json`.
- Class: submitted construction/API identity; backend agreement is an extraction inference.
- Scope: `Eijen-512`, 512-bit digest, `CryptHash`, canonical public bitstrings, reference and optimized submitted paths in this pinned source tree.
- Claim: For the same valid bitstring and 512-bit output profile, both submitted implementations of this named hash instance should return the same digest.
- Preconditions: Identical message bytes and exact bit length, both calls succeed, same source snapshot and fixed instance.
- Extraction inference/ambiguity: The PDF defines the named hash construction; equality across software paths follows from their shared instance identity, not an explicit PDF statement about backends. This is draft until human review.
- Limitations: Shared code may hide common errors; agreement proves neither independent conformance nor collision/preimage security. A mismatch does not identify the faulty path.

## S2 — Submitted KAT consistency

- Source locator: `Eijen/Test_Vectors/KAT_2_12_Eijen-512.txt`, SHA-256 `c4fbc06aefc1c72968366b0cc19f2ed15aaecbc373df4896bcba7b35149817da`, fields `Msg_Len`, `Msg`, `Dst_Len`, `Dst`.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact pinned 512-bit KAT records and the two submitted `Eijen-512` `CryptHash` paths.
- Claim: The exact recorded message and bit length should reproduce its corresponding submitted digest on each backend.
- Preconditions: Exact record index, bytes, bit length, output length and KAT-file digest are bound in the case.
- Extraction inference/ambiguity: Vector provenance is the archive itself; the vector generator may share implementation lineage.
- Limitations: A mismatch is candidate consistency evidence requiring review. Finite KAT sampling proves no computational security property.
