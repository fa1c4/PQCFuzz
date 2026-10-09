---
status: draft
target: hash-08
algorithm: Duet
source_path: third_party/hash-08/source
source_sha256: d7980d98d29bfcde4525625b6fd3a78d206d64e45bba19e2fe242122f4f25cbd
document_path: third_party/hash-08/specification.pdf
document_sha256: 6a846acc98114368059b96e42925877e06a4cdd423e36143ee274e2679dfbf9f
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# Duet-512 draft claim extraction

The original source and PDF are pinned above. This extract covers only the
`Duet-512` submitted `CryptHash` API. The cited construction and parameter
discussion is on PDF pp. 13–14, 18; the exact source and PDF files are authoritative.

## S1 — Same-instance deterministic digest agreement

- Source locator: `third_party/hash-08/specification.pdf`, PDF pp. 13–14, 18; submitted `Duet/Implementations/Reference_Implementation/Duet-512/CryptHash_Duet-512.h` and the corresponding optimized implementation listed in `data/build_sources.json`.
- Class: submitted construction/API identity; backend agreement is an extraction inference.
- Scope: `Duet-512`, 512-bit digest, `CryptHash`, canonical public bitstrings, reference and optimized submitted paths in this pinned source tree.
- Claim: For the same valid bitstring and 512-bit output profile, both submitted implementations of this named hash instance should return the same digest.
- Preconditions: Identical message bytes and exact bit length, both calls succeed, same source snapshot and fixed instance.
- Extraction inference/ambiguity: The PDF defines the named hash construction; equality across software paths follows from their shared instance identity, not an explicit PDF statement about backends. This is draft until human review.
- Limitations: Shared code may hide common errors; agreement proves neither independent conformance nor collision/preimage security. A mismatch does not identify the faulty path.

## S2 — Submitted KAT consistency

- Source locator: `Duet/Test_Vectors/KAT_2_12_Duet-512.txt`, SHA-256 `e3efcfa89ed14f5acabf4c75703eff855f8a5a51b1e1248465e7e9b54102058a`, fields `Msg_Len`, `Msg`, `Dst_Len`, `Dst`.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact pinned 512-bit KAT records and the two submitted `Duet-512` `CryptHash` paths.
- Claim: The exact recorded message and bit length should reproduce its corresponding submitted digest on each backend.
- Preconditions: Exact record index, bytes, bit length, output length and KAT-file digest are bound in the case.
- Extraction inference/ambiguity: Vector provenance is the archive itself; the vector generator may share implementation lineage.
- Limitations: A mismatch is candidate consistency evidence requiring review. Finite KAT sampling proves no computational security property.
