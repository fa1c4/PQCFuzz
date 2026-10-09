---
status: draft
target: hash-32
algorithm: ZC-EDMC
source_path: third_party/hash-32/source
source_sha256: ac099f785acf815e71d0a8f0236c6026ff58172310767f2dd1f49f8491e70179
document_path: third_party/hash-32/specification.pdf
document_sha256: fa729c66f685e527e8ccf47667f150e5e5858e5a4693368651346a081b58c6d0
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# ZC-EDMC-1280-512 draft claim extraction

The original source and PDF are pinned above. This extract covers only the
`ZC-EDMC-1280-512` submitted `CryptHash` API. The cited construction and parameter
discussion is on PDF pp. 5–6; the exact source and PDF files are authoritative.

## S1 — Same-instance deterministic digest agreement

- Source locator: `third_party/hash-32/specification.pdf`, PDF pp. 5–6; submitted `ZC-EDMC/Implementations/Implementations/Reference_Implementation/ZC-EDMC-1280-512/CryptHash_AlgorithmInstance.h` and the corresponding optimized implementation listed in `data/build_sources.json`.
- Class: submitted construction/API identity; backend agreement is an extraction inference.
- Scope: `ZC-EDMC-1280-512`, 512-bit digest, `CryptHash`, canonical public bitstrings, reference and optimized submitted paths in this pinned source tree.
- Claim: For the same valid bitstring and 512-bit output profile, both submitted implementations of this named hash instance should return the same digest.
- Preconditions: Identical message bytes and exact bit length, both calls succeed, same source snapshot and fixed instance.
- Extraction inference/ambiguity: The PDF defines the named hash construction; equality across software paths follows from their shared instance identity, not an explicit PDF statement about backends. This is draft until human review.
- Limitations: Shared code may hide common errors; agreement proves neither independent conformance nor collision/preimage security. A mismatch does not identify the faulty path.

## S2 — Submitted KAT consistency

- Source locator: `ZC-EDMC/Test_Vectors/KAT_2_12_ZC-EDMC-1280-512.txt`, SHA-256 `44873938d8fc07aff8f3de72b2ba1dfe2043528e7623226058454b0c70c43249`, fields `Msg_Len`, `Msg`, `Dst_Len`, `Dst`.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact pinned 512-bit KAT records and the two submitted `ZC-EDMC-1280-512` `CryptHash` paths.
- Claim: The exact recorded message and bit length should reproduce its corresponding submitted digest on each backend.
- Preconditions: Exact record index, bytes, bit length, output length and KAT-file digest are bound in the case.
- Extraction inference/ambiguity: Vector provenance is the archive itself; the vector generator may share implementation lineage.
- Limitations: A mismatch is candidate consistency evidence requiring review. Finite KAT sampling proves no computational security property.
