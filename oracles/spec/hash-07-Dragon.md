---
status: draft
target: hash-07
algorithm: Dragon
source_path: third_party/hash-07/source
source_sha256: 99229052452e211f316d453514dd4a336d6300f5470577b4e43f88ffaa38b2a5
document_path: third_party/hash-07/specification.pdf
document_sha256: 5b53060d5ae14c3434bb16a460b034a7c692de54366f936915a0023aa367f7f2
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# Dragon-512 draft claim extraction

The original source and PDF are pinned above. This extract covers only the
`Dragon-512` submitted `CryptHash` API. The cited construction and parameter
discussion is on PDF pp. 9–10; the exact source and PDF files are authoritative.

## S1 — Same-instance deterministic digest agreement

- Source locator: `third_party/hash-07/specification.pdf`, PDF pp. 9–10; submitted `Dragon/Implementations and Test_vector/Dragon-x86/Implementations/Reference_Implementation/Dragon-512/CryptHash_AlgorithmInstance.h` and the corresponding optimized implementation listed in `data/build_sources.json`.
- Class: submitted construction/API identity; backend agreement is an extraction inference.
- Scope: `Dragon-512`, 512-bit digest, `CryptHash`, canonical public bitstrings, reference and optimized submitted paths in this pinned source tree.
- Claim: For the same valid bitstring and 512-bit output profile, both submitted implementations of this named hash instance should return the same digest.
- Preconditions: Identical message bytes and exact bit length, both calls succeed, same source snapshot and fixed instance.
- Extraction inference/ambiguity: The PDF defines the named hash construction; equality across software paths follows from their shared instance identity, not an explicit PDF statement about backends. This is draft until human review.
- Limitations: Shared code may hide common errors; agreement proves neither independent conformance nor collision/preimage security. A mismatch does not identify the faulty path.

## S2 — Submitted KAT consistency

- Source locator: `Dragon/Implementations and Test_vector/Dragon-ARM/Test_Vector/KAT_2_12_Dragon-512.txt`, SHA-256 `438da40db1be304ea37a037914750019fc74140446dc7fc03c4cd39b16beefb2`, fields `Msg_Len`, `Msg`, `Dst_Len`, `Dst`.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact pinned 512-bit KAT records and the two submitted `Dragon-512` `CryptHash` paths.
- Claim: The exact recorded message and bit length should reproduce its corresponding submitted digest on each backend.
- Preconditions: Exact record index, bytes, bit length, output length and KAT-file digest are bound in the case.
- Extraction inference/ambiguity: Vector provenance is the archive itself; the vector generator may share implementation lineage.
- Limitations: A mismatch is candidate consistency evidence requiring review. Finite KAT sampling proves no computational security property.
