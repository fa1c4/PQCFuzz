---
status: draft
target: hash-12
algorithm: Iphe
source_path: third_party/hash-12/source
source_sha256: f595fbb8cc190036ca76ca3e22602f0f4b9f3843e803b462840ca6043c1f2969
document_path: third_party/hash-12/specification.pdf
document_sha256: 552cdcf57adb4be223bec166db944405907c8b201452681f9aee96a4785b408b
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# Iphe-512 draft claim extraction

The original source and PDF are pinned above. This extract covers only the
`Iphe-512` submitted `CryptHash` API. The cited construction and parameter
discussion is on PDF p. 4; the exact source and PDF files are authoritative.

## S1 — Same-instance deterministic digest agreement

- Source locator: `third_party/hash-12/specification.pdf`, PDF p. 4; submitted `Iphe/Implementations/Reference_Implementation/Iphe-512/CryptHash_AlgorithmInstance.h` and the corresponding optimized implementation listed in `data/build_sources.json`.
- Class: submitted construction/API identity; backend agreement is an extraction inference.
- Scope: `Iphe-512`, 512-bit digest, `CryptHash`, canonical public bitstrings, reference and optimized submitted paths in this pinned source tree.
- Claim: For the same valid bitstring and 512-bit output profile, both submitted implementations of this named hash instance should return the same digest.
- Preconditions: Identical message bytes and exact bit length, both calls succeed, same source snapshot and fixed instance.
- Extraction inference/ambiguity: The PDF defines the named hash construction; equality across software paths follows from their shared instance identity, not an explicit PDF statement about backends. This is draft until human review.
- Limitations: Shared code may hide common errors; agreement proves neither independent conformance nor collision/preimage security. A mismatch does not identify the faulty path.

## S2 — Submitted KAT consistency

- Source locator: `Iphe/Test_Vectors/KAT_2_12_Iphe-512.txt`, SHA-256 `ed52fd6dd923ed52e17b63301bcd8ab4c529750a149414ecde4dd8f6d7069bcf`, fields `Msg_Len`, `Msg`, `Dst_Len`, `Dst`.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact pinned 512-bit KAT records and the two submitted `Iphe-512` `CryptHash` paths.
- Claim: The exact recorded message and bit length should reproduce its corresponding submitted digest on each backend.
- Preconditions: Exact record index, bytes, bit length, output length and KAT-file digest are bound in the case.
- Extraction inference/ambiguity: Vector provenance is the archive itself; the vector generator may share implementation lineage.
- Limitations: A mismatch is candidate consistency evidence requiring review. Finite KAT sampling proves no computational security property.

## IPHE1024-K — Iphe-1024 submitted CryptHash known-answer relation

- Source locator: PDF p. 4; `Iphe/Implementations/Reference_Implementation/Iphe-1024/CryptHash_AlgorithmInstance.h` SHA-256 `948d42ebff121dc79a1bdc83d5d12ef1f53f99b83ea7b44537ec5ecba48d5c10`; `Iphe/Test_Vectors/KAT_2_12_Iphe-1024.txt` SHA-256 `a451150e557a015ff5c183912141ae94b0239f9205e9c1fa3b996870c546b7d5`.
- Class: submitted vector observation with PDF algorithm context; vectors are not independent normative truth.
- Scope: `Iphe-1024` reference `CryptHash` at exactly 1024 output bits, with eighteen pinned public KAT records.
- Claim: Each recorded input bitstring yields its own submitted digest through the selected public API.
- Preconditions: Exact source/KAT digests, requested output length, canonical message storage, successful public call and intact output guard.
- Extraction inference/ambiguity: KAT generator and reference implementation may share code lineage.
- Limitations: Candidate-only; no claim about collision/preimage security or other backends.

## IPHE768-K — Iphe-768 submitted CryptHash known-answer relation

- Source locator: PDF p. 4; `Iphe/Implementations/Reference_Implementation/Iphe-768/CryptHash_AlgorithmInstance.h` SHA-256 `9daacbb3aca1e0773e0ad2cfad100429105d36b2e3d42f591d75c0e81a0ac067`; `Iphe/Test_Vectors/KAT_2_12_Iphe-768.txt` SHA-256 `722e09ec85dba2125998f926a42d3d9fc5d2f4750bc06c5720332863e1e04f23`.
- Class: submitted vector observation with PDF algorithm context; vectors are not independent normative truth.
- Scope: `Iphe-768` reference `CryptHash` at exactly 768 output bits, with eighteen pinned public KAT records.
- Claim: Each recorded input bitstring yields its own submitted digest through the selected public API.
- Preconditions: Exact source/KAT digests, requested output length, canonical message storage, successful public call and intact output guard.
- Extraction inference/ambiguity: KAT generator and reference implementation may share code lineage.
- Limitations: Candidate-only; no claim about collision/preimage security or other backends.
