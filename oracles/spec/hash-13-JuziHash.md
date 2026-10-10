---
status: draft
target: hash-13
algorithm: JuziHash
source_path: third_party/hash-13/source
source_sha256: 039916a21db84b8df9981b13716e10610663bcf07e0161ef77a828e242b10b80
document_path: third_party/hash-13/specification.pdf
document_sha256: d441005afa2186e668f22ebfdc0ededf9eb796cecdc89a2f654a354d8bc2e7d9
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# JuziHash-512 draft claim extraction

The original source and PDF are pinned above. This extract covers only the
`JuziHash-512` submitted `CryptHash` API. The cited construction and parameter
discussion is on PDF pp. 6, 11; the exact source and PDF files are authoritative.

## S1 — Same-instance deterministic digest agreement

- Source locator: `third_party/hash-13/specification.pdf`, PDF pp. 6, 11; submitted `Juzi/Implementations/Implementation/Reference_Implementation/JuziHash-512/CryptHash_AlgorithmInstance.h` and the corresponding optimized implementation listed in `data/build_sources.json`.
- Class: submitted construction/API identity; backend agreement is an extraction inference.
- Scope: `JuziHash-512`, 512-bit digest, `CryptHash`, canonical public bitstrings, reference and optimized submitted paths in this pinned source tree.
- Claim: For the same valid bitstring and 512-bit output profile, both submitted implementations of this named hash instance should return the same digest.
- Preconditions: Identical message bytes and exact bit length, both calls succeed, same source snapshot and fixed instance.
- Extraction inference/ambiguity: The PDF defines the named hash construction; equality across software paths follows from their shared instance identity, not an explicit PDF statement about backends. This is draft until human review.
- Limitations: Shared code may hide common errors; agreement proves neither independent conformance nor collision/preimage security. A mismatch does not identify the faulty path.

## S2 — Submitted KAT consistency

- Source locator: `Juzi/Test_Vectors/KAT_2_12_JuziHash-512.txt`, SHA-256 `a1a7249238b156075147d1aa5e66ebd3a959bc7e7d040958af5bb96f8129080f`, fields `Msg_Len`, `Msg`, `Dst_Len`, `Dst`.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact pinned 512-bit KAT records and the two submitted `JuziHash-512` `CryptHash` paths.
- Claim: The exact recorded message and bit length should reproduce its corresponding submitted digest on each backend.
- Preconditions: Exact record index, bytes, bit length, output length and KAT-file digest are bound in the case.
- Extraction inference/ambiguity: Vector provenance is the archive itself; the vector generator may share implementation lineage.
- Limitations: A mismatch is candidate consistency evidence requiring review. Finite KAT sampling proves no computational security property.

## JUZIHASH1024-K — JuziHash-1024 submitted CryptHash known-answer relation

- Source locator: PDF pp. 6, 11; `Juzi/Implementations/Implementation/Reference_Implementation/JuziHash-1024/CryptHash_AlgorithmInstance.h` SHA-256 `7a2b5af6b24c700263f3f0ad811bb3bf2a11b159e10fc3b607b23e5f1046bafa`; `Juzi/Test_Vectors/KAT_2_12_JuziHash-1024.txt` SHA-256 `b2984c25da27d0601e5d705ce5ff75cfc3822a7dbc295b343cc593dada0a8e03`.
- Class: submitted vector observation with PDF algorithm context; vectors are not independent normative truth.
- Scope: `JuziHash-1024` reference `CryptHash` at exactly 1024 output bits, with eighteen pinned public KAT records.
- Claim: Each recorded input bitstring yields its own submitted digest through the selected public API.
- Preconditions: Exact source/KAT digests, requested output length, canonical message storage, successful public call and intact output guard.
- Extraction inference/ambiguity: KAT generator and reference implementation may share code lineage.
- Limitations: Candidate-only; no claim about collision/preimage security or other backends.
