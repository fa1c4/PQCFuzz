---
status: draft
target: hash-25
algorithm: TaiChi
source_path: third_party/hash-25/source
source_sha256: 547aa059d8cc328edac9f68546b48ba040ecb52ff4f9865c83ea204d4d73f0dd
document_path: third_party/hash-25/specification.pdf
document_sha256: be46175008c1761d0ef5418339c60eb7c125da69ab5cdd4589c95ef890f8ceae
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# TaiChi-512 draft claim extraction

The original source and PDF are pinned above. This extract covers only the
`TaiChi-512` submitted `CryptHash` API. The cited construction and parameter
discussion is on PDF pp. 5, 13; the exact source and PDF files are authoritative.

## S1 — Same-instance deterministic digest agreement

- Source locator: `third_party/hash-25/specification.pdf`, PDF pp. 5, 13; submitted `TaiChi/Implementations/Reference_Implementation/TaiChi-512/CryptHash_AlgorithmInstance.h` and the corresponding optimized implementation listed in `data/build_sources.json`.
- Class: submitted construction/API identity; backend agreement is an extraction inference.
- Scope: `TaiChi-512`, 512-bit digest, `CryptHash`, canonical public bitstrings, reference and optimized submitted paths in this pinned source tree.
- Claim: For the same valid bitstring and 512-bit output profile, both submitted implementations of this named hash instance should return the same digest.
- Preconditions: Identical message bytes and exact bit length, both calls succeed, same source snapshot and fixed instance.
- Extraction inference/ambiguity: The PDF defines the named hash construction; equality across software paths follows from their shared instance identity, not an explicit PDF statement about backends. This is draft until human review.
- Limitations: Shared code may hide common errors; agreement proves neither independent conformance nor collision/preimage security. A mismatch does not identify the faulty path.

## S2 — Submitted KAT consistency

- Source locator: `TaiChi/Test_Vectors/KAT_2_12_TaiChi-512.txt`, SHA-256 `ab5c781564d4278d575c4b669984f68ba070551b15aa1d1d9b730df27e588021`, fields `Msg_Len`, `Msg`, `Dst_Len`, `Dst`.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact pinned 512-bit KAT records and the two submitted `TaiChi-512` `CryptHash` paths.
- Claim: The exact recorded message and bit length should reproduce its corresponding submitted digest on each backend.
- Preconditions: Exact record index, bytes, bit length, output length and KAT-file digest are bound in the case.
- Extraction inference/ambiguity: Vector provenance is the archive itself; the vector generator may share implementation lineage.
- Limitations: A mismatch is candidate consistency evidence requiring review. Finite KAT sampling proves no computational security property.

## TAICHI1024-K — TaiChi-1024 submitted CryptHash known-answer relation

- Source locator: PDF pp. 5, 13; `TaiChi/Implementations/Reference_Implementation/TaiChi-1024/CryptHash_AlgorithmInstance.h` SHA-256 `9502823b8532d8142ad5bdf58d6e66ba5298d9bb891002212e88c7af3e9c37f6`; `TaiChi/Test_Vectors/KAT_2_12_TaiChi-1024.txt` SHA-256 `b1cab06a69ffe259500199d9ceed3b1cae89e56d726481189f9a2e9f6678828f`.
- Class: submitted vector observation with PDF algorithm context; vectors are not independent normative truth.
- Scope: `TaiChi-1024` reference `CryptHash` at exactly 1024 output bits, with eighteen pinned public KAT records.
- Claim: Each recorded input bitstring yields its own submitted digest through the selected public API.
- Preconditions: Exact source/KAT digests, requested output length, canonical message storage, successful public call and intact output guard.
- Extraction inference/ambiguity: KAT generator and reference implementation may share code lineage.
- Limitations: Candidate-only; no claim about collision/preimage security or other backends.

## TAICHI768-K — TaiChi-768 submitted CryptHash known-answer relation

- Source locator: PDF pp. 5, 13; `TaiChi/Implementations/Reference_Implementation/TaiChi-768/CryptHash_AlgorithmInstance.h` SHA-256 `7db6d4a8afd23e0e67c47ffc3c7e0fc672d4f34c79781e67143b94dd3b78230a`; `TaiChi/Test_Vectors/KAT_2_12_TaiChi-768.txt` SHA-256 `3e30053a633167b50e49dc1e5ce38f0a80d7c3d70a66917547eabb2bb7a63093`.
- Class: submitted vector observation with PDF algorithm context; vectors are not independent normative truth.
- Scope: `TaiChi-768` reference `CryptHash` at exactly 768 output bits, with eighteen pinned public KAT records.
- Claim: Each recorded input bitstring yields its own submitted digest through the selected public API.
- Preconditions: Exact source/KAT digests, requested output length, canonical message storage, successful public call and intact output guard.
- Extraction inference/ambiguity: KAT generator and reference implementation may share code lineage.
- Limitations: Candidate-only; no claim about collision/preimage security or other backends.
