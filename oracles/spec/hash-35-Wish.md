---
status: draft
target: hash-35
algorithm: Wish
source_path: third_party/hash-35/source
source_sha256: aaeadf2dc3fed716a7e9a917d57d208e6816344df4df7d3137459e184e8b86d8
document_path: third_party/hash-35/specification.pdf
document_sha256: a84b946a93f0fe772c1b08d29c90f894d928ea13cef9ee6ed1fd2fdee118dd2c
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# Wish512 draft claim extraction

The original source and PDF are pinned above. This extract covers only the
`Wish512` submitted `CryptHash` API. The cited construction and parameter
discussion is on PDF pp. 5–8; the exact source and PDF files are authoritative.

## S1 — Same-instance deterministic digest agreement

- Source locator: `third_party/hash-35/specification.pdf`, PDF pp. 5–8; submitted `Wish/Implementations/Reference_Implementation/Wish512_reference/CryptHash_AlgorithmInstance.h` and the corresponding optimized implementation listed in `data/build_sources.json`.
- Class: submitted construction/API identity; backend agreement is an extraction inference.
- Scope: `Wish512`, 512-bit digest, `CryptHash`, canonical public bitstrings, reference and optimized submitted paths in this pinned source tree.
- Claim: For the same valid bitstring and 512-bit output profile, both submitted implementations of this named hash instance should return the same digest.
- Preconditions: Identical message bytes and exact bit length, both calls succeed, same source snapshot and fixed instance.
- Extraction inference/ambiguity: The PDF defines the named hash construction; equality across software paths follows from their shared instance identity, not an explicit PDF statement about backends. This is draft until human review.
- Limitations: Shared code may hide common errors; agreement proves neither independent conformance nor collision/preimage security. A mismatch does not identify the faulty path.

## S2 — Submitted KAT consistency

- Source locator: `Wish/Test_Vectors/Test_Vector/Wish512/KAT_2_12_Wish512.txt`, SHA-256 `5f9406c0f372376392e3a5031a88bfcce55d460bb9274025ff661188ad5c2da9`, fields `Msg_Len`, `Msg`, `Dst_Len`, `Dst`.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact pinned 512-bit KAT records and the two submitted `Wish512` `CryptHash` paths.
- Claim: The exact recorded message and bit length should reproduce its corresponding submitted digest on each backend.
- Preconditions: Exact record index, bytes, bit length, output length and KAT-file digest are bound in the case.
- Extraction inference/ambiguity: Vector provenance is the archive itself; the vector generator may share implementation lineage.
- Limitations: A mismatch is candidate consistency evidence requiring review. Finite KAT sampling proves no computational security property.

## WISH1024-K — Wish1024 submitted CryptHash known-answer relation

- Source locator: PDF pp. 5–8; `Wish/Implementations/Reference_Implementation/Wish1024_reference/CryptHash_AlgorithmInstance.h` SHA-256 `21229b8c17554f71fd1b044d601ef605baf278122f4a8fde5873a1ab57721528`; `Wish/Test_Vectors/Test_Vector/Wish1024/KAT_2_12_Wish1024.txt` SHA-256 `33ea939b4b699cc1e49b54cfed2173d1db3c454f230704dcb817dff278b7326c`.
- Class: submitted vector observation with PDF algorithm context; vectors are not independent normative truth.
- Scope: `Wish1024` reference `CryptHash` at exactly 1024 output bits, with eighteen pinned public KAT records.
- Claim: Each recorded input bitstring yields its own submitted digest through the selected public API.
- Preconditions: Exact source/KAT digests, requested output length, canonical message storage, successful public call and intact output guard.
- Extraction inference/ambiguity: KAT generator and reference implementation may share code lineage.
- Limitations: Candidate-only; no claim about collision/preimage security or other backends.
