---
status: draft
target: hash-04
algorithm: CHAMP
source_path: third_party/hash-04/source
source_sha256: f8b2d7e5de33360fe72713a3d23fbcefc6e70ae917d28a88d8f26e19458edb21
document_path: third_party/hash-04/specification.pdf
document_sha256: c1201fe48fe45033c9a97e39ff83928e683ac1d69703ec31987752f6f7dfaa69
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# CHAMP-512 draft claim extraction

The original source and PDF are pinned above. This extract covers only the
`CHAMP-512` submitted `CryptHash` API. The cited construction and parameter
discussion is on PDF p. 4; the exact source and PDF files are authoritative.

## S1 — Same-instance deterministic digest agreement

- Source locator: `third_party/hash-04/specification.pdf`, PDF p. 4; submitted `CHAMP/Implementations and Test_Vectors/API_CryptHash/Implementations/Reference_Implementation/CHAMP-512/CryptHash_AlgorithmInstance.h` and the corresponding optimized implementation listed in `data/build_sources.json`.
- Class: submitted construction/API identity; backend agreement is an extraction inference.
- Scope: `CHAMP-512`, 512-bit digest, `CryptHash`, canonical public bitstrings, reference and optimized submitted paths in this pinned source tree.
- Claim: For the same valid bitstring and 512-bit output profile, both submitted implementations of this named hash instance should return the same digest.
- Preconditions: Identical message bytes and exact bit length, both calls succeed, same source snapshot and fixed instance.
- Extraction inference/ambiguity: The PDF defines the named hash construction; equality across software paths follows from their shared instance identity, not an explicit PDF statement about backends. This is draft until human review.
- Limitations: Shared code may hide common errors; agreement proves neither independent conformance nor collision/preimage security. A mismatch does not identify the faulty path.

## S2 — Submitted KAT consistency

- Source locator: `CHAMP/Implementations and Test_Vectors/API_CryptHash/Test_Vectors/KAT_2_12_CHAMP-512.txt`, SHA-256 `7c7744834dd60a6e431664fd06cb6028e880d863c69ef255dd1bc28f2028f285`, fields `Msg_Len`, `Msg`, `Dst_Len`, `Dst`.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact pinned 512-bit KAT records and the two submitted `CHAMP-512` `CryptHash` paths.
- Claim: The exact recorded message and bit length should reproduce its corresponding submitted digest on each backend.
- Preconditions: Exact record index, bytes, bit length, output length and KAT-file digest are bound in the case.
- Extraction inference/ambiguity: Vector provenance is the archive itself; the vector generator may share implementation lineage.
- Limitations: A mismatch is candidate consistency evidence requiring review. Finite KAT sampling proves no computational security property.

## CHAMP1024-K — CHAMP-1024 submitted CryptHash known-answer relation

- Source locator: PDF p. 4; `CHAMP/Implementations and Test_Vectors/API_CryptHash/Implementations/Reference_Implementation/CHAMP-1024/CryptHash_AlgorithmInstance.h` SHA-256 `0b3181b842b82713fea38e2ac42c72e22da65178e3e544de80c1ac7dfa08e94d`; `CHAMP/Implementations and Test_Vectors/API_CryptHash/Test_Vectors/KAT_2_12_CHAMP-1024.txt` SHA-256 `7609a32270418bac434daade83837177fbf01984099f9262b18a15a361690d5f`.
- Class: submitted vector observation with PDF algorithm context; vectors are not independent normative truth.
- Scope: `CHAMP-1024` reference `CryptHash` at exactly 1024 output bits, with eighteen pinned public KAT records.
- Claim: Each recorded input bitstring yields its own submitted digest through the selected public API.
- Preconditions: Exact source/KAT digests, requested output length, canonical message storage, successful public call and intact output guard.
- Extraction inference/ambiguity: KAT generator and reference implementation may share code lineage.
- Limitations: Candidate-only; no claim about collision/preimage security or other backends.
