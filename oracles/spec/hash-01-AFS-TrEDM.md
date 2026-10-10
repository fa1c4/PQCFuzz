---
status: draft
target: hash-01
algorithm: AFS-TrEDM
source_path: third_party/hash-01/source
source_sha256: 662c16fed66079fae51f975b7aa46e207e475278ec4e2808a7a1626f108f0945
document_path: third_party/hash-01/specification.pdf
document_sha256: 96a297867ec5fa8b10d4d5aa7282251c59e56536bfd33b66797f1736fdfcb76c
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# AFS-TrEDM-512 draft claim extraction

The original source and PDF are pinned above. This extract covers only the
`AFS-TrEDM-512` submitted `CryptHash` API. The cited construction and parameter
discussion is on PDF pp. 8–9, 18; the exact source and PDF files are authoritative.

## S1 — Same-instance deterministic digest agreement

- Source locator: `third_party/hash-01/specification.pdf`, PDF pp. 8–9, 18; submitted `AFS-TrEDM/Implementations/Reference_Implementation/AFS-TrEDM-512/CryptHash_AlgorithmInstance.h` and the corresponding optimized implementation listed in `data/build_sources.json`.
- Class: submitted construction/API identity; backend agreement is an extraction inference.
- Scope: `AFS-TrEDM-512`, 512-bit digest, `CryptHash`, canonical public bitstrings, reference and optimized submitted paths in this pinned source tree.
- Claim: For the same valid bitstring and 512-bit output profile, both submitted implementations of this named hash instance should return the same digest.
- Preconditions: Identical message bytes and exact bit length, both calls succeed, same source snapshot and fixed instance.
- Extraction inference/ambiguity: The PDF defines the named hash construction; equality across software paths follows from their shared instance identity, not an explicit PDF statement about backends. This is draft until human review.
- Limitations: Shared code may hide common errors; agreement proves neither independent conformance nor collision/preimage security. A mismatch does not identify the faulty path.

## S2 — Submitted KAT consistency

- Source locator: `AFS-TrEDM/Test_Vectors/KAT_2_12_AFS-TrEDM-512.txt`, SHA-256 `5ec5f7d705b313e5148d7d4f31b4ec49db79a4254be84072691d8ca5ffcd0c71`, fields `Msg_Len`, `Msg`, `Dst_Len`, `Dst`.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact pinned 512-bit KAT records and the two submitted `AFS-TrEDM-512` `CryptHash` paths.
- Claim: The exact recorded message and bit length should reproduce its corresponding submitted digest on each backend.
- Preconditions: Exact record index, bytes, bit length, output length and KAT-file digest are bound in the case.
- Extraction inference/ambiguity: Vector provenance is the archive itself; the vector generator may share implementation lineage.
- Limitations: A mismatch is candidate consistency evidence requiring review. Finite KAT sampling proves no computational security property.

## AFSTREDM1024-K — AFS-TrEDM-1024 submitted CryptHash known-answer relation

- Source locator: PDF pp. 8–9, 18; `AFS-TrEDM/Implementations/Reference_Implementation/AFS-TrEDM-1024/CryptHash_AlgorithmInstance.h` SHA-256 `b7a0ee100abeb882ec13ff8748f65ec98da88231c6b6ba61f02e0320a3eaea92`; `AFS-TrEDM/Test_Vectors/KAT_2_12_AFS-TrEDM-1024.txt` SHA-256 `60c18a919b6fece8d1e3df350347c7de41be2fad3ec8a0398177b5c7fed05a39`.
- Class: submitted vector observation with PDF algorithm context; vectors are not independent normative truth.
- Scope: `AFS-TrEDM-1024` reference `CryptHash` at exactly 1024 output bits, with eighteen pinned public KAT records.
- Claim: Each recorded input bitstring yields its own submitted digest through the selected public API.
- Preconditions: Exact source/KAT digests, requested output length, canonical message storage, successful public call and intact output guard.
- Extraction inference/ambiguity: KAT generator and reference implementation may share code lineage.
- Limitations: Candidate-only; no claim about collision/preimage security or other backends.

## AFSTREDM768-K — AFS-TrEDM-768 submitted CryptHash known-answer relation

- Source locator: PDF pp. 8–9, 18; `AFS-TrEDM/Implementations/Reference_Implementation/AFS-TrEDM-768/CryptHash_AlgorithmInstance.h` SHA-256 `f696fde04fe207968800e31758fa39763e3ab5cb4cc77072b4921bc559916d6a`; `AFS-TrEDM/Test_Vectors/KAT_2_12_AFS-TrEDM-768.txt` SHA-256 `b267eb72b1ce2a7e2f162f7fddcdafaade51b052f661ec1e1bc5779cd4851b3b`.
- Class: submitted vector observation with PDF algorithm context; vectors are not independent normative truth.
- Scope: `AFS-TrEDM-768` reference `CryptHash` at exactly 768 output bits, with eighteen pinned public KAT records.
- Claim: Each recorded input bitstring yields its own submitted digest through the selected public API.
- Preconditions: Exact source/KAT digests, requested output length, canonical message storage, successful public call and intact output guard.
- Extraction inference/ambiguity: KAT generator and reference implementation may share code lineage.
- Limitations: Candidate-only; no claim about collision/preimage security or other backends.
