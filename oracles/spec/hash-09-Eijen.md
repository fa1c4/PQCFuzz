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

## EIJEN1024-K — Eijen-1024 submitted CryptHash known-answer relation

- Source locator: PDF pp. 5, 10; `Eijen/Implementations/Reference_Implementation/Eijen-1024/CryptHash_AlgorithmInstance.h` SHA-256 `346f5af34e8057aac3c236294e408a11e5fa75176e16a80131d5140b8da5bdb9`; `Eijen/Test_Vectors/KAT_2_12_Eijen-1024.txt` SHA-256 `cb71785e899ba51fcf7e955f9cfec453827f871af0b3415cce648726e334f61e`.
- Class: submitted vector observation with PDF algorithm context; vectors are not independent normative truth.
- Scope: `Eijen-1024` reference `CryptHash` at exactly 1024 output bits, with eighteen pinned public KAT records.
- Claim: Each recorded input bitstring yields its own submitted digest through the selected public API.
- Preconditions: Exact source/KAT digests, requested output length, canonical message storage, successful public call and intact output guard.
- Extraction inference/ambiguity: KAT generator and reference implementation may share code lineage.
- Limitations: Candidate-only; no claim about collision/preimage security or other backends.

## EIJEN256-K — Eijen-256 submitted CryptHash known-answer relation

- Source locator: PDF pp. 5, 10; `Eijen/Implementations/Reference_Implementation/Eijen-256/CryptHash_AlgorithmInstance.h` SHA-256 `f12869355a847875c7bddd4d64323946e598343624317d0010779991e5fed1bd`; `Eijen/Test_Vectors/KAT_2_12_Eijen-256.txt` SHA-256 `ae96fba851ae851a91718eeedcac88f6fc5305ee1d6ea74ccdc5ecd54baedb18`.
- Class: submitted vector observation with PDF algorithm context; vectors are not independent normative truth.
- Scope: `Eijen-256` reference `CryptHash` at exactly 256 output bits, with eighteen pinned public KAT records.
- Claim: Each recorded input bitstring yields its own submitted digest through the selected public API.
- Preconditions: Exact source/KAT digests, requested output length, canonical message storage, successful public call and intact output guard.
- Extraction inference/ambiguity: KAT generator and reference implementation may share code lineage.
- Limitations: Candidate-only; no claim about collision/preimage security or other backends.

## EIJEN384-K — Eijen-384 submitted CryptHash known-answer relation

- Source locator: PDF pp. 5, 10; `Eijen/Implementations/Reference_Implementation/Eijen-384/CryptHash_AlgorithmInstance.h` SHA-256 `8d66605bfad0003d10fd46f9954ebf5f7d8260c9093dc21e1c8a3c08b13d853b`; `Eijen/Test_Vectors/KAT_2_12_Eijen-384.txt` SHA-256 `30afffe48c8ba4e1defd7b0a169820cde1a014f52283da24bd788e2c1fcaeaee`.
- Class: submitted vector observation with PDF algorithm context; vectors are not independent normative truth.
- Scope: `Eijen-384` reference `CryptHash` at exactly 384 output bits, with eighteen pinned public KAT records.
- Claim: Each recorded input bitstring yields its own submitted digest through the selected public API.
- Preconditions: Exact source/KAT digests, requested output length, canonical message storage, successful public call and intact output guard.
- Extraction inference/ambiguity: KAT generator and reference implementation may share code lineage.
- Limitations: Candidate-only; no claim about collision/preimage security or other backends.

## EIJEN768-K — Eijen-768 submitted CryptHash known-answer relation

- Source locator: PDF pp. 5, 10; `Eijen/Implementations/Reference_Implementation/Eijen-768/CryptHash_AlgorithmInstance.h` SHA-256 `3b1a45ffde4ecfb8e2f286d2c6c3d974ffbb283df98f8648ce18d567feebe36f`; `Eijen/Test_Vectors/KAT_2_12_Eijen-768.txt` SHA-256 `aa754d0cab3640e8bbcb346ca758e530d73a9bff47da484e6dec47f63dc2e990`.
- Class: submitted vector observation with PDF algorithm context; vectors are not independent normative truth.
- Scope: `Eijen-768` reference `CryptHash` at exactly 768 output bits, with eighteen pinned public KAT records.
- Claim: Each recorded input bitstring yields its own submitted digest through the selected public API.
- Preconditions: Exact source/KAT digests, requested output length, canonical message storage, successful public call and intact output guard.
- Extraction inference/ambiguity: KAT generator and reference implementation may share code lineage.
- Limitations: Candidate-only; no claim about collision/preimage security or other backends.
