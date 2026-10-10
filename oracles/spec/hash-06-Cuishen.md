---
status: draft
target: hash-06
algorithm: Cuishen
source_path: third_party/hash-06/source
source_sha256: 5608ba9aac7ef64fe6a7b3495219fc70fa3215f5afae4263d83dd84e9ef2dbc8
document_path: third_party/hash-06/specification.pdf
document_sha256: fc36e428a82d77bcfc54231bc911f124dd21cce61c97e3fe29b6bfef33c8635f
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# Cuishen-512 draft claim extraction

The original source and PDF are pinned above. This extract covers only the
`Cuishen-512` submitted `CryptHash` API. The cited construction and parameter
discussion is on PDF pp. 7–9; the exact source and PDF files are authoritative.

## S1 — Same-instance deterministic digest agreement

- Source locator: `third_party/hash-06/specification.pdf`, PDF pp. 7–9; submitted `Cuishen/Implementations/Reference_Implementation/Cuishen-512/CryptHash_Cuishen-512.h` and the corresponding optimized implementation listed in `data/build_sources.json`.
- Class: submitted construction/API identity; backend agreement is an extraction inference.
- Scope: `Cuishen-512`, 512-bit digest, `CryptHash`, canonical public bitstrings, reference and optimized submitted paths in this pinned source tree.
- Claim: For the same valid bitstring and 512-bit output profile, both submitted implementations of this named hash instance should return the same digest.
- Preconditions: Identical message bytes and exact bit length, both calls succeed, same source snapshot and fixed instance.
- Extraction inference/ambiguity: The PDF defines the named hash construction; equality across software paths follows from their shared instance identity, not an explicit PDF statement about backends. This is draft until human review.
- Limitations: Shared code may hide common errors; agreement proves neither independent conformance nor collision/preimage security. A mismatch does not identify the faulty path.

## S2 — Submitted KAT consistency

- Source locator: `Cuishen/Test_Vectors/KAT_2_12_Cuishen-512.txt`, SHA-256 `ec00f79d10e285e475e39f99ed0fd1f6f21c46bfe082d2bde8c668c5adc3530b`, fields `Msg_Len`, `Msg`, `Dst_Len`, `Dst`.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact pinned 512-bit KAT records and the two submitted `Cuishen-512` `CryptHash` paths.
- Claim: The exact recorded message and bit length should reproduce its corresponding submitted digest on each backend.
- Preconditions: Exact record index, bytes, bit length, output length and KAT-file digest are bound in the case.
- Extraction inference/ambiguity: Vector provenance is the archive itself; the vector generator may share implementation lineage.
- Limitations: A mismatch is candidate consistency evidence requiring review. Finite KAT sampling proves no computational security property.

## CUISHEN1024-K — Cuishen-1024 submitted CryptHash known-answer relation

- Source locator: PDF pp. 7–9; `Cuishen/Implementations/Reference_Implementation/Cuishen-1024/CryptHash_Cuishen-1024.h` SHA-256 `47969954ffee6230e5bc8203d68470e45776c5f7198d49f53a23acd3e0500887`; `Cuishen/Test_Vectors/KAT_2_12_Cuishen-1024.txt` SHA-256 `fee17c0fbe2c5638f008ec36ede2858a1ee8009d95279fc2880b7da2e397a9c1`.
- Class: submitted vector observation with PDF algorithm context; vectors are not independent normative truth.
- Scope: `Cuishen-1024` reference `CryptHash` at exactly 1024 output bits, with eighteen pinned public KAT records.
- Claim: Each recorded input bitstring yields its own submitted digest through the selected public API.
- Preconditions: Exact source/KAT digests, requested output length, canonical message storage, successful public call and intact output guard.
- Extraction inference/ambiguity: KAT generator and reference implementation may share code lineage.
- Limitations: Candidate-only; no claim about collision/preimage security or other backends.

## CUISHEN768-K — Cuishen-768 submitted CryptHash known-answer relation

- Source locator: PDF pp. 7–9; `Cuishen/Implementations/Reference_Implementation/Cuishen-768/CryptHash_Cuishen-768.h` SHA-256 `e236cebc8824394fc0488d1652c106cf0fec5b90ec0e289c2d45fe4bc59a33a0`; `Cuishen/Test_Vectors/KAT_2_12_Cuishen-768.txt` SHA-256 `18dcee6282ccd8171fc68aa848a04993ae21ff742efd2e70eaf01a4555c2c935`.
- Class: submitted vector observation with PDF algorithm context; vectors are not independent normative truth.
- Scope: `Cuishen-768` reference `CryptHash` at exactly 768 output bits, with eighteen pinned public KAT records.
- Claim: Each recorded input bitstring yields its own submitted digest through the selected public API.
- Preconditions: Exact source/KAT digests, requested output length, canonical message storage, successful public call and intact output guard.
- Extraction inference/ambiguity: KAT generator and reference implementation may share code lineage.
- Limitations: Candidate-only; no claim about collision/preimage security or other backends.
