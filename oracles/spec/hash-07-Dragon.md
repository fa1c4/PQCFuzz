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

## DRAGON1024-K — Dragon-1024 submitted CryptHash known-answer relation

- Source locator: PDF pp. 9–10; `Dragon/Implementations and Test_vector/Dragon-ARM/Implementations/Reference_Implementation/Dragon-1024/CryptHash_AlgorithmInstance.h` SHA-256 `7c736caa59bf8ea30da200877a65d91b89ce7c4c0ec67eadd4f6a137d5b57ad7`; `Dragon/Implementations and Test_vector/Dragon-ARM/Test_Vector/KAT_2_12_Dragon-1024.txt` SHA-256 `c58ddbfda4740304f72247dfb7ef92f57cb73dc6fad1c291f37218cc65e00748`.
- Class: submitted vector observation with PDF algorithm context; vectors are not independent normative truth.
- Scope: `Dragon-1024` reference `CryptHash` at exactly 1024 output bits, with eighteen pinned public KAT records.
- Claim: Each recorded input bitstring yields its own submitted digest through the selected public API.
- Preconditions: Exact source/KAT digests, requested output length, canonical message storage, successful public call and intact output guard.
- Extraction inference/ambiguity: KAT generator and reference implementation may share code lineage.
- Limitations: Candidate-only; no claim about collision/preimage security or other backends.

## DRAGON768-K — Dragon-768 submitted CryptHash known-answer relation

- Source locator: PDF pp. 9–10; `Dragon/Implementations and Test_vector/Dragon-ARM/Implementations/Reference_Implementation/Dragon-768/CryptHash_AlgorithmInstance.h` SHA-256 `a523f44d56252e27d2276057feb96cc3a7f12b3e6ca63f27aa70228eece5fe0f`; `Dragon/Implementations and Test_vector/Dragon-ARM/Test_Vector/KAT_2_12_Dragon-768.txt` SHA-256 `3661777eb35d496e0ed203c5f6a4a508e1a50a0c53add967b69b7b1e4d5352f8`.
- Class: submitted vector observation with PDF algorithm context; vectors are not independent normative truth.
- Scope: `Dragon-768` reference `CryptHash` at exactly 768 output bits, with eighteen pinned public KAT records.
- Claim: Each recorded input bitstring yields its own submitted digest through the selected public API.
- Preconditions: Exact source/KAT digests, requested output length, canonical message storage, successful public call and intact output guard.
- Extraction inference/ambiguity: KAT generator and reference implementation may share code lineage.
- Limitations: Candidate-only; no claim about collision/preimage security or other backends.

## DRAGONXOF256-K — Dragon-XOF-256 submitted CryptHash known-answer relation

- Source locator: PDF pp. 9–10; `Dragon/Implementations and Test_vector/Dragon-ARM/Implementations/Reference_Implementation/Dragon-XOF-256/CryptHash_AlgorithmInstance.h` SHA-256 `af8edc23237e25758349c3e6330c83f3176c2644c3f06961e294cb2c9cf26fc4`; `Dragon/Implementations and Test_vector/Dragon-ARM/Test_Vector/KAT_2_12_Dragon-XOF-256.txt` SHA-256 `a70bbac199ca8a8eb394e4d864b7d79795abd42f37abb90f5bb522cb4c226da8`.
- Class: submitted vector observation with PDF algorithm context; vectors are not independent normative truth.
- Scope: `Dragon-XOF-256` reference `CryptHash` at exactly 1280 output bits, with eighteen pinned public KAT records.
- Claim: Each recorded input bitstring yields its own submitted digest through the selected public API.
- Preconditions: Exact source/KAT digests, requested output length, canonical message storage, successful public call and intact output guard.
- Extraction inference/ambiguity: KAT generator and reference implementation may share code lineage.
- Limitations: Candidate-only; no claim about collision/preimage security or other backends.

## DRAGONXOF384-K — Dragon-XOF-384 submitted CryptHash known-answer relation

- Source locator: PDF pp. 9–10; `Dragon/Implementations and Test_vector/Dragon-ARM/Implementations/Reference_Implementation/Dragon-XOF-384/CryptHash_AlgorithmInstance.h` SHA-256 `c07b2186daf6fc8d2bef8c4011b99561669a9ea9d5318f42adf69a9f523d0fbe`; `Dragon/Implementations and Test_vector/Dragon-ARM/Test_Vector/KAT_2_12_Dragon-XOF-384.txt` SHA-256 `e6c582b5368610210bdfc77d31e30a602a0be915a9226c03ab359270f1e0ec0e`.
- Class: submitted vector observation with PDF algorithm context; vectors are not independent normative truth.
- Scope: `Dragon-XOF-384` reference `CryptHash` at exactly 1152 output bits, with eighteen pinned public KAT records.
- Claim: Each recorded input bitstring yields its own submitted digest through the selected public API.
- Preconditions: Exact source/KAT digests, requested output length, canonical message storage, successful public call and intact output guard.
- Extraction inference/ambiguity: KAT generator and reference implementation may share code lineage.
- Limitations: Candidate-only; no claim about collision/preimage security or other backends.

## DRAGONXOF512-K — Dragon-XOF-512 submitted CryptHash known-answer relation

- Source locator: PDF pp. 9–10; `Dragon/Implementations and Test_vector/Dragon-ARM/Implementations/Reference_Implementation/Dragon-XOF-512/CryptHash_AlgorithmInstance.h` SHA-256 `c4157bf496f16fc3433638bab0b56b75d6b8f423399c5b20c3bb8d0921ab3b12`; `Dragon/Implementations and Test_vector/Dragon-ARM/Test_Vector/KAT_2_12_Dragon-XOF-512.txt` SHA-256 `b2056e396f79f9c92d623708dfb579b68b68af6def2c0021206b3aaecc0d4a98`.
- Class: submitted vector observation with PDF algorithm context; vectors are not independent normative truth.
- Scope: `Dragon-XOF-512` reference `CryptHash` at exactly 1024 output bits, with eighteen pinned public KAT records.
- Claim: Each recorded input bitstring yields its own submitted digest through the selected public API.
- Preconditions: Exact source/KAT digests, requested output length, canonical message storage, successful public call and intact output guard.
- Extraction inference/ambiguity: KAT generator and reference implementation may share code lineage.
- Limitations: Candidate-only; no claim about collision/preimage security or other backends.
