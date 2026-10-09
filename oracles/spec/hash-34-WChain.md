---
status: draft
target: hash-34
algorithm: WChain
source_path: third_party/hash-34/source
source_sha256: 02eb17cab1d15c69a4f02e2af97b71e976572628c0e105c9cffd968cbc77a222
document_path: third_party/hash-34/specification.pdf
document_sha256: 646ca79b6295eb75bc476b01cb3e1670882394ed6a4ca48c1f791f3287b7b0e7
source_version: WChain NGCC Round 1 submission
extract_version: 2
---

# WChain submitted claim extraction

This draft covers the submitted WChain parameter sets listed in the registry, including the original instance and additional fixed-output instances. The original source and document locations are recorded in `third_party/hash-34/download.json`. The submission is a candidate proposal; only a human reviewer may change this extraction to `verified`.

## S1 — WChain-V1-512 bitstring hashing

- Source locator: PDF pp. 6–9, §2.2 Table 1 and §§3.1–3.2 Algorithm 1 (WChain Version I). The submitted reference and optimized `WChain-V1-512` API headers identify the same 512-bit instance.
- Class: candidate specification construction and submitted API identity.
- Scope: WChain-V1-512, 512-bit digest, public bitstring input, the two submitted C backends in this exact snapshot, and a little-endian x86-64 host.
- Claim: WChain Version I pads and processes a valid bitstring through FChain and truncates the final state to a deterministic 512-bit digest. The two backends for this same named instance should return equal digests on identical valid inputs.
- Preconditions: Both calls use `digest_len_bits=512`, the same message bytes and exact bit length; unused storage bits are zero. The input passed to the submitted API follows its KAT representation.
- Limitations: Agreement does not prove independent specification conformance, collision or preimage resistance. Shared implementation lineage can hide common errors; a mismatch does not identify the faulty backend.
- Extraction inference/ambiguity: Cross-backend equality follows from a common deterministic algorithm identity, not an explicit software-backend statement in the PDF. Unsupported digest lengths are outside this oracle.

## S2 — Submitted WChain-V1-512 test-vector control

- Source locator: `WChain/Implementations and Test_Vectors/Test_Vectors/KAT_2_12_WChain-V1-512.txt` in the official source ZIP, with `Msg_Len`, `Msg`, `Dst_Len` and `Dst` records generated through the submitted `KAT_CryptHash.c` API.
- Class: submitted test-vector observation, not an independent normative claim.
- Scope: Exact selected 512-bit-digest records copied into the target package, with source-file SHA-256 and original record index.
- Claim: Both backends should reproduce the recorded digest for each exact submitted message and bit length used as a control.
- Preconditions: Exact KAT row, `Dst_Len=512`, and no parameter-set substitution.
- Limitations: The vector generator and backends may share defects. A mismatch is a candidate consistency issue requiring source and specification review, not a confirmed security violation.
- Extraction inference/ambiguity: KAT values are submitted expectations used for control and consistency, not human-verified normative values.

## WCHAINV21024-D — WChain-V2-1024 submitted path agreement

- Source locator: PDF pp. 6–9 §§2.2, 3.1–3.2 and Algorithm 1; submitted instance headers under `Implementations` identify `WChain-V2-1024` and `1024`-bit output.
- Class: candidate specification construction and submitted API identity.
- Scope: WChain-V2-1024, exact `1024`-bit digest, public bitstrings, submitted reference and optimized CryptHash backends, little-endian x86-64 host.
- Claim: For the same valid bitstring and digest length, the two submitted paths for `WChain-V2-1024` should return the same deterministic digest.
- Preconditions: Exact input bytes and bit length, `1024`-bit output, and the same archived source snapshot.
- Limitations: Shared code lineage can conceal common defects. Agreement does not prove independent conformance or a computational security claim; disagreement does not identify a faulty path.
- Extraction inference/ambiguity: Cross-path agreement follows from their common deterministic instance identity; the PDF does not make a software-backend claim. Unsupported digest lengths are excluded.

## WCHAINV21024-K — WChain-V2-1024 submitted KAT control

- Source locator: `WChain/Implementations and Test_Vectors/Test_Vectors/KAT_2_12_WChain-V2-1024.txt` in the archived submission, SHA-256 `9958b95e727bfca815c4e2c11fc58f7a27b77fe0f9c737e6ba74a54d02776175`, with `Msg_Len`, `Msg`, `Dst_Len` and `Dst` fields.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact selected `1024`-bit KAT rows, their source indices and both registered paths for `WChain-V2-1024`.
- Claim: Each exact submitted input should reproduce its own recorded `1024`-bit digest through the selected path.
- Preconditions: Row bytes, bit length, output length, source-file digest and parameter set all match their pinned records.
- Limitations: Vectors may share defects with the implementation. A mismatch is candidate consistency evidence only; finite testing proves no security property.
- Extraction inference/ambiguity: The submitted vector is an experimental control and requires human specification review before normative promotion.
