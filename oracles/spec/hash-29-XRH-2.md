---
status: draft
target: hash-29
algorithm: XRH-2
source_path: third_party/hash-29/source
source_sha256: 34c6e9844bf713db121849b035e35ca33254a7449441b993c5102996c9603111
document_path: third_party/hash-29/specification.pdf
document_sha256: a0c0687be9cc738eb7c7555971e10e7f1e34d07dbe62ceb84b49319f47f9c6a4
source_version: XRH-2 NGCC submission, 2026-06-29
extract_version: 2
---

# XRH-2 submitted claim extraction

This draft covers the submitted XRH-2 parameter sets listed in the registry, including the original instance and additional fixed-output instances. The original source and document locations are recorded in `third_party/hash-29/download.json`. The submission is a candidate proposal; only a human reviewer may change this extraction to `verified`.

## S1 — XRH-2-512 bitstring hashing

- Source locator: PDF p. 13, §1.3 Table 1.1 and Algorithm 4 (XRH-2-512 SPONGE-DM). The submitted reference and optimized `XRH-2-512` API headers identify the same 512-bit instance.
- Class: candidate specification construction and submitted API identity.
- Scope: XRH-2-512, 512-bit digest, public bitstring input, the two submitted C backends in this exact snapshot, and a little-endian x86-64 host.
- Claim: XRH-2-512 applies the specified SPONGE-DM construction to a valid bitstring and returns a deterministic 512-bit digest. The two backends for this same named instance should return equal digests on identical valid inputs.
- Preconditions: Both calls use `digest_len_bits=512`, the same message bytes and exact bit length; unused storage bits are zero. The input passed to the submitted API follows its KAT representation.
- Limitations: Agreement does not prove independent specification conformance, collision or preimage resistance. Shared implementation lineage can hide common errors; a mismatch does not identify the faulty backend.
- Extraction inference/ambiguity: Cross-backend equality follows from a common deterministic algorithm identity, not an explicit software-backend statement in the PDF. Unsupported digest lengths are outside this oracle.

## S2 — Submitted XRH-2-512 test-vector control

- Source locator: `XRH-2/Test_Vectors/KAT_2_12_XRH-2-512.txt` in the official source ZIP, with `Msg_Len`, `Msg`, `Dst_Len` and `Dst` records generated through the submitted `KAT_CryptHash.c` API.
- Class: submitted test-vector observation, not an independent normative claim.
- Scope: Exact selected 512-bit-digest records copied into the target package, with source-file SHA-256 and original record index.
- Claim: Both backends should reproduce the recorded digest for each exact submitted message and bit length used as a control.
- Preconditions: Exact KAT row, `Dst_Len=512`, and no parameter-set substitution.
- Limitations: The vector generator and backends may share defects. A mismatch is a candidate consistency issue requiring source and specification review, not a confirmed security violation.
- Extraction inference/ambiguity: KAT values are submitted expectations used for control and consistency, not human-verified normative values.

## XRH2768-D — XRH-2-768 submitted path agreement

- Source locator: PDF pp. 13–14 §1.3 and Algorithm 4; submitted instance headers under `Implementations` identify `XRH-2-768` and `768`-bit output.
- Class: candidate specification construction and submitted API identity.
- Scope: XRH-2-768, exact `768`-bit digest, public bitstrings, submitted reference and optimized CryptHash backends, little-endian x86-64 host.
- Claim: For the same valid bitstring and digest length, the two submitted paths for `XRH-2-768` should return the same deterministic digest.
- Preconditions: Exact input bytes and bit length, `768`-bit output, and the same archived source snapshot.
- Limitations: Shared code lineage can conceal common defects. Agreement does not prove independent conformance or a computational security claim; disagreement does not identify a faulty path.
- Extraction inference/ambiguity: Cross-path agreement follows from their common deterministic instance identity; the PDF does not make a software-backend claim. Unsupported digest lengths are excluded.

## XRH2768-K — XRH-2-768 submitted KAT control

- Source locator: `XRH-2/Test_Vectors/KAT_2_12_XRH-2-768.txt` in the archived submission, SHA-256 `fd65104f8449243b5c76df65b0c0bd92e34d7ae7aa5460ffb827e30b65c32132`, with `Msg_Len`, `Msg`, `Dst_Len` and `Dst` fields.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact selected `768`-bit KAT rows, their source indices and both registered paths for `XRH-2-768`.
- Claim: Each exact submitted input should reproduce its own recorded `768`-bit digest through the selected path.
- Preconditions: Row bytes, bit length, output length, source-file digest and parameter set all match their pinned records.
- Limitations: Vectors may share defects with the implementation. A mismatch is candidate consistency evidence only; finite testing proves no security property.
- Extraction inference/ambiguity: The submitted vector is an experimental control and requires human specification review before normative promotion.

## XRH21024-D — XRH-2-1024 submitted path agreement

- Source locator: PDF pp. 13–14 §1.3 and Algorithm 4; submitted instance headers under `Implementations` identify `XRH-2-1024` and `1024`-bit output.
- Class: candidate specification construction and submitted API identity.
- Scope: XRH-2-1024, exact `1024`-bit digest, public bitstrings, submitted reference and optimized CryptHash backends, little-endian x86-64 host.
- Claim: For the same valid bitstring and digest length, the two submitted paths for `XRH-2-1024` should return the same deterministic digest.
- Preconditions: Exact input bytes and bit length, `1024`-bit output, and the same archived source snapshot.
- Limitations: Shared code lineage can conceal common defects. Agreement does not prove independent conformance or a computational security claim; disagreement does not identify a faulty path.
- Extraction inference/ambiguity: Cross-path agreement follows from their common deterministic instance identity; the PDF does not make a software-backend claim. Unsupported digest lengths are excluded.

## XRH21024-K — XRH-2-1024 submitted KAT control

- Source locator: `XRH-2/Test_Vectors/KAT_2_12_XRH-2-1024.txt` in the archived submission, SHA-256 `77160621fe443d3e4f7cddd6141251e0a4b505b04415231f3cb996dd6cbd440b`, with `Msg_Len`, `Msg`, `Dst_Len` and `Dst` fields.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact selected `1024`-bit KAT rows, their source indices and both registered paths for `XRH-2-1024`.
- Claim: Each exact submitted input should reproduce its own recorded `1024`-bit digest through the selected path.
- Preconditions: Row bytes, bit length, output length, source-file digest and parameter set all match their pinned records.
- Limitations: Vectors may share defects with the implementation. A mismatch is candidate consistency evidence only; finite testing proves no security property.
- Extraction inference/ambiguity: The submitted vector is an experimental control and requires human specification review before normative promotion.
