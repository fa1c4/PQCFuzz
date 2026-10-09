---
status: draft
target: hash-03
algorithm: C-Hash
source_path: third_party/hash-03/source
source_sha256: 89bbed92fb655567e5ff9c82ce06392f2ad7c23a168adafeaf8f33d5e6be36b8
document_path: third_party/hash-03/specification.pdf
document_sha256: 1df58eec9b28ca09720928858de7a212f84b5adcf162da2a808bde8e289bee4f
source_version: C Hash NGCC submission, 2026-06-30
extract_version: 2
---

# C-Hash submitted claim extraction

This draft covers the submitted C-Hash parameter sets listed in the registry, including the original instance and additional fixed-output instances. The original source and document locations are recorded in `third_party/hash-03/download.json`. The submission is a candidate proposal; only a human reviewer may change this extraction to `verified`.

## S1 — C-Hash-512 bitstring hashing

- Source locator: PDF pp. 5–6 and 14, §1.1 and §1.4 (C-Hash-512 CTR-Perm and the mandatory short-message path). The submitted reference and optimized `CHash_512` API headers identify the same 512-bit instance.
- Class: candidate specification construction and submitted API identity.
- Scope: C-Hash-512, 512-bit digest, public bitstring input, the two submitted C backends in this exact snapshot, and a little-endian x86-64 host.
- Claim: C-Hash-512 maps a valid input bitstring to a deterministic 512-bit digest; messages shorter than 512 bits use its specified LDRH path. The two backends for this same named instance should return equal digests on identical valid inputs.
- Preconditions: Both calls use `digest_len_bits=512`, the same message bytes and exact bit length; unused storage bits are zero. The input passed to the submitted API follows its KAT representation.
- Limitations: Agreement does not prove independent specification conformance, collision or preimage resistance. Shared implementation lineage can hide common errors; a mismatch does not identify the faulty backend.
- Extraction inference/ambiguity: Cross-backend equality follows from a common deterministic algorithm identity, not an explicit software-backend statement in the PDF. Unsupported digest lengths are outside this oracle.

## S2 — Submitted C-Hash-512 test-vector control

- Source locator: `C Hash/Test_Vectors/KAT_2_12_CHash_512.txt` in the official source ZIP, with `Msg_Len`, `Msg`, `Dst_Len` and `Dst` records generated through the submitted `KAT_CryptHash.c` API.
- Class: submitted test-vector observation, not an independent normative claim.
- Scope: Exact selected 512-bit-digest records copied into the target package, with source-file SHA-256 and original record index.
- Claim: Both backends should reproduce the recorded digest for each exact submitted message and bit length used as a control.
- Preconditions: Exact KAT row, `Dst_Len=512`, and no parameter-set substitution.
- Limitations: The vector generator and backends may share defects. A mismatch is a candidate consistency issue requiring source and specification review, not a confirmed security violation.
- Extraction inference/ambiguity: KAT values are submitted expectations used for control and consistency, not human-verified normative values.

## CHASH1024-D — C-Hash-1024 submitted path agreement

- Source locator: PDF pp. 5–6 §1.1 and p. 14 §1.4; submitted instance headers under `Implementations` identify `C-Hash-1024` and `1024`-bit output.
- Class: candidate specification construction and submitted API identity.
- Scope: C-Hash-1024, exact `1024`-bit digest, public bitstrings, submitted reference and optimized CryptHash backends, little-endian x86-64 host.
- Claim: For the same valid bitstring and digest length, the two submitted paths for `C-Hash-1024` should return the same deterministic digest.
- Preconditions: Exact input bytes and bit length, `1024`-bit output, and the same archived source snapshot.
- Limitations: Shared code lineage can conceal common defects. Agreement does not prove independent conformance or a computational security claim; disagreement does not identify a faulty path.
- Extraction inference/ambiguity: Cross-path agreement follows from their common deterministic instance identity; the PDF does not make a software-backend claim. Unsupported digest lengths are excluded.

## CHASH1024-K — C-Hash-1024 submitted KAT control

- Source locator: `C Hash/Test_Vectors/KAT_2_12_CHash_1024.txt` in the archived submission, SHA-256 `93e29224b4efd2837dbd13edad4274d640f7a69bfb7287ffdf48de4c20f09f8b`, with `Msg_Len`, `Msg`, `Dst_Len` and `Dst` fields.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact selected `1024`-bit KAT rows, their source indices and both registered paths for `C-Hash-1024`.
- Claim: Each exact submitted input should reproduce its own recorded `1024`-bit digest through the selected path.
- Preconditions: Row bytes, bit length, output length, source-file digest and parameter set all match their pinned records.
- Limitations: Vectors may share defects with the implementation. A mismatch is candidate consistency evidence only; finite testing proves no security property.
- Extraction inference/ambiguity: The submitted vector is an experimental control and requires human specification review before normative promotion.
