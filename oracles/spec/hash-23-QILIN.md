---
status: draft
target: hash-23
algorithm: QILIN
source_path: third_party/hash-23/source
source_sha256: 369b3ba92203c64692df2788e43d339a4237536e7d86af97bd8bc93f4ffaba32
document_path: third_party/hash-23/specification.pdf
document_sha256: e439fab38326cceff893a17cc3f2fd2df78be9e2f603a737efec445de328e849
source_version: Qilin v2 2026-06-30 NGCC Round 1 submission
extract_version: 2
---

# QILIN submission claim extraction

This draft covers the submitted QILIN parameter sets listed in the registry, including the original instance and additional fixed-output instances. The original source and document locations are recorded in `third_party/hash-23/download.json`. The submission is a candidate proposal; only a human reviewer may change this extraction to `verified`.

## S1 — QILIN-512 bitstring hashing

- Source locator: Qilin v2, printed pp. 3–4 (PDF pp. 4–5), §1.1 bitstring notation, §1.2 Algorithm 1, and §1.3 QILIN-512 round count. The submitted `QILIN/Implementations/{Reference_Implementation,Optimized_Implementation}/QILIN-512/CryptHash_AlgorithmInstance.h` names the same instance and 512-bit digest.
- Class: candidate specification construction and submitted API identity.
- Scope: QILIN-512 only, 512-bit digest, public bitstring input, little-endian host, `CryptHash` reference and optimized implementations in this source snapshot.
- Claim: Algorithm 1 defines a deterministic 512-bit digest for a given input bitstring. The two submitted QILIN-512 implementations of that same instance should return the same digest for the same valid bitstring.
- Preconditions: Identical bit length and most-significant-bit-first message content; both calls use `digest_len_bits=512` and the same submitted snapshot. Only the two named backends are compared.
- Limitations: Agreement does not establish conformity to Algorithm 1, collision resistance, preimage resistance, or independence of the two implementations. A mismatch alone does not identify the faulty backend.
- Extraction inference/ambiguity: Cross-backend equality follows from the common function identity and deterministic construction; Algorithm 1 does not itself discuss software backends. The PDF does not specify behavior for unsupported digest lengths, so this oracle never exercises them.

## S2 — Submitted QILIN-512 test-vector control

- Source locator: `QILIN/Test_Vectors/KAT_2_12_QILIN-512.txt` in the same official ZIP; its `Msg_Len`, `Msg`, `Dst_Len`, and `Dst` records are generated through the ICCS `KAT_CryptHash.c` API. The submitted QILIN-512 README specifies MSB-first handling for partial-byte inputs.
- Class: submitted test-vector observation, not an independent normative claim.
- Scope: QILIN-512, `CryptHash`, the exact selected vector records copied into the target package with source file SHA-256.
- Claim: A control case should reproduce the digest recorded for that exact submitted message and bit length in both backends.
- Preconditions: Exact `Msg_Len`, `Msg`, and `Dst_Len=512` from a recorded row; no substitution between parameter sets.
- Limitations: These vectors may share lineage with the submitted implementations. Matching them cannot prove an independent security property. A mismatch is a candidate consistency issue requiring triage.
- Extraction inference/ambiguity: The vectors are treated as submitted expectations for control and consistency, not as human-verified specification conformance.

## QILIN768-D — QILIN-768 submitted path agreement

- Source locator: PDF pp. 4–5 §1.2 Algorithm 1 and p. 19 family table; submitted instance headers under `Implementations` identify `QILIN-768` and `768`-bit output.
- Class: candidate specification construction and submitted API identity.
- Scope: QILIN-768, exact `768`-bit digest, public bitstrings, submitted reference and optimized CryptHash backends, little-endian x86-64 host.
- Claim: For the same valid bitstring and digest length, the two submitted paths for `QILIN-768` should return the same deterministic digest.
- Preconditions: Exact input bytes and bit length, `768`-bit output, and the same archived source snapshot.
- Limitations: Shared code lineage can conceal common defects. Agreement does not prove independent conformance or a computational security claim; disagreement does not identify a faulty path.
- Extraction inference/ambiguity: Cross-path agreement follows from their common deterministic instance identity; the PDF does not make a software-backend claim. Unsupported digest lengths are excluded.

## QILIN768-K — QILIN-768 submitted KAT control

- Source locator: `QILIN/Test_Vectors/KAT_2_12_QILIN-768.txt` in the archived submission, SHA-256 `d1e38fc7c9a93d91fee32039bc7e5a7cda827cb828e631dc535d2f9f31516390`, with `Msg_Len`, `Msg`, `Dst_Len` and `Dst` fields.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact selected `768`-bit KAT rows, their source indices and both registered paths for `QILIN-768`.
- Claim: Each exact submitted input should reproduce its own recorded `768`-bit digest through the selected path.
- Preconditions: Row bytes, bit length, output length, source-file digest and parameter set all match their pinned records.
- Limitations: Vectors may share defects with the implementation. A mismatch is candidate consistency evidence only; finite testing proves no security property.
- Extraction inference/ambiguity: The submitted vector is an experimental control and requires human specification review before normative promotion.

## QILIN1024-D — QILIN-1024 submitted path agreement

- Source locator: PDF pp. 4–5 §1.2 Algorithm 1 and p. 19 family table; submitted instance headers under `Implementations` identify `QILIN-1024` and `1024`-bit output.
- Class: candidate specification construction and submitted API identity.
- Scope: QILIN-1024, exact `1024`-bit digest, public bitstrings, submitted reference and optimized CryptHash backends, little-endian x86-64 host.
- Claim: For the same valid bitstring and digest length, the two submitted paths for `QILIN-1024` should return the same deterministic digest.
- Preconditions: Exact input bytes and bit length, `1024`-bit output, and the same archived source snapshot.
- Limitations: Shared code lineage can conceal common defects. Agreement does not prove independent conformance or a computational security claim; disagreement does not identify a faulty path.
- Extraction inference/ambiguity: Cross-path agreement follows from their common deterministic instance identity; the PDF does not make a software-backend claim. Unsupported digest lengths are excluded.

## QILIN1024-K — QILIN-1024 submitted KAT control

- Source locator: `QILIN/Test_Vectors/KAT_2_12_QILIN-1024.txt` in the archived submission, SHA-256 `4c9cad7de191c5751e3c9477e1159ba0e676d01e81c9181da7395a671580f851`, with `Msg_Len`, `Msg`, `Dst_Len` and `Dst` fields.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact selected `1024`-bit KAT rows, their source indices and both registered paths for `QILIN-1024`.
- Claim: Each exact submitted input should reproduce its own recorded `1024`-bit digest through the selected path.
- Preconditions: Row bytes, bit length, output length, source-file digest and parameter set all match their pinned records.
- Limitations: Vectors may share defects with the implementation. A mismatch is candidate consistency evidence only; finite testing proves no security property.
- Extraction inference/ambiguity: The submitted vector is an experimental control and requires human specification review before normative promotion.
