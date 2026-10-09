---
status: draft
target: hash-05
algorithm: uHash
source_path: third_party/hash-05/source
source_sha256: 928e536fc96eabd2ab052ef2d35be5bae569f2f0f231780b7ec178498774d910
document_path: third_party/hash-05/specification.pdf
document_sha256: 65ae853b822e967f63eacb441ffeb68c37861441e7e3e4812c519f6de71c7e87
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# uHash-512 draft claim extraction

The original source and PDF are pinned above. This extract covers only the
`uHash-512` submitted `CryptHash` API. The cited construction and parameter
discussion is on PDF pp. 4–5; the exact source and PDF files are authoritative.

## S2 — Submitted KAT consistency

- Source locator: `uHash/Test_Vectors/4 测试向量/Test_Vectors/KAT_2_12_uHash-512.txt`, SHA-256 `015811a8d1bb0fafb096004df4e82173a2718b1b2a95c4a27f5dfb7b8b827588`, fields `Msg_Len`, `Msg`, `Dst_Len`, `Dst`.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact pinned 512-bit KAT records and the registered reference `uHash-512` `CryptHash` path.
- Claim: The exact recorded message and bit length should reproduce its corresponding submitted digest on each backend.
- Preconditions: Exact record index, bytes, bit length, output length and KAT-file digest are bound in the case.
- Extraction inference/ambiguity: Vector provenance is the archive itself; the vector generator may share implementation lineage.
- Limitations: A mismatch is candidate consistency evidence requiring review. Finite KAT sampling proves no computational security property.
