---
status: draft
target: hash-11
algorithm: Garnet
source_path: third_party/hash-11/source
source_sha256: f043bbc1935c347a717fa0295058b990ff68f28a927931006f2f3bd9ca5ba2e9
document_path: third_party/hash-11/specification.pdf
document_sha256: 2e979d34a1a938f1730780a25ca252130c6c7a9e2ae4acd155d55568586e0083
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# Garnet_512_Cap1024 draft claim extraction

The original source and PDF are pinned above. This extract covers only the
`Garnet_512_Cap1024` submitted `CryptHash` API. The cited construction and parameter
discussion is on PDF pp. 10–13; the exact source and PDF files are authoritative.

## S2 — Submitted KAT consistency

- Source locator: `Garnet/Implementations/API_CryptHash/Test_Vector/KAT_2_12_Garnet_512_Cap1024.txt`, SHA-256 `00d568ae3e7627c7580f2c50106db53856192f2d2e8b616b7336a49c47e7a39a`, fields `Msg_Len`, `Msg`, `Dst_Len`, `Dst`.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact pinned 512-bit KAT records and the registered reference `Garnet_512_Cap1024` `CryptHash` path.
- Claim: The exact recorded message and bit length should reproduce its corresponding submitted digest on each backend.
- Preconditions: Exact record index, bytes, bit length, output length and KAT-file digest are bound in the case.
- Extraction inference/ambiguity: Vector provenance is the archive itself; the vector generator may share implementation lineage.
- Limitations: A mismatch is candidate consistency evidence requiring review. Finite KAT sampling proves no computational security property.
