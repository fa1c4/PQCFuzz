---
status: draft
target: hash-14
algorithm: Laurus
source_path: third_party/hash-14/source
source_sha256: 30fde56f556b4921e20ec32f6c83bc5e8d9b23f89f4082f5cacc92d6acbe6572
document_path: third_party/hash-14/specification.pdf
document_sha256: 63190edaf6bd2b85c93f21f49412567cfcb0c8330063c9124d19cd64cd91b141
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# laurus_512 draft claim extraction

The original source and PDF are pinned above. This extract covers only the
`laurus_512` submitted `CryptHash` API. The cited construction and parameter
discussion is on PDF pp. 7–8; the exact source and PDF files are authoritative.

## S2 — Submitted KAT consistency

- Source locator: `Laurus/Test_Vectors/KAT_2_12_laurus_512.txt`, SHA-256 `6f9e07e6fe31084f75875a62ae16680319c26d304f1686f69d689f22ef1c14ba`, fields `Msg_Len`, `Msg`, `Dst_Len`, `Dst`.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact pinned 512-bit KAT records and the registered reference `laurus_512` `CryptHash` path.
- Claim: The exact recorded message and bit length should reproduce its corresponding submitted digest on each backend.
- Preconditions: Exact record index, bytes, bit length, output length and KAT-file digest are bound in the case.
- Extraction inference/ambiguity: Vector provenance is the archive itself; the vector generator may share implementation lineage.
- Limitations: A mismatch is candidate consistency evidence requiring review. Finite KAT sampling proves no computational security property.
