---
status: draft
target: demo-stream-hash
algorithm: DEMO-HASH
source_path: third_party/demo-stream-hash/source
source_sha256: d108f4e6ba99e181c2bdd48356bce6d7d2f901f69031ce42159d9340a46e8912
document_path: third_party/demo-stream-hash/specification.md
document_sha256: 87e0e0db9f0cc239a035ee5ee078ab5903ab52cf907ba8ee0da7f7b09a34b91c
source_version: local-fixture-v1
extract_version: 1
---

# Demo stream hash claim extraction

Original document: §third_party/demo-stream-hash/specification.md§, Section 1.
Document SHA-256: §87e0e0db9f0cc239a035ee5ee078ab5903ab52cf907ba8ee0da7f7b09a34b91c`.
This is a local test fixture, not a PQC standard.

## S1 — Streaming consistency

- Source locator: Section 1, streaming relation.
- Class: local API contract.
- Scope: DEMO-HASH, 32-byte digest, stream API, arbitrary public byte message.
- Claim: Splitting the same message into chunks does not change its digest.
- Preconditions: Concatenated chunk bytes are identical.
- Limitations: Does not claim collision or preimage resistance.
- Extraction inference/ambiguity: none for this fixture.
