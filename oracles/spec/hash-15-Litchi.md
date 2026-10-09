---
status: draft
target: hash-15
algorithm: Litchi
source_path: third_party/hash-15/source
source_sha256: 6bab82bda853334a6f628430e6309cd360997f966f5a5f08768da0be3bda5b41
document_path: third_party/hash-15/specification.pdf
document_sha256: 454300f46f71ea5cb74daa4df99f0a1a9c2276cdeb9aa7f9ff72f178b8e32bec
source_version: Litchi NGCC Round 1 submission
extract_version: 2
---

# Litchi submitted claim extraction

This draft covers the submitted Litchi parameter sets listed in the registry, including the original instance and additional fixed-output instances. The original source and document locations are recorded in `third_party/hash-15/download.json`. The submission is a candidate proposal; only a human reviewer may change this extraction to `verified`.

## S1 — Litchi-XOF requested output length and wrapper contract

- Source locator: Litchi PDF pp. 7–8, §2.2 (`Litchi[c,fid]` output construction and `MSB_|h|`), p. 11 §2.5 (`Litchi-XOF(M,|xof|)=Litchi[1024,1](M,|xof|)`); submitted `Litchi/Implementations/Reference_Implementation/Litchi-XOF/CryptHash_AlgorithmInstance.h` documents `digest_len_bits` as the total digest bits and the digest output pointer.
- Class: candidate specification construction plus submitted API contract.
- Scope: Litchi-XOF, valid public input bitstrings, requested 512/768/1024-bit outputs, the submitted `litchi_xof` core and `CryptHash` wrapper in this source snapshot, little-endian host.
- Claim: The XOF produces the requested number of digest bits. For the same input and request, the wrapper should match the core's requested output and should not write beyond the caller's requested output region.
- Preconditions: Both calls use the same message bytes, exact bit length and requested digest length; output space is provisioned with a visible canary past the requested length. Inputs follow the submitted KAT's MSB-first partial-byte representation.
- Limitations: The core and wrapper share implementation lineage. A canary change is candidate API write-bound evidence, not a sanitizer finding or demonstrated exploit. The PDF does not specify C buffer ownership; the write-bound relation is inferred from the submitted API header's requested-bit-length contract and requires human review before normative promotion. Finite tests do not prove XOF security.
- Extraction inference/ambiguity: The PDF specifies variable output; the C write bound follows from interpreting the wrapper's documented `digest_len_bits` as the caller-visible output size. This oracle does not claim a streaming API or prefix relation across different requests.

## S2 — Submitted 1024-bit Litchi-XOF KAT control

- Source locator: `Litchi/Test_Vectors/KAT_2_12_litchi_xof.txt` in the official ZIP; each record has `Msg_Len`, `Msg`, `Dst_Len=1024` and `Dst`.
- Class: submitted vector observation, not an independent normative claim.
- Scope: Exact selected records copied into the target package with source-file SHA-256 and original record index.
- Claim: A 1024-bit control call through both paths should reproduce its submitted `Dst`.
- Preconditions: Exact recorded message and bit length, 1024-bit request, no parameter-set substitution.
- Limitations: Vector generation uses the same submitted code lineage. Matching cannot establish independent conformance or security.
- Extraction inference/ambiguity: The submitted KAT is used for healthy control; requests shorter than 1024 bits are evaluated under S1 rather than by inventing unsupplied KAT values.

## LITCHI512-D — Litchi-512 submitted path agreement

- Source locator: PDF pp. 7–8 §2.2 and p. 11 §2.5; submitted instance headers under `Implementations` identify `Litchi-512` and `512`-bit output.
- Class: candidate specification construction and submitted API identity.
- Scope: Litchi-512, exact `512`-bit digest, public bitstrings, submitted fixed-length core and CryptHash wrapper, little-endian x86-64 host.
- Claim: For the same valid bitstring and digest length, the two submitted paths for `Litchi-512` should return the same deterministic digest.
- Preconditions: Exact input bytes and bit length, `512`-bit output, and the same archived source snapshot.
- Limitations: Shared code lineage can conceal common defects. Agreement does not prove independent conformance or a computational security claim; disagreement does not identify a faulty path.
- Extraction inference/ambiguity: Cross-path agreement follows from their common deterministic instance identity; the PDF does not make a software-backend claim. Unsupported digest lengths are excluded.

## LITCHI512-K — Litchi-512 submitted KAT control

- Source locator: `Litchi/Test_Vectors/KAT_2_12_litchi_512.txt` in the archived submission, SHA-256 `65c2f577d9f19e1e4b9ba65e5369f100c03fd71b28ada9e73f57e6f61ee222f8`, with `Msg_Len`, `Msg`, `Dst_Len` and `Dst` fields.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact selected `512`-bit KAT rows, their source indices and both registered paths for `Litchi-512`.
- Claim: Each exact submitted input should reproduce its own recorded `512`-bit digest through the selected path.
- Preconditions: Row bytes, bit length, output length, source-file digest and parameter set all match their pinned records.
- Limitations: Vectors may share defects with the implementation. A mismatch is candidate consistency evidence only; finite testing proves no security property.
- Extraction inference/ambiguity: The submitted vector is an experimental control and requires human specification review before normative promotion.

## LITCHI768-D — Litchi-768 submitted path agreement

- Source locator: PDF pp. 7–8 §2.2 and p. 11 §2.5; submitted instance headers under `Implementations` identify `Litchi-768` and `768`-bit output.
- Class: candidate specification construction and submitted API identity.
- Scope: Litchi-768, exact `768`-bit digest, public bitstrings, submitted fixed-length core and CryptHash wrapper, little-endian x86-64 host.
- Claim: For the same valid bitstring and digest length, the two submitted paths for `Litchi-768` should return the same deterministic digest.
- Preconditions: Exact input bytes and bit length, `768`-bit output, and the same archived source snapshot.
- Limitations: Shared code lineage can conceal common defects. Agreement does not prove independent conformance or a computational security claim; disagreement does not identify a faulty path.
- Extraction inference/ambiguity: Cross-path agreement follows from their common deterministic instance identity; the PDF does not make a software-backend claim. Unsupported digest lengths are excluded.

## LITCHI768-K — Litchi-768 submitted KAT control

- Source locator: `Litchi/Test_Vectors/KAT_2_12_litchi_768.txt` in the archived submission, SHA-256 `48eedb2ae42d26c0b386c0ee55bbebe3ddfe4610f5d980b19b9de2765f9b1e5f`, with `Msg_Len`, `Msg`, `Dst_Len` and `Dst` fields.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact selected `768`-bit KAT rows, their source indices and both registered paths for `Litchi-768`.
- Claim: Each exact submitted input should reproduce its own recorded `768`-bit digest through the selected path.
- Preconditions: Row bytes, bit length, output length, source-file digest and parameter set all match their pinned records.
- Limitations: Vectors may share defects with the implementation. A mismatch is candidate consistency evidence only; finite testing proves no security property.
- Extraction inference/ambiguity: The submitted vector is an experimental control and requires human specification review before normative promotion.

## LITCHI1024-D — Litchi-1024 submitted path agreement

- Source locator: PDF pp. 7–8 §2.2 and p. 11 §2.5; submitted instance headers under `Implementations` identify `Litchi-1024` and `1024`-bit output.
- Class: candidate specification construction and submitted API identity.
- Scope: Litchi-1024, exact `1024`-bit digest, public bitstrings, submitted fixed-length core and CryptHash wrapper, little-endian x86-64 host.
- Claim: For the same valid bitstring and digest length, the two submitted paths for `Litchi-1024` should return the same deterministic digest.
- Preconditions: Exact input bytes and bit length, `1024`-bit output, and the same archived source snapshot.
- Limitations: Shared code lineage can conceal common defects. Agreement does not prove independent conformance or a computational security claim; disagreement does not identify a faulty path.
- Extraction inference/ambiguity: Cross-path agreement follows from their common deterministic instance identity; the PDF does not make a software-backend claim. Unsupported digest lengths are excluded.

## LITCHI1024-K — Litchi-1024 submitted KAT control

- Source locator: `Litchi/Test_Vectors/KAT_2_12_litchi_1024.txt` in the archived submission, SHA-256 `b8477da6479801299dddd2a61487553fedabd7101ef6fdcf014c21dd198ffcc3`, with `Msg_Len`, `Msg`, `Dst_Len` and `Dst` fields.
- Class: submitted vector observation, not independent normative truth.
- Scope: Exact selected `1024`-bit KAT rows, their source indices and both registered paths for `Litchi-1024`.
- Claim: Each exact submitted input should reproduce its own recorded `1024`-bit digest through the selected path.
- Preconditions: Row bytes, bit length, output length, source-file digest and parameter set all match their pinned records.
- Limitations: Vectors may share defects with the implementation. A mismatch is candidate consistency evidence only; finite testing proves no security property.
- Extraction inference/ambiguity: The submitted vector is an experimental control and requires human specification review before normative promotion.

## S3 — Litchi-XOF output-request prefix relation

- Source locator: Litchi PDF pp. 7–8, §2.2 Squeezing Phase and Algorithm steps (4)–(5), where output is `MSB_|h|` of the generated blocks; p. 11 §2.5 defines Litchi-XOF as `Litchi[1024,1](M,|xof|)`.
- Class: candidate specification construction for the submitted XOF API.
- Scope: Litchi-XOF only, the same bitstring and same core or wrapper path, with 512-, 768- and 1024-bit output requests in the campaign domain.
- Claim: A shorter request returns the prefix of a longer request for the same message, because block generation depends on the fixed XOF parameters and block index while the request length selects how many leading bits are returned.
- Preconditions: Identical message and backend, only output request changes, both requests valid and both calls successful.
- Limitations: A prefix match does not prove XOF security or C buffer safety. The latter is assessed separately under S1.
- Extraction inference/ambiguity: The prefix relation follows from the stated `MSB` return rule and fixed `c=1024,fid=1`; the PDF does not directly specify software wrapper behavior, so wrapper evidence remains draft.
