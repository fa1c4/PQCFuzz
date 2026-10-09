---
status: draft
target: sign-33
algorithm: VDOO
source_path: third_party/sign-33/source
source_sha256: 779727a3bac2b4783260ef485899a406291c062340d63b49216c0d6a5733bfc0
document_path: third_party/sign-33/specification.pdf
document_sha256: eb22504626a5d02191b7790061de0ffa499eeb6b1d19d99cf5b87d3e28696ab0
source_version: NGCC Round 1 submitted archive
extract_version: 1
---

# VDOO draft claim extraction

This document covers public submitted KAT verification and fresh signing
under the exact `sig_sign` and `sig_verify` APIs. The algorithm construction and correctness context is
at PDF p. 10 Algorithm 5 and p. 23 §7.5–7.7. Original PDF and archived source are authoritative.

## VDOO128-K — VDOO-128 submitted valid-vector consistency

- Source locator: PDF p. 10 Algorithm 5 and p. 23 §7.5–7.7; `Test_Vectors/KAT_SIG_VDOO-128.txt`, SHA-256 `661ed1a59e7936beaf74d3efb029b25cc72ee6aab4299f53b08b2479fe850469`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `VDOO-128` `sig_verify` on the ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record is accepted by verification.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## VDOO256-K — VDOO-256 submitted valid-vector consistency

- Source locator: PDF p. 10 Algorithm 5 and p. 23 §7.5–7.7; `Test_Vectors/KAT_SIG_VDOO-256.txt`, SHA-256 `50b581be5fe415906c38be3041c320d46322ddac1b42e515db4332238ea0eb43`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `VDOO-256` `sig_verify` on the ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record is accepted by verification.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## VDOO512-K — VDOO-512 submitted valid-vector consistency

- Source locator: PDF p. 10 Algorithm 5 and p. 23 §7.5–7.7; `Test_Vectors/KAT_SIG_VDOO-512.txt`, SHA-256 `f6c600292058fc42755492d4d655e68db4c091443c40dce37ac04cec630ae0bf`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `VDOO-512` `sig_verify` on the ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record is accepted by verification.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## VDOO128-V — VDOO-128 signed-message acceptance boundary

- Source locator: `third_party/sign-33/specification.pdf`, PDF p. 10 Algorithm 5 (verification), p. 19 §5.7 (EUF-CMA claim); submitted `Test_Vectors/KAT_SIG_VDOO-128.txt` signed-message records.
- Class: proposed verification rule and public submitted-vector observation.
- Scope: Exact `VDOO-128` public KAT key/signature/message triple, changing only the first bit of a nonempty message.
- Claim: The archived signature verifies on its archived message; the same signature on a different message should reject, absent a concrete collision/forgery witness.
- Preconditions: One indexed KAT record, same public key/signature, nonempty message, exactly one changed message bit, actual `sig_verify` calls.
- Extraction inference/ambiguity: Algorithm 5 compares the signature's public-map value with the hash of message and salt; acceptance after mutation would need cryptographic review, not automatic normative promotion.
- Limitations: A finite rejection run does not prove EUF-CMA security; only one altered bit and public vectors are tested.

## VDOO256-V — VDOO-256 signed-message acceptance boundary

- Source locator: `third_party/sign-33/specification.pdf`, PDF p. 10 Algorithm 5 (verification), p. 19 §5.7 (EUF-CMA claim); submitted `Test_Vectors/KAT_SIG_VDOO-256.txt` signed-message records.
- Class: proposed verification rule and public submitted-vector observation.
- Scope: Exact `VDOO-256` public KAT key/signature/message triple, changing only the first bit of a nonempty message.
- Claim: The archived signature verifies on its archived message; the same signature on a different message should reject, absent a concrete collision/forgery witness.
- Preconditions: One indexed KAT record, same public key/signature, nonempty message, exactly one changed message bit, actual `sig_verify` calls.
- Extraction inference/ambiguity: Algorithm 5 compares the signature's public-map value with the hash of message and salt; acceptance after mutation would need cryptographic review, not automatic normative promotion.
- Limitations: A finite rejection run does not prove EUF-CMA security; only one altered bit and public vectors are tested.

## VDOO512-V — VDOO-512 signed-message acceptance boundary

- Source locator: `third_party/sign-33/specification.pdf`, PDF p. 10 Algorithm 5 (verification), p. 19 §5.7 (EUF-CMA claim); submitted `Test_Vectors/KAT_SIG_VDOO-512.txt` signed-message records.
- Class: proposed verification rule and public submitted-vector observation.
- Scope: Exact `VDOO-512` public KAT key/signature/message triple, changing only the first bit of a nonempty message.
- Claim: The archived signature verifies on its archived message; the same signature on a different message should reject, absent a concrete collision/forgery witness.
- Preconditions: One indexed KAT record, same public key/signature, nonempty message, exactly one changed message bit, actual `sig_verify` calls.
- Extraction inference/ambiguity: Algorithm 5 compares the signature's public-map value with the hash of message and salt; acceptance after mutation would need cryptographic review, not automatic normative promotion.
- Limitations: A finite rejection run does not prove EUF-CMA security; only one altered bit and public vectors are tested.

## VDOO128-R — VDOO-128 fresh signing under submitted honest keypair

- Source locator: `third_party/sign-33/specification.pdf`, PDF p. 10 Algorithms 4–5 and p. 23 §7.5–7.7; archived `Test_Vectors/KAT_SIG_VDOO-128.txt`, SHA-256 `661ed1a59e7936beaf74d3efb029b25cc72ee6aab4299f53b08b2479fe850469`.
- Class: signature correctness relation from PDF, with public submitted key/message/seed controls.
- Scope: `VDOO-128` actual `sig_sign` then `sig_verify` on ten indexed submitted keypairs and their recorded messages; the keypairs were produced by the submitted KAT driver using `sig_keygen`.
- Claim: A newly generated signature on the matching message verifies under its matching honest public key.
- Preconditions: Exact source/PDF/KAT identity, matching parameter/lengths, public KAT keypair, nonempty message, seeded signing RNG and successful `sig_sign`.
- Extraction inference/ambiguity: This oracle does not assert that the newly generated signature matches the archived signature bytes; seed controls the implementation RNG but signing may consume it differently.
- Limitations: Finite valid-message round trips do not prove unforgeability, signing reliability or malformed-signature rejection.

## VDOO256-R — VDOO-256 fresh signing under submitted honest keypair

- Source locator: `third_party/sign-33/specification.pdf`, PDF p. 10 Algorithms 4–5 and p. 23 §7.5–7.7; archived `Test_Vectors/KAT_SIG_VDOO-256.txt`, SHA-256 `50b581be5fe415906c38be3041c320d46322ddac1b42e515db4332238ea0eb43`.
- Class: signature correctness relation from PDF, with public submitted key/message/seed controls.
- Scope: `VDOO-256` actual `sig_sign` then `sig_verify` on ten indexed submitted keypairs and their recorded messages; the keypairs were produced by the submitted KAT driver using `sig_keygen`.
- Claim: A newly generated signature on the matching message verifies under its matching honest public key.
- Preconditions: Exact source/PDF/KAT identity, matching parameter/lengths, public KAT keypair, nonempty message, seeded signing RNG and successful `sig_sign`.
- Extraction inference/ambiguity: This oracle does not assert that the newly generated signature matches the archived signature bytes; seed controls the implementation RNG but signing may consume it differently.
- Limitations: Finite valid-message round trips do not prove unforgeability, signing reliability or malformed-signature rejection.

## VDOO512-R — VDOO-512 fresh signing under submitted honest keypair

- Source locator: `third_party/sign-33/specification.pdf`, PDF p. 10 Algorithms 4–5 and p. 23 §7.5–7.7; archived `Test_Vectors/KAT_SIG_VDOO-512.txt`, SHA-256 `f6c600292058fc42755492d4d655e68db4c091443c40dce37ac04cec630ae0bf`.
- Class: signature correctness relation from PDF, with public submitted key/message/seed controls.
- Scope: `VDOO-512` actual `sig_sign` then `sig_verify` on ten indexed submitted keypairs and their recorded messages; the keypairs were produced by the submitted KAT driver using `sig_keygen`.
- Claim: A newly generated signature on the matching message verifies under its matching honest public key.
- Preconditions: Exact source/PDF/KAT identity, matching parameter/lengths, public KAT keypair, nonempty message, seeded signing RNG and successful `sig_sign`.
- Extraction inference/ambiguity: This oracle does not assert that the newly generated signature matches the archived signature bytes; seed controls the implementation RNG but signing may consume it differently.
- Limitations: Finite valid-message round trips do not prove unforgeability, signing reliability or malformed-signature rejection.
