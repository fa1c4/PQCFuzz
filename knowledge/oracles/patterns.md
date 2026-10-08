# Active oracle patterns

Catalog version: 1. Imported 2026-10-08 from E:/PQCFuzz/oracles/oracle_design_patterns.md, SHA-256 6FCB4FAAF55A1439C463660F42638941AB2D2DA0562B6FF7D694D355DA6D10CC. Each entry cites section 3, P1–P9, of that source. These are reusable design patterns, not proof of an implementation feature or a target-specific normative claim. Scheduling still requires an applicable property, source-backed claim, capability check, controls and smoke gate.

## Selection rule

Select a pattern only when its preconditions and target/API scope are established. Multiple patterns may apply to one oracle or target. A finite pass does not prove IND-CCA, unforgeability or other computational security goals.

### P1 — Known-answer and reference conformance

- Version: 1
- Scope: KEM, signature, hash/XOF/KDF, encoding or wrapper API with vectors or a compatible independent reference.
- Preconditions: Exact parameter set, representation, mode, context and randomness are aligned or explicitly normalized.
- Relation: Target output/status/length equals the vector or normalized reference on a shared defined input.
- Input design: Use official vectors or an independent reference with matched coins, profile and serialization.
- Failure predicate: A normalized value, length or return status differs where both sides are defined.
- Limitations: Agreement covers only the shared domain; common implementation lineage can hide a shared defect.
- Source: section 3, P1.

### P2 — Round-trip and inverse relation

- Version: 1
- Scope: KEM, signature, codec or another API with complementary operations.
- Preconditions: A valid baseline and the inverse/recovery relation are specified.
- Relation: Honest encapsulation/decapsulation, sign/verify or encode/decode satisfies its profile-specific relation.
- Input design: Construct honest keys, objects and calls through the declared API.
- Failure predicate: A valid transcript fails its inverse relation beyond permitted normalization.
- Limitations: Both operations can share a defect; a pass does not establish confidentiality or unforgeability.
- Source: section 3, P2.

### P3 — Cross-implementation and cross-backend differential

- Version: 1
- Scope: Compatible implementations, backends, wrappers or API paths.
- Preconditions: Common input domain and normalized bytes, status, lengths, randomness and encoding.
- Relation: Semantically equivalent executions yield equivalent normalized observations.
- Input design: Route one canonical structured input through explicitly compatible adapters.
- Failure predicate: Only one path accepts or normalized status, length or output diverges.
- Limitations: Divergence alone does not identify which side is wrong; an independent third source may be needed.
- Source: section 3, P3.

### P4 — Controlled-field metamorphic

- Version: 1
- Scope: KEM, signature, hash, protocol component or codec with a specified relation under field change.
- Preconditions: Valid baseline, one effective security-relevant field change, unrelated fields held fixed and target reachability.
- Relation: The specification-derived preserve/change/reject relation holds after the mutation.
- Input design: Change one message, context, domain, key, ciphertext or parameter field while holding unrelated fields fixed.
- Failure predicate: The follow-up execution violates the declared relation after effective mutation and target reachability.
- Limitations: Distinct inputs need not produce distinct outputs; a generic difference rule is unsound.
- Source: section 3, P4.

### P5 — Acceptance set and freshness

- Version: 1
- Scope: Verification, validation or acceptance APIs for signatures, keys, ciphertexts, tags and mathematical objects.
- Preconditions: A defined permitted validity set and, when needed, signed-message/pair history.
- Relation: Accepted objects satisfy the profile-specific validity predicate; a fresh witness is assessed under the right game.
- Input design: Mutate candidate objects and retain message/signature or key-use history where freshness matters.
- Failure predicate: The API accepts a witness excluded by the stated validity set or freshness relation.
- Limitations: A concrete witness requires normative and API interpretation; finite tests do not prove a forgery game.
- Source: section 3, P5.

### P6 — Canonical encoding and strict decoding

- Version: 1
- Scope: Serialized keys, signatures, ciphertexts, OIDs, structured objects and codecs.
- Preconditions: Raw encodings reach the API and the governing specification defines length/domain/canonicality.
- Relation: Canonical objects round trip; explicitly forbidden encodings reject.
- Input design: Vary length, unused bits, coefficients, OIDs, ordering, duplicates and trailing bytes at the raw API boundary.
- Failure predicate: A forbidden encoding is accepted, a canonical one is rejected or re-encoding violates the rule.
- Limitations: Multiple encodings are a bug only if canonicality or rejection is required by that API.
- Source: section 3, P6.

### P7 — Rejection, fallback and error contract

- Version: 1
- Scope: APIs with documented explicit rejection, implicit rejection or output-after-failure behavior.
- Preconditions: Public format errors and internal invalidity are separable; status and required outputs are observable.
- Relation: Each failure class follows its specified status, output and fallback relation without partial secret exposure.
- Input design: Separate public format errors from correctly sized internally invalid objects; record status, output length and bytes.
- Failure predicate: Wrong error class, exposed implicit rejection, stale/partial secret or incorrect fallback relation.
- Limitations: Functional observations do not establish constant-time behavior.
- Source: section 3, P7.

### P8 — Randomness dependency and failure propagation

- Version: 1
- Scope: Key generation, encapsulation, signing and other randomness-dependent operations.
- Preconditions: Random source can be injected, controlled or observed; failure/short read can be simulated.
- Relation: Required entropy failure propagates; no supposedly valid output is reported after it.
- Input design: Use scripted random sources for success, short read, repeated bytes, delayed failure and immediate failure.
- Failure predicate: An operation reports success after required RNG failure or consumes uninitialized bytes.
- Limitations: Scripted failures do not measure platform entropy quality or prove randomness.
- Source: section 3, P8.

### P9 — Runtime safety and progress

- Version: 1
- Scope: Public APIs processing external or structurally complex inputs.
- Preconditions: Sanitizer, timeout or resource instrumentation is enabled with a declared budget.
- Relation: Execution terminates safely within budget without memory/undefined-behavior findings.
- Input design: Exercise zero, exact and adjacent boundaries, truncation, oversized lengths and arithmetic wrap points.
- Failure predicate: Sanitizer finding, process crash, timeout, non-progress loop or abnormal memory growth.
- Limitations: A runtime failure is bug evidence, but does not alone establish cryptographic impact.
- Source: section 3, P9.


