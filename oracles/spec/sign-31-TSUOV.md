---
status: draft
target: sign-31
algorithm: TSUOV
source_path: third_party/sign-31/source
source_sha256: c970311c547b4ce2436dd4d7f6e3d25da99439299574b30d94bc40fd75bd9c58
document_path: third_party/sign-31/specification.pdf
document_sha256: 17b2cb0d43a3f45c59fe79f2819bb6dcdc988fdc1a9776a40054d27761f5697a
source_version: NGCC Round 1 submitted archive
extract_version: 2
---

# TSUOV draft claim extraction

This document covers source-pinned public vector records and public API relations
for the named parameter sets. The algorithm construction and correctness context is
at PDF p. 4 (algorithm context). Original PDF and archived source are authoritative.

## TSUOV128-K — TSUOV_128 submitted valid-vector consistency

- Source locator: PDF p. 4 (algorithm context); `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Test_Vector/KAT_SIG_TSUOV_128.txt`, SHA-256 `f880573499a298ace2e834a9ea21be65e8aca4e9cd2543d48b273140618cd34c`.
- Class: correctness context from the PDF and submitted-vector observation; the latter is not independent normative truth.
- Scope: `TSUOV_128` `sig_verify` on the ten exact public submitted records, with API lengths and status.
- Claim: A valid submitted record is accepted by verification.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: The submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: A mismatch is candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## TSUOV128-SIGGETPKLENBYTES-C — TSUOV_128 sig_get_pk_len_bytes public API relation

- Source locator: `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Implementations/Reference_Implementation/TSUOV_128/SIG_AlgorithmInstance.h` SHA-256 `4611e1abc6fcb3365a73842c2912a7ea7cd02dcaa32b9d06126d227ce775d538`; `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Test_Vector/KAT_SIG_TSUOV_128.txt` SHA-256 `f880573499a298ace2e834a9ea21be65e8aca4e9cd2543d48b273140618cd34c`.
- Class: submitted API length/KAT observation.
- Scope: `TSUOV_128` `sig_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TSUOV128-SIGGETSKLENBYTES-C — TSUOV_128 sig_get_sk_len_bytes public API relation

- Source locator: `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Implementations/Reference_Implementation/TSUOV_128/SIG_AlgorithmInstance.h` SHA-256 `4611e1abc6fcb3365a73842c2912a7ea7cd02dcaa32b9d06126d227ce775d538`; `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Test_Vector/KAT_SIG_TSUOV_128.txt` SHA-256 `f880573499a298ace2e834a9ea21be65e8aca4e9cd2543d48b273140618cd34c`.
- Class: submitted API length/KAT observation.
- Scope: `TSUOV_128` `sig_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TSUOV128-SIGGETSNLENBYTES-C — TSUOV_128 sig_get_sn_len_bytes public API relation

- Source locator: `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Implementations/Reference_Implementation/TSUOV_128/SIG_AlgorithmInstance.h` SHA-256 `4611e1abc6fcb3365a73842c2912a7ea7cd02dcaa32b9d06126d227ce775d538`; `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Test_Vector/KAT_SIG_TSUOV_128.txt` SHA-256 `f880573499a298ace2e834a9ea21be65e8aca4e9cd2543d48b273140618cd34c`.
- Class: submitted API length/KAT observation.
- Scope: `TSUOV_128` `sig_get_sn_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TSUOV128-SIGKEYGEN-C — TSUOV_128 sig_keygen public API relation

- Source locator: PDF p. 24; `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Implementations/Reference_Implementation/TSUOV_128/SIG_AlgorithmInstance.h` SHA-256 `4611e1abc6fcb3365a73842c2912a7ea7cd02dcaa32b9d06126d227ce775d538`; `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Test_Vector/KAT_SIG_TSUOV_128.txt` SHA-256 `f880573499a298ace2e834a9ea21be65e8aca4e9cd2543d48b273140618cd34c`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `TSUOV_128` `sig_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TSUOV128-SIGSIGN-C — TSUOV_128 sig_sign public API relation

- Source locator: PDF p. 24; `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Implementations/Reference_Implementation/TSUOV_128/SIG_AlgorithmInstance.h` SHA-256 `4611e1abc6fcb3365a73842c2912a7ea7cd02dcaa32b9d06126d227ce775d538`; `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Test_Vector/KAT_SIG_TSUOV_128.txt` SHA-256 `f880573499a298ace2e834a9ea21be65e8aca4e9cd2543d48b273140618cd34c`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `TSUOV_128` `sig_sign` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TSUOV256-K — TSUOV_256 submitted valid-vector consistency

- Source locator: PDF p. 24 (algorithm context); `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Test_Vector/KAT_SIG_TSUOV_256.txt` SHA-256 `21651f608d47524782f6728d34de20d80823a2e45bee67a4f327d6481bd54dec`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `TSUOV_256` `sig_verify` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records are accepted by sig_verify.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## TSUOV512-K — TSUOV_512 submitted valid-vector consistency

- Source locator: PDF p. 24 (algorithm context); `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Test_Vector/KAT_SIG_TSUOV_512.txt` SHA-256 `bac1cf750e1900bc72d283ab7c0ecb6991303464b258546a9adfb1f9f7fd9f6e`.
- Class: PDF correctness context and submitted-vector observation; the latter is not independent normative truth.
- Scope: `TSUOV_512` `sig_verify` on ten exact public submitted records, with API lengths and status.
- Claim: Both valid submitted records are accepted by sig_verify.
- Preconditions: Exact source/KAT digest, parameter set, record index, public test-vector fields and matching API lengths.
- Extraction inference/ambiguity: Submitted vectors may share implementation lineage and do not prove reliability or security.
- Limitations: Candidate-only; this slice does not exercise fresh key generation or malformed inputs.

## TSUOV256-SIGGETPKLENBYTES-C — TSUOV_256 sig_get_pk_len_bytes public API relation

- Source locator: `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Implementations/Reference_Implementation/TSUOV_256/SIG_AlgorithmInstance.h` SHA-256 `4611e1abc6fcb3365a73842c2912a7ea7cd02dcaa32b9d06126d227ce775d538`; `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Test_Vector/KAT_SIG_TSUOV_256.txt` SHA-256 `21651f608d47524782f6728d34de20d80823a2e45bee67a4f327d6481bd54dec`.
- Class: submitted API length/KAT observation.
- Scope: `TSUOV_256` `sig_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TSUOV256-SIGGETSKLENBYTES-C — TSUOV_256 sig_get_sk_len_bytes public API relation

- Source locator: `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Implementations/Reference_Implementation/TSUOV_256/SIG_AlgorithmInstance.h` SHA-256 `4611e1abc6fcb3365a73842c2912a7ea7cd02dcaa32b9d06126d227ce775d538`; `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Test_Vector/KAT_SIG_TSUOV_256.txt` SHA-256 `21651f608d47524782f6728d34de20d80823a2e45bee67a4f327d6481bd54dec`.
- Class: submitted API length/KAT observation.
- Scope: `TSUOV_256` `sig_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TSUOV256-SIGGETSNLENBYTES-C — TSUOV_256 sig_get_sn_len_bytes public API relation

- Source locator: `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Implementations/Reference_Implementation/TSUOV_256/SIG_AlgorithmInstance.h` SHA-256 `4611e1abc6fcb3365a73842c2912a7ea7cd02dcaa32b9d06126d227ce775d538`; `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Test_Vector/KAT_SIG_TSUOV_256.txt` SHA-256 `21651f608d47524782f6728d34de20d80823a2e45bee67a4f327d6481bd54dec`.
- Class: submitted API length/KAT observation.
- Scope: `TSUOV_256` `sig_get_sn_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TSUOV256-SIGKEYGEN-C — TSUOV_256 sig_keygen public API relation

- Source locator: PDF p. 24; `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Implementations/Reference_Implementation/TSUOV_256/SIG_AlgorithmInstance.h` SHA-256 `4611e1abc6fcb3365a73842c2912a7ea7cd02dcaa32b9d06126d227ce775d538`; `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Test_Vector/KAT_SIG_TSUOV_256.txt` SHA-256 `21651f608d47524782f6728d34de20d80823a2e45bee67a4f327d6481bd54dec`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `TSUOV_256` `sig_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TSUOV256-SIGSIGN-C — TSUOV_256 sig_sign public API relation

- Source locator: PDF p. 24; `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Implementations/Reference_Implementation/TSUOV_256/SIG_AlgorithmInstance.h` SHA-256 `4611e1abc6fcb3365a73842c2912a7ea7cd02dcaa32b9d06126d227ce775d538`; `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Test_Vector/KAT_SIG_TSUOV_256.txt` SHA-256 `21651f608d47524782f6728d34de20d80823a2e45bee67a4f327d6481bd54dec`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `TSUOV_256` `sig_sign` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TSUOV512-SIGGETPKLENBYTES-C — TSUOV_512 sig_get_pk_len_bytes public API relation

- Source locator: `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Implementations/Reference_Implementation/TSUOV_512/SIG_AlgorithmInstance.h` SHA-256 `4611e1abc6fcb3365a73842c2912a7ea7cd02dcaa32b9d06126d227ce775d538`; `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Test_Vector/KAT_SIG_TSUOV_512.txt` SHA-256 `bac1cf750e1900bc72d283ab7c0ecb6991303464b258546a9adfb1f9f7fd9f6e`.
- Class: submitted API length/KAT observation.
- Scope: `TSUOV_512` `sig_get_pk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TSUOV512-SIGGETSKLENBYTES-C — TSUOV_512 sig_get_sk_len_bytes public API relation

- Source locator: `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Implementations/Reference_Implementation/TSUOV_512/SIG_AlgorithmInstance.h` SHA-256 `4611e1abc6fcb3365a73842c2912a7ea7cd02dcaa32b9d06126d227ce775d538`; `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Test_Vector/KAT_SIG_TSUOV_512.txt` SHA-256 `bac1cf750e1900bc72d283ab7c0ecb6991303464b258546a9adfb1f9f7fd9f6e`.
- Class: submitted API length/KAT observation.
- Scope: `TSUOV_512` `sig_get_sk_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TSUOV512-SIGGETSNLENBYTES-C — TSUOV_512 sig_get_sn_len_bytes public API relation

- Source locator: `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Implementations/Reference_Implementation/TSUOV_512/SIG_AlgorithmInstance.h` SHA-256 `4611e1abc6fcb3365a73842c2912a7ea7cd02dcaa32b9d06126d227ce775d538`; `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Test_Vector/KAT_SIG_TSUOV_512.txt` SHA-256 `bac1cf750e1900bc72d283ab7c0ecb6991303464b258546a9adfb1f9f7fd9f6e`.
- Class: submitted API length/KAT observation.
- Scope: `TSUOV_512` `sig_get_sn_len_bytes` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: Its reported allocation/serialization length equals the exact submitted KAT object length (signature length may be an upper bound where documented).
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; submitted KAT length is same-lineage control data.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TSUOV512-SIGKEYGEN-C — TSUOV_512 sig_keygen public API relation

- Source locator: PDF p. 24; `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Implementations/Reference_Implementation/TSUOV_512/SIG_AlgorithmInstance.h` SHA-256 `4611e1abc6fcb3365a73842c2912a7ea7cd02dcaa32b9d06126d227ce775d538`; `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Test_Vector/KAT_SIG_TSUOV_512.txt` SHA-256 `bac1cf750e1900bc72d283ab7c0ecb6991303464b258546a9adfb1f9f7fd9f6e`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `TSUOV_512` `sig_keygen` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.

## TSUOV512-SIGSIGN-C — TSUOV_512 sig_sign public API relation

- Source locator: PDF p. 24; `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Implementations/Reference_Implementation/TSUOV_512/SIG_AlgorithmInstance.h` SHA-256 `4611e1abc6fcb3365a73842c2912a7ea7cd02dcaa32b9d06126d227ce775d538`; `Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Test_Vector/KAT_SIG_TSUOV_512.txt` SHA-256 `bac1cf750e1900bc72d283ab7c0ecb6991303464b258546a9adfb1f9f7fd9f6e`.
- Class: correctness construction and API contract; P2 relation is an explicit extraction inference.
- Scope: `TSUOV_512` `sig_sign` in the pinned primary reference implementation and ten public submitted KAT records.
- Claim: For a valid submitted key pair or a freshly generated key pair, the submitted complementary public operations complete an honest roundtrip.
- Preconditions: Exact source/KAT digest, declared buffer capacities, valid submitted key or deterministic public KAT seed, matching parameter set and reached public API.
- Extraction inference/ambiguity: The source API declares the operation; honest inverse relation follows the cited construction and submitted API pairing, while randomness bytes are not expected to match the submitted KAT.
- Limitations: Candidate-only with draft extraction; no computational security proof, independent implementation claim or malformed-input conclusion.
