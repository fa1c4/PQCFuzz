# Adapters design

Parent: [architecture.md](architecture.md). Implements DES-01, DES-03, DES-06.

## Declaration

Each target package contains an explicit `implement/adapter.py`. Its manifest declares primitive, algorithm, parameter set, API, implementation/source digest, status/length semantics and capabilities (`rng_control`, `fault_injection`, `intermediate_state`, `decapsulation_failure`, and any target-specific named capability). The adapter never substitutes another algorithm, profile or implementation. It invokes the copied target source in the run directory and normalizes one call into structured status, output and reached-target evidence.

## Invocation protocol

The isolated worker calls `invoke(structured_input, source_root, profile) -> observation`. An observation includes `reached`, `status`, `output`, `output_length` and optional public diagnostics. Target exceptions, crashes or timeout remain harness/process observations, not semantic success. Inputs and outputs are JSON values, with binary values encoded as lowercase hex and lengths checked by the adapter. The adapter rejects malformed input before a target call and marks reachability false. It may not claim independent-reference status solely because a second wrapper exists.

## Capability and controls

Runtime checks required capabilities before scheduling. A missing capability is `unsupported`; an out-of-scope primitive is `not_applicable`. Reachability must refer to the actual target API call, not just arrival at the adapter. Control cases use the same adapter path as campaigns.

## Acceptance

A wrong capability or API is rejected; one real target call yields reached=true; a pre-call validation rejection yields reached=false.