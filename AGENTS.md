# PQCFuzz instructions for Codex

`designs/architecture.md` is the working design authority for PQCFuzz behavior. Read the relevant module document linked from the Modules section of `designs/architecture.md` before changing that module; only those linked module documents refine the root and none may contradict it. Unlisted design notes are not authoritative module designs. A target's external specification is the authority for algorithm-specific claims. `designs/actuality.md` records observed implementation behavior and has no design authority.

The design documents are initial drafts for human refinement. Follow their explicit requirements for current scoped work. If code and design disagree, record the discrepancy and implement the design when it is clear. If the design is ambiguous or a change requires a different decision, draft a focused design amendment for human review; do not silently invent or weaken a security claim.

For each behavior change, identify its design requirement and observable acceptance evidence. Run focused verification when the environment permits; record an unrun gate explicitly and do not claim it passed. Record the change in `history/YYYY-MM-DD.md` with intent, design references, implementation paths, verification commands/results, known limitations and unresolved human decisions. Implementation plans belong in `plans/`.

For target onboarding, read `agent/pqc_sop.md` in addition to the relevant designs. Do not infer a standard's normative claim from implementation behavior. Finite fuzzing does not prove a computational security game. Current campaigns produce candidate-only findings with exact source provenance, positive/negative controls and enough information for later replay; automatic replay validation and confirmed-vulnerability promotion are outside the current architecture.


