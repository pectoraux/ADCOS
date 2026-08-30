# WORK-040 Correction-Cycle Handoff (repository-local)

**Status: ACTIVE — the durable handoff for the WORK-040 correction cycle
referenced by the active authorization `WORK-040-CORRECTION-001`.**

This is the governance-level handoff on `main`. The implementation-level
handoff (topology, roles, journal, evidence model) lives on the delivery
branch `work-040-pilot-deployment` (PR #48) as `docs/WORK-040-handoff.md`
and in the PR #48 body. Nothing in chat is authoritative.

## Authority

- Authorization: `spec/architect/authorizations/WORK-040.yaml` —
  `WORK-040-CORRECTION-001`, `status: active`, baseline
  `93efa54f1edc2ec3c0bb5646827719f92af06b86`.
- Decision: DEC-0046 (round 1 verdict on PR #48: CHANGES_REQUIRED) —
  `spec/architect/decisions/DEC-0046-w040-correction-authorization.yaml`.
- The authorization becomes persistent authority when PR #61 merges; until
  then it is proposed state carried by PR #61.

## What exists already (do not regress)

- Delivered pilot on PR #48, head `ee9b356`, CI run 33278751838 SUCCESS:
  a REAL multi-process deployment (4 OS processes, 3 real TCP carriage
  paths + a real upstream egress probe, production chains only, a genuine
  local service invocation, verbatim relay carriage, a REAL declared
  failure transition survived by the SAME logical session), deterministic
  run digest `sha256:079845bfe8c44dcaa7ea4c3678ea76547b0d4148b00b9ee3d86c44ef1dc4f551`.
- Criteria 3–6 are evidenced (operational class): non-cellular path,
  relay/backhaul path, resilience/failover, operational evidence.

## Required corrections (the ONLY authorized implementation scope)

1. Demonstrate real-device participation using an actual physical endpoint
   while preserving the production ADCOS chain (EVID-007).
2. Attempt and, only if genuinely available, demonstrate a real 5G access
   path; distinguish 5G from generic cellular evidence (EVID-008).
3. Preserve the already demonstrated non-cellular, relay/backhaul,
   failover, and operational evidence.
4. Keep all evidence provenance exact; classify unavailable physical
   evidence as NOT-TESTABLE or OPEN — never promote software evidence.

## Forbidden (hard boundaries)

- No new identity/session/routing/federation authority; no pilot-specific
  protocol semantics; no modification of frozen spec semantics.
- No private-method fallbacks to manufacture physical evidence; no
  synthetic interface substitution for physical-path acceptance.
- No promotion of software or emulated evidence to PHYSICAL PASS
  (three-level anti-promotion stays enforced).
- No W041+ behavior (blocked pending ACR-004).

## Discipline for the correction PR

- Branch from main at the authorization baseline; inherit
  `spec/architect/authorizations/WORK-040.yaml` byte-identically
  (ARCH-08: self-authorization fails closed).
- Scope: `pilot/`, `tools/pilot_selftest.py`, `docs/WORK-040-handoff.md`,
  `docs/WORK-040-evidence.md`, `evidence/work-040/`.
- Never modify `spec/architect/` in the implementation PR.
- Evidence honesty rules: `spec/architect/evidence-obligations.yaml`
  (EVID-007/EVID-008 carry DEC-0046); a genuine PHYSICAL PASS for either
  criterion additionally requires an Architect acceptance decision.
- Resume procedure: `spec/architect/resume-protocol.md`.
