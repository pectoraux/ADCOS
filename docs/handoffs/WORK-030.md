# WORK-030 — Management API

**Handoff status:** AUTHORITATIVE DERIVED HANDOFF — frozen Work Item remains the source of semantic truth.

## 1. Identity / source
- Work Item: WORK-030
- Title: Management API
- Phase: Phase 5 — Resilience, Security, Operations
- Status: **Architect-accepted; PR #32 cleared for merge at head `7cfe4fb`; not yet merged.**
- Frozen source: `spec/work-items.md` WORK-030; `spec/architecture.md`; `spec/architecture-lock.md`.
- Architect acceptance record: PR #32 review `PRR_kwDOUB21ts8AAAABLNtL-w`, explicitly closing blockers from review `5047201533`.

## 2. Objective
Implement management, configuration, audit, and operational-control APIs as a management-plane boundary over existing authorities. Management requests operations; it does not become a replacement policy, routing, session, federation, telemetry, or resource authority.

## 3. Hard dependencies
WORK-010, WORK-011, WORK-012, WORK-015, WORK-026.

## 4. Dependency classes
- DAG/semantic: the five frozen hard dependencies above.
- Execution: one active Work Item at a time; W030 was the active/review target and is now architecturally accepted. Downstream execution remains blocked until PR #32 is merged and the next Work Item is explicitly designated.
- Verification: API security + audit + RBAC tests, plus the complete repository battery.
- External evidence: use only the frozen W030 requirement; do not invent a hardware/interoperability gate.

## 5. Existing authorities consumed
W010 policy decisions; W011 routes/route data; W012 session lifecycle; W015 federation scope/relationship data; W026 telemetry. Consume them through their accepted public/least-authority contracts.

## 6. Authority boundary
**THIS WORK ITEM MAY:** expose management requests, configuration views, authorization gates, audit evidence, operator-facing control results, and orchestration calls into owning authorities.

**THIS WORK ITEM MUST NOT:** implement a second policy engine; directly mutate session/topology/routing/resource/federation/telemetry state; treat caller-supplied authority-bearing objects as trusted merely because their digests are valid; mint a substitute identity/session/route/policy authority; import vendor/access implementations into management core.

## 7. New authority
W030 may own management-plane configuration/control/audit/RBAC state. It must not acquire authority over the domain state it controls. Each privileged operation must have a clear management action identity, RBAC/capability authorization, and W010 policy authorization before side effects.

## 8. Interfaces / state
Every management operation needs an explicit request, target scope, authorization context, outcome, and audit record. State transitions must be atomic or explicitly represented as partial/pending. Caller-visible outcomes must use stable reason codes and must not leak secret/error text.

## 9. Security contract
Require two independent authorization dimensions for privileged actions: management capability/RBAC plus a genuine W010 policy decision bound to the exact requested scope. Validate authority-bearing inputs against their canonical owner. Do not use private attribute names as security. Audit both accepted privileged actions and security-relevant rejections at the universal operation boundary.

## 10. Failure / persistence / recovery
Unexpected exceptions at the outer management operation boundary must still produce exactly one auditable outcome for the operation, without swallowing the exception into a false success. Partial external/domain effects must remain explicit; no rollback success may be claimed without proof. Restart must reload only authoritative persisted state and revalidate revocation/expiry/scope before reuse. Unproven cleanup remains pending/degraded.

## 11. Architect acceptance / correction record
Initial Architect review `5047201533` identified two blockers: (1) no universal guarantee of exactly one audit record on unexpected exceptions; (2) missing content-derived integrity validation for constructor-injected RBAC events. Correction cycle 1 at `7cfe4fb` added the universal `_invoke` boundary, per-invocation audit accounting, frozen `management.failed` handling, narrowed expected exception catches, constructor-side `derive_role_event_id` validation, and discriminating regressions case_38/case_39. Both regressions were verified to fail against the pre-correction implementation. The subsequent Architect review accepted W030 and cleared PR #32 for merge.

## 12. Verification
Architecture conformance: authority ownership, least-authority calls, no direct domain mutation, no vendor leakage. Automated: positive/negative RBAC, policy denial, foreign-scope/caller injection, forged/tampered role events, unexpected exception audit exactly-once, replay/idempotency, restart and cleanup cases, determinism. Evidence recorded by the accepted review includes management battery 39/39, mypy clean for the management family, spec/policy/telemetry verification, and GitHub Actions run 33134964463 success (35/35 steps). External evidence: not required by the frozen W030 contract.

## 13. Acceptance gate
**Accepted.** Architect explicitly recorded W030 acceptance and clearance for merge. Merge/CI alone is not sufficient in general; here explicit Architect acceptance exists. Downstream Work Items remain gated until PR #32 is actually merged.

## 14. Out of scope
No replacement policy/routing/session/federation/telemetry/resource engines; no direct domain writers; no vendor SDKs; no UI-specific semantics that bypass the management contract; no W031+ behavior.

## 15. Accepted precedent
W007 provenance; W010 policy ownership; W012 session writer ownership; W015 federation scope ownership; W025 born-bound invocation/revocation/cleanup; W026 recordedness/provenance; W027 authority-owned receipt issuance; W029 transactional migration/audit discipline.

## 16. No architecture drift
Do not modify frozen `spec/` unless an accepted ACR explicitly requires it. Do not re-open ACR-001 or ACR-002. No semantic invention is permitted.
