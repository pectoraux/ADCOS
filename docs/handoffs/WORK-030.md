# WORK-030 — Management API

**Handoff status:** AUTHORITATIVE DERIVED HANDOFF — frozen Work Item remains the source of semantic truth.

## 1. Identity / source
- Frozen Work Item: `spec/work-items.md` WORK-030.
- Hard dependencies: WORK-010, WORK-011, WORK-012, WORK-015, WORK-026.
- Frozen acceptance: privileged actions require explicit policy; audit logs immutable/tamper-evident; management cannot bypass core authority boundaries.
- Current repository status: PR #32 is in Architect re-review and **not accepted** on current `main`. Do not treat the PR's self-assessment or green CI as acceptance.

## 2. Objective
Implement management, configuration, audit, and operational-control APIs as a management-plane boundary over existing authorities. Management requests operations; it does not become a replacement policy, routing, session, federation, telemetry, or resource authority.

## 3. Dependency classes
- DAG/semantic: the five frozen hard dependencies above.
- Execution: one active Work Item at a time; W030 is the current active/review target until explicitly resolved.
- Verification: API security + audit + RBAC tests, plus the complete repository battery.
- External evidence: use only the frozen W030 requirement; do not invent a hardware/interoperability gate.

## 4. Existing authorities consumed
W010 policy decisions; W011 routes/route data; W012 session lifecycle; W015 federation scope/relationship data; W026 telemetry. Consume them through their accepted public/least-authority contracts.

## 5. Authority boundary
**THIS WORK ITEM MAY:** expose management requests, configuration views, authorization gates, audit evidence, operator-facing control results, and orchestration calls into owning authorities.

**THIS WORK ITEM MUST NOT:** implement a second policy engine; directly mutate session/topology/routing/resource/federation/telemetry state; treat caller-supplied authority-bearing objects as trusted merely because their digests are valid; mint a substitute identity/session/route/policy authority; import vendor/access implementations into management core.

## 6. New authority
W030 may own management-plane configuration/control/audit/RBAC state. It must not acquire authority over the domain state it controls. Each privileged operation must have a clear management action identity, RBAC/capability authorization, and W010 policy authorization before side effects.

## 7. Interfaces / state
Every management operation needs an explicit request, target scope, authorization context, outcome, and audit record. State transitions must be atomic or explicitly represented as partial/pending. Caller-visible outcomes must use stable reason codes and must not leak secret/error text.

## 8. Security contract
Require two independent authorization dimensions for privileged actions: management capability/RBAC plus a genuine W010 policy decision bound to the exact requested scope. Validate authority-bearing inputs against their canonical owner. Do not use private attribute names as security. Audit both accepted privileged actions and security-relevant rejections at the universal operation boundary.

## 9. Failure / recovery
Unexpected exceptions at the outer management operation boundary must still produce exactly one auditable outcome for the operation, without swallowing the exception into a false success. Partial external/domain effects must remain explicit; no rollback success may be claimed without proof. Restart must reload only authoritative persisted state and revalidate revocation/expiry/scope before reuse.

## 10. Current review blockers to preserve
The current PR #32 Architect review identified two acceptance-critical issues: (1) the universal outer operation boundary did not guarantee exactly one audit record on unexpected exceptions; (2) constructor-injected RBAC initial events were not integrity-validated against `derive_role_event_id`. The current correction must close both. These are review facts, not new architecture.

## 11. Verification
Architecture conformance: authority ownership, least-authority calls, no direct domain mutation, no vendor leakage. Automated: positive/negative RBAC, policy denial, foreign-scope/caller injection, forged/tampered role events, unexpected exception audit exactly-once, replay/idempotency, restart and cleanup cases, determinism. External evidence: report the frozen W030 state only.

## 12. Acceptance gate
Architect must inspect full diff, prove both authorization keys are real and scope-bound, prove audit exactly-once under success/rejection/exception, verify RBAC event integrity, run full battery, and explicitly record acceptance. Merge/CI alone is insufficient.

## 13. Out of scope
No replacement policy/routing/session/federation/telemetry/resource engines; no direct domain writers; no vendor SDKs; no UI-specific semantics that bypass the management contract; no W031+ behavior.

## 14. Accepted precedent
W007 provenance; W010 policy ownership; W012 session writer ownership; W015 federation scope ownership; W025 born-bound invocation/revocation/cleanup; W026 recordedness/provenance; W027 authority-owned receipt issuance; W029 transactional migration/audit discipline.

## 15. No architecture drift
Do not modify frozen `spec/` unless an accepted ACR explicitly requires it. Do not re-open ACR-001 or ACR-002. No semantic invention is permitted.
