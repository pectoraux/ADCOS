# ADCOS Global Invariant Catalog

**Status:** DERIVED REVIEW REGISTER — subordinate to frozen architecture; turns established precedents into explicit review obligations.

| ID | Statement | Owner / origin | Applies to | Security impact | Failure behavior | Verification |
|---|---|---|---|---|---|---|
| **AUTH-001** | Policy decisions are minted only by the policy authority; consumers execute or verify, never re-evaluate them. | W010 | All policy consumers | Authorization bypass | Fail closed | Policy selftests + consumer provenance tests |
| **AUTH-002** | Content validity/integrity does not prove authority provenance. | Cross-cutting | All authority-bearing objects | Security boundary | Reject caller-injected/unrecorded authority artifacts | Discriminating provenance tests |
| **AUTH-003** | Management must not directly mutate session/topology/routing/resource/policy authority. | W030 candidate / LOCK model | Management | Privilege escalation | Use owner APIs/contracts | W030 review + boundary tests |
| **AUTH-004** | Access/vendor-specific semantics remain behind adapter/provider boundaries. | LOCK-001/002/003/016/017 | Core authorities | Vendor lock-in/authority leakage | Reject imports/branches; isolate provider state | Security/import scans |
| **AUTH-005** | Rollback/cleanup success is claimed only when cleanup is proven; otherwise explicit degraded/pending state remains. | Cross-cutting precedent | Services/adapters/upgrades/mobility | State stranding | Pending/degraded state + audit | W025/W029/adversarial tests |
| **AUTH-006** | Replay state is committed only after successful authenticity/provenance verification. | Protocol/security precedent | Replay-sensitive domains | Replay poisoning | Verify first; commit second | Replay red tests |
| **AUTH-007** | Security authority must not depend on attacker-reachable mutable trust collections. | Cross-cutting precedent | Policy/revalidation/management/security | Authority forgery | Immutable/closure-owned state or accepted equivalent | W027/W030 tests |
| **AUTH-008** | State established under a genuine authority/provider retains that owner across later rebinding. | Cross-cutting precedent | Provider/resource state | Authority replacement | Capture genuine dependency at establishment | W017/W023/W027 tests |
| **AUTH-009** | Remote claims remain claims by the reporter until an explicit authority-owned promotion path authorizes promotion. | LOCK-008 | Topology/federation/telemetry | Provenance collapse | Preserve reporter/subject/source class | W007/W015/W026 tests |
| **AUTH-010** | Authoritative management actions require RBAC/capability plus policy authorization; universal audit is part of the reviewed W030 intent, pending acceptance. | W030 review | Management | Privilege escalation/audit gaps | Fail closed + audit | W030 correction tests |
| **DET-001** | Normative identity/state derivation uses injected time and deterministic ordering; no uncontrolled wall clock/randomness in deterministic authorities. | W003/W027 precedent | Core authorities | Non-reproducibility | Inject time/seed | Determinism suites |
| **DET-002** | State reached by different arrival/insertion orders canonicalizes identically where convergence is required. | W006/W007/W013 precedent | Stores/convergence | Non-determinism | Total ordering/conflict preservation | Cross-process tests |
| **FUT-001** | Unknown optional/future features may be preserved opaquely; unknown required/security-critical features fail closed. | LOCK-014/015 | Protocol/future profiles | Upgrade/interoperability ambiguity | Explicit classification | Schema/conformance tests |

## Discriminating-test rule

For each security-critical invariant, passing one happy-path test is insufficient. Evidence should show that a vulnerable implementation would accept or corrupt the adversarial case and that the corrected implementation rejects or contains it.

Canonical repository examples include provenance injection, replay poisoning, mutating/raising migration functions, authority replacement after establishment, and cleanup failure.

A more specific frozen Work Item invariant may constrain an implementation further. A derived invariant may never loosen a frozen rule.
