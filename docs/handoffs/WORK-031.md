# WORK-031 — Network and Behavior Simulator

**Handoff status:** AUTHORITATIVE DERIVED HANDOFF — frozen Work Item is normative.

## 1. Identity / source
- Work Item: WORK-031
- Title: Network and behavior simulator
- Phase: Phase 6 — Executable reference platform
- Status: DAG-ready on current accepted ancestors; execution-blocked until Architect explicitly designates it active under the one-Work-Item rule.
- Frozen source: `spec/work-items.md` WORK-031; `spec/dependency-graph.md`; `spec/architecture.md`; `spec/architecture-lock.md`.

## 2. Objective
Build a deterministic simulator for ADCOS nodes, links, failures, resources, mobility, and policies. The simulator is a controlled environment around the existing authorities, not a replacement protocol implementation.

## 3. Hard dependencies
WORK-007, WORK-011, WORK-012, WORK-013, WORK-027.

## 4. Dependency classes
DAG/semantic dependencies are W007 topology, W011 routing, W012 sessions, W013 multipath, W027 resilience. Execution dependency is the frozen DAG plus the one-active-Work-Item rule. Verification dependency is the deterministic scenario matrix and affected family batteries. External evidence is NOT REQUIRED unless a later accepted architecture change says otherwise.

## 5. Real authorities consumed
Use real accepted W007 topology, W011 routing, W012 session, W013 multipath, and W027 resilience contracts/data where composition is required. Reuse their object vocabulary and validation; do not create parallel simulation versions of authoritative protocol objects when the real contract can be composed.

## 6. Simulation boundary
**MAY:** create simulated nodes/links/failure schedules, controlled resource observations, mobility events, policy inputs, partitions, restart/rejoin events, and deterministic scenario traces; compose accepted authorities through explicit test seams; collect observations.

**MUST NOT:** mutate production authority state except through an explicitly provided test seam whose purpose and restoration are proven; reimplement routing, policy, session, topology, multipath, resource, telemetry or identity semantics; mint authority-bearing production objects outside their owners; turn simulator state into protocol truth; become a **second protocol authority**; use the simulator to satisfy an independent external-evidence gate.

## 7. Deterministic execution contract
Time is always injected through scenario time; no uncontrolled wall clock. Randomness, where simulation semantics genuinely require stochastic variation, is generated only from an explicit scenario seed and a documented deterministic PRNG stream; identical seed + scenario + execution order produces byte-identical results. Tests must pin both seed and time. No hidden object-id/hash-seed dependence.

## 8. Simulation state model
Separate scenario configuration, simulated environment state, scheduled events, observed authoritative outputs, and evidence/trace state. Event application is deterministic and ordered by explicit sequence/time keys. A failed event must not partially advance simulator identity/sequence state unless that partial state is itself explicitly modeled.

## 9. Fault injection / partition / recovery
Faults are first-class scenario events: link down/degraded, provider failure, resource exhaustion, partition, loss/reordering/duplication, restart, stale data, cleanup failure, and recovery. Recovery is driven by the same owner contracts used in reality. The simulator must prove that offline/recovery behavior cannot resurrect revoked/expired authority and that replay state is committed only after successful verification.

## 10. Topology / policy / resource observation
Topology observation is consumed from real W007 semantics and must preserve reporter/subject/source provenance. Policy behavior is injected/evaluated through the real W010 authority when policy evaluation is part of a scenario; the simulator must not contain a shadow policy engine. Resource simulation uses W008 resource kinds/units and produces measurements as data, not an alternate resource authority.

## 11. Session / multipath / mobility
Scenario actions may create and manipulate sessions only via W012 contracts; multipath only via W013; mobility only via the accepted W014 contract when a scenario needs it. The simulator may orchestrate events but must not mutate session state directly or invent a primary route.

## 12. Telemetry
Telemetry produced by the scenario is evidence/data. It must use W026 vocabulary and provenance discipline. A simulated observation may exercise promotion/security paths but is never independent external evidence and must never bypass the W026 recordedness/authorization model.

## 13. Failure / recovery contract
Scenario failure is explicit and replayable. The simulator must capture pre/post authoritative snapshots around injected faults and demonstrate whether each owner contract commits, rejects, degrades, or remains pending. Cleanup is correctness: unresolved external/simulated resource cleanup becomes an explicit pending/degraded state.

## 14. Security / anti-drift rules
Integrity is not provenance. Simulation objects that look valid must not be substituted for real authority objects where the contract requires owner verification. Private fields are not a security boundary. Adapter/vendor names remain opaque data at the simulator layer. Simulation code must not import future W032+ runtime semantics or create a second protocol truth source.

## 15. Verification / acceptance
Required cases include deterministic replay of complete scenarios; insertion/order independence; explicit seed/time reproducibility; topology/policy/resource/session/multipath observation; partition/recovery; restart/rejoin; fault injection; cleanup failure; provenance injection; policy denial; route/session immutability; simulator-versus-authority state separation; and cross-process determinism. Architect acceptance requires evidence that the old/vulnerable simulator implementation would fail every newly introduced security regression where applicable.

## 16. Out of scope
No protocol semantic rewrite; no second authority; no production networking stack; no real radio/vendor integration; no conformance certification by simulation alone; no W032 conformance suite implementation; no Linux Agent implementation; no new architecture semantics.

## 17. Accepted precedent
W007 provenance/state independence; W010 policy authority; W012 session authority; W013 fold/history semantics; W027 deterministic simulation + partition/recovery; W029 transactional failure/recovery.

## 18. No architecture drift
Frozen architecture and DAG remain unchanged. Any required semantic change becomes an ACR before implementation proceeds.
