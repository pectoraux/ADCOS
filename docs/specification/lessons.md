# ADCOS Architectural Lessons & Anti-Patterns

**Status:** DERIVED REVIEW HEURISTICS. Frozen locks/contracts remain authoritative.

| Lesson | Rule |
|---|---|
| Integrity ≠ provenance | A correct hash proves content consistency, not that the rightful authority created/recorded it. |
| Private naming ≠ security | `_private`, uppercase, hidden registries, and naming conventions are not structural authority boundaries. |
| Mutable trust state is dangerous | Do not make security authority depend on attacker-reachable mutable state unless the contract explicitly establishes the mechanism as safe. |
| Capture genuine dependencies | If state is established under an authority/provider, later global/default rebinding must not retroactively replace that ownership. |
| Replay is transactional | Authenticate/verify before advancing replay state; invalid replay cannot poison future legitimate input. |
| Cleanup is correctness | Never report rollback/release/close success without proof; use explicit pending/degraded state for unresolved cleanup. |
| Migrations are transactional | Rehearse/apply on isolated state and publish only after the complete transition succeeds. |
| Recovery cannot resurrect authority | Restart/offline recovery must revalidate expiry, revocation, ownership, and provenance before reuse. |
| Caller-supplied authority objects need provenance | Structurally perfect caller objects remain untrusted until verified against the genuine owner. |
| Vendor implementations are adapters | Provider/vendor details belong behind the frozen adapter/provider boundary. |
| CI green ≠ architecture acceptance | CI verifies defined checks; only the Architect accepts the architecture of a Work Item. |
| Tests must discriminate | A security regression must demonstrate the vulnerability, not merely exercise the path. |
| Membership ≠ authorization | Federation membership, telemetry sourcing, route candidacy, or service existence does not itself grant unrelated authority. |
| Simulation ≠ external evidence | A deterministic simulator proves modeled semantics only; it cannot substitute for required real-device/lab/independent-implementation evidence. |

These are heuristics, not a substitute for a contract. A conflict with frozen rules must stop and enter the Architect/ACR process.
