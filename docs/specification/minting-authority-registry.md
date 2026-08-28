# ADCOS Minting Authority Registry

**Status:** DERIVED CONTRACT — subordinate to frozen specification and accepted Work Item contracts.

| Object / semantic | Class | Canonical minting authority | Canonical verifier | Identity / derivation | Injection rule | Provenance rule |
|---|---|---|---|---|---|---|
| PolicyDecision | Authority-bearing | W010 PolicyEngine | W010 policy consumers | Content-derived `decision_id`; policy set/version binding | Arbitrary injection forbidden | Verify id + binding against policy authority |
| CapabilityStatement | Attributable assertion | W005 capabilities | W005 | W005 content/signature model | Transport/reference allowed; not retyped | Verify provider identity/lifecycle/signature |
| TopologyClaim | Evidence/authority input | W007 topology ingest | W007 | `claim_id` covers claim data | Remote/direct/self allowed only as declared | Reporter/subject/source class retained |
| RouteDecision / Path | Authoritative selection output | W011 routing | W011 | Content-bound route/path ids | Reference only; consumers do not recompute authority | Verify id, selected path and policy/intent binding |
| Session | Authoritative lifecycle state | W012 sessions | W012 | `session_id` derives from frozen binding | Replayed events only through session contract | Verify event sequence/binding |
| FederationRelationship / Grant | Domain authorization state | W015 federation | W015 | Domain/relationship/grant identity + sequence | Exchange declaration is not authority by itself | Verify lifecycle + scope |
| TelemetryObservation | Operational observation | W026 telemetry | W026 | `observation_id` covers complete canonical data | May be queued/transported; promotion is separate | Verify recordedness when used as authority evidence |
| TopologyPromotion | Authorized DATA | W010 born-bound policy + W026 | W007/W026 boundary | `promotion_id` covers complete promotion data | Must originate from accepted policy path | Verify policy binding + source provenance |
| RoleAssignmentEvent | Management authority artifact (candidate) | W030 management | W030 | Full event content/lineage | Caller cannot inject a self-consistent unrecorded event | Verify genuine W030 lineage |
| AuditRecord | Management evidence (candidate) | W030 management | W030 | Content/hash chain per accepted design | Evidence only; not authorization alone | Verify chain and source |
| Upgrade/MigrationResult | Lifecycle/compatibility result | W029 upgrade | W029 | State/content binding | Only owning manager applies migration | Verify transactional stage/version |
| Replay state | Security state, not a general minted object | Owning protocol/domain | Owning replay verifier | Sequence/watermark rules are owner-specific | Never blindly restored | Verify authenticate-before-commit |

## Universal rule

```text
structurally valid + internally consistent
        !=
authorized / provenance-valid
```

An implementation must have a genuine path to the canonical minting authority when an object is authority-bearing. A caller may not bypass that path by constructing a self-consistent replacement.
