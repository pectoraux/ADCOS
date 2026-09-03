# WORK-048 Implementation Evidence — Provider Connectivity Sharing Runtime, Isolation & Quota Enforcement

**Authorization:** WORK-048-CORE-001 (DEC-0073; baseline reconciled by DEC-0074)  
**Containment authority:** DEC-0072 / ACR-012  
**Baseline (authorization record):** `bd544dbce0aec345521d340f45ad4562567927cf`  
**Implementation branch base:** `72810f4d8d48c16157864017ecf155538a4243c4` (the mainline carrying the reconciled authorization record)  
**Work Item:** WORK-048 (issue #92)  
**Battery:** `tools/sharing_selftest.py` (38 deterministic cases, stdlib only)

---

## 1. Delivery statement

This PR implements WORK-048 as a **local enforcement mechanism** under the
frozen authority boundaries:

- **`containment/`** — the ACR-012 Buyer-Traffic Containment Boundary
  authority: the frozen capability dimension (`unsupported | unknown |
  supported | restricted`), the frozen boundary lifecycle
  (`prepared -> verified -> active -> degraded | failed | revoked | closed`),
  the technology-neutral `IsolationPrimitive` contract (the `/adapters`-facing
  boundary), the deterministic sandbox reference primitive
  (SOFTWARE evidence only), denial-by-default reachability, verification
  proofs, breach/revocation/teardown semantics, fail-closed transitions, and
  typed security evidence (LOCK-022/LOCK-023).
- **`sharing/`** — the provider sharing runtime: the sharing-session
  lifecycle (`prepared -> authorized -> active -> paused -> expired/revoked ->
  closed`, a DISTINCT state machine from the containment boundary), provider
  consent (`not_granted -> granted -> withdrawn | emergency_stopped`,
  append-only history), the quota/capacity/concurrency ledger, W051 lease
  truth composition (read-only), W041 NetworkPath composition (through the
  public machinery only), and W052 usage-evidence correlation (idempotent
  emission INTO the canonical ledger; never a second ledger).
- **`tools/sharing_selftest.py`** — the 38-case deterministic battery
  (§4 below).
- **`.github/workflows/spec-check.yml`** — additive CI wiring (one battery
  step; nothing removed).

The central frozen invariant is enforced end-to-end:

```text
NO PROVEN CONTAINMENT  =>  NO BUYER TRAFFIC
```

Buyer traffic is admitted only in boundary state `active` (reachable only
from `verified`, with a primitive-produced proof), and every admission point
re-checks every condition: lease active, provider consent granted,
NetworkPath active for the exact logical session, quota available, capability
supported/restricted within the documented set, containment proof valid, and
isolation currently established.  Unknown/unsupported capabilities refuse
exposure with no silent downgrade.  Isolation failure, isolation loss, proof
invalidity, and unmodeled exceptions all fail closed with typed reasons.

## 2. Authority-boundary audit (composition, never duplication)

| Authority | W048 relationship (verified by the battery) |
|---|---|
| `/identity` | Referenced only (buyer/provider refs are claims; LOCK-008). No identity import in the family (case 30). |
| `/session` | Logical `session_id` referenced, never minted. No session import (case 30). |
| `/routing` | Never imported; no path computation anywhere (case 30). |
| `/transport` | Never imported; no transport semantics (case 30). |
| W041 NetworkPath | Composed through the public machinery: validate/bind/probe/activate/handover/retire. `PATH_ACTIVE` is only ever the W041 machinery's fact; unvalidated candidates never activate; path loss/change compose W041 transitions; the logical session_id is stable across handover (cases 09/10/22/23). |
| W051 CommercialCore | Read-only: only `transaction()` reads in the family source (regex-audited, case 31); no commercial command is ever issued; the W051 journal is byte-identical after every W048 operation (case 07). |
| W052 UsageLedger | Idempotent evidence emission INTO the canonical journal through its public typed surface; W048 constructs no ledger; duplicates reconcile through the ledger's own durable dedup (cases 25/26). |
| ACR-012 containment | Implemented as the first-class `containment/` authority; exactly one ContainmentBoundary per sharing session; the sharing-session state machine is provably distinct from the boundary state machine (case 02). |
| `/adapters` | Platform primitives implement the neutral `IsolationPrimitive` contract; the core `containment/` imports no platform SDK, no Android/iOS SDK, no 3GPP RAN/Core type (case 30). The sandbox primitive is the deterministic SOFTWARE model. |
| W050 | Advisory only: capability rows may be composed from the advisory matrix by the caller; the capability gate never depends on W050 (case 16). |
| Plaintext payloads | No payload type, no inspection API, no DPI token anywhere; byte accounting operates on integer counts at the boundary only (case 32). |
| Payment custody | None (out of scope; no payment code). |

**No second authority of any kind exists in the family** (cases 30/31:
no authority construction, no commercial command issuance, no private usage
ledger, no session/routing/transport mutation surface).

## 3. Verification results (SOFTWARE class)

```text
python3 tools/sharing_selftest.py
Result: PASS (38/38 cases passed)
```

- two consecutive runs are **byte-identical** (identical stdout);
- the golden digest stream is reproduced **byte-for-byte** under
  `PYTHONHASHSEED=0`, `PYTHONHASHSEED=1`, `PYTHONHASHSEED=7919`, and unset
  (case 28; 21 stream lines);
- the ONLY time source is the injected WORK-033 `StepClock` seam (no
  wall-clock reads, no `datetime`, no randomness anywhere in the family —
  case 30);
- every failure mode is a typed fail-closed denial; unmodeled exceptions on
  security-critical operations become typed denials carrying the exception
  CLASS NAME only (LOCK-023; cases 17/37);
- failure-injection results: establishment failure (boundary and session
  stay `prepared`), unmodeled exception (boundary `failed`), scope loss
  (boundary and session `revoked` `ISOLATION_LOST`), breach (emergency stop
  with security evidence), degraded proof (no new buyer traffic), lease
  out-of-window (revoked `LEASE_NO_LONGER_ACTIVE`), quota exhaustion
  (expired `BYTE_QUOTA_REACHED`, zero bytes past the quota), unverifiable
  counter (refused `QUOTA_UNVERIFIABLE`), recovery without re-provable
  containment (session revoked; no traffic resumes from stale proof);
- recovery results: snapshot/restore journal-identical; revalidation of
  lease/consent/path/quota plus a FRESH containment re-proof before
  enforcement resumes; revoked stays revoked; expired stays expired; the
  historical usage facts and the canonical W052 journal digest are
  byte-identical after teardown and revocation (cases 24/33).

## 4. Battery manifest (38 cases → the required coverage)

| Required battery item (handoff) | Case(s) |
|---|---|
| 1. sharing lifecycle | 03 |
| 2. provider consent | 04 |
| 3. consent withdrawal | 05 |
| 4. emergency stop | 06 |
| 5. lease validation | 07 |
| 6. lease expiry | 08 |
| 7. NetworkPath validation | 09, 23 |
| 8. invalid/unvalidated path rejection | 09, 10 |
| 9. byte quota | 11 |
| 10. time quota | 12 |
| 11. capacity reservation | 13 |
| 12. concurrent buyer limit | 14, 27 |
| 13. over-reservation | 15 |
| 14. containment capability | 16 |
| 15. isolation establishment | 17 |
| 16. isolation verification | 18 |
| 17. isolation failure | 17, 19 |
| 18. fail-closed admission | 20 (plus 05/06/08/10/11/12/19/22) |
| 19. deny-by-default | 21 |
| 20. path loss | 22 |
| 21. recovery/process death | 24 |
| 22. usage correlation into W042 | 25 |
| 23. replay/idempotency | 26, 29 |
| 24. deterministic concurrency | 27 |
| 25. PYTHONHASHSEED determinism | 28 |
| 26. golden digest reproducibility | 29 |
| 27. forbidden imports | 30 |
| 28. forbidden authority writes | 31 |
| 29. plaintext-inspection absence | 32 |
| 30. teardown/revocation historical-usage immutability | 33 |
| (structural) frozen vocabularies; two state machines distinct | 01, 02 |
| (hygiene) py_compile; frozen-spec integrity; PR-delta scope; secret hygiene; evidence-class honesty | 34–38 |

## 5. The golden digest stream (the deterministic evidence document)

Produced by `python3 tools/sharing_selftest.py --determinism-stream`
(byte-identical across runs and hash seeds):

```text
accounted_bytes=800000
accounting_epochs=2
boundary_admitted_bytes=800000
boundary_state_final=revoked
consent_state_final=withdrawn
consent_transitions=2
containment_events=4
containment_journal_digest=sha256:e6693486999fa5038640b06ada188c51d876300b3d53dfceff50b367877fa3a2
latest_proof_digest=sha256:97fd10aee2dd7c8fdb28c31eec1495cc68aefc2c2767bb166d598fa3d9a8d22d
proof_count=1
quota_reserved_after=0
security_evidence_count=0
session_id=sha256:3a9a66a4984205a42f4a69d634078558d5dd6a0aadbedfb5e201e2e1d76e74f5
session_state_final=closed
session_termination=CONSENT_WITHDRAWN
sharing_events=7
sharing_journal_digest=sha256:8bab70f16e760ff7c18a76585a553af104b0b502031c2ad0233a8ded9d87f165
usage_correlation_id=sha256:090e948a1e92faf61cee68fb2c370fdc98595ec1fc7191941969bd4376f93e31
usage_journal_digest=sha256:e369f81b505a33295d7c4fe6aa79bd6f3866897a5aa04a659a9b0745b82d8d71
usage_records=1
usage_replay_identical=true
```

The golden scenario is the full chain over the composed world: prepare →
(authorize refused without consent) → grant → authorize → activate →
account ×2 → usage emission (idempotent replay) → consent withdrawal →
revoked → closed.

## 6. Evidence-class honesty (SOFTWARE ≠ PHYSICAL)

**Every result in this document is SOFTWARE-class.** The sandbox isolation
primitive is a deterministic software model of the OS/network mechanism
(netns/nftables, VRF, VpnService, Network Extension): it proves the
*mechanism contract*, the *deterministic enforcement semantics*, and the
*fail-closed discipline*.  It does **not** prove physical containment on any
real device/network.

- A `supported` capability claim is a software-conformance claim only.
- A containment verification `proof` is the primitive implementation's own
  observation — SOFTWARE evidence.
- No software PASS is promoted to physical PASS anywhere in this delivery.
- **PHYSICAL evidence obligations remain OPEN.** Buyer traffic being unable
  to reach a real provider control-plane/local resources on real hardware is
  a PHYSICAL claim that must be demonstrated independently (real platform
  adapter implementations under `/adapters`, on real devices/networks).
- W040's obligations (EVID-007, EVID-008) remain W040-owned and untouched:
  nothing in this PR self-registers, self-closes, or implies the closure of
  any W040 physical-evidence obligation (case 38).  Physical evidence
  registration belongs to Architect governance
  (`spec/architect/evidence-obligations.yaml`).

## 7. Out-of-scope statement (unchanged frozen boundaries)

No frozen architecture, protocol schema, lock, dependency-graph, work-item
registry, or `spec/architect/` file is modified by this PR (case 35:
byte-identical to origin/main; ARCH-08 provenance enforces the same on the
PR).  The PR delta is exactly the authorized WORK-048-CORE-001 literal scope
(case 36): `sharing/`, `containment/`, `tools/sharing_selftest.py`,
`docs/WORK-048-evidence.md`, and additive `.github/workflows/spec-check.yml`
wiring.  `docs/WORK-048-handoff.md` is unmodified.  Payment processing
(W044), marketplace ranking (W047), the developer API (W046), W049, W050,
and new protocol semantics are out of scope and untouched.

## 8. Status

```text
implemented:      YES (this PR; the exact delivery SHA is the PR head)
verified:         YES (SOFTWARE class: 38/38 deterministic battery,
                     two-run byte-identical, hash-seed stable, golden
                     stream reproduced)
in-review:        YES (this PR awaits the Architect's exact-SHA review)
accepted:         NO (only the Architect can accept the exact delivery SHA;
                     tests passing is not acceptance)
```
