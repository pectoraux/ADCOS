# ADCOS 5G Core Integration — 5G Core integration adapter (WORK-019)

## Status

**ACTIVE — Module Authority: 5G Core integration boundary (the session↔PDU-session mapping + 5G Core NF interop, NOT session/identity/resource/5G-state authority).**

Implements `spec/work-items.md` WORK-019 (5G Core integration adapter); architecture §3/§10/§16/§25-rule-9/§27/§28/§29 + locks LOCK-002/016/017/019/023/024; accepted WORK-016 (adapter SDK) + WORK-017 (secure transport) + WORK-018 (IPv6/IP integration) as authoritative handoff. No `spec/prompts/WORK-019.md` exists on the accepted `main`; WORK-019 is anchored to the frozen sources (`spec/work-items.md`, `spec/dependency-graph.md`, `spec/architecture-lock.md`), disclosed in worklog `1-orchestrator`.

## Authority boundary

```
FIVEGC INTEGRATION
    != SESSION AUTHORITY        (read-only WORK-012 SessionReader lookup; session_id sacred)
    != 5G ROUTE IDENTITY         (pdu_session_id is 5G route identity; never
                                  collapses onto session_id -- R1 invariant)
    != IDENTITY AUTHORITY        (WORK-004 facade; 5G credentials access-specific,
                                  slot NAMES only -- LOCK-023)
    != RESOURCE AUTHORITY        (WORK-008; 5GC bearer/QoS = DATA)
    != POLICY AUTHORITY          (caller-supplied policy DATA)
    != TOPOLOGY AUTHORITY
    != ACCESS/VENDOR AUTHORITY   (LOCK-016; concrete 5G Core stacks = adapters
                                  behind the seam)
    != 5GC STATE AUTHORITY       (5G Core NF state lives in the adapter/
                                  conformance peer, NEVER in ADCOS core)
```

## The standards boundary (LOCK-018)

```
ADCOS 5GC INTEGRATION CONTRACT (core semantics)
    session↔PDU-session mapping, route/session identity separation,
    credential slot names, 5G Core NF interop translation
        |
        |  behind FiveGCoreContract -> SandboxedFiveGCore -> FiveGCoreManager
        v
CONCRETE 5G CORE STACKS (external implementations)
    Open5GS (real C 5GC: AMF/SMF/UPF/AUSF/UDM/UDR/PCF/NRF/NSSF/HSS)
    another 3GPP R15/R16 5GC implementation
    free5GC (Go 5GC)
    future IMT-2030/6G core (WORK-038)
```

Three consequences, stated plainly:

1. The ADCOS core defines NO 5G primitive of its own. The 3GPP TS 23.501/33.501/29.500 reference SHAPES appear as DATA with TS citations; no 5G Core state machine, no AMF/SMF/UPF type, no 5G credential material is imported into the core (LOCK-002/016; verified by the WORK-019 selftest's no-core-5GC-leakage audit).
2. Concrete 5G Core stacks plug in behind `FiveGCoreContract` without modifying the manager or any core semantics. The `Open5GSAdapter` is one production-shaped implementation; another 5G Core plugs in behind the same ABC (the W019 acceptance criterion "core remains usable with another 5G implementation").
3. 5G authentication credentials (K, OPC, RAND, AUTN, XRES*, K_seaf, K_amf) live ONLY in the adapter's private credential store + the 5G Core's AUSF/UDM. The boundary exposes slot NAMES only (LOCK-023; the W019 acceptance criterion "5G authentication credentials remain access-specific").

## Session/PDU-session identity separation (R1)

The boundary holds the mapping between a WORK-012 session (sacred content-derived `session_id`) and a 5G Core ROUTE identity (the content-derived `pdu_session_id`). Route/session identity SEPARATION is the central invariant: a route change produces a NEW `pdu_session_id` bound to the SAME `session_id`; the boundary NEVER collapses them (mirrors the WORK-018 `flow_id`/`session_id` separation).

## Credential isolation (LOCK-023)

5G authentication credentials live ONLY in the adapter's private credential store. The `FiveGCoreContext` facade exposes NO credential material; the `SubscriberProfileView` projection carries the slot NAME only. The `validate_credential_slot_name` rejects names that resemble secret material (`private_key`, `secret_key`, `password`, `token`, `opc`, `k_`, `rand`, `autn`, `xres`, ...) so an implementation cannot smuggle a key through the slot name.

## Application transparency (LOCK-019 analog)

```python
# An ordinary application uses ONLY standard session semantics.
# It imports NO ADCOS symbol, NO 3GPP type, NO 5G Core SDK.
session = manager.app_session(session_id="...", now="...").value
session.connect("internet")       # a standard destination string (DNN/IP)
session.send(b"hello")             # bytes traverse AppSession -> manager ->
                                  # sandbox -> Open5GSAdapter -> real 5G Core
data = session.recv()              # real bytes echoed by the 5G Core data peer
session.close()
```

## Real 5G Core interoperability (B3 analog, frozen W019 acceptance)

```
ordinary application
      |  standard session semantics (connect/send/recv/close)
      v
AppSession.send  ->  FiveGCoreManager.egress_pdu
      v
SandboxedFiveGCore  ->  FiveGCoreContract.egress_pdu
      v
Open5GSAdapter  (production-shaped; targets real Open5GS SBi + NGAP)
      |  egress_pdu() writes payload to the real data socket
      |  establish_pdu_session() POSTs real 3GPP TS 29.502 SBi JSON
      v
real 5G Core NF peer  (real HTTP + real TCP; real 3GPP JSON schemas)
      v
real HTTP response / echoed bytes
      v
AppSession.recv  =  real bytes
```

Open5GS itself cannot run in this sandbox (no root, no Docker — the Open5GS C core needs system libs to install; free5GC needs Go + Docker/mongod). The `Open5GSAdapter` is PRODUCTION-SHAPED: it targets real Open5GS SBi (HTTP, 3GPP TS 29.5xx) + NGAP (SCTP) endpoints; pointing it at a running Open5GS deployment is an endpoint config change, NOT a core change. The conformance evidence runs against `Reference5GCoreConformanceServer`, a real 3GPP-SBi-over-HTTP NF peer that runs as user `z` (real sockets, real 3GPP JSON, real bytes) — the WORK-018 `LoopbackIPv6ConformanceEngine` analog. This is transparently disclosed in the PR; the Architect is asked to confirm whether this satisfies the "real standards-compliant 5G Core implementation" criterion or whether the environment must be expanded (root/Docker) to run Open5GS itself.

## Real Open5GS interoperability gate (B1, frozen W019 acceptance)

The Architect's PR #20 review identified one acceptance-critical blocker (B1): the frozen WORK-019 acceptance requires interoperation with an INDEPENDENT standards-compliant 5G Core implementation, not the in-repo `Reference5GCoreConformanceServer` (which is an ADCOS test implementation, not an independent 5G Core). The required correction is an environment-gated REAL Open5GS interop suite.

```
ADCOS
  -> FiveGCoreContract                  (the stable core-side seam)
  -> Open5GSAdapter                     (production-shaped real-HTTP adapter)
  -> REAL Open5GS
     |- real SBI interactions            (HTTP POST 3GPP TS 29.500 §4.2 SBi;
                                         /nausf-auth TS 29.509;
                                         /nudm-uecm TS 29.503;
                                         /nsmf-pdusession TS 29.502)
     |- real PDU/session establishment   (Nsmf_PDUSession_Create, TS 29.502 §6)
     |- real user-plane path             (bytes -> Open5GS UPF data network
                                          -> DN echo peer -> back)
  -> ordinary IP traffic                (bytes echoed byte-identical)
```

The gate (`adapters/fivegc/open5gs_interop.py`, selftest case_30) is environment-gated:

- `OPEN5GS_INTEROP` unset → SKIP with a transparent gate-disabled disclosure. The conformance suite (case_29) remains the strongest honest evidence in this run.
- `OPEN5GS_INTEROP=1` + Open5GS unreachable at `OPEN5GS_SBI_URL` → SKIP with a transparent **verification-environment blocker** disclosure. The gate does NOT fake success with the in-repo conformance server (the Architect's B1 correction is explicit on this point).
- `OPEN5GS_INTEROP=1` + Open5GS reachable + bytes traverse the real Open5GS SBI + real user-plane path → PASS with real-bytes-evidence detail. **This is the outcome that closes B1.**
- `OPEN5GS_INTEROP=1` + Open5GS reachable + SBI failure / data-peer unreachable / byte mismatch → FAIL with the specific reason. The gate does NOT mask real failures as SKIP.

CI / local acceptance invocation:

```bash
OPEN5GS_INTEROP=1 \
OPEN5GS_SBI_URL=http://127.0.0.1:7777 \
OPEN5GS_DATA_PEER=127.0.0.1:5555 \
python3 tools/fivegc_selftest.py
```

`OPEN5GS_SBI_URL` defaults to `http://127.0.0.1:7777` (the Open5GS default SBI port). `OPEN5GS_DATA_PEER` is optional; set it to the DN echo host the Open5GS UPF routes to (a real Open5GS SMF response does NOT carry `dataEndpoint` — 3GPP TS 29.502 `Nsmf_PDUSession_CreateServiceOperation` does not standardize a data-plane endpoint; the user plane is the UPF GTP-U tunnel on N3, not an SBi-returned socket).

**Sandbox environment blocker (honestly disclosed):** this sandbox (user `z`, no root, no Docker, no Go) cannot host a real Open5GS process. The gate therefore reports `UNREACHABLE` in this sandbox — a verification-environment blocker, NOT architecture permission to redefine "real 5G Core" as "our own reference server." The gate closes B1 the moment the environment is expanded (root/Docker) to run Open5GS itself; the adapter, contract, and sandbox code need no change.

## Determinism

All instants are injected (WORK-003 `parse_instant` grammar); no wall clock. All ids are content-derived over `protocol.canonicalization.canonical_json_bytes`; no `urandom`/`secrets`/`random` anywhere in the package. The `FiveGCoreManager.snapshot()` is byte-identical across runs and across implementations (B2: `implementation_label` excluded from canonical state, exposed only via `diagnostic_state()`).

## Out of scope

- Concrete 5G vendor stacks (Open5GS-the-process, free5GC, vendor SDKs) behind the seam — production adapters, not this module. This module ships a production-shaped `Open5GSAdapter` + a real conformance NF peer + a real-Open5GS interop gate; running the real Open5GS process needs a root/Docker-capable environment (a verification-environment requirement, NOT an architecture permission to redefine "real 5G Core" as "our own reference server" — see the B1 gate section above).
- 5G radio PHY (WORK-020), gNB/UE (W020), N3IWF/TNGF (W021), distributed core/UPF (W024).
- Reinventing 3GPP standards (LOCK-018) — the model uses TS 23.501/33.501/29.500 reference SHAPES as DATA with TS citations.
- Any second session/identity/topology/resource authority — the WORK-012 sessions module owns the session identity; the WORK-004 identity module owns node identity; this module owns the session↔PDU-session MAPPING + 5G Core NF interop translation only.

## Verification

```
python3 tools/fivegc_selftest.py
```

Real 5G Core interoperability evidence in two layers:

1. **Conformance suite (case_29, always runs):** real HTTP SBi + real TCP data socket + real 3GPP JSON + real bytes traversing the AppSession→Manager→Sandbox→Open5GSAdapter→real NF peer path. This is the strongest honest evidence achievable in the sandbox (no root, no Docker); the WORK-018 `::1` echo analog.
2. **Real Open5GS interop gate (case_30, environment-gated by `OPEN5GS_INTEROP=1`):** exercises the full byte-path against a REAL Open5GS (real SBI + real PDU session establishment + real user-plane path → ordinary IP traffic). Closes B1 when Open5GS is reachable; SKIPS with a transparent verification-environment blocker when it is not (no in-repo simulator fallback).

Plus R1 (session/PDU-session identity separation), R2 (credential isolation + NF-unavailable fail-closed), R3 (AppSession surface audit + leaky-session rejection), R4 (per-binding sandbox ownership across register_implementation swaps), R5 (standards-boundary audit + frozen-spec-intact + no-core-5GC-leakage), R6 (determinism + cross-impl byte-identical canonical state + 3GPP TS citation), and failure isolation (mirrors the W016/W017/W018 selftest discipline). Runs in CI after the IP integration suite.
