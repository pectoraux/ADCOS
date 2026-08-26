# ADCOS Wi-Fi / non-3GPP Access — access adapter (WORK-021)

## Status

**ACTIVE — Module Authority: Wi-Fi/non-3GPP access boundary (the session↔association/tunnel mapping + N3IWF interop translation, NOT session/identity/resource/access-state authority).**

Implements `spec/work-items.md` WORK-021 (Wi-Fi/non-3GPP access adapter) per the architect-anchored brief `spec/prompts/WORK-021.md`; architecture §29 + locks LOCK-001/002/006/016/017/019/023/024; accepted WORK-016 (adapter SDK), WORK-018 (IPv6/IP integration), and WORK-019 (5G Core integration) as authoritative handoffs. WORK-020 (RAN) is NOT a dependency and remains independently blocked on SDR-lab evidence; this family neither imports nor references it.

## Authority boundary

```
WIFI/NON-3GPP ACCESS
    != SESSION AUTHORITY        (read-only WORK-012 SessionReader lookup; session_id sacred)
    != ACCESS IDENTITY          (assoc_ref is Wi-Fi association identity; tunnel_ref is
                                  N3IWF tunnel identity; neither ever collapses onto
                                  session_id -- the W021 identity invariant)
    != IDENTITY AUTHORITY       (WORK-004 facade; Wi-Fi/802.1X/N3IWF credentials
                                  access-specific, slot NAMES only -- LOCK-023)
    != RESOURCE AUTHORITY       (WORK-008; AP/SSID/station/tunnel capacity = DATA)
    != POLICY AUTHORITY         (caller-supplied policy DATA)
    != TOPOLOGY AUTHORITY
    != ACCESS/VENDOR AUTHORITY  (LOCK-016/017; concrete Wi-Fi stacks, chipsets,
                                  drivers, N3IWF implementations = adapters behind
                                  the seam)
    != ACCESS STATE AUTHORITY   (station/association/tunnel/IPsec state lives in
                                  the adapter/conformance peer, NEVER in core)
    != IPv4/NAT AUTHORITY       (WORK-018 IP integration layer's concern; NAT/IPv4
                                  is adapter/policy behavior, never core identity)
```

## The standards boundary (LOCK-018)

```
ADCOS WI-FI/NON-3GPP ACCESS CONTRACT (core semantics)
    session↔association/tunnel mapping, identity separation,
    credential slot names, N3IWF/802.11 translation
        |
        |  behind WifiContract -> SandboxedWifi -> WifiManager
        |        (+ WifiTechnologyAdapter onto the WORK-016 Adapter SDK)
        v
CONCRETE WI-FI / NON-3GPP PATHS (external implementations)
    a real Wi-Fi radio path (IEEE 802.11-2020 association, 802.1X-2020/EAP)
    a real N3IWF/TNGF (3GPP TS 23.316/24.302; IKEv2 per RFC 7296, IPsec per RFC 4301)
    the in-repo deterministic reference engine + conformance peer
    future Wi-Fi 7/8 and IMT-2030 non-3GPP accesses (WORK-038)
```

IEEE 802.11-2020, IEEE 802.1X-2020, RFC 3748, 3GPP TS 23.316/TS 24.302,
RFC 7296, and RFC 4301 are used as DATA with citations (shapes, names,
capacity bounds); the family never reinvents Wi-Fi, EAP, or IPsec
standards and carries no chipset/vendor vocabulary (LOCK-016/017).

## Session / access identity separation (the W021 identity invariant)

`session_id` is sacred and access-independent. Three distinct identity
axes — the ADCOS `session_id` (WORK-012, LOCK-006), the Wi-Fi
association identity (`wifi:assoc:<hex>`), and the N3IWF tunnel
identity (`wifi:tunnel:<hex>`) — never collapse. An access change
(Wi-Fi↔5G, re-association, tunnel re-establishment) re-binds the SAME
`session_id` to NEW access refs after release; the boundary never
mints a session_id because the access changed, and rejects
cross-binding session collapse, requirements-map identity overrides,
and session-authority/digest-fragment smuggling in caller text
fail-closed (`ACCESS_SESSION_COLLAPSE` / `INVALID_INPUT`).

## Credential isolation (LOCK-023)

Wi-Fi/802.1X/N3IWF credential MATERIAL (passphrases/PSKs, EAP
credentials, IPsec/IKEv2 credentials) never crosses the boundary;
only slot NAMES. Credential-LIKE text (material-looking slot names,
station labels, requirement keys/values) is rejected at the seam.

## Application transparency (LOCK-019 analog)

```
# An ordinary application uses ONLY standard session semantics.
# It imports NO ADCOS symbol, NO Wi-Fi type, NO N3IWF SDK.
session.connect("lobby-service")
session.send(payload)      # -> bytes -> manager -> sandbox -> adapter -> peer
data = session.recv()
session.close()
```

The facade the application holds is the IMPLEMENTATION'S OWN
sandbox-validated `WifiAppSession`, returned verbatim by the manager
(with the manager-routed egress bound); a real tunnel data path is
ENCAPSULATED INSIDE that facade — no bare socket ever crosses a
seam (the accepted WORK-019 `AppSession` pattern).

## The one mediated authority path (PR #22 architect review)

```
W016 Adapter Runtime
        |
WifiTechnologyAdapter   (bridge: thin translation; holds the MANAGER
        |                 and nothing else — no implementation ref)
        v
WifiManager             (family runtime; binding table + events)
        |
SandboxedWifi           (BaseException isolation, contract-shape
        |                 validation, W021 identity checks, frozen
        |                 per-op step charging)
        v
WifiContract implementation
```

There is no path from the SDK surface around the family mediator:
the sandbox exposes no data-path/capability accessor onto the
implementation (no `getattr` reach-around of any kind — pinned by
case_36's structural + source scan), and the bridge cannot call a
concrete implementation because it holds no reference to one.

## Real Wi-Fi/N3IWF interoperability (a4: in-sandbox honest evidence)

`adapters/wifi/conformance.py` — a REAL N3IWF-shaped peer (real UDP
control plane carrying the RFC 7296 IKE_SA_INIT/IKE_AUTH/
CREATE_CHILD_SA message-schema SHAPES + a real TCP tunnel-data echo;
honestly NOT a real radio, NOT real IKEv2 crypto, NOT IPsec).
`adapters/wifi/n3iwf.py` — the production-shaped `N3IWFAdapter` (the
Open5GSAdapter analog): it runs the real UDP exchanges and writes the
application's bytes to the real tunnel data socket; pointing it at a
real N3IWF deployment is an endpoint config change, not a core
change. The selftest's case_31 proves the full byte path
`WifiAppSession -> WifiManager -> SandboxedWifi -> N3IWFAdapter ->
real peer -> recv` byte-identical, and case_33 proves mixed-access
session continuity with the accepted WORK-019 family over BOTH
families' real conformance peers (5G → Wi-Fi → 5G, one session_id).

## Real Wi-Fi/N3IWF interoperability gate (B1, frozen W021 acceptance)

`adapters/wifi/wifi_interop.py` — the environment-gated REAL interop
suite (`WIFI_INTEROP=1` + `WIFI_N3IWF_ENDPOINT`/`WIFI_DATA_PEER`).
`adapters/wifi/interop_env_probe.py` — the environment-capability
probe (radio interfaces / nl80211 tools / association daemons /
IPsec / endpoint reachability) + the HARD anti-faking
`WIFI_PEER_KIND` guard: an explicit in-repo-simulator assertion is
FORBIDDEN before any probe; a SKIP is a transparent verification-
environment blocker and NEVER a fabricated PASS (acceptance
criterion 6). See the interop runbook in that module.

## Determinism

No wall clock, no randomness, no environment reads outside the
documented gate surface (which uses `os.environ` only, with
os.urandom/system/popen/fork/exec forbidden). Content-derived opaque
refs; byte-identical canonical manager snapshots across runs and
across equivalent implementations (implementation labels stay out —
B2); frozen `STEP_CHARGES` + `DEFAULT_STEP_BUDGET` (pinned by the
selftest).

## Out of scope

WORK-020 RAN implementation or SDR acceptance; Wi-Fi chipset
firmware; vendor SDKs crossing into core; application-layer Wi-Fi
APIs; replacing WORK-018 IP semantics; changes to frozen
architecture/specification documents unless explicitly authorized by
an ACR.

## Verification

`python3 tools/wifi_selftest.py` — 36 cases covering the brief's nine
verification bullets: the frozen 12-op contract surface, least-authority
context, happy paths, identity separation + collapse/smuggling
rejection, credential isolation, availability/capability/capacity
ladders, leaky-facade rejection, per-binding ownership across
implementation swaps, the standards-boundary audit (imports/secret/
vendor/RAN tokens + citations), frozen `spec/` byte identity,
no-core-wifi-leakage, read-only reader facades, pinned step charges,
same-impl + cross-impl determinism, BaseException/contract-shape/
budget/secret-leak failure isolation, the a4 real conformance byte
path, the WORK-016 SDK nine-op bridge (over the family MANAGER —
proven by the manager's canonical event history), mixed-access session
continuity with 5G, the environment-gated real interop gate +
anti-faking hardening, and the PR #22 architect-review authority-path
regressions (no sandbox escape hatch; the implementation's facade
returned verbatim; two-layer BaseException isolation through the
bridge; the real data path encapsulated inside the returned facade).
