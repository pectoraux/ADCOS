#!/usr/bin/env python3
"""ADCOS Wi-Fi/non-3GPP access adapter self-test (WORK-021).

Mirrors the WORK-018/019 selftest discipline and verifies the frozen
WORK-021 brief's nine verification bullets:

* WORK-016 SDK bridge and nine-op surface (case_32);
* Wi-Fi/non-3GPP capability/health/resource translation (cases 16,
  31-32: the capability ladder, the health aggregate, the SDK
  observe/capabilities translation);
* session identity/access identity separation (cases 12-14: the
  sacred session_id never appears in any adapter-side ref; the
  identity axes never collapse; requirements-map smuggling rejected);
* adapter failure isolation, BaseException isolation, contract-shape
  validation, deterministic budget (cases 27-30);
* per-binding implementation ownership across implementation swaps
  (case_19);
* standards-boundary audit for N3IWF/TNGF/vendor leakage (cases
  20-22: import/secret-token/citation audit, frozen-spec byte
  identity, no-core-wifi-leakage);
* mixed-access session continuity with 5G (case_33: the SAME sacred
  session_id carries bytes over the accepted WORK-019 5G Core
  conformance path (real HTTP SBi + real TCP data socket), then over
  the WORK-021 Wi-Fi/N3IWF conformance path (real UDP control plane
  + real TCP tunnel data), then BACK to 5G -- the access changes,
  the session identity does not);
* deterministic snapshots and cross-implementation canonical
  equivalence (cases 24-26);
* environment-gated real interoperability with anti-faking behavior
  (cases 34-35: the WIFI_INTEROP gate never fakes success; the
  WIFI_PEER_KIND anti-faking guard fires FORBIDDEN before any
  probe; SKIP never converts to acceptance);
* the PR #22 architect-review authority-path corrections, as pinnable
  regressions (case_36: no sandbox escape hatch -- structural +
  source scan; the manager returns the implementation's
  sandbox-validated app-session facade VERBATIM (object identity);
  the W016 bridge adapts the family MANAGER, with the family
  sandbox's BaseException isolation provably in the path; the real
  data path encapsulated INSIDE the returned facade).

The a4 conformance byte path (case_31) proves bytes traverse the
WifiAppSession -> WifiManager -> SandboxedWifi -> N3IWFAdapter ->
real N3IWF-shaped peer (real UDP RFC 7296 IKE-shaped control plane +
real TCP tunnel data socket) path, including a real
observe_external_association round-trip and a register_implementation
swap leg.
"""

from __future__ import annotations

import ast
import hashlib
import os
import subprocess
import sys
from typing import Any, List, Optional, Tuple

# Make the repository root importable.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from adapters.wifi import (  # noqa: E402
    CONTEXT_SURFACE,
    CONTRACT_OPERATIONS,
    ApDescriptor,
    ApProfileReader,
    ApProfileView,
    AuthResult,
    DEFAULT_STEP_BUDGET,
    N3IWFAdapter,
    ReferenceWifiConformanceServer,
    ReferenceWifiEngine,
    SecurityPolicy,
    SessionReader,
    SessionView,
    SsidProfile,
    STEP_CHARGES,
    WifiContext,
    WifiContract,
    WifiError,
    WifiManager,
    WifiReasonCode,
    WifiEnvProbeConfig,
    WifiInteropConfig,
    probe_wifi_interop_capability,
    run_wifi_interop,
    wifi_gate_enabled,
)

# WORK-016 SDK surface (the accepted generic adapter SDK this family
# bridges onto -- case_32/case_36 drive the family THROUGH the SDK
# runtime).
from adapters import (  # noqa: E402
    AdapterContext,
    AdapterDescriptor,
    AdapterRuntime,
    AdapterSecurityState,
    ResourceMappingEntry,
    derive_adapter_id,
)

# The accepted WORK-019 family -- the mixed-access continuity case
# (case_33) is the composition point; the two families never import
# each other (verified by case_22's import audit).
from adapters.fivegc import (  # noqa: E402
    Dnn,
    FiveGCoreManager,
    NfEndpoint,
    Open5GSAdapter,
    Snssai,
    SubscriberReader,
    SubscriberProfileView,
    SessionReader as FiveGcSessionReader,
    SessionView as FiveGcSessionView,
    Reference5GCoreConformanceServer,
)

# ---------------------------------------------------------------------------
# Deterministic module-level constants (no wall clock, no randomness)
# ---------------------------------------------------------------------------

_T0 = "2026-06-01T00:00:00Z"
_NOW = "2026-06-01T12:00:00Z"
_LATER = "2026-06-01T13:00:00Z"

_SESSION_ID = "sha256:" + "1" * 64
_SESSION_ID_2 = "sha256:" + "2" * 64

_AP_NAME = "lobby-ap"
_SSID = "lobby"
_CRED_SLOT = "wifi-technology-credentials"
_STATION = "station-a"
_STATION_B = "station-b"

_SUPI = "imsi-001010000000001"
_SNSSAI = Snssai(sst=1, sd="010203")
_DNN = Dnn(value="internet")

_PAYLOAD = b"adcospktpath-wifi-selftest-v1"

Result = Tuple[str, bool, str]


def ok(name: str, detail: str = "") -> Result:
    return (name, True, detail)


def fail(name: str, detail: str) -> Result:
    return (name, False, detail)


# ---------------------------------------------------------------------------
# Test doubles (implement the same interfaces used by real adapters)
# ---------------------------------------------------------------------------


class _TestSessionReader(SessionReader):
    def lookup(self, session_id: str) -> Optional[SessionView]:
        return SessionView(
            session_id=session_id,
            secureable=True,
            initiator_node_id="adcos:node:init",
            responder_node_id="adcos:node:resp",
        )


class _UnsecureableSessionReader(SessionReader):
    def lookup(self, session_id: str) -> Optional[SessionView]:
        return SessionView(
            session_id=session_id,
            secureable=False,
            initiator_node_id="adcos:node:init",
            responder_node_id="adcos:node:resp",
        )


class _TestApProfileReader(ApProfileReader):
    def profile_for(self, ap_name: str) -> Optional[ApProfileView]:
        return ApProfileView(
            ap_name=ap_name,
            ssid_names=(_SSID,),
            credential_slot_name=_CRED_SLOT,
        )


class _StoreSessionReader(SessionReader):
    """A REAL read-only WORK-012 session reader over a SessionStore
    (the composition root's wiring for the SDK-bridge composition in
    case_32/case_36): the family manager verifies the session through
    the SAME store the SDK runtime verifies bindability against.
    Replaces the pre-redesign bridge's fabricated passthrough reader
    (which echoed secureable=True for ANY session id) with a real
    lookup."""

    def __init__(self, store) -> None:
        self._store = store

    def lookup(self, session_id: str) -> Optional[SessionView]:
        session = self._store.get(session_id)
        if session is None:
            return None
        return SessionView(
            session_id=session.session_id,
            secureable=session.state in ("ESTABLISHED", "DEGRADED"),
            initiator_node_id=session.binding.source_node_id,
            responder_node_id=session.binding.destination_node_id,
        )


class _CrashingImpl(WifiContract):
    """An implementation whose every op raises SystemExit (failure
    isolation test)."""

    label = "crashing-impl"

    def open(self, context):
        return None  # open succeeds; the OTHER ops crash

    def provision_ap(self, context, *, descriptor, credential_slot_name):
        raise SystemExit("vendor Wi-Fi SDK crashed")

    def bind_session(self, context, *, session_id, ap_ref, ssid_name,
                     station_label, requirements=None):
        raise SystemExit("vendor Wi-Fi SDK crashed")

    def authenticate(self, context, *, assoc_ref):
        raise SystemExit("vendor Wi-Fi SDK crashed")

    def establish_tunnel(self, context, *, assoc_ref):
        raise SystemExit("vendor Wi-Fi SDK crashed")

    def egress_frame(self, context, *, tunnel_ref, payload):
        raise SystemExit("vendor Wi-Fi SDK crashed")

    def release_tunnel(self, context, *, tunnel_ref):
        raise SystemExit("vendor Wi-Fi SDK crashed")

    def app_session(self, context, *, session_id):
        raise SystemExit("vendor Wi-Fi SDK crashed")

    def health(self):
        return "HEALTHY"  # health succeeds; the OTHER ops crash

    def close(self, context, *, assoc_ref):
        raise SystemExit("vendor Wi-Fi SDK crashed")


class _LeakyAppSession:
    """An app-session-shaped object that leaks ADCOS/Wi-Fi tokens as
    public attributes (the sandbox must reject it at the seam -- the
    R3 analog)."""

    def __init__(self) -> None:
        self.session_id = "leak"  # forbidden public attr
        self.assoc_ref = "leak"  # forbidden public attr
        self._private = "ok"

    def connect(self, destination): pass
    def send(self, data): return 0
    def recv(self): return b""
    def close(self): pass


class _LeakyAppSessionImpl(ReferenceWifiEngine):
    """An implementation whose app_session returns a leaky facade."""

    label = "leaky-appsession-impl"

    def app_session(self, context, *, session_id):
        return _LeakyAppSession()


class _SecretLeakingImpl(ReferenceWifiEngine):
    """An implementation that raises WifiError carrying secret-looking
    material in the message (the sandbox must NOT capture the message
    text -- LOCK-023 failure isolation)."""

    label = "secret-leaking-impl"

    def bind_session(self, context, *, session_id, ap_ref, ssid_name,
                     station_label, requirements=None):
        raise WifiError(
            WifiReasonCode.INVALID_INPUT,
            "secret=psk=0xdeadbeef0xcafebad0x1234567890abcdef",
        )


class _ContractViolatingImpl(ReferenceWifiEngine):
    """An implementation that returns a non-contract value (the sandbox
    must discard it -- R6)."""

    label = "contract-violating-impl"

    def bind_session(self, context, *, session_id, ap_ref, ssid_name,
                     station_label, requirements=None):
        return "not-an-AssociationBinding"  # type: ignore[return-value]


class _SecondImpl(ReferenceWifiEngine):
    """A second distinct-label implementation (cross-impl byte-identical
    canonical state -- R6)."""

    label = "second-impl-engine"


class _FacadeCapturingImpl(ReferenceWifiEngine):
    """An implementation that records the WifiAppSession facade its
    app_session operation returns (the verbatim-return proof: the
    manager must return THAT OBJECT, never a re-constructed facade)."""

    label = "facade-capturing-impl"

    def __init__(self) -> None:
        super().__init__()
        self.returned_facades: List[Any] = []

    def app_session(self, context, *, session_id):
        facade = super().app_session(context, session_id=session_id)
        self.returned_facades.append(facade)
        return facade


# fivegc test doubles (case_33 -- the mixed-access composition point).


class _FiveGcTestSessionReader(FiveGcSessionReader):
    def lookup(self, session_id: str) -> Optional[FiveGcSessionView]:
        return FiveGcSessionView(
            session_id=session_id,
            secureable=True,
            initiator_node_id="adcos:node:init",
            responder_node_id="adcos:node:resp",
        )


class _FiveGcTestSubscriberReader(SubscriberReader):
    def profile_for(self, supi: str) -> Optional[SubscriberProfileView]:
        return SubscriberProfileView(
            supi=supi,
            subscribed_sst=1,
            subscribed_sd="010203",
            subscribed_dnn="internet",
            credential_slot_name="subscriber-credentials",
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _descriptor(
    name: str = _AP_NAME,
    ssid: str = _SSID,
    *,
    max_stations: int = 8,
    max_associations: int = 8,
    second_ssid: Optional[str] = None,
) -> ApDescriptor:
    ssids = [
        SsidProfile(
            ssid=ssid, band="5ghz",
            security_policy=SecurityPolicy.OPEN,
            max_stations=max_stations,
        )
    ]
    if second_ssid is not None:
        ssids.append(
            SsidProfile(
                ssid=second_ssid, band="5ghz",
                security_policy=SecurityPolicy.OPEN,
                max_stations=max_stations,
            )
        )
    return ApDescriptor(
        name=name,
        ssids=tuple(ssids),
        bands=("5ghz",),
        max_associations=max_associations,
    )


def _new_manager(
    implementation=None,
    *,
    integration_id: str = "adcos:wifi:test",
    session_reader=None,
    step_budget: int = DEFAULT_STEP_BUDGET,
) -> WifiManager:
    reader = session_reader if session_reader is not None else _TestSessionReader()
    mgr = WifiManager(
        integration_id=integration_id,
        step_budget=step_budget,
        session_reader=reader,
        ap_profile_reader=_TestApProfileReader(),
    )
    if implementation is None:
        implementation = ReferenceWifiEngine()
    result = mgr.register_implementation(
        implementation,
        label=getattr(implementation, "label", "") or "impl",
        make_default=True, now=_NOW,
    )
    assert result.ok, "register failed: %s" % result.detail
    return mgr


def _provision(
    mgr: WifiManager,
    *,
    descriptor: Optional[ApDescriptor] = None,
    cred_slot: str = _CRED_SLOT,
) -> str:
    result = mgr.provision_ap(
        now=_NOW,
        descriptor=descriptor if descriptor is not None else _descriptor(),
        credential_slot_name=cred_slot,
    )
    assert result.ok, "provision_ap failed: %s" % result.detail
    return result.value.ap_ref


def _provision_bind(
    mgr: WifiManager,
    *,
    session_id: str,
    descriptor: Optional[ApDescriptor] = None,
    station: str = _STATION,
):
    descriptor = descriptor if descriptor is not None else _descriptor()
    ap_ref = _provision(mgr, descriptor=descriptor)
    result = mgr.bind_session(
        now=_NOW, session_id=session_id, ap_ref=ap_ref,
        ssid_name=descriptor.ssids[0].ssid,
        station_label=station,
    )
    assert result.ok, "bind_session failed: %s" % result.detail
    return result.value


def _bind_auth_establish(
    mgr: WifiManager,
    *,
    session_id: str,
    descriptor: Optional[ApDescriptor] = None,
    station: str = _STATION,
):
    binding = _provision_bind(
        mgr, session_id=session_id, descriptor=descriptor, station=station
    )
    result = mgr.authenticate(now=_NOW, binding_id=binding.binding_id)
    assert result.ok, "authenticate failed: %s" % result.detail
    result = mgr.establish_tunnel(now=_NOW, binding_id=binding.binding_id)
    assert result.ok, "establish_tunnel failed: %s" % result.detail
    return binding, result.value.tunnel_ref


# ---------------------------------------------------------------------------
# Session fixture for the WORK-016 SDK runtime (case_32): a real
# WORK-012 SessionStore with an ESTABLISHED session (the runtime
# verifies bindability against it read-only).  Mirrors the WORK-016
# adapter_selftest fixture.
# ---------------------------------------------------------------------------


def _established_session():
    from policy.model import PolicyDecision
    from resources import ResourceStore
    from routing import (
        LinkMetrics,
        RoutingContext,
        RoutingEngine,
    )
    from topology import (
        ClaimType,
        SourceClass,
        TopologyClaim,
        TopologyGraph,
        make_link_subject,
    )
    from sessions import SessionState, SessionStore

    node_a = "adcos:node:test.profile.v1:" + "a" * 64
    node_b = "adcos:node:test.profile.v1:" + "b" * 64

    def policy_decision(instant: str = _NOW) -> PolicyDecision:
        ph = PolicyDecision(
            decision_id="0" * 64, effect="allow", code="allow",
            detail="fixture", matched_rule_ids=("r1",), policy_set_id="ps-1",
            policy_set_version=2, evaluation_instant=instant,
        )
        digest = hashlib.sha256(ph.canonical_bytes()).hexdigest()
        return PolicyDecision(
            decision_id=digest, effect="allow", code="allow",
            detail="fixture", matched_rule_ids=("r1",), policy_set_id="ps-1",
            policy_set_version=2, evaluation_instant=instant,
        )

    graph = TopologyGraph()
    graph.merge(TopologyClaim(
        subject=make_link_subject(node_a, node_b), reporter=node_a,
        claim_type=ClaimType.LINK_STATE, value="up",
        source_class=SourceClass.SELF_ADVERTISEMENT,
        issued_at=_T0, freshness_until="2026-12-31T23:59:59Z",
        sequence=1, provenance="",
    ))
    graph.merge(TopologyClaim(
        subject=node_b, reporter=node_a,
        claim_type=ClaimType.REACHABLE, value="true",
        source_class=SourceClass.DIRECT_OBSERVATION,
        issued_at=_T0, freshness_until="2026-12-31T23:59:59Z",
        sequence=1, provenance="",
    ))
    ctx = RoutingContext(
        source_node_id=node_a, destination_node_id=node_b,
        topology=graph, resources=ResourceStore(),
        evaluation_instant=_NOW, policy_decision=policy_decision(_NOW),
        link_metrics={
            make_link_subject(node_a, node_b): LinkMetrics(
                latency_ms=10, loss_basis_points=0, capacity_bps=1_000_000,
                energy_cost_millijoules=100, confidence_basis_points=10_000,
                observed_at=_T0, freshness_until="2026-12-31T23:59:59Z",
            ),
        },
    )
    res = RoutingEngine().evaluate(ctx)
    assert res.decision is not None and res.decision.selected is not None
    store = SessionStore()
    created = store.create(
        res.decision, policy_decision(_NOW), source_node_id=node_a,
        destination_node_id=node_b, creation_instant=_NOW,
    )
    assert created.ok and created.session is not None
    sid = created.session.session_id
    store.transition(sid, SessionState.AUTHORIZED, event_instant=_NOW)
    store.transition(sid, SessionState.ESTABLISHED, event_instant=_NOW)
    return store, sid


# ==========================================================================
# Cases
# ==========================================================================


def case_01_contract_surface_frozen() -> Result:
    name = "case_01_contract_surface_frozen"
    expected = (
        "open", "provision_ap", "bind_session", "attach_external_association",
        "observe_external_association", "authenticate", "establish_tunnel",
        "egress_frame", "release_tunnel", "app_session", "health", "close",
    )
    if tuple(CONTRACT_OPERATIONS) != expected:
        return fail(name, "contract operations changed: %s" % (CONTRACT_OPERATIONS,))
    return ok(name, "12 frozen Wi-Fi/non-3GPP contract operations")


def case_02_context_least_authority() -> Result:
    name = "case_02_context_least_authority"
    ctx = WifiContext(
        "adcos:wifi:test", _NOW, 100,
        _TestSessionReader(), _TestApProfileReader(),
    )
    surface = {a for a in dir(ctx) if not a.startswith("_")}
    if surface != set(CONTEXT_SURFACE):
        return fail(name, "context surface drift: %s" % sorted(surface))
    try:
        ctx._smuggle = "nope"  # type: ignore[attr-defined]
        return fail(name, "frozen __setattr__ did not reject state injection")
    except TypeError:
        pass
    return ok(name, "CONTEXT_SURFACE exact; state injection rejected")


def case_03_context_injected_instant_and_budget() -> Result:
    name = "case_03_context_injected_instant_and_budget"
    ctx = WifiContext(
        "adcos:wifi:test", _NOW, 10,
        _TestSessionReader(), None,
    )
    if ctx.now() != _NOW:
        return fail(name, "instant not the injected value")
    if ctx.integration_id != "adcos:wifi:test":
        return fail(name, "integration_id not exposed verbatim")
    ctx.charge(4)
    if ctx.steps_left() != 6:
        return fail(name, "charge did not decrement: %d" % ctx.steps_left())
    ctx.charge(6)
    if ctx.steps_left() != 0:
        return fail(name, "budget not exhausted: %d" % ctx.steps_left())
    try:
        ctx.charge(1)
        return fail(name, "charge past zero did not raise the budget sentinel")
    except Exception:
        pass
    return ok(name, "injected instant + deterministic step budget (no wall clock)")


def case_04_provision_ap_happy() -> Result:
    name = "case_04_provision_ap_happy"
    mgr = _new_manager()
    ap_ref = _provision(mgr)
    if not ap_ref.startswith("wifi:ap:") or len(ap_ref) != len("wifi:ap:") + 32:
        return fail(name, "ap_ref not content-derived wifi:ap:<hex>: %s" % ap_ref)
    if _SESSION_ID in ap_ref:
        return fail(name, "ap_ref embeds a session id (W021 identity collapse)")
    return ok(name, "ap_ref=%s (opaque, content-derived)" % ap_ref)


def case_05_bind_session_happy() -> Result:
    name = "case_05_bind_session_happy"
    mgr = _new_manager()
    binding = _provision_bind(mgr, session_id=_SESSION_ID)
    if not binding.assoc_ref.startswith("wifi:assoc:"):
        return fail(name, "assoc_ref grammar: %s" % binding.assoc_ref)
    if binding.session_id != _SESSION_ID:
        return fail(name, "session_id not stored EXACTLY as given (LOCK-006)")
    if binding.binding_id == binding.assoc_ref:
        return fail(name, "binding_id collapsed onto assoc_ref")
    # A session that is not secureable is rejected fail-closed.
    mgr2 = _new_manager(session_reader=_UnsecureableSessionReader())
    ap_ref = _provision(mgr2)
    r = mgr2.bind_session(
        now=_NOW, session_id=_SESSION_ID, ap_ref=ap_ref,
        ssid_name=_SSID, station_label=_STATION,
    )
    if r.ok or r.reason != WifiReasonCode.SESSION_NOT_SECUREABLE:
        return fail(name, "unsecureable session not rejected: %s" % r.reason)
    return ok(name, "assoc_ref=%s; unsecureable session rejected fail-closed"
               % binding.assoc_ref)


def case_06_authenticate_happy() -> Result:
    name = "case_06_authenticate_happy"
    mgr = _new_manager()
    binding = _provision_bind(mgr, session_id=_SESSION_ID)
    r = mgr.authenticate(now=_NOW, binding_id=binding.binding_id)
    if not r.ok:
        return fail(name, "authenticate failed: %s" % r.detail)
    auth = r.value
    if not isinstance(auth, AuthResult) or not auth.success:
        return fail(name, "AuthResult not success")
    if not auth.auth_ref or auth.station_label != _STATION:
        return fail(name, "auth_ref/station mismatch")
    return ok(name, "auth_ref=%s... (opaque; slot NAME only -- LOCK-023)" % auth.auth_ref[:36])


def case_07_establish_tunnel_happy() -> Result:
    name = "case_07_establish_tunnel_happy"
    mgr = _new_manager()
    binding, tunnel_ref = _bind_auth_establish(mgr, session_id=_SESSION_ID)
    if not tunnel_ref.startswith("wifi:tunnel:"):
        return fail(name, "tunnel_ref grammar: %s" % tunnel_ref)
    # Establish-before-auth is rejected.
    mgr2 = _new_manager()
    binding2 = _provision_bind(mgr2, session_id=_SESSION_ID)
    r = mgr2.establish_tunnel(now=_NOW, binding_id=binding2.binding_id)
    if r.ok or r.reason != WifiReasonCode.AUTHENTICATION_REJECTED:
        return fail(name, "establish-before-auth not rejected: %s" % r.reason)
    return ok(name, "tunnel_ref=%s; unauthenticated establish rejected" % tunnel_ref)


def case_08_egress_frame_happy() -> Result:
    name = "case_08_egress_frame_happy"
    mgr = _new_manager()
    _, tunnel_ref = _bind_auth_establish(mgr, session_id=_SESSION_ID)
    r = mgr.egress_frame(now=_NOW, tunnel_ref=tunnel_ref, payload=_PAYLOAD)
    if not r.ok:
        return fail(name, "egress failed: %s" % r.detail)
    if r.value != _PAYLOAD:
        return fail(name, "contract-path bytes not byte-identical")
    return ok(name, "deterministic echo through the mediated tunnel path")


def case_09_app_session_happy() -> Result:
    name = "case_09_app_session_happy"
    mgr = _new_manager()
    _bind_auth_establish(mgr, session_id=_SESSION_ID)
    r = mgr.app_session(now=_NOW, session_id=_SESSION_ID)
    if not r.ok:
        return fail(name, "app_session failed: %s" % r.detail)
    session = r.value
    for method in ("connect", "send", "recv", "close"):
        if not callable(getattr(session, method, None)):
            return fail(name, "app session missing %s" % method)
    public = {a for a in vars(session) if not a.startswith("_")}
    if public:
        return fail(name, "app session has public attrs: %s" % sorted(public))
    return ok(name, "manager-routed facade; standard semantics only (LOCK-019 analog)")


def case_10_tunnel_round_trip() -> Result:
    name = "case_10_tunnel_round_trip"
    mgr = _new_manager()
    _bind_auth_establish(mgr, session_id=_SESSION_ID)
    r = mgr.app_session(now=_NOW, session_id=_SESSION_ID)
    session = r.value
    session.connect("lobby-service")
    n = session.send(_PAYLOAD)
    if n != len(_PAYLOAD):
        return fail(name, "send returned wrong length")
    echoed = b""
    while len(echoed) < len(_PAYLOAD):
        chunk = session.recv()
        if not chunk:
            break
        echoed += chunk
    session.close()
    if echoed != _PAYLOAD:
        return fail(name, "round-trip mismatch: %r" % echoed)
    return ok(name, "App->WifiAppSession->Manager->Sandbox->impl->recv round trip")


def case_11_close_happy() -> Result:
    name = "case_11_close_happy"
    mgr = _new_manager()
    binding, tunnel_ref = _bind_auth_establish(mgr, session_id=_SESSION_ID)
    # Close fails closed while the tunnel is outstanding.
    r = mgr.close_binding(now=_NOW, binding_id=binding.binding_id)
    if r.ok or r.reason != WifiReasonCode.ILLEGAL_STATE:
        return fail(name, "close with outstanding tunnel not rejected: %s" % r.reason)
    if not mgr.release_tunnel(now=_NOW, tunnel_ref=tunnel_ref).ok:
        return fail(name, "release_tunnel failed")
    if not mgr.close_binding(now=_NOW, binding_id=binding.binding_id).ok:
        return fail(name, "close_binding failed")
    # Double close is a caller-side state error.
    try:
        mgr.close_binding(now=_NOW, binding_id=binding.binding_id)
        return fail(name, "double close not rejected")
    except WifiError as exc:
        if exc.reason != WifiReasonCode.BINDING_UNKNOWN:
            return fail(name, "double close wrong reason: %s" % exc.reason)
    mgr.close()
    return ok(name, "fail-closed close ladder (release -> close -> double-close rejected)")


def case_12_r1_identity_separation() -> Result:
    name = "case_12_r1_identity_separation"
    mgr = _new_manager()
    binding, tunnel_ref = _bind_auth_establish(mgr, session_id=_SESSION_ID)
    ids = {
        "session_id": _SESSION_ID,
        "assoc_ref": binding.assoc_ref,
        "tunnel_ref": tunnel_ref,
        "binding_id": binding.binding_id,
        "ap_ref": binding.ap_ref,
    }
    if len(set(ids.values())) != len(ids):
        return fail(name, "identity axes collapsed: %s" % ids)
    for label, value in ids.items():
        if label == "session_id":
            continue
        if _SESSION_ID in value or _SESSION_ID.split(":", 1)[1] in value:
            return fail(name, "%s embeds session identity text" % label)
    return ok(name, "session != assoc != tunnel != binding != ap (5 distinct axes)")


def case_13_r1_session_collapse_rejected() -> Result:
    name = "case_13_r1_session_collapse_rejected"
    mgr = _new_manager()
    binding = _provision_bind(mgr, session_id=_SESSION_ID)
    # Double live-bind of the same session through another binding.
    try:
        mgr.bind_session(
            now=_NOW, session_id=_SESSION_ID, ap_ref=binding.ap_ref,
            ssid_name=_SSID, station_label=_STATION_B,
        )
        return fail(name, "double live-bind not rejected")
    except WifiError as exc:
        if exc.reason != WifiReasonCode.ACCESS_SESSION_COLLAPSE:
            return fail(name, "collapse wrong reason: %s" % exc.reason)
    # Access CHANGE: release, then re-bind the SAME session_id -> a NEW
    # assoc_ref (never a new session_id).  The re-bind reuses the SAME
    # provisioned AP (the access change re-associates the session, not
    # the infrastructure).
    if not mgr.close_binding(now=_NOW, binding_id=binding.binding_id).ok:
        return fail(name, "close failed")
    try:
        rebinding_result = mgr.bind_session(
            now=_NOW, session_id=_SESSION_ID, ap_ref=binding.ap_ref,
            ssid_name=_SSID, station_label=_STATION_B,
        )
    except Exception as exc:
        return fail(name, "re-bind raised %s: %s" % (type(exc).__name__, exc))
    if not rebinding_result.ok:
        return fail(name, "re-bind failed: %s" % rebinding_result.detail)
    rebinding = rebinding_result.value
    if rebinding.session_id != _SESSION_ID:
        return fail(name, "re-bind minted a new session_id (W021 violation)")
    if rebinding.assoc_ref == binding.assoc_ref:
        return fail(name, "re-bind reused the old assoc_ref")
    return ok(name, "collapse rejected; access change re-binds SAME session to NEW assoc_ref")


def case_14_requirements_smuggling_rejected() -> Result:
    name = "case_14_requirements_smuggling_rejected"
    mgr = _new_manager()
    ap_ref = _provision(mgr)
    for key in ("session_id", "assoc_ref", "tunnel_ref", "ap_ref", "ssid_name"):
        try:
            mgr.bind_session(
                now=_NOW, session_id=_SESSION_ID, ap_ref=ap_ref,
                ssid_name=_SSID, station_label=_STATION,
                requirements={key: "override"},
            )
            return fail(name, "requirements key %r not rejected" % key)
        except WifiError as exc:
            if exc.reason != WifiReasonCode.ACCESS_SESSION_COLLAPSE:
                return fail(name, "key %r wrong reason: %s" % (key, exc.reason))
    return ok(name, "requirements-map identity overrides rejected caller-side (LOCK-006)")


def case_15_r2_credential_isolation() -> Result:
    name = "case_15_r2_credential_isolation"
    mgr = _new_manager()
    # Credential-LIKE slot names are rejected at the boundary
    # (LOCK-023: material never crosses; names that look like
    # material are rejected too).
    for bad_slot in ("wpa-psk", "the-password", "secret-key"):
        r = mgr.provision_ap(
            now=_NOW, descriptor=_descriptor(name="ap-x"),
            credential_slot_name=bad_slot,
        )
        if r.ok or r.reason != WifiReasonCode.INVALID_INPUT:
            return fail(name, "credential-like slot %r not rejected: %s" % (bad_slot, r.reason))
    # Station labels + requirements values carrying credential-like
    # text, session-authority text, or digest fragments are rejected
    # at the implementation seam.
    ap_ref = _provision(mgr)
    smuggling = [
        ("station", _STATION, {"psk": "my passphrase"}),
        ("station-embeds-session", _STATION + "-" + _SESSION_ID, None),
        ("station-digest-run", "station-" + "1" * 20, None),
        ("cred-station", "station-password", None),
    ]
    for label, station, requirements in smuggling:
        r = mgr.bind_session(
            now=_NOW, session_id=_SESSION_ID, ap_ref=ap_ref,
            ssid_name=_SSID, station_label=station, requirements=requirements,
        )
        if r.ok or r.reason != WifiReasonCode.INVALID_INPUT:
            return fail(name, "%s not rejected: ok=%s reason=%s" % (label, r.ok, r.reason))
    # Honest requirements + honest labels pass.
    r = mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID, ap_ref=ap_ref,
        ssid_name=_SSID, station_label=_STATION,
        requirements={"link-metric": "latency", "priority": "high"},
    )
    if not r.ok:
        return fail(name, "honest requirements rejected: %s" % r.detail)
    return ok(name, "LOCK-023: material-like text rejected at slot/station/requirements seams")


def case_16_availability_ladders() -> Result:
    name = "case_16_availability_ladders"
    engine = ReferenceWifiEngine()
    if engine.health() != "NOT_RUNNING":
        return fail(name, "unopened engine health: %s" % engine.health())
    mgr = _new_manager(engine)
    # Open with an empty AP store: the access path is DOWN.
    r = mgr.health(now=_NOW)
    if not r.ok or r.value != "FAILED":
        return fail(name, "empty-store health: %s" % (r.value if r.ok else r.detail))
    binding, tunnel_ref = _bind_auth_establish(mgr, session_id=_SESSION_ID)
    if mgr.health(now=_NOW).value != "HEALTHY":
        return fail(name, "active-SSID health not HEALTHY")
    # Degrade loudly: a deactivated SSID fails the data path CLOSED
    # (never a silent drop), then recovers on reactivation.
    engine.set_ssid_state(binding.ap_ref, _SSID, active=False)
    if mgr.health(now=_NOW).value != "DEGRADED":
        return fail(name, "deactivated-SSID health not DEGRADED")
    r = mgr.egress_frame(now=_NOW, tunnel_ref=tunnel_ref, payload=_PAYLOAD)
    if r.ok or r.reason != WifiReasonCode.WIFI_UNAVAILABLE:
        return fail(name, "deactivated SSID egress not WIFI_UNAVAILABLE: %s" % r.reason)
    engine.set_ssid_state(binding.ap_ref, _SSID, active=True)
    if not mgr.egress_frame(now=_NOW, tunnel_ref=tunnel_ref, payload=_PAYLOAD).ok:
        return fail(name, "egress did not recover after reactivation")
    # An inactive AP fails the same way.
    engine.set_ap_state(binding.ap_ref, active=False)
    r = mgr.egress_frame(now=_NOW, tunnel_ref=tunnel_ref, payload=_PAYLOAD)
    if r.ok or r.reason != WifiReasonCode.WIFI_UNAVAILABLE:
        return fail(name, "inactive AP egress not WIFI_UNAVAILABLE: %s" % r.reason)
    engine.set_ap_state(binding.ap_ref, active=True)
    # Capability ladder: boundary caps when open; +data-path with an
    # active SSID; the ladder is honest, never fabricated.
    caps_active = engine.capabilities()
    if "capability.profile.wifi.data-path" not in caps_active:
        return fail(name, "data-path capability missing with active SSID: %s" % (caps_active,))
    engine.set_ssid_state(binding.ap_ref, _SSID, active=False)
    caps_degraded = engine.capabilities()
    if "capability.profile.wifi.data-path" in caps_degraded:
        return fail(name, "data-path capability present with no active SSID")
    if not set(caps_degraded) < set(caps_active):
        return fail(name, "capability ladder did not narrow on degradation")
    return ok(name, "health ladder NOT_RUNNING/FAILED/HEALTHY/DEGRADED; degrade loudly; honest capability ladder")


def case_17_capacity_ladders() -> Result:
    name = "case_17_capacity_ladders"
    # Per-SSID station capacity: max_stations=1 -> a second bind on
    # the SAME provisioned AP+SSID is WIFI_UNAVAILABLE (fail closed,
    # never silently over).
    mgr = _new_manager()
    desc = _descriptor(max_stations=1, max_associations=8)
    ap_ref = _provision(mgr, descriptor=desc)
    r = mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID, ap_ref=ap_ref,
        ssid_name=_SSID, station_label=_STATION,
    )
    if not r.ok:
        return fail(name, "first bind failed: %s" % r.detail)
    r = mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID_2, ap_ref=ap_ref,
        ssid_name=_SSID, station_label=_STATION_B,
    )
    if r.ok or r.reason != WifiReasonCode.WIFI_UNAVAILABLE:
        return fail(name, "per-SSID station capacity not enforced: %s" % r.reason)
    # Per-AP association capacity: max_associations=1 with two SSIDs.
    mgr2 = _new_manager()
    desc2 = _descriptor(max_stations=8, max_associations=1, second_ssid="guest")
    ap_ref2 = _provision(mgr2, descriptor=desc2)
    r = mgr2.bind_session(
        now=_NOW, session_id=_SESSION_ID, ap_ref=ap_ref2,
        ssid_name=_SSID, station_label=_STATION,
    )
    if not r.ok:
        return fail(name, "first AP bind failed: %s" % r.detail)
    r = mgr2.bind_session(
        now=_NOW, session_id=_SESSION_ID_2, ap_ref=ap_ref2,
        ssid_name="guest", station_label=_STATION_B,
    )
    if r.ok or r.reason != WifiReasonCode.WIFI_UNAVAILABLE:
        return fail(name, "per-AP association capacity not enforced: %s" % r.reason)
    # Per-association tunnel capacity: one N3IWF tunnel per
    # association (TS 23.316 shape) -> a second concurrent establish
    # is WIFI_UNAVAILABLE; after release a re-establish mints a NEW
    # tunnel_ref for the SAME session.
    mgr3 = _new_manager()
    binding3, tunnel_a = _bind_auth_establish(mgr3, session_id=_SESSION_ID)
    r = mgr3.establish_tunnel(now=_NOW, binding_id=binding3.binding_id)
    if r.ok or r.reason != WifiReasonCode.WIFI_UNAVAILABLE:
        return fail(name, "per-association tunnel capacity not enforced: %s" % r.reason)
    if not mgr3.release_tunnel(now=_NOW, tunnel_ref=tunnel_a).ok:
        return fail(name, "release failed")
    r = mgr3.establish_tunnel(now=_NOW, binding_id=binding3.binding_id)
    if not r.ok:
        return fail(name, "re-establish after release failed: %s" % r.detail)
    if r.value.tunnel_ref == tunnel_a:
        return fail(name, "re-establish reused the old tunnel_ref")
    if r.value.session_id != _SESSION_ID:
        return fail(name, "re-establish changed the session_id")
    return ok(name, "per-SSID/per-AP/per-association capacity fail-closed; re-establish mints NEW tunnel_ref")


def case_18_r3_app_session_surface_audited() -> Result:
    name = "case_18_r3_app_session_surface_audited"
    # A leaky facade (ADCOS/Wi-Fi tokens as public attrs) is rejected
    # at the sandbox seam.
    mgr = _new_manager(_LeakyAppSessionImpl())
    _bind_auth_establish(mgr, session_id=_SESSION_ID)
    r = mgr.app_session(now=_NOW, session_id=_SESSION_ID)
    if r.ok:
        return fail(name, "leaky app session not rejected")
    if r.reason != WifiReasonCode.CONTRACT_VIOLATION:
        return fail(name, "leaky app session wrong reason: %s" % r.reason)
    return ok(name, "leaky facade rejected at the seam (session_id/assoc_ref tokens)")


def case_19_r4_default_swap_preserves_live_binding() -> Result:
    name = "case_19_r4_default_swap_preserves_live_binding"
    engine_a = ReferenceWifiEngine()
    mgr = _new_manager(engine_a)
    binding, tunnel_ref = _bind_auth_establish(mgr, session_id=_SESSION_ID)
    # Register a SECOND implementation as the new default.  Its SSID
    # is DEGRADED, so any new bind on IT fails -- while the live
    # binding's egress (owned by impl A) keeps working.  (The second
    # implementation is a distinct-label engine so the diagnostic
    # label proves the default actually moved.)
    engine_b = _SecondImpl()
    r = mgr.register_implementation(
        engine_b, label="impl-b", make_default=True, now=_NOW,
    )
    assert r.ok, r.detail
    ap_b = _provision(mgr, descriptor=_descriptor(name="ap-b"))
    engine_b.set_ssid_state(ap_b, _SSID, active=False)
    r = mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID_2, ap_ref=ap_b,
        ssid_name=_SSID, station_label=_STATION,
    )
    if r.ok or r.reason != WifiReasonCode.WIFI_UNAVAILABLE:
        return fail(name, "new bind did not route to the new default: %s" % r.reason)
    # The LIVE binding still egresses through its OWNING sandbox (A).
    r = mgr.egress_frame(now=_NOW, tunnel_ref=tunnel_ref, payload=_PAYLOAD)
    if not r.ok:
        return fail(name, "live binding egress broken after swap: %s" % r.detail)
    if mgr.diagnostic_state().get("implementation_label") != _SecondImpl.label:
        return fail(name, "default label not swapped: %s" % mgr.diagnostic_state().get("implementation_label"))
    return ok(name, "default swapped; live binding kept its owning sandbox (B2)")


def case_20_r5_standards_boundary_audit() -> Result:
    name = "case_20_r5_standards_boundary_audit"
    pkg_dir = os.path.join(_ROOT, "adapters", "wifi")
    forbidden_import_roots = ("ssl", "cryptography", "crypto", "random", "secrets")
    # conformance.py + n3iwf.py + wifi_interop.py + interop_env_probe.py
    # may use real-network stdlib (socket/json).  wifi_interop.py is
    # the B1 real-Wi-Fi/N3IWF interop gate -- it legitimately probes a
    # real N3IWF peer over a real UDP socket (no in-repo simulator
    # fallback).  interop_env_probe.py is the anti-faking gate
    # surface: it probes environment capabilities (radio interfaces/
    # nl80211 tools/association daemons/IPsec/endpoint reachability)
    # and enforces the WIFI_PEER_KIND guard -- it is gate SURFACE, a
    # sibling of wifi_interop.py, and uses real sockets + os.environ
    # for the same gate-config env vars.  Both gate-surface files need
    # `os` for env-var-driven config (WIFI_INTEROP/WIFI_N3IWF_ENDPOINT/
    # WIFI_DATA_PEER/WIFI_PEER_KIND/WIFI_PROBE_TIMEOUT_S); the
    # sub-scan below rejects os.urandom/system/popen/fork/exec so the
    # `os` import cannot smuggle non-determinism or sandbox escape.
    real_network_allowed = {
        "conformance.py", "n3iwf.py", "wifi_interop.py", "interop_env_probe.py",
    }
    env_aware_allowed = {"wifi_interop.py", "interop_env_probe.py"}
    forbidden_os_calls = ("os.urandom", "os.system", "os.popen", "os.fork", "os.exec", "os.spawn")
    real_network_modules = ("http", "socket", "urllib", "json")
    # Secret-MATERIAL-looking tokens (not credential NAMES cited in
    # docstrings to explain LOCK-023 -- those are legitimate;
    # validation.py defines the _CREDENTIAL_LIKE_FORBIDDEN vocabulary
    # and is excluded from the text scan, exactly as the WORK-019
    # audit excludes its enforcement module).
    secret_tokens = (
        "private_key", "secret_key", "password", "api_key", "shared_secret",
    )
    # Vendor/chipset vocabulary is allowed ONLY in the gate surface
    # (interop_env_probe.py probes for the REAL environment's
    # association-management daemons); the deterministic family files
    # carry NONE (LOCK-016/017 -- no vendor authority).
    vendor_tokens = (
        "hostapd", "wpa_supplicant", "strongswan", "qualcomm", "broadcom",
        "mediatek", "realtek", "charon",
    )
    vendor_allowed = {"interop_env_probe.py"}
    # RAN vocabulary (the unaccepted WORK-020 family) appears NOWHERE.
    ran_tokens = ("gnb", "ngap", "rnti", "openran")
    for fname in sorted(os.listdir(pkg_dir)):
        if not fname.endswith(".py"):
            continue
        fpath = os.path.join(pkg_dir, fname)
        with open(fpath, "r", encoding="utf-8") as f:
            source = f.read()
        lower = source.lower()
        if fname != "validation.py":
            for tok in secret_tokens:
                if tok in lower:
                    return fail(name, "%s: secret-looking token %r" % (fname, tok))
        for tok in ran_tokens:
            if tok in lower:
                return fail(name, "%s: RAN token %r (W020 independence)" % (fname, tok))
        if fname not in vendor_allowed:
            for tok in vendor_tokens:
                if tok in lower:
                    return fail(name, "%s: vendor token %r outside gate surface" % (fname, tok))
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if root in forbidden_import_roots:
                        return fail(name, "%s: forbidden import root %r" % (fname, root))
                    if root == "os" and fname not in env_aware_allowed:
                        return fail(name, "%s: forbidden import root %r (only %s may import os for env-var config)" % (fname, root, sorted(env_aware_allowed)))
            elif isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".")[0]
                if root in forbidden_import_roots:
                    return fail(name, "%s: forbidden import-from root %r" % (fname, root))
                if root == "os" and fname not in env_aware_allowed:
                    return fail(name, "%s: forbidden import-from root %r (only %s may import os for env-var config)" % (fname, root, sorted(env_aware_allowed)))
        # Non-real-network files must NOT use http/socket/urllib/json.
        if fname not in real_network_allowed:
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    mod = node.module if isinstance(node, ast.ImportFrom) else node.names[0].name
                    root = mod.split(".")[0] if mod else ""
                    if root in real_network_modules:
                        return fail(name, "%s: real-network import %r forbidden outside %s" % (fname, root, sorted(real_network_allowed)))
        # Env-aware files must NOT call os.urandom/system/popen/fork/exec
        # (the `os` import is for os.environ config ONLY).
        if fname in env_aware_allowed:
            for bad_call in forbidden_os_calls:
                if bad_call in source:
                    return fail(name, "%s: forbidden os call %r (env-aware files may use os.environ only)" % (fname, bad_call))
    # Standards citations (LOCK-018: standards leverage as DATA with
    # citations -- the family never reinvents Wi-Fi/EAP/IPsec).
    def _src(fname: str) -> str:
        with open(os.path.join(pkg_dir, fname), encoding="utf-8") as f:
            return f.read().lower()

    engine_src = _src("engine.py")
    if "802.11" not in engine_src or "23.316" not in engine_src:
        return fail(name, "engine.py missing IEEE 802.11 / TS 23.316 citations")
    conf_src = _src("conformance.py")
    if "7296" not in conf_src or "23.316" not in conf_src:
        return fail(name, "conformance.py missing RFC 7296 / TS 23.316 citations")
    n3iwf_src = _src("n3iwf.py")
    if "23.316" not in n3iwf_src or "7296" not in n3iwf_src:
        return fail(name, "n3iwf.py missing TS 23.316 / RFC 7296 citations")
    interop_src = _src("wifi_interop.py")
    if "7296" not in interop_src and "23.316" not in interop_src:
        return fail(name, "wifi_interop.py missing RFC 7296 / TS 23.316 citations")
    probe_src = _src("interop_env_probe.py")
    if "7296" not in probe_src or "802.11" not in probe_src:
        return fail(name, "interop_env_probe.py missing RFC 7296 / IEEE 802.11 citations")
    return ok(name, "no forbidden imports/secret/vendor/RAN tokens; standards cited; real-network stdlib only in conformance/n3iwf/interop/gate; os.environ-only in env-aware gate surface")


def case_21_r5_frozen_spec_intact() -> Result:
    name = "case_21_r5_frozen_spec_intact"
    diff = subprocess.run(
        ["git", "diff", "origin/main", "HEAD", "--", "spec/"],
        capture_output=True, text=True, cwd=_ROOT,
    )
    status = subprocess.run(
        ["git", "status", "--porcelain", "--", "spec/"],
        capture_output=True, text=True, cwd=_ROOT,
    )
    if diff.stdout.strip() or status.stdout.strip():
        return fail(name, "spec/ not byte-identical to origin/main")
    return ok(name, "spec/ byte-identical to origin/main; working tree clean")


def case_22_r5_no_core_wifi_leakage() -> Result:
    name = "case_22_r5_no_core_wifi_leakage"
    # The ADCOS core may cite Wi-Fi in access-NEUTRALITY prose (LOCK-
    # 001's canonical non-3GPP example -- exactly as the W016 SDK
    # cites 3GPP in access-neutrality docstrings); what must NEVER
    # cross is an IMPLEMENTATION dependency: no core module may
    # IMPORT adapters.wifi, and no Wi-Fi chipset/vendor API or
    # non-3GPP implementation TYPE may appear in core source.
    core_dirs = [
        "sessions", "identity", "protocol", "capabilities", "discovery",
        "transport", "topology", "routing", "multipath", "mobility",
        "federation", "policy", "intent", "resources",
    ]
    impl_type_tokens = (
        "WifiContract", "WifiManager", "WifiTechnologyAdapter",
        "N3IWFAdapter", "ReferenceWifiEngine", "SandboxedWifi",
        "WifiAppSession", "adapters.wifi", "adapters/wifi",
        "hostapd", "wpa_supplicant", "strongswan",
    )
    scanned = 0
    for d in core_dirs:
        dp = os.path.join(_ROOT, d)
        if not os.path.isdir(dp):
            continue
        for fn in sorted(os.listdir(dp)):
            if not fn.endswith(".py"):
                continue
            fpath = os.path.join(dp, fn)
            with open(fpath, "r", encoding="utf-8") as f:
                src = f.read()
            scanned += 1
            lower = src.lower()
            for tok in impl_type_tokens:
                if tok.lower() in lower:
                    return fail(name, "%s/%s: Wi-Fi implementation token %r leaks into core domain" % (d, fn, tok))
            tree = ast.parse(src)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name == "adapters.wifi" or alias.name.startswith("adapters.wifi."):
                            return fail(name, "%s/%s imports %r (LOCK-002/016 leak)" % (d, fn, alias.name))
                elif isinstance(node, ast.ImportFrom):
                    mod = node.module or ""
                    if mod == "adapters.wifi" or mod.startswith("adapters.wifi."):
                        return fail(name, "%s/%s imports %r (LOCK-002/016 leak)" % (d, fn, mod))
    # The generic W016 SDK + the W018/W019 peer families must not
    # import the Wi-Fi family either (peer independence).
    peer_scopes = [os.path.join(_ROOT, "adapters", f) for f in (
        "__init__.py", "contract.py", "sandbox.py", "runtime.py",
        "model.py", "validation.py", "serialization.py", "errors.py",
    )]
    for sub in ("ip", "fivegc"):
        d = os.path.join(_ROOT, "adapters", sub)
        if os.path.isdir(d):
            peer_scopes.extend(
                os.path.join(d, fn) for fn in sorted(os.listdir(d))
                if fn.endswith(".py")
            )
    for fpath in peer_scopes:
        if not os.path.exists(fpath):
            continue
        with open(fpath, "r", encoding="utf-8") as f:
            src = f.read()
        scanned += 1
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "adapters.wifi" or alias.name.startswith("adapters.wifi."):
                        return fail(name, "%s imports adapters.wifi (peer leak)" % fpath)
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                if mod == "adapters.wifi" or mod.startswith("adapters.wifi."):
                    return fail(name, "%s imports adapters.wifi (peer leak)" % fpath)
    # And the Wi-Fi family imports NEITHER the fivegc family NOR the
    # unaccepted ran family (the selftest is the composition point,
    # never the families themselves).  The ONLY sanctioned crossing
    # out of the family is the W016 SDK contract (..contract).
    wifi_dir = os.path.join(_ROOT, "adapters", "wifi")
    for fn in sorted(os.listdir(wifi_dir)):
        if not fn.endswith(".py"):
            continue
        with open(os.path.join(wifi_dir, fn), "r", encoding="utf-8") as f:
            src = f.read()
        scanned += 1
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("adapters.fivegc") or alias.name.startswith("adapters.ran"):
                        return fail(name, "adapters/wifi/%s imports %r (family independence)" % (fn, alias.name))
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                if mod.startswith("adapters.fivegc") or mod.startswith("adapters.ran"):
                    return fail(name, "adapters/wifi/%s imports %r (family independence)" % (fn, mod))
                if node.level == 2 and mod not in ("contract",):
                    return fail(name, "adapters/wifi/%s crosses the family boundary to %r (only ..contract is sanctioned)" % (fn, mod))
    return ok(name, "no adapters.wifi import in core (%d files scanned); no peer leak; family independence holds" % scanned)


def case_23_authority_session_reader_read_only() -> Result:
    name = "case_23_authority_session_reader_read_only"
    reader = _TestSessionReader()
    surface = {
        a for a in dir(reader)
        if not a.startswith("_") and a != "lookup" and callable(getattr(reader, a, None))
    }
    if surface:
        return fail(name, "SessionReader exposes beyond lookup: %s" % sorted(surface))
    view = reader.lookup(_SESSION_ID)
    try:
        view.secureable = False  # type: ignore[misc, union-attr]
        return fail(name, "SessionView is mutable")
    except Exception:
        pass
    return ok(name, "SessionReader: lookup only; SessionView frozen")


def case_24_step_charges_pinned() -> Result:
    name = "case_24_step_charges_pinned"
    expected = {
        "open": 4, "provision_ap": 10, "bind_session": 8,
        "attach_external_association": 8, "observe_external_association": 2,
        "authenticate": 12, "establish_tunnel": 16, "egress_frame": 4,
        "release_tunnel": 6, "app_session": 6, "health": 1, "close": 4,
    }
    if dict(STEP_CHARGES) != expected:
        return fail(name, "STEP_CHARGES drifted: %s" % dict(STEP_CHARGES))
    if DEFAULT_STEP_BUDGET != 10000:
        return fail(name, "DEFAULT_STEP_BUDGET drifted: %d" % DEFAULT_STEP_BUDGET)
    try:
        STEP_CHARGES["open"] = 0  # type: ignore[index]
        return fail(name, "STEP_CHARGES is mutable")
    except TypeError:
        pass
    return ok(name, "frozen step-charge table + DEFAULT_STEP_BUDGET=10000 (pinnable surface)")


def case_25_determinism_byte_identical_snapshot() -> Result:
    name = "case_25_determinism_byte_identical_snapshot"

    def build() -> bytes:
        mgr = _new_manager()
        _bind_auth_establish(mgr, session_id=_SESSION_ID)
        return mgr.to_canonical_bytes()

    a = build()
    b = build()
    if a != b:
        return fail(name, "snapshot not byte-identical across runs")
    return ok(name, "byte-identical canonical snapshots across runs")


def case_26_determinism_cross_impl_byte_identical() -> Result:
    name = "case_26_determinism_cross_impl_byte_identical"
    m1 = _new_manager(ReferenceWifiEngine())
    _bind_auth_establish(m1, session_id=_SESSION_ID)
    m2 = _new_manager(_SecondImpl())
    _bind_auth_establish(m2, session_id=_SESSION_ID)
    a = m1.to_canonical_bytes()
    b = m2.to_canonical_bytes()
    if a != b:
        return fail(name, "canonical state differs across impls")
    # implementation_label is NOT in the snapshot (B2).
    snap = m1.snapshot()
    if "implementation_label" in snap:
        return fail(name, "implementation_label in canonical snapshot (B2 violation)")
    d1 = m1.diagnostic_state().get("implementation_label", "")
    d2 = m2.diagnostic_state().get("implementation_label", "")
    if d1 == d2:
        return fail(name, "two impls have the same label (test invalid)")
    return ok(name, "byte-identical canonical state across impls (DIRECT, no normalization); implementation_label excluded")


def case_27_failure_isolation_base_exception() -> Result:
    name = "case_27_failure_isolation_base_exception"
    mgr = _new_manager(_CrashingImpl())
    r = mgr.provision_ap(
        now=_NOW, descriptor=_descriptor(), credential_slot_name=_CRED_SLOT,
    )
    if r.ok:
        return fail(name, "crashing impl did not fail")
    if r.reason != WifiReasonCode.WIFI_FAILURE:
        return fail(name, "wrong reason: %s" % r.reason)
    if r.failure is None or r.failure.exception_class_name != "SystemExit":
        return fail(name, "exception class name not captured")
    if "crashed" in (r.detail or "").lower():
        return fail(name, "exception message text captured (LOCK-023 leak)")
    return ok(name, "SystemExit -> isolated value; class name only; message text not captured")


def case_28_failure_isolation_contract_violation() -> Result:
    name = "case_28_failure_isolation_contract_violation"
    mgr = _new_manager(_ContractViolatingImpl())
    ap_ref = _provision(mgr)
    r = mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID, ap_ref=ap_ref,
        ssid_name=_SSID, station_label=_STATION,
    )
    if r.ok:
        return fail(name, "contract-violating impl did not fail")
    if r.reason != WifiReasonCode.CONTRACT_VIOLATION:
        return fail(name, "wrong reason: %s" % r.reason)
    if r.value is not None:
        return fail(name, "non-contract value was returned")
    return ok(name, "non-contract return discarded (R6)")


def case_29_failure_isolation_budget_exhaustion() -> Result:
    name = "case_29_failure_isolation_budget_exhaustion"
    # The sandbox grants each mediated operation a FRESH context with
    # the manager's step budget (the deterministic hang model); a
    # single operation whose charge exceeds the budget fails closed
    # with BUDGET_EXHAUSTED as an isolated VALUE (never a hang, never
    # a wall clock).  provision_ap charges 10 -> budget 6 exhausts.
    mgr = _new_manager(step_budget=6)
    r = mgr.provision_ap(
        now=_NOW, descriptor=_descriptor(), credential_slot_name=_CRED_SLOT,
    )
    if r.ok:
        return fail(name, "provision_ap did not exhaust budget")
    if r.reason != WifiReasonCode.BUDGET_EXHAUSTED:
        return fail(name, "wrong reason: %s" % r.reason)
    if "hang" not in (r.detail or "").lower():
        return fail(name, "no hang model mentioned in failure detail")
    # The manager itself stays healthy for caller-side ops (the
    # failure is an isolated adapter-side value, not a crash).
    if mgr.diagnostic_state().get("integration_id") != "adcos:wifi:test":
        return fail(name, "manager bookkeeping corrupted by budget failure")
    return ok(name, "BUDGET_EXHAUSTED; hang model; no wall clock")


def case_30_failure_isolation_no_secret_leak() -> Result:
    name = "case_30_failure_isolation_no_secret_leak"
    mgr = _new_manager(_SecretLeakingImpl())
    ap_ref = _provision(mgr)
    r = mgr.bind_session(
        now=_NOW, session_id=_SESSION_ID, ap_ref=ap_ref,
        ssid_name=_SSID, station_label=_STATION,
    )
    if r.ok:
        return fail(name, "secret-leaking impl did not fail")
    blob = ""
    if r.failure is not None:
        blob = repr(r.failure.to_dict()) + " " + (r.detail or "")
    if "deadbeef" in blob or "cafebad" in blob or "1234567890abcdef" in blob:
        return fail(name, "secret material leaked through failure diagnostics")
    return ok(name, "exception message text never captured (LOCK-023)")


def case_31_a4_real_conformance_byte_path() -> Result:
    """The a4 conformance byte path (the WORK-019 case_29 analog).

    Proves bytes traverse the WifiAppSession -> WifiManager ->
    SandboxedWifi -> N3IWFAdapter -> real N3IWF-shaped peer (real UDP
    RFC 7296 IKE-shaped control plane + real TCP tunnel data socket)
    path, plus a REAL observe_external_association round-trip through
    the peer's association table.
    """
    name = "case_31_a4_real_conformance_byte_path"
    payload = b"adcospktpath-wifi-n3iwf-conformance-v1"
    server = ReferenceWifiConformanceServer()
    try:
        # leg 1: N3IWFAdapter -> real conformance N3IWF peer.
        adapter1 = N3IWFAdapter(control_endpoint=server.control_endpoint)
        mgr = WifiManager(
            integration_id="adcos:wifi:a4",
            session_reader=_TestSessionReader(),
            ap_profile_reader=_TestApProfileReader(),
        )
        r = mgr.register_implementation(
            adapter1, label="n3iwf-leg1", make_default=True, now=_NOW,
        )
        if not r.ok:
            return fail(name, "register failed: %s" % r.detail)
        binding1 = _provision_bind(mgr, session_id=_SESSION_ID)
        if not mgr.authenticate(now=_NOW, binding_id=binding1.binding_id).ok:
            return fail(name, "real IKE_SA_INIT/IKE_AUTH attach failed")
        r = mgr.establish_tunnel(now=_NOW, binding_id=binding1.binding_id)
        if not r.ok:
            return fail(name, "real CREATE_CHILD_SA tunnel establishment failed")
        tunnel_ref1 = r.value.tunnel_ref
        # A REAL observe round-trip against the peer's association
        # table (the adapter's observe override; the reference engine
        # honestly raises WIFI_UNAVAILABLE -- it has no peer).
        obs = mgr.observe_external_association(
            now=_NOW, external_association_id="n3iwf-assoc-1",
        )
        if not obs.ok:
            return fail(name, "real OBSERVE round-trip failed: %s" % obs.detail)
        if obs.value.ssid != _SSID or obs.value.state != "authenticated":
            return fail(name, "observed evidence mismatch: %s" % obs.value)
        # The application byte path over the REAL peer.
        r = mgr.app_session(now=_NOW, session_id=_SESSION_ID)
        if not r.ok:
            return fail(name, "app_session failed: %s" % r.detail)
        session = r.value
        session.connect("lobby-service")
        if session.send(payload) != len(payload):
            return fail(name, "leg1 send returned wrong length")
        echo = b""
        while len(echo) < len(payload):
            chunk = session.recv()
            if not chunk:
                break
            echo += chunk
        session.close()
        if echo != payload:
            return fail(name, "leg1 round-trip mismatch: %r != %r" % (echo, payload))

        # leg 2: register_implementation swap + fresh session + the
        # same real byte path (replaceability via the same seam).
        adapter2 = N3IWFAdapter(control_endpoint=server.control_endpoint)
        r = mgr.register_implementation(
            adapter2, label="n3iwf-leg2", make_default=True, now=_NOW,
        )
        if not r.ok:
            return fail(name, "register swap failed: %s" % r.detail)
        binding2 = _provision_bind(
            mgr, session_id=_SESSION_ID_2, descriptor=_descriptor(name="ap-leg2"),
        )
        if not mgr.authenticate(now=_NOW, binding_id=binding2.binding_id).ok:
            return fail(name, "leg2 attach failed")
        r = mgr.establish_tunnel(now=_NOW, binding_id=binding2.binding_id)
        if not r.ok:
            return fail(name, "leg2 tunnel establishment failed")
        tunnel_ref2 = r.value.tunnel_ref
        r = mgr.app_session(now=_NOW, session_id=_SESSION_ID_2)
        if not r.ok:
            return fail(name, "leg2 app_session failed: %s" % r.detail)
        session2 = r.value
        session2.connect("lobby-service")
        session2.send(payload)
        echo2 = b""
        while len(echo2) < len(payload):
            chunk = session2.recv()
            if not chunk:
                break
            echo2 += chunk
        session2.close()
        if echo2 != payload:
            return fail(name, "leg2 round-trip mismatch")

        # Cleanup: release both tunnels, close both bindings.
        mgr.release_tunnel(now=_NOW, tunnel_ref=tunnel_ref1)
        mgr.release_tunnel(now=_NOW, tunnel_ref=tunnel_ref2)
        mgr.close_binding(now=_NOW, binding_id=binding1.binding_id)
        mgr.close_binding(now=_NOW, binding_id=binding2.binding_id)
        mgr.close()
        return ok(
            name,
            "WifiAppSession->Manager->Sandbox->N3IWFAdapter->real UDP IKE + "
            "real TCP tunnel peer->recv (leg1 + leg2 register_implementation "
            "swap + real OBSERVE round-trip); payload=%r byte-identical both "
            "legs" % payload,
        )
    finally:
        server.close()


def case_32_w016_sdk_bridge_nine_op_surface() -> Result:
    """The WORK-016 SDK bridge: the family ON the accepted generic
    nine-op Adapter SDK surface (driven THROUGH the SDK runtime, with
    the SDK's own sandbox mediating -- the brief's "using the accepted
    WORK-016 Adapter SDK as the generic bridge").

    The architect-reviewed authority path (PR #22 redesign): the
    bridge adapts the family RUNTIME (WifiManager), never the
    WifiContract implementation -- AdapterRuntime -> bridge ->
    manager -> SandboxedWifi -> implementation.  The composition root
    registers the implementation with the manager FIRST (the family
    access path comes up at manager registration), then constructs
    the bridge over the manager, then registers the bridge on the SDK
    runtime; the family-side session verification is the manager's
    REAL read-only SessionReader over the same WORK-012 store the SDK
    runtime verifies against (the bridge fabricates no session
    facts)."""
    name = "case_32_w016_sdk_bridge_nine_op_surface"
    from adapters.wifi import WifiTechnologyAdapter

    store, sid = _established_session()
    runtime = AdapterRuntime(session_store=store)
    technology = "access.ieee.80211"
    adapter_id = derive_adapter_id(technology, "wifi-0")
    descriptor = AdapterDescriptor(
        adapter_id=adapter_id,
        access_technology_id=technology,
        supported_profile_versions=("v1-0-0",),
        capabilities=(
            "capability.profile.wifi.non-3gpp-access",
            "capability.profile.wifi.association",
            "capability.profile.wifi.authentication",
            "capability.profile.wifi.n3iwf-tunnel",
            "capability.profile.wifi.data-path",
        ),
        resource_mapping=(
            ResourceMappingEntry(
                technology_resource="ap-association-capacity",
                kind="coverage",
                unit="count",
                quantity=4,
                availability="continuous",
            ),
        ),
        security_state=AdapterSecurityState(
            profile="baseline",
            credential_slots=("wifi-technology-credentials",),
            attested=False,
        ),
    )
    # The composition root's wiring: the family runtime is constructed
    # FIRST, the implementation is registered with it (opening + health
    # probing it through the family sandbox), and the bridge is built
    # OVER THE MANAGER.  The family-side session verification is a
    # REAL read-only reader over the same WORK-012 store the SDK
    # runtime verifies bindability against -- the bridge asserts no
    # session facts of its own.
    engine = ReferenceWifiEngine()
    mgr = WifiManager(
        integration_id="adcos:wifi:sdk-bridge",
        session_reader=_StoreSessionReader(store),
        ap_profile_reader=_TestApProfileReader(),
    )
    r = mgr.register_implementation(
        engine, label="wifi-sdk", make_default=True, now=_T0,
    )
    if not r.ok:
        return fail(name, "family register_implementation failed: %s" % r.detail)
    bridge = WifiTechnologyAdapter(mgr, label="wifi-sdk-bridge")
    # The bridge holds a MANAGER reference and NOTHING else -- no
    # implementation reference, no fabricated session reader, no
    # context-construction state.
    if "_implementation" in vars(bridge):
        return fail(name, "bridge holds an implementation reference")
    if set(vars(bridge)) != {"_manager", "label"}:
        return fail(name, "bridge carries state beyond manager+label: %s"
                    % sorted(vars(bridge)))
    runtime.register(descriptor, bridge, now=_T0)
    if runtime.adapter_ids() != (adapter_id,):
        return fail(name, "bridge not registered on the SDK runtime")
    # SDK open -> a MEDIATED manager health probe (the family access
    # path came up at manager registration; SDK open verifies it is
    # observable through the mediated path).
    sdk_r = runtime.open_adapter(adapter_id, now=_NOW)
    if not sdk_r.ok:
        return fail(name, "SDK open failed: %s" % sdk_r.failure)
    # SDK capabilities -> the manager's informational capability ladder
    # (derived from MEDIATED manager state), FILTERED to the
    # descriptor's declared set (the runtime never lets an
    # implementation inflate exposure beyond its registration
    # declaration -- exposure is by reference).
    caps_before = runtime.capabilities(adapter_id, now=_NOW)
    if "capability.profile.wifi.non-3gpp-access" not in caps_before:
        return fail(name, "boundary capabilities missing pre-allocation: %s" % (caps_before,))
    if "capability.profile.wifi.data-path" in caps_before:
        return fail(name, "data-path capability fabricated before an active SSID")
    # SDK observe -> the honest link-metric translation (link-down
    # before any provisioned AP: HEALTHY requires an ACTIVE SSID).
    obs_before = runtime.observe(adapter_id, now=_NOW)
    if not obs_before.ok:
        return fail(
            name, "SDK observe failed: %s"
            % (obs_before.failure.detail if obs_before.failure else "?")
        )
    samples = {s.metric: s.value for s in obs_before.value}
    if samples.get("link-up") != 0:
        return fail(name, "link-up must be 0 with an empty AP store: %s" % samples)
    # SDK allocate -> manager provision_ap (the opaque wifi:ap:<hex>
    # technology ref; the runtime keeps it internal -- recover it from
    # the engine for the bind coordinates).
    sdk_r = runtime.allocate(
        adapter_id, kind="coverage", quantity=4, unit="count",
        purpose="lobby-ap", now=_NOW,
    )
    if not sdk_r.ok:
        return fail(name, "SDK allocate failed: %s" % (sdk_r.failure.detail if sdk_r.failure else "?"))
    ap_refs = sorted(engine._aps)  # test reach-around
    if len(ap_refs) != 1 or not ap_refs[0].startswith("wifi:ap:"):
        return fail(name, "allocate did not provision exactly one AP: %s" % (ap_refs,))
    ap_ref = ap_refs[0]
    caps_after = runtime.capabilities(adapter_id, now=_NOW)
    if "capability.profile.wifi.data-path" not in caps_after:
        return fail(name, "data-path capability missing after allocation: %s" % (caps_after,))
    if not set(caps_before) < set(caps_after):
        return fail(name, "capability ladder did not grow on allocation")
    obs_after = runtime.observe(adapter_id, now=_NOW)
    if not obs_after.ok:
        return fail(
            name, "SDK observe (post-allocate) failed: %s"
            % (obs_after.failure.detail if obs_after.failure else "?")
        )
    samples_after = {s.metric: s.value for s in obs_after.value}
    if samples_after.get("link-up") != 1:
        return fail(name, "link-up must be 1 with an active SSID: %s" % samples_after)
    # SDK bind_session -> manager bind + authenticate + establish (each
    # MEDIATED through the binding's owning sandbox; requirements carry
    # the Wi-Fi binding coordinates -- DATA the bridge CONSUMES as the
    # manager's explicit parameters, forwarding only the leftover QoS
    # map.  The bridge's documented allocate translation names the
    # provisioned SSID after the mapped resource kind, so the SSID to
    # associate on here is "coverage").
    sdk_r = runtime.bind_session(
        adapter_id, session_id=sid, now=_NOW,
        requirements={"ap_ref": ap_ref, "ssid_name": "coverage"},
    )
    if not sdk_r.ok:
        return fail(name, "SDK bind_session failed: %s" % (sdk_r.failure.detail if sdk_r.failure else "?"))
    bearer_ref = sdk_r.value.bearer_ref
    if not str(bearer_ref).startswith("wifi:tunnel:"):
        return fail(name, "SDK bearer is not the N3IWF tunnel ref: %s" % bearer_ref)
    if sid in str(bearer_ref):
        return fail(name, "SDK bearer embeds the session id (W021 collapse)")
    binding_id = sdk_r.value.binding_id
    # The manager's canonical event history PROVES the bridge routed
    # every operation through the family runtime (only the manager
    # appends these events): provision -> bind -> authenticate ->
    # establish, all mediated.
    event_types = [e["event_type"] for e in mgr.snapshot()["events"]]
    for expected_event in (
        "AP_PROVISIONED", "BIND_SESSION", "AUTHENTICATE",
        "ESTABLISH_TUNNEL",
    ):
        if expected_event not in event_types:
            return fail(
                name,
                "manager event history missing %s (the bridge must route "
                "through the manager): %s" % (expected_event, event_types),
            )
    # SDK health -> the manager's mediated-outcomes health translated
    # onto the SDK's three-state vocabulary.
    health = runtime.health(adapter_id, now=_NOW)
    if getattr(health, "state", "") != "HEALTHY":
        return fail(name, "SDK health not HEALTHY after provisioning: %s" % health)
    # SDK unbind -> manager release_tunnel (the tunnel index routes
    # the release to the OWNING binding's sandbox).
    sdk_r = runtime.unbind_session(binding_id, now=_NOW)
    if not sdk_r.ok:
        return fail(name, "SDK unbind failed: %s" % (sdk_r.failure.detail if sdk_r.failure else "?"))
    if "RELEASE_TUNNEL" not in [
        e["event_type"] for e in mgr.snapshot()["events"]
    ]:
        return fail(name, "manager event history missing RELEASE_TUNNEL")
    # SDK release of the AP allocation fails CLOSED honestly (the
    # frozen 12-op family contract has no AP decommission operation)
    # -- the bridge refuses to silently drop the release.  Surfaced
    # as an advisory in the PR: an SDK-level AP allocation cannot be
    # released through this bridge; the profile retires with the
    # implementation instance.
    state = runtime._adapters.get(adapter_id)  # test reach-around
    alloc_id = None
    if state is not None:
        for aid, allocation in state.allocations.items():
            if str(allocation.state) == "ACTIVE":
                alloc_id = aid
                break
    if alloc_id is not None:
        sdk_r = runtime.release(alloc_id, now=_NOW)
        if sdk_r.ok:
            return fail(name, "AP-ref SDK release silently succeeded (should fail closed)")
        # The SDK sandbox isolates the WifiError (message text not
        # captured -- its own LOCK-023 discipline, verified here as a
        # side effect); the fail-closed OUTCOME is the assertion.
    # An ASSOCIATION ref fails closed at this seam too (the SDK
    # surface carries no assoc refs; the association release is the
    # family-native manager.close_binding).
    try:
        bridge.release(
            AdapterContext(adapter_id, technology, _NOW, 100),
            "wifi:assoc:" + "a" * 32,
        )
        return fail(name, "assoc-ref release silently succeeded (should fail closed)")
    except WifiError:
        pass
    return ok(
        name,
        "nine-op SDK surface over the family RUNTIME (bridge->manager->"
        "sandbox->impl, proven by the manager event history); honest "
        "ladder + link translation; AP + assoc releases fail closed; "
        "the bridge holds manager+label only",
    )


def case_33_mixed_access_session_continuity_with_5g() -> Result:
    """Mixed-access session continuity with 5G (the brief's bullet 7).

    The SAME sacred, access-independent session_id carries application
    bytes over the accepted WORK-019 5G Core conformance path (real
    HTTP SBi + real TCP data socket), then -- after an access change
    (release + re-bind, never a new session) -- over the WORK-021
    Wi-Fi/N3IWF conformance path (real UDP control plane + real TCP
    tunnel data), then BACK to 5G.  The access changes; the session
    identity does not; no adapter-side ref from either family ever
    appears in the other's namespace.
    """
    name = "case_33_mixed_access_session_continuity_with_5g"
    payload = b"adcospktpath-mixed-access-continuity-v1"
    fivegc_server = Reference5GCoreConformanceServer()
    wifi_server = ReferenceWifiConformanceServer()
    try:
        # ---- leg 1: the session over 5G access (WORK-019). ----
        fivegc_mgr = FiveGCoreManager(
            integration_id="adcos:fivegc:mixed",
            session_reader=_FiveGcTestSessionReader(),
            subscriber_reader=_FiveGcTestSubscriberReader(),
        )
        adapter1 = Open5GSAdapter(
            nf_endpoint=NfEndpoint(nf_type="SMF", url=fivegc_server.base_url)
        )
        r = fivegc_mgr.register_implementation(adapter1, now=_NOW)
        if not r.ok:
            return fail(name, "fivegc register failed: %s" % r.detail)
        fivegc_mgr.provision_subscriber(
            now=_NOW, supi=_SUPI, credential_slot_name="subscriber-credentials",
            subscribed_snssai=_SNSSAI, subscribed_dnn=_DNN,
        )
        r = fivegc_mgr.bind_session(
            now=_NOW, session_id=_SESSION_ID, supi=_SUPI,
            snssai=_SNSSAI, dnn=_DNN,
        )
        if not r.ok:
            return fail(name, "fivegc bind failed: %s" % r.detail)
        pdu_ref = r.value.pdu_session_ref
        if not fivegc_mgr.authenticate(now=_NOW, pdu_session_ref=pdu_ref).ok:
            return fail(name, "fivegc authenticate failed")
        if not fivegc_mgr.establish_pdu_session(now=_NOW, pdu_session_ref=pdu_ref).ok:
            return fail(name, "fivegc establish failed")
        r = fivegc_mgr.app_session(now=_NOW, session_id=_SESSION_ID)
        if not r.ok:
            return fail(name, "fivegc app_session failed: %s" % r.detail)
        sock = r.value
        sock.connect("internet")
        sock.send(payload)
        echo_5g = b""
        while len(echo_5g) < len(payload):
            chunk = sock.recv()
            if not chunk:
                break
            echo_5g += chunk
        sock.close()
        if echo_5g != payload:
            return fail(name, "5G leg round-trip mismatch")
        # Access change: release the 5G binding (the SAME session
        # moves; the session_id is never re-minted).
        if not fivegc_mgr.close_binding(now=_NOW, pdu_session_ref=pdu_ref).ok:
            return fail(name, "fivegc close failed")
        fivegc_mgr.close()

        # ---- leg 2: the SAME session over Wi-Fi/non-3GPP access
        # (WORK-021, real conformance peer). ----
        wifi_mgr = WifiManager(
            integration_id="adcos:wifi:mixed",
            session_reader=_TestSessionReader(),
            ap_profile_reader=_TestApProfileReader(),
        )
        wifi_adapter = N3IWFAdapter(control_endpoint=wifi_server.control_endpoint)
        wr = wifi_mgr.register_implementation(
            wifi_adapter, label="n3iwf-mixed", make_default=True, now=_NOW,
        )
        if not wr.ok:
            return fail(name, "wifi register failed: %s" % wr.detail)
        binding = _provision_bind(wifi_mgr, session_id=_SESSION_ID)
        if binding.session_id != _SESSION_ID:
            return fail(name, "wifi binding changed the session id")
        if not wifi_mgr.authenticate(now=_NOW, binding_id=binding.binding_id).ok:
            return fail(name, "wifi attach failed")
        wr = wifi_mgr.establish_tunnel(now=_NOW, binding_id=binding.binding_id)
        if not wr.ok:
            return fail(name, "wifi tunnel establishment failed: %s" % wr.detail)
        tunnel_ref = wr.value.tunnel_ref
        # Identity separation across FAMILIES: no fivegc-side ref text
        # appears in the wifi refs and vice versa.
        if "pdu" in tunnel_ref or "fivegc" in tunnel_ref:
            return fail(name, "wifi ref carries 5G-side identity text")
        if "wifi" in pdu_ref:
            return fail(name, "fivegc ref carries Wi-Fi-side identity text")
        wr = wifi_mgr.app_session(now=_NOW, session_id=_SESSION_ID)
        if not wr.ok:
            return fail(name, "wifi app_session failed: %s" % wr.detail)
        wsession = wr.value
        wsession.connect("lobby-service")
        wsession.send(payload)
        echo_wifi = b""
        while len(echo_wifi) < len(payload):
            chunk = wsession.recv()
            if not chunk:
                break
            echo_wifi += chunk
        wsession.close()
        if echo_wifi != payload:
            return fail(name, "wifi leg round-trip mismatch")
        # Access change back: release the wifi binding, re-bind on 5G.
        wifi_mgr.release_tunnel(now=_NOW, tunnel_ref=tunnel_ref)
        if not wifi_mgr.close_binding(now=_NOW, binding_id=binding.binding_id).ok:
            return fail(name, "wifi close failed")
        wifi_mgr.close()

        # ---- leg 3: BACK to 5G access with the SAME session id. ----
        fivegc_mgr2 = FiveGCoreManager(
            integration_id="adcos:fivegc:mixed2",
            session_reader=_FiveGcTestSessionReader(),
            subscriber_reader=_FiveGcTestSubscriberReader(),
        )
        adapter2 = Open5GSAdapter(
            nf_endpoint=NfEndpoint(nf_type="SMF", url=fivegc_server.base_url)
        )
        r = fivegc_mgr2.register_implementation(adapter2, now=_NOW)
        if not r.ok:
            return fail(name, "fivegc re-register failed: %s" % r.detail)
        fivegc_mgr2.provision_subscriber(
            now=_NOW, supi=_SUPI, credential_slot_name="subscriber-credentials",
            subscribed_snssai=_SNSSAI, subscribed_dnn=_DNN,
        )
        r = fivegc_mgr2.bind_session(
            now=_NOW, session_id=_SESSION_ID, supi=_SUPI,
            snssai=_SNSSAI, dnn=_DNN,
        )
        if not r.ok:
            return fail(name, "fivegc re-bind failed: %s" % r.detail)
        pdu_ref2 = r.value.pdu_session_ref
        if not fivegc_mgr2.authenticate(now=_NOW, pdu_session_ref=pdu_ref2).ok:
            return fail(name, "fivegc re-authenticate failed")
        if not fivegc_mgr2.establish_pdu_session(now=_NOW, pdu_session_ref=pdu_ref2).ok:
            return fail(name, "fivegc re-establish failed")
        r = fivegc_mgr2.app_session(now=_NOW, session_id=_SESSION_ID)
        if not r.ok:
            return fail(name, "fivegc re-app_session failed: %s" % r.detail)
        sock2 = r.value
        sock2.connect("internet")
        sock2.send(payload)
        echo_5g2 = b""
        while len(echo_5g2) < len(payload):
            chunk = sock2.recv()
            if not chunk:
                break
            echo_5g2 += chunk
        sock2.close()
        if echo_5g2 != payload:
            return fail(name, "5G return leg round-trip mismatch")
        fivegc_mgr2.close_binding(now=_NOW, pdu_session_ref=pdu_ref2)
        fivegc_mgr2.close()
        return ok(
            name,
            "session %s... carried bytes over 5G (real SBi+TCP) -> Wi-Fi/N3IWF "
            "(real UDP+TCP) -> BACK to 5G; access changed twice, session id "
            "never re-minted; no cross-family ref leakage; payload %r "
            "byte-identical on all three legs"
            % (_SESSION_ID[:14], payload),
        )
    finally:
        fivegc_server.close()
        wifi_server.close()


def case_34_b1_real_wifi_n3iwf_interop_gate() -> Result:
    """The B1 real Wi-Fi/N3IWF interop gate (environment-gated).

    * ``WIFI_INTEROP`` unset -> SKIP with a transparent gate-disabled
      disclosure (the conformance suite case_31 remains the strongest
      evidence in this run; the gate does NOT run).
    * ``WIFI_INTEROP=1`` + no reachable real peer -> SKIP with a
      transparent verification-environment blocker disclosure (the
      gate does NOT fake success with the in-repo conformance peer).
    * reachable real peer + real bytes end-to-end -> PASSED (the
      outcome that closes the gate -- never observed in this sandbox).
    * real failures -> FAIL statuses (never masked as SKIPs).
    """
    name = "case_34_b1_real_wifi_n3iwf_interop_gate"
    if not wifi_gate_enabled():
        return ok(
            name,
            "SKIP (environment-gated WIFI_INTEROP!=1): the B1 real-Wi-Fi/N3IWF "
            "interop suite is not run; the conformance suite (case_31) covers "
            "the deterministic reference peer.  Set WIFI_INTEROP=1 with a "
            "reachable real N3IWF control-plane endpoint "
            "(WIFI_N3IWF_ENDPOINT=host:port) + a tunnel data peer "
            "(WIFI_DATA_PEER=host:port) to close the gate; see the interop "
            "runbook in adapters/wifi/interop_env_probe.py.",
        )
    outcome = run_wifi_interop(WifiInteropConfig.from_env())
    if outcome.status == "PASSED":
        return ok(name, "REAL Wi-Fi/N3IWF interop PASSED -- gate closed: %s" % outcome.detail)
    if outcome.status in ("UNREACHABLE", "FORBIDDEN"):
        return ok(
            name,
            "SKIP (verification-environment blocker): WIFI_INTEROP=1 set but "
            "%s -- the gate does NOT fake success with the in-repo "
            "conformance peer; expand the environment (a real N3IWF + radio "
            "path) to close the gate." % outcome.detail.splitlines()[0],
        )
    return fail(name, "Wi-Fi/N3IWF interop %s: %s" % (outcome.status, outcome.detail))


def case_35_b1_gate_hardening_matrix_and_anti_faking() -> Result:
    """B1 gate-hardening regression (the WORK-019 case_31 analog).

    Asserts the two hardening properties hold in THIS sandbox:

    (1) EXPLICIT environment-capability matrix -- the probe reports
        the real missing capabilities (radio interfaces / nl80211
        tools / association daemons / IPsec) and declares SKIP (not
        acceptance); the gate's UNREACHABLE detail CARRIES the
        structured matrix, not an opaque string.
    (2) HARD anti-faking peer_kind guard -- an EXPLICIT in-repo-
        simulator assertion (WIFI_PEER_KIND=reference) produces
        FORBIDDEN at the gate boundary BEFORE any probe (never
        PASSED, never a silent fallback to the in-repo conformance
        peer).

    Acceptance semantics are PRESERVED: this case never observes
    PASSED (the sandbox cannot host a real Wi-Fi/N3IWF path); it only
    asserts the honest non-acceptance outcomes (UNREACHABLE +
    FORBIDDEN) carry the approved hardening diagnostics.
    """
    name = "case_35_b1_gate_hardening_matrix_and_anti_faking"
    env_keys = (
        "WIFI_INTEROP", "WIFI_PEER_KIND", "WIFI_N3IWF_ENDPOINT",
        "WIFI_DATA_PEER", "WIFI_PROBE_TIMEOUT_S",
    )
    saved = {k: os.environ.get(k) for k in env_keys}
    try:
        # Leg 1: probe directly -- sandbox is incapable; the matrix
        # must report the real missing capabilities and declare SKIP.
        os.environ.pop("WIFI_INTEROP", None)
        os.environ.pop("WIFI_PEER_KIND", None)
        os.environ.pop("WIFI_N3IWF_ENDPOINT", None)
        os.environ["WIFI_PROBE_TIMEOUT_S"] = "1.0"
        report = probe_wifi_interop_capability(WifiEnvProbeConfig.from_env())
        if report.forbidden_substitution is not None:
            return fail(name, "leg1: guard should not fire with unset PEER_KIND; got %s" % report.forbidden_substitution)
        if report.reachable:
            return fail(name, "leg1: probe reports reachable=True; expected False (sandbox cannot host a real Wi-Fi/N3IWF path)")
        matrix = report.summary()
        for entry in (
            "wifi_radio_interfaces", "nl80211_tools",
            "association_daemons", "ipsec_user_plane",
        ):
            if entry not in matrix:
                return fail(name, "leg1: matrix missing %r; got:\n%s" % (entry, matrix))
        if "SKIP" not in matrix or "PASSED" in matrix:
            return fail(name, "leg1: matrix must declare SKIP and never PASSED; got:\n%s" % matrix)

        # Leg 2: anti-faking guard -- explicit reference-kind must
        # fire FORBIDDEN (never acceptance).
        os.environ["WIFI_PEER_KIND"] = "reference"
        report2 = probe_wifi_interop_capability(WifiEnvProbeConfig.from_env())
        if report2.forbidden_substitution is None:
            return fail(name, "leg2: guard did not fire on WIFI_PEER_KIND=reference")
        if "FORBIDDEN" not in report2.summary():
            return fail(name, "leg2: matrix must declare FORBIDDEN; got:\n%s" % report2.summary())

        # Leg 3: integrated gate -- run_wifi_interop with the
        # forbidden peer kind must short-circuit to FORBIDDEN BEFORE
        # any probe (anti-faking enforced at the gate boundary).
        os.environ["WIFI_INTEROP"] = "1"
        os.environ.pop("WIFI_N3IWF_ENDPOINT", None)
        outcome = run_wifi_interop(WifiInteropConfig.from_env())
        if outcome.status != "FORBIDDEN":
            return fail(name, "leg3: gate must return FORBIDDEN on reference peer kind; got %s: %s" % (outcome.status, outcome.detail))

        # Leg 4: integrated gate -- real-kind assertion + unreachable
        # endpoint must return UNREACHABLE whose detail CARRIES the
        # explicit capability matrix, and must NOT be PASSED.
        os.environ["WIFI_PEER_KIND"] = "real_n3iwf"
        os.environ["WIFI_N3IWF_ENDPOINT"] = "127.0.0.1:7777"
        outcome2 = run_wifi_interop(WifiInteropConfig.from_env())
        if outcome2.status != "UNREACHABLE":
            return fail(name, "leg4: gate must return UNREACHABLE on unreachable peer; got %s: %s" % (outcome2.status, outcome2.detail))
        for entry in ("wifi_radio_interfaces", "ipsec_user_plane"):
            if entry not in outcome2.detail:
                return fail(name, "leg4: UNREACHABLE detail must carry matrix entry %r; got:\n%s" % (entry, outcome2.detail))

        # Leg 5: acceptance semantics preserved -- no leg observed PASSED.
        for label, st in (("leg3", outcome.status), ("leg4", outcome2.status)):
            if st == "PASSED":
                return fail(name, "%s: gate must NEVER report PASSED in this sandbox (acceptance semantics preserved)" % label)

        return ok(
            name,
            "matrix emits explicit capabilities on SKIP (radio/nl80211/daemons/"
            "ipsec); anti-faking guard fires FORBIDDEN on "
            "WIFI_PEER_KIND=reference; gate short-circuits FORBIDDEN before "
            "probes + enriches UNREACHABLE with the matrix; no PASSED "
            "observed (acceptance semantics preserved)",
        )
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def case_36_architect_review_authority_path() -> Result:
    """The PR #22 architect-review corrections, as pinnable regressions.

    Verifies the redesigned authority path MECHANICALLY:

    (1) NO sandbox escape hatch -- the sandbox exposes no
        data-path/capability accessor onto the implementation, and no
        family module contains a generic getattr(implementation,
        "_...") capability escape (source scan).
    (2) The manager's app_session returns the implementation's
        sandbox-validated facade VERBATIM (object identity) and never
        constructs a second facade (source scan).
    (3) The bridge routes through the manager -> sandbox mediator:
        a BaseException raised by the implementation is isolated by
        the FAMILY sandbox first (the SDK runtime's failure detail
        shows the WifiError the bridge re-raised from the family's
        isolated failure VALUE -- not the raw SystemExit a direct
        implementation call would have leaked to the SDK layer).
    (4) The real data path is ENCAPSULATED INSIDE the returned facade
        (the adapter attaches its own socket to its own facade; a
        byte round-trip over the real conformance peer still works).
    """
    name = "case_36_architect_review_authority_path"
    from adapters.wifi import N3IWFAdapter as _N3IWF
    from adapters.wifi import SandboxedWifi as _SandboxedWifi
    from adapters.wifi import WifiTechnologyAdapter

    # ---- (1) structural escape-hatch elimination ---------------------
    if hasattr(_SandboxedWifi, "data_path_for_binding"):
        return fail(name, "SandboxedWifi still exposes data_path_for_binding")
    if hasattr(_N3IWF, "_data_path_for_binding"):
        return fail(name, "N3IWFAdapter still exposes _data_path_for_binding")
    pkg_dir = os.path.join(_ROOT, "adapters", "wifi")
    for fname in sorted(os.listdir(pkg_dir)):
        if not fname.endswith(".py"):
            continue
        with open(os.path.join(pkg_dir, fname), encoding="utf-8") as f:
            source = f.read()
        for banned in (
            "data_path_for_binding", "_data_path_for_binding",
        ):
            if banned in source:
                return fail(
                    name,
                    "adapters/wifi/%s still references %r (the escape "
                    "hatch must be gone)" % (fname, banned),
                )
        for banned_getattr in (
            "getattr(self._implementation", "getattr(self._manager",
            "getattr(implementation", 'getattr(implementation,',
        ):
            if banned_getattr in source:
                return fail(
                    name,
                    "adapters/wifi/%s contains the generic capability "
                    "escape %r (no getattr reach-around onto the "
                    "implementation/manager may exist)" % (fname, banned_getattr),
                )
        if fname == "manager.py" and "WifiAppSession(" in source:
            return fail(
                name,
                "manager.py constructs a WifiAppSession (the manager must "
                "return the implementation's facade verbatim, never build "
                "a second one)",
            )

    # ---- (2) the manager returns the implementation's facade verbatim
    engine = _FacadeCapturingImpl()
    mgr = _new_manager(engine)
    binding, _tunnel_ref = _bind_auth_establish(mgr, session_id=_SESSION_ID)
    r = mgr.app_session(now=_NOW, session_id=_SESSION_ID)
    if not r.ok:
        return fail(name, "app_session failed: %s" % r.detail)
    if not engine.returned_facades:
        return fail(name, "implementation returned no facade (capture empty)")
    if r.value is not engine.returned_facades[-1]:
        return fail(
            name,
            "manager returned a DIFFERENT object than the implementation's "
            "validated facade (Blocker 3: the facade must be returned "
            "verbatim)",
        )
    # The facade is fully functional through the manager-routed byte
    # path (send -> manager.egress_frame -> sandbox -> impl -> echo ->
    # recv).
    session = r.value
    session.connect("lobby-service")
    if session.send(_PAYLOAD) != len(_PAYLOAD):
        return fail(name, "verbatim facade send returned wrong length")
    echoed = b""
    while len(echoed) < len(_PAYLOAD):
        chunk = session.recv()
        if not chunk:
            break
        echoed += chunk
    session.close()
    if echoed != _PAYLOAD:
        return fail(name, "verbatim facade round-trip mismatch")

    # ---- (3) the bridge routes through manager -> sandbox (BaseException
    # isolation by the FAMILY sandbox, then the SDK sandbox) ----------
    store, sid = _established_session()
    runtime = AdapterRuntime(session_store=store)
    technology = "access.ieee.80211"
    adapter_id = derive_adapter_id(technology, "wifi-crash")
    descriptor = AdapterDescriptor(
        adapter_id=adapter_id,
        access_technology_id=technology,
        supported_profile_versions=("v1-0-0",),
        capabilities=("capability.profile.wifi.non-3gpp-access",),
        resource_mapping=(
            ResourceMappingEntry(
                technology_resource="ap-association-capacity",
                kind="coverage", unit="count", quantity=4,
                availability="continuous",
            ),
        ),
        security_state=AdapterSecurityState(
            profile="baseline",
            credential_slots=("wifi-technology-credentials",),
            attested=False,
        ),
    )
    crashing = _CrashingImpl()
    crash_mgr = WifiManager(
        integration_id="adcos:wifi:crash-bridge",
        session_reader=_StoreSessionReader(store),
        ap_profile_reader=_TestApProfileReader(),
    )
    crash_reg = crash_mgr.register_implementation(
        crashing, label="crashing", make_default=True, now=_T0,
    )
    if not crash_reg.ok:
        return fail(name, "crashing register failed: %s" % crash_reg.detail)
    crash_bridge = WifiTechnologyAdapter(crash_mgr, label="wifi-crash-bridge")
    runtime.register(descriptor, crash_bridge, now=_T0)
    if not runtime.open_adapter(adapter_id, now=_NOW).ok:
        return fail(name, "crashing SDK open failed")
    # The crashing implementation crashes on provision_ap too, so no
    # allocation is possible; bind directly with a grammar-valid (but
    # nonexistent) ap_ref -- the crashing implementation raises long
    # before any existence check, which is exactly what this leg
    # isolates.
    crash_bind = runtime.bind_session(
        adapter_id, session_id=sid, now=_NOW,
        requirements={
            "ap_ref": "wifi:ap:" + "a" * 32, "ssid_name": "coverage",
        },
    )
    if crash_bind.ok:
        return fail(name, "crashing impl bind did not fail")
    detail = (
        crash_bind.failure.detail if crash_bind.failure is not None else ""
    )
    # The family sandbox isolated the SystemExit into a typed failure
    # VALUE; the bridge re-raised it as WifiError; the SDK sandbox
    # isolated THAT.  A raw "raised SystemExit" detail would mean the
    # bridge had called the implementation DIRECTLY (the pre-redesign
    # bypass -- exactly what this regression pins out).
    if "SystemExit" in detail:
        return fail(
            name,
            "the implementation's SystemExit reached the SDK layer raw "
            "(the bridge bypassed the family sandbox): %s" % detail,
        )
    if "WifiError" not in detail:
        return fail(
            name,
            "expected the bridge's WifiError (re-raised from the family "
            "sandbox's isolated failure value) in the SDK failure detail: %s"
            % detail,
        )

    # ---- (4) the real data path is encapsulated INSIDE the facade ---
    server = ReferenceWifiConformanceServer()
    try:
        adapter = N3IWFAdapter(control_endpoint=server.control_endpoint)
        real_mgr = WifiManager(
            integration_id="adcos:wifi:encap",
            session_reader=_TestSessionReader(),
            ap_profile_reader=_TestApProfileReader(),
        )
        r = real_mgr.register_implementation(
            adapter, label="n3iwf-encap", make_default=True, now=_NOW,
        )
        if not r.ok:
            return fail(name, "encap register failed: %s" % r.detail)
        real_binding = _provision_bind(real_mgr, session_id=_SESSION_ID)
        if not real_mgr.authenticate(
            now=_NOW, binding_id=real_binding.binding_id
        ).ok:
            return fail(name, "encap authenticate failed")
        if not real_mgr.establish_tunnel(
            now=_NOW, binding_id=real_binding.binding_id
        ).ok:
            return fail(name, "encap tunnel establishment failed")
        r = real_mgr.app_session(now=_NOW, session_id=_SESSION_ID)
        if not r.ok:
            return fail(name, "encap app_session failed: %s" % r.detail)
        facade = r.value
        # The facade OWNS the adapter's private real data path (the
        # manager extracted nothing -- there is no data-path hook to
        # extract with; the adapter attached the socket to the facade
        # it returned).
        if getattr(facade, "_real_socket", None) is None:
            return fail(name, "facade carries no encapsulated real data path")
        facade.connect("lobby-service")
        if facade.send(_PAYLOAD) != len(_PAYLOAD):
            return fail(name, "encap facade send returned wrong length")
        echo = b""
        while len(echo) < len(_PAYLOAD):
            chunk = facade.recv()
            if not chunk:
                break
            echo += chunk
        facade.close()
        if echo != _PAYLOAD:
            return fail(name, "encap facade round-trip mismatch")
        real_mgr.release_tunnel(
            now=_NOW,
            tunnel_ref=real_mgr._live_tunnel_for_binding(
                real_binding.binding_id
            ) or "",
        )
        real_mgr.close_binding(now=_NOW, binding_id=real_binding.binding_id)
        real_mgr.close()
    finally:
        server.close()
    mgr.close_binding(now=_NOW, binding_id=binding.binding_id)
    mgr.close()
    crash_mgr.close()
    return ok(
        name,
        "no sandbox escape hatch (structural + source scan); manager "
        "returns the implementation's facade verbatim (object identity); "
        "bridge->manager->sandbox proven by two-layer BaseException "
        "isolation; real data path encapsulated inside the returned "
        "facade (byte round-trip over the real peer)",
    )


# ==========================================================================
# Main
# ==========================================================================


def main() -> int:
    cases: List = [
        case_01_contract_surface_frozen,
        case_02_context_least_authority,
        case_03_context_injected_instant_and_budget,
        case_04_provision_ap_happy,
        case_05_bind_session_happy,
        case_06_authenticate_happy,
        case_07_establish_tunnel_happy,
        case_08_egress_frame_happy,
        case_09_app_session_happy,
        case_10_tunnel_round_trip,
        case_11_close_happy,
        case_12_r1_identity_separation,
        case_13_r1_session_collapse_rejected,
        case_14_requirements_smuggling_rejected,
        case_15_r2_credential_isolation,
        case_16_availability_ladders,
        case_17_capacity_ladders,
        case_18_r3_app_session_surface_audited,
        case_19_r4_default_swap_preserves_live_binding,
        case_20_r5_standards_boundary_audit,
        case_21_r5_frozen_spec_intact,
        case_22_r5_no_core_wifi_leakage,
        case_23_authority_session_reader_read_only,
        case_24_step_charges_pinned,
        case_25_determinism_byte_identical_snapshot,
        case_26_determinism_cross_impl_byte_identical,
        case_27_failure_isolation_base_exception,
        case_28_failure_isolation_contract_violation,
        case_29_failure_isolation_budget_exhaustion,
        case_30_failure_isolation_no_secret_leak,
        case_31_a4_real_conformance_byte_path,
        case_32_w016_sdk_bridge_nine_op_surface,
        case_33_mixed_access_session_continuity_with_5g,
        case_34_b1_real_wifi_n3iwf_interop_gate,
        case_35_b1_gate_hardening_matrix_and_anti_faking,
        case_36_architect_review_authority_path,
    ]
    results: List[Result] = []
    for case in cases:
        try:
            results.append(case())
        except Exception as exc:  # noqa: BLE001
            results.append(fail(case.__name__, "case raised %s: %s" % (type(exc).__name__, exc)))
    print("ADCOS Wi-Fi/non-3GPP access adapter self-test (WORK-021)")
    print("=" * 72)
    for name, ok_flag, detail in results:
        print("[%s] %-56s %s" % ("ok  " if ok_flag else "FAIL", name, detail))
    print("-" * 72)
    passed = sum(1 for _, ok_flag, _ in results if ok_flag)
    if passed == len(results):
        print("Result: PASS (%d/%d cases)" % (passed, len(results)))
        return 0
    print("Result: FAIL (%d/%d cases passed)" % (passed, len(results)))
    return 1


if __name__ == "__main__":
    sys.exit(main())
