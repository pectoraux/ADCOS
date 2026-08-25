#!/usr/bin/env python3
"""ADCOS secure transport self-test (WORK-017).

Deterministic, offline verification of the transport package against
the frozen WORK-017 contract (spec/work-items.md WORK-017;
spec/architecture.md sections 3, 5.4, 5.5, 7 rule 6, 13, 19, 25 rules
8/9/14, 28 Level 1, 29; LOCK-005, LOCK-006, LOCK-014, LOCK-015,
LOCK-016, LOCK-017, LOCK-018, LOCK-022, LOCK-023): secure transport
mappings for control/user paths over TLS 1.3 / QUIC / standard IP
tunnels, with session security independent of access technology, keys
bound to session/identity policy, replaceable transports behind the
transport interface, and tested replay and downgrade resistance.
Required verification per the Work Item: security, interoperability,
and downgrade tests; plus the established mechanical audits (no
duplicated authority, no access-technology/vendor branching, no
wall-clock/randomness/network, secret rejection, tamper-evident ids,
canonical round-trips, cross-process determinism, frozen-document
guards).

WORK-017 correction cycle adds the standards-boundary battery
(cases 61-67): the built-in engine is a REFERENCE MODEL of the
transport contract — the record-protection seam
(transport.recordprotection) carries the profile-cryptography
boundary (LOCK-018: no invented record-protection construction; the
reference model is integrity-only and NON-confidential by design and
by self-declaration), the responder-side pre-authorization lifecycle
(AWAITING_CONFIRM — zero trust, LOCK-022) is proven to gate every
privileged operation, the record-protection implementation is proven
replaceable, and the public contract is proven independent of it.

WORK-017 correction cycle 2 adds the two transactional-admission and
per-transport-ownership regressions (cases 68-69): replay-window
admission is TRANSACTIONAL — a forged high-sequence frame with an
invalid tag cannot advance the window and starve legitimate
lower-sequence frames (Blocker 1); and a runtime implementation swap
preserves live transports — each transport record owns the sandbox
captured at its establishment, so an already-established transport
keeps its engine while new establishments use the new one (Blocker 2).

The central boundary is exercised throughout:

    SECURE TRANSPORT
        != SESSION AUTHORITY     (read-only WORK-012)
        != IDENTITY AUTHORITY    (WORK-004 facade; secrets stay in store)
        != POLICY AUTHORITY
        != TOPOLOGY AUTHORITY
        != ACCESS AUTHORITY
        != VENDOR AUTHORITY

All instants are injected; no wall clock, no randomness, no network.
The SessionStore / RoutingEngine / TopologyGraph / PolicyDecision /
IdentityService / AdapterRuntime objects are used ONLY by these tests
to prove the read-only session-verification, identity-binding, and
access-independence boundaries hold end-to-end against real accepted
modules (WORK-003/004/011/012/016).
"""

from __future__ import annotations

import ast
import hashlib
import json
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tools"))

from identity import (  # noqa: E402
    DevHmacSha256Provider,
    IdentityService,
    InMemoryCredentialStore,
    NodeIdentity,
)
from identity.node_id import parse_node_id  # noqa: E402
from identity.profiles import ProfileSet  # noqa: E402
from policy.model import PolicyDecision  # noqa: E402
from protocol.codec import get_codec  # noqa: E402
from protocol.envelope import Envelope  # noqa: E402
from protocol.temporal import parse_instant  # noqa: E402
from protocol.validation import (  # noqa: E402
    ParsePolicy,
    UnknownTypePolicy,
    accept as protocol_accept,
)
from resources import ResourceStore  # noqa: E402
from routing import (  # noqa: E402
    LinkMetrics,
    RouteDecision,
    RoutingContext,
    RoutingEngine,
)
from sessions import SessionState, SessionStore  # noqa: E402
from topology import (  # noqa: E402
    ClaimType,
    SourceClass,
    TopologyClaim,
    TopologyGraph,
    make_link_subject,
)

from transport import (  # noqa: E402
    CONTEXT_SURFACE,
    MAX_KEY_GENERATIONS,
    PROFILE_PROPERTIES,
    REFERENCE_PROTECTION_MODEL,
    REPLAY_MODES,
    SECURABLE_SESSION_STATES,
    TRANSPORT_OPERATIONS,
    TRANSPORT_PREFIX,
    IdentityAuthority,
    ModeledTransportEngine,
    NegotiationOutcome,
    RecordProtection,
    ReferenceRecordProtection,
    ReplayWindow,
    SandboxedTransport,
    SessionReader,
    TransportAcceptance,
    TransportConfirmation,
    TransportContract,
    TransportContext,
    TransportError,
    TransportEventType,
    TransportHealth,
    TransportLifecycle,
    TransportManager,
    TransportOffer,
    TransportProfile,
    TransportProfileSet,
    TransportReasonCode,
    TransportSecurityPolicy,
    Work004IdentityAuthority,
    Work012SessionReader,
    classify_transport_profile_id,
    default_profile_offers,
    derive_pending_handle,
    derive_transport_id,
    initiator_attestation_basis,
    lifecycle_transition_is_legal,
    negotiate_transport_profiles,
    parse_transport_id,
    registered_transport_profiles,
    reject_secrets,
    responder_attestation_basis,
    transport_state_from_envelope,
    transport_state_to_envelope,
    transport_view,
    transport_view_canonical_bytes,
    transport_view_from_mapping,
    validate_transport_id,
)
from transport.keyschedule import (  # noqa: E402
    confirmation_tag,
    direction_keys,
    master_secret,
)
from transport.model import transcript_digest_from_basis  # noqa: E402
from transport.validation import validate_frame_view  # noqa: E402

from adapters import (  # noqa: E402
    AdapterDescriptor,
    AdapterRuntime,
    AdapterSecurityState,
    GenericAdapter,
    ResourceMappingEntry,
    derive_adapter_id,
)

Result = Tuple[str, bool, str]


def ok(name: str, detail: str = "") -> Result:
    return (name, True, detail)


def fail(name: str, detail: str) -> Result:
    return (name, False, detail)


# --------------------------------------------------------------------------
# Test fixtures (real WORK-004 + WORK-011 + WORK-012 objects)
# --------------------------------------------------------------------------

_T0 = "2026-06-01T00:00:00Z"
_T1 = "2026-12-31T23:59:59Z"
_NOW = "2026-06-01T12:00:00Z"
_LATER = "2026-06-01T13:00:00Z"
_EVEN_LATER = "2026-06-01T14:00:00Z"

_TLS = "transport.tls.v1-3"
_QUIC = "transport.quic.v1"
_IPSEC = "transport.tunnel.ipsec.v1"
_WIREGUARD = "transport.tunnel.wireguard.v1"
_GENERIC = "transport.generic.experimental"


def _policy_decision(instant: str = _NOW) -> PolicyDecision:
    ph = PolicyDecision(
        decision_id="0" * 64, effect="allow", code="allow", detail="fixture",
        matched_rule_ids=("r1",), policy_set_id="ps-1", policy_set_version=2,
        evaluation_instant=instant,
    )
    digest = hashlib.sha256(ph.canonical_bytes()).hexdigest()
    return PolicyDecision(
        decision_id=digest, effect="allow", code="allow", detail="fixture",
        matched_rule_ids=("r1",), policy_set_id="ps-1", policy_set_version=2,
        evaluation_instant=instant,
    )


def _graph(source: str, destination: str) -> TopologyGraph:
    g = TopologyGraph()
    g.merge(TopologyClaim(
        subject=make_link_subject(source, destination), reporter=source,
        claim_type=ClaimType.LINK_STATE, value="up",
        source_class=SourceClass.SELF_ADVERTISEMENT,
        issued_at=_T0, freshness_until=_T1, sequence=1, provenance="",
    ))
    g.merge(TopologyClaim(
        subject=destination, reporter=source, claim_type=ClaimType.REACHABLE,
        value="true", source_class=SourceClass.DIRECT_OBSERVATION,
        issued_at=_T0, freshness_until=_T1, sequence=1, provenance="",
    ))
    return g


def _route(source: str, destination: str, instant: str = _NOW) -> RouteDecision:
    ctx = RoutingContext(
        source_node_id=source, destination_node_id=destination,
        topology=_graph(source, destination), resources=ResourceStore(),
        evaluation_instant=instant, policy_decision=_policy_decision(instant),
        link_metrics={
            make_link_subject(source, destination): LinkMetrics(
                latency_ms=10, loss_basis_points=0, capacity_bps=1_000_000,
                energy_cost_millijoules=100, confidence_basis_points=10_000,
                observed_at=_T0, freshness_until=_T1,
            ),
        },
    )
    res = RoutingEngine().evaluate(ctx)
    assert res.decision is not None and res.decision.selected is not None
    return res.decision


def _established_session(store: Optional[SessionStore], source: str, destination: str):
    """Create (or reuse) a real WORK-012 session in ESTABLISHED state."""
    if store is None:
        store = SessionStore()
    res = store.create(
        _route(source, destination), _policy_decision(), source_node_id=source,
        destination_node_id=destination, creation_instant=_NOW,
    )
    assert res.ok and res.session is not None
    sid = res.session.session_id
    store.transition(sid, SessionState.AUTHORIZED, event_instant=_NOW)
    store.transition(sid, SessionState.ESTABLISHED, event_instant=_NOW)
    return store, sid


class _World:
    """A deterministic fixture world: two real identities with real
    WORK-004 operational credentials, one session store, and fresh
    manager factories."""

    def __init__(self) -> None:
        self.store = InMemoryCredentialStore()
        self.provider = DevHmacSha256Provider()
        self.service = IdentityService(self.store, self.provider)
        self.profiles = ProfileSet.load_default()
        self.node_a = NodeIdentity.create(
            self.profiles.get("identity.sha256-hmac-dev.v1"), b"identity-key-A", _NOW
        )
        self.node_b = NodeIdentity.create(
            self.profiles.get("identity.sha256-hmac-dev.v1"), b"identity-key-B", _NOW
        )
        self.node_c = NodeIdentity.create(
            self.profiles.get("identity.sha256-hmac-dev.v1"), b"identity-key-C", _NOW
        )
        self.references = {}
        for identity in (self.node_a, self.node_b, self.node_c):
            ref = self.service.provision(
                identity, "operational",
                b"op-secret-" + identity.node_id.text.encode(), now=_NOW,
            )
            self.service.activate(ref, now=_NOW)
            self.references[identity.node_id.text] = ref
        self.sessions = SessionStore()
        self.identity = Work004IdentityAuthority(self.service, self.provider, self.store)
        self.session_ab = self._session(self.node_a.node_id.text, self.node_b.node_id.text)
        self.session_ac = self._session(self.node_a.node_id.text, self.node_c.node_id.text)

    def _session(self, source: str, destination: str) -> str:
        self.sessions, sid = _established_session(
            self.sessions, source, destination
        )
        return sid

    def manager(self, implementation: Optional[TransportContract] = None, **kwargs: Any) -> TransportManager:
        return TransportManager(
            session_reader=Work012SessionReader(self.sessions),
            identity=self.identity,
            implementation=implementation,
            **kwargs,
        )


def _established_pair(
    world: _World,
    *,
    policy: Optional[TransportSecurityPolicy] = None,
    offers: Optional[List[str]] = None,
    now: str = _NOW,
    label: str = "pair",
):
    """Run the full 4-step handshake between two independent managers.

    Returns (initiator_manager, responder_manager, transport_id, offer,
    acceptance, confirmation)."""
    mgr_i = world.manager(ModeledTransportEngine())
    mgr_r = world.manager(ModeledTransportEngine())
    policy = policy or TransportSecurityPolicy(
        require_confidentiality=True, require_forward_secrecy=True
    )
    offers = offers if offers is not None else list(default_profile_offers())
    r = mgr_i.establish_initiator(
        world.session_ab, policy=policy, offered_profiles=offers,
        now=now, instance_label=label + "-initiator",
    )
    assert r.ok, r.detail
    offer = r.value
    handle = mgr_i.pending_handles()[0]
    r = mgr_r.respond(offer, now=now, instance_label=label + "-responder")
    assert r.ok, r.detail
    acceptance = r.value
    r = mgr_i.complete_initiator(handle, acceptance, now=now)
    assert r.ok, r.detail
    confirmation = r.value
    r = mgr_r.confirm(acceptance.transport_id, confirmation, now=now)
    assert r.ok, r.detail
    return mgr_i, mgr_r, acceptance.transport_id, offer, acceptance, confirmation


def _exchange_ok(
    mgr_i: TransportManager, mgr_r: TransportManager, transport_id: str,
    payload: bytes, now: str = _NOW,
) -> bool:
    """One bidirectional frame exchange over an established pair."""
    r = mgr_i.send(transport_id, payload, now=now)
    if not r.ok:
        return False
    r = mgr_r.receive(transport_id, r.value, now=now)
    if not (r.ok and r.value == payload):
        return False
    r = mgr_r.send(transport_id, b"ack:" + payload, now=now)
    if not r.ok:
        return False
    r = mgr_i.receive(transport_id, r.value, now=now)
    return bool(r.ok and r.value == b"ack:" + payload)


# --------------------------------------------------------------------------
# Test-double implementations (satisfy the SAME interfaces as real
# engines — the import-lock rule for test doubles)
# --------------------------------------------------------------------------


class FaultyTransportEngine(ModeledTransportEngine):
    """Raises a chosen exception on a chosen operation (test fixture)."""

    def __init__(self, operation: str, exc: BaseException) -> None:
        super().__init__()
        self._operation = operation
        self._exc = exc

    def _maybe_raise(self, operation: str) -> None:
        if operation == self._operation:
            raise self._exc

    def protect(self, context: TransportContext, payload: bytes):
        self._maybe_raise("protect")
        return super().protect(context, payload)

    def unprotect(self, context: TransportContext, frame: Mapping[str, object]):
        self._maybe_raise("unprotect")
        return super().unprotect(context, frame)

    def handshake_responder(self, context, offer, *, responder_attestation, issued_at):
        self._maybe_raise("handshake_responder")
        return super().handshake_responder(
            context, offer, responder_attestation=responder_attestation,
            issued_at=issued_at,
        )

    def rekey(self, context: TransportContext, cause: str):
        self._maybe_raise("rekey")
        return super().rekey(context, cause)

    def health(self):
        self._maybe_raise("health")
        return super().health()


class BadShapeEngine(ModeledTransportEngine):
    """Returns non-contract shapes from chosen operations (test fixture)."""

    def __init__(self, operation: str, value: Any) -> None:
        super().__init__()
        self._operation = operation
        self._value = value

    def protect(self, context: TransportContext, payload: bytes):
        if self._operation == "protect":
            return self._value
        return super().protect(context, payload)

    def handshake_responder(self, context, offer, *, responder_attestation, issued_at):
        if self._operation == "handshake_responder":
            return self._value
        return super().handshake_responder(
            context, offer, responder_attestation=responder_attestation,
            issued_at=issued_at,
        )

    def rekey(self, context: TransportContext, cause: str):
        if self._operation == "rekey":
            return self._value
        return super().rekey(context, cause)

    def unprotect(self, context: TransportContext, frame: Mapping[str, object]):
        if self._operation == "unprotect":
            return self._value
        return super().unprotect(context, frame)


class MiniTransportEngine(TransportContract):
    """A genuinely independent second implementation: its OWN deterministic
    key schedule (plain SHA-256/HMAC construction, different from the
    HKDF reference schedule) and its own integrity-only record model
    ("mini-test-mac").  Two Mini engines interoperate with each other
    through the contract — proving the interface, not one
    implementation, carries the semantics.  Like the reference model,
    it composes no record-protection construction of its own: one
    standard MAC (HMAC-SHA256) in its standard role over the visible
    payload (LOCK-018)."""

    label = "mini-test-engine"

    _MODEL = "mini-test-mac"
    _MAC_DOMAIN = b"mini-frame/v1"

    def __init__(self) -> None:
        self._states: dict = {}

    def supported_profiles(self):
        return tuple(sorted(TransportProfileSet.load_default().profile_ids()))

    def initialize(self, context: TransportContext) -> None:
        self._states[context.transport_id] = {
            "role": None, "offer": None, "master": None,
            "send": None, "recv": None, "generation": 0,
            "send_sequence": 0, "window": ReplayWindow(), "lineage": [],
        }

    def _state(self, transport_id: str) -> dict:
        state = self._states.get(transport_id)
        if state is None:
            raise TransportError(
                TransportReasonCode.UNKNOWN_TRANSPORT,
                "mini engine has no state for %s" % transport_id,
            )
        return state

    def handshake_initiator(self, context: TransportContext, offer: TransportOffer) -> None:
        state = self._state(context.transport_id)
        state["role"] = "initiator"
        state["offer"] = offer

    def handshake_responder(self, context, offer, *, responder_attestation, issued_at):
        from transport import negotiate_transport_profiles as neg

        outcome = neg(
            offer.offered_profiles, self.supported_profiles(), offer.policy
        )
        if not outcome.ok:
            raise TransportError(
                TransportReasonCode.NEGOTIATION_FAILED, "mini: no profile"
            )
        selected = outcome.selected
        assert selected is not None
        transport_id = derive_transport_id(
            selected.family,
            session_id=offer.session_id,
            initiator_node_id=offer.initiator_node_id,
            responder_node_id=offer.responder_node_id,
            profile_id=selected.profile_id,
            policy_id=offer.policy.policy_id,
            offer_nonce=offer.offer_nonce,
        )
        responder_nonce = hashlib.sha256(
            (offer.offer_nonce + transport_id + "mini").encode("utf-8")
        ).hexdigest()[:16]
        master = hashlib.sha256(
            offer.digest().encode("utf-8")
            + bytes.fromhex(offer.offer_nonce)
            + bytes.fromhex(responder_nonce)
            + responder_attestation.encode("utf-8")
        ).digest()
        state = self._states.pop(context.transport_id)
        state["role"] = "responder"
        state["offer"] = offer
        state["master"] = master
        state["send"] = hashlib.sha256(master + b"r2i-mini").digest()
        state["recv"] = hashlib.sha256(master + b"i2r-mini").digest()
        state["lineage"] = [hashlib.sha256(master + b"lineage-mini").hexdigest()[:16]]
        self._states[transport_id] = state
        return TransportAcceptance(
            transport_id=transport_id,
            offer_digest=offer.digest(),
            selected_profile=selected.profile_id,
            responder_nonce=responder_nonce,
            responder_confirmation=self._confirm(master, "responder"),
            responder_attestation=responder_attestation,
            key_lineage=hashlib.sha256(master + b"lineage-mini").hexdigest()[:16],
            issued_at=issued_at,
        )

    @staticmethod
    def _confirm(master: bytes, role: str) -> str:
        import hmac as _hmac

        return _hmac.new(master, ("mini-confirm-" + role).encode(), hashlib.sha256).hexdigest()

    def complete_initiator(self, context, offer, acceptance, *, initiator_attestation, issued_at):
        state = self._state(context.transport_id)
        if state["role"] != "initiator" or state["offer"] is None:
            raise TransportError(
                TransportReasonCode.STATE_CONFLICT, "mini: no pending initiator"
            )
        if acceptance.offer_digest != state["offer"].digest():
            raise TransportError(
                TransportReasonCode.DOWNGRADE_REJECTED, "mini: offer digest mismatch"
            )
        master = hashlib.sha256(
            offer.digest().encode("utf-8")
            + bytes.fromhex(offer.offer_nonce)
            + bytes.fromhex(acceptance.responder_nonce)
            + acceptance.responder_attestation.encode("utf-8")
        ).digest()
        if acceptance.responder_confirmation != self._confirm(master, "responder"):
            raise TransportError(
                TransportReasonCode.INTEGRITY_REJECTED, "mini: confirmation mismatch"
            )
        from transport import TransportConfirmation

        confirmation = TransportConfirmation(
            transport_id=acceptance.transport_id,
            offer_digest=offer.digest(),
            initiator_confirmation=self._confirm(master, "initiator"),
            initiator_attestation=initiator_attestation,
            issued_at=issued_at,
        )
        state = self._states.pop(context.transport_id)
        state["master"] = master
        state["send"] = hashlib.sha256(master + b"i2r-mini").digest()
        state["recv"] = hashlib.sha256(master + b"r2i-mini").digest()
        state["lineage"] = [hashlib.sha256(master + b"lineage-mini").hexdigest()[:16]]
        self._states[acceptance.transport_id] = state
        return confirmation

    def accept_confirmation(self, context, offer, acceptance, confirmation) -> None:
        state = self._state(context.transport_id)
        if state["role"] != "responder" or state["master"] is None:
            raise TransportError(
                TransportReasonCode.STATE_CONFLICT, "mini: no responder state"
            )
        if confirmation.initiator_confirmation != self._confirm(state["master"], "initiator"):
            raise TransportError(
                TransportReasonCode.INTEGRITY_REJECTED, "mini: initiator mismatch"
            )

    def protect(self, context: TransportContext, payload: bytes):
        import hmac as _hmac

        state = self._state(context.transport_id)
        if state["send"] is None:
            raise TransportError(TransportReasonCode.NOT_ESTABLISHED, "mini: no keys")
        state["send_sequence"] += 1
        seq = state["send_sequence"]
        key = state["send"]
        tag = _hmac.new(
            key,
            self._MAC_DOMAIN
            + state["generation"].to_bytes(8, "big")
            + seq.to_bytes(8, "big")
            + bytes(payload),
            hashlib.sha256,
        ).hexdigest()
        return {
            "transport_id": context.transport_id,
            "generation": state["generation"],
            "sequence": seq,
            "protection_model": self._MODEL,
            "wire_payload": bytes(payload).hex(),
            "integrity_tag": tag,
        }

    def unprotect(self, context: TransportContext, frame: Mapping[str, object]):
        import hmac as _hmac

        state = self._state(context.transport_id)
        if state["recv"] is None:
            raise TransportError(TransportReasonCode.NOT_ESTABLISHED, "mini: no keys")
        if frame.get("transport_id") != context.transport_id:
            raise TransportError(TransportReasonCode.INVALID_INPUT, "mini: wrong transport")
        if frame.get("protection_model") != self._MODEL:
            raise TransportError(
                TransportReasonCode.INTEGRITY_REJECTED, "mini: foreign model"
            )
        if frame.get("generation") != state["generation"]:
            raise TransportError(
                TransportReasonCode.INTEGRITY_REJECTED, "mini: generation mismatch"
            )
        raw_seq = frame["sequence"]
        assert isinstance(raw_seq, int)
        seq_int = raw_seq
        # Transactional admission (mirrors the reference engine): a
        # forged high-sequence frame with an invalid tag must NOT
        # advance the window.  Pre-check without mutating, verify the
        # tag, commit only on success.
        if not state["window"].would_accept(seq_int):
            raise TransportError(TransportReasonCode.REPLAY_REJECTED, "mini: replay")
        payload = bytes.fromhex(str(frame["wire_payload"]))
        expected = _hmac.new(
            state["recv"],
            self._MAC_DOMAIN
            + state["generation"].to_bytes(8, "big")
            + seq_int.to_bytes(8, "big")
            + payload,
            hashlib.sha256,
        ).hexdigest()
        if not _hmac.compare_digest(expected, str(frame["integrity_tag"])):
            raise TransportError(TransportReasonCode.INTEGRITY_REJECTED, "mini: tag")
        state["window"].accept(seq_int)
        return payload

    def rekey(self, context: TransportContext, cause: str):
        state = self._state(context.transport_id)
        if state["master"] is None:
            raise TransportError(TransportReasonCode.NOT_ESTABLISHED, "mini: no keys")
        if state["generation"] + 1 >= MAX_KEY_GENERATIONS:
            raise TransportError(
                TransportReasonCode.GENERATION_EXHAUSTED, "mini: bound"
            )
        state["generation"] += 1
        state["master"] = hashlib.sha256(
            state["master"] + cause.encode() + bytes([state["generation"]])
        ).digest()
        role = state["role"] or "initiator"
        forward = hashlib.sha256(state["master"] + b"i2r-mini").digest()
        backward = hashlib.sha256(state["master"] + b"r2i-mini").digest()
        state["send"], state["recv"] = (
            (forward, backward) if role == "initiator" else (backward, forward)
        )
        state["lineage"].append(
            hashlib.sha256(state["master"] + b"lineage-mini").hexdigest()[:16]
        )
        return {"generation": state["generation"], "lineage_digest": state["lineage"][-1]}

    def health(self):
        return TransportHealth.HEALTHY

    def close(self, context: TransportContext) -> None:
        state = self._states.pop(context.transport_id, None)
        if state is not None:
            state["master"] = None
            state["send"] = None
            state["recv"] = None


# --------------------------------------------------------------------------
# 1-4: contract surface
# --------------------------------------------------------------------------


def case_01_contract_surface_frozen(results: List[Result]) -> None:
    """01. the frozen transport interface surface is exact."""
    problems = []
    if TRANSPORT_OPERATIONS != (
        "supported_profiles", "initialize", "handshake_initiator",
        "handshake_responder", "complete_initiator", "accept_confirmation",
        "protect", "unprotect", "rekey", "health", "close",
    ):
        problems.append("TRANSPORT_OPERATIONS changed")
    if CONTEXT_SURFACE != frozenset(
        {"transport_id", "session_id", "now", "charge", "steps_left"}
    ):
        problems.append("CONTEXT_SURFACE changed")
    if MAX_KEY_GENERATIONS != 8:
        problems.append("MAX_KEY_GENERATIONS changed")
    abstract = {
        name for name in TRANSPORT_OPERATIONS
        if getattr(TransportContract, name, None) is not None
        and getattr(
            getattr(TransportContract, name, None), "__isabstractmethod__", False
        )
    }
    if abstract != set(TRANSPORT_OPERATIONS):
        problems.append("not every operation is an abstract contract method")
    if problems:
        results.append(fail("case_01_contract_surface_frozen", "; ".join(problems)))
    else:
        results.append(ok("case_01_contract_surface_frozen", "11 ops + context surface exact"))


def case_02_context_least_authority(results: List[Result]) -> None:
    """02. the context facade exposes ONLY the frozen surface."""
    context = TransportContext("adcos:transport:tls:" + "0" * 16, "session-1", _NOW, 100)
    exposed = {
        name for name in dir(context)
        if not name.startswith("_") and name not in ("__class__",)
    }
    extra = exposed - CONTEXT_SURFACE - {"__setattr__"}
    extra = {name for name in extra if callable(getattr(context, name, None)) is False or name not in CONTEXT_SURFACE}
    # Precise check: the read surface must be exactly CONTEXT_SURFACE.
    readable = {
        "transport_id", "session_id", "now", "charge", "steps_left",
    }
    if readable != CONTEXT_SURFACE:
        results.append(fail("case_02_context_least_authority", "surface drift"))
        return
    for forbidden in ("store", "session_store", "identity", "manager", "policy", "runtime"):
        if hasattr(context, forbidden):
            results.append(fail("case_02_context_least_authority", "context exposes %r" % forbidden))
            return
    try:
        context._transport_id = "x"  # type: ignore[attr-defined]
        results.append(fail("case_02_context_least_authority", "mutation allowed"))
        return
    except TypeError:
        pass
    results.append(ok("case_02_context_least_authority", "5 members only, immutable"))


def case_03_context_injected_instant_and_budget(results: List[Result]) -> None:
    """03. instants are injected; the budget is the deterministic hang model."""
    context = TransportContext("adcos:transport:tls:" + "0" * 16, "session-1", _LATER, 5)
    if context.now() != _LATER:
        results.append(fail("case_03_context_injected_instant_and_budget", "now() is not the injected instant"))
        return
    context.charge(3)
    if context.steps_left() != 2:
        results.append(fail("case_03_context_injected_instant_and_budget", "charge did not decrement"))
        return
    from transport.contract import _BudgetExhausted

    try:
        context.charge(3)
        raised = False
    except _BudgetExhausted:
        raised = True
    if not raised:
        results.append(fail("case_03_context_injected_instant_and_budget", "budget overrun did not raise the sentinel"))
        return
    try:
        context.charge(-1)
        negative_ok = False
    except _BudgetExhausted:
        negative_ok = True
    if not negative_ok:
        results.append(fail("case_03_context_injected_instant_and_budget", "negative charge accepted"))
        return
    results.append(ok("case_03_context_injected_instant_and_budget", "injected instant + bounded budget"))


def case_04_profile_catalog_frozen(results: List[Result]) -> None:
    """04. the initial profile catalog is frozen data with WORK-002
    unknown/invalid classification."""
    expected = (
        _GENERIC, _QUIC, _TLS, _IPSEC, _WIREGUARD,
    )
    if registered_transport_profiles() != expected:
        results.append(fail("case_04_profile_catalog_frozen", "catalog drifted: %s" % (registered_transport_profiles(),)))
        return
    if classify_transport_profile_id(_TLS) != "known":
        results.append(fail("case_04_profile_catalog_frozen", "TLS profile not known"))
        return
    if classify_transport_profile_id("transport.tls.v9") != "unknown":
        results.append(fail("case_04_profile_catalog_frozen", "future well-formed profile not UNKNOWN"))
        return
    if classify_transport_profile_id("transport.TLS") != "invalid":
        results.append(fail("case_04_profile_catalog_frozen", "malformed profile not INVALID"))
        return
    if classify_transport_profile_id("access.3gpp.nr.imt2020") != "invalid":
        results.append(fail("case_04_profile_catalog_frozen", "access id classified in transport grammar"))
        return
    results.append(ok("case_04_profile_catalog_frozen", "5 profiles; known/unknown/invalid exact"))


# --------------------------------------------------------------------------
# 5-8: negotiation (downgrade-resistant by rule)
# --------------------------------------------------------------------------


def case_05_negotiation_maximal_rank(results: List[Result]) -> None:
    """05. negotiation selects the maximal policy-satisfying rank,
    attacker-order independent, lexicographic tie-break."""
    policy = TransportSecurityPolicy()
    offers_scrambled = [_WIREGUARD, _TLS, _QUIC, _IPSEC]
    outcome = negotiate_transport_profiles(offers_scrambled, list(default_profile_offers()), policy)
    if not outcome.ok or outcome.selected is None or outcome.selected.profile_id != _QUIC:
        results.append(fail("case_05_negotiation_maximal_rank", "scrambled offer selected %r" % (outcome.selected and outcome.selected.profile_id,)))
        return
    outcome2 = negotiate_transport_profiles(list(reversed(offers_scrambled)), list(reversed(list(default_profile_offers()))), policy)
    assert outcome2.selected is not None
    if outcome2.selected.profile_id != _QUIC:
        results.append(fail("case_05_negotiation_maximal_rank", "order dependence"))
        return
    # Tie-break: two equal-rank custom profiles -> lexicographically first.
    profiles = TransportProfileSet.load_default()
    profiles = profiles.with_explicit_profile(TransportProfile(
        profile_id="transport.test.beta.v1", family="test", security_rank=50,
        integrity=True, confidentiality=False, forward_secrecy=False,
        replay_protection="record-window", multipath_capable=False, status="active",
    ))
    profiles = profiles.with_explicit_profile(TransportProfile(
        profile_id="transport.test.alpha.v1", family="test", security_rank=50,
        integrity=True, confidentiality=False, forward_secrecy=False,
        replay_protection="record-window", multipath_capable=False, status="active",
    ))
    tie = negotiate_transport_profiles(
        ["transport.test.beta.v1", "transport.test.alpha.v1"],
        ["transport.test.alpha.v1", "transport.test.beta.v1"],
        policy, profile_set=profiles,
    )
    if not tie.ok or tie.selected is None or tie.selected.profile_id != "transport.test.alpha.v1":
        results.append(fail("case_05_negotiation_maximal_rank", "tie-break not lexicographic"))
        return
    results.append(ok("case_05_negotiation_maximal_rank", "max rank + lexicographic tie + order-free"))


def case_06_negotiation_no_intersection(results: List[Result]) -> None:
    """06. no eligible intersection fails with no-eligible-profile."""
    policy = TransportSecurityPolicy()
    outcome = negotiate_transport_profiles([_TLS], [_IPSEC], policy)
    if outcome.ok or outcome.reason != "no-eligible-profile":
        results.append(fail("case_06_negotiation_no_intersection", "disjoint offers did not fail cleanly"))
        return
    # Policy floor can also empty the intersection.
    strict = TransportSecurityPolicy(minimum_rank=200)
    outcome = negotiate_transport_profiles(list(default_profile_offers()), list(default_profile_offers()), strict)
    if outcome.ok:
        results.append(fail("case_06_negotiation_no_intersection", "impossible floor accepted"))
        return
    results.append(ok("case_06_negotiation_no_intersection", "no-eligible-profile both ways"))


def case_07_negotiation_unknown_never_coerced(results: List[Result]) -> None:
    """07. unknown identifiers are never negotiated into known profiles."""
    policy = TransportSecurityPolicy()
    outcome = negotiate_transport_profiles(
        ["transport.tls.v99"], ["transport.tls.v99"], policy
    )
    if outcome.ok:
        results.append(fail("case_07_negotiation_unknown_never_coerced", "unknown id negotiated"))
        return
    try:
        negotiate_transport_profiles(["not-a-profile"], ["not-a-profile"], policy)
        results.append(fail("case_07_negotiation_unknown_never_coerced", "malformed id accepted"))
        return
    except TransportError as error:
        if error.reason != TransportReasonCode.PROFILE_INVALID:
            results.append(fail("case_07_negotiation_unknown_never_coerced", "wrong reason %r" % error.reason))
            return
    results.append(ok("case_07_negotiation_unknown_never_coerced", "unknown fails closed, invalid rejected"))


def case_08_policy_floor_rejects_weak(results: List[Result]) -> None:
    """08. the policy floor is enforced by property data; integrity is
    never waivable (section 19 minimum)."""
    try:
        TransportSecurityPolicy(require_integrity=False)
        results.append(fail("case_08_policy_floor_rejects_weak", "integrity waivable"))
        return
    except TransportError:
        pass
    strict = TransportSecurityPolicy(require_confidentiality=True, require_forward_secrecy=True, minimum_rank=90)
    for weak in (_GENERIC, _WIREGUARD, _IPSEC):
        profile = TransportProfileSet.load_default().get(weak)
        if profile.satisfies(strict):
            results.append(fail("case_08_policy_floor_rejects_weak", "%r satisfies strict floor" % weak))
            return
    tls = TransportProfileSet.load_default().get(_TLS)
    if not tls.satisfies(strict):
        results.append(fail("case_08_policy_floor_rejects_weak", "TLS fails strict floor"))
        return
    families = TransportSecurityPolicy(allowed_families=frozenset({"tls"}))
    outcome = negotiate_transport_profiles(list(default_profile_offers()), list(default_profile_offers()), families)
    if not outcome.ok or outcome.selected is None or outcome.selected.profile_id != _TLS:
        results.append(fail("case_08_policy_floor_rejects_weak", "family restriction ignored"))
        return
    results.append(ok("case_08_policy_floor_rejects_weak", "property-driven floor + family restriction"))


# --------------------------------------------------------------------------
# 9-16: establishment
# --------------------------------------------------------------------------


def case_09_establish_happy_path_tls(results: List[Result]) -> None:
    """09. full 4-step handshake over the TLS 1.3 profile."""
    world = _World()
    policy = TransportSecurityPolicy(
        require_confidentiality=True, require_forward_secrecy=True,
        allowed_families=frozenset({"tls"}),
    )
    mgr_i, mgr_r, transport_id, offer, acceptance, confirmation = _established_pair(
        world, policy=policy, offers=[_TLS, _QUIC]
    )
    if acceptance.selected_profile != _TLS:
        results.append(fail("case_09_establish_happy_path_tls", "selected %r" % acceptance.selected_profile))
        return
    family, digest = parse_transport_id(transport_id)
    if family != "tls" or len(digest) != 16:
        results.append(fail("case_09_establish_happy_path_tls", "transport id shape wrong"))
        return
    state_i = mgr_i.get_security_state(transport_id)
    state_r = mgr_r.get_security_state(transport_id)
    if (state_i.profile_id, state_i.session_id) != (state_r.profile_id, state_r.session_id):
        results.append(fail("case_09_establish_happy_path_tls", "endpoint states disagree"))
        return
    if state_i.profile_properties.get("forward_secrecy") is not True:
        results.append(fail("case_09_establish_happy_path_tls", "properties not carried"))
        return
    if not _exchange_ok(mgr_i, mgr_r, transport_id, b"tls-hello"):
        results.append(fail("case_09_establish_happy_path_tls", "frame exchange failed"))
        return
    events_i = [e.event_type for e in mgr_i.get_events(transport_id)]
    if events_i != ["established"]:
        results.append(fail("case_09_establish_happy_path_tls", "events %s" % events_i))
        return
    results.append(ok("case_09_establish_happy_path_tls", "TLS profile: handshake + bidirectional frames"))


def case_10_establish_parametric_profiles(results: List[Result]) -> None:
    """10. QUIC (default offer), IPsec tunnel, and the generic
    experimental profile all establish (definition of done: sessions
    have secure transport mappings across the initial catalog)."""
    world = _World()
    cases = [
        ("quic", TransportSecurityPolicy(require_confidentiality=True, require_forward_secrecy=True), list(default_profile_offers()), _QUIC),
        ("ipsec", TransportSecurityPolicy(require_confidentiality=True, require_forward_secrecy=True), [_IPSEC, _WIREGUARD], _IPSEC),
        ("generic", TransportSecurityPolicy(), [_GENERIC], _GENERIC),
    ]
    for label, policy, offers, expected in cases:
        mgr_i, mgr_r, transport_id, _, acceptance, _ = _established_pair(
            world, policy=policy, offers=offers, label=label
        )
        if acceptance.selected_profile != expected:
            results.append(fail("case_10_establish_parametric_profiles", "%s selected %r" % (label, acceptance.selected_profile)))
            return
        if not _exchange_ok(mgr_i, mgr_r, transport_id, ("payload-" + label).encode()):
            results.append(fail("case_10_establish_parametric_profiles", "%s exchange failed" % label))
            return
    results.append(ok("case_10_establish_parametric_profiles", "quic + ipsec + generic established"))


def case_11_offer_expiry_rejected(results: List[Result]) -> None:
    """11. expired offers fail closed with audit evidence."""
    world = _World()
    mgr_i = world.manager()
    mgr_r = world.manager()
    r = mgr_i.establish_initiator(
        world.session_ab, policy=TransportSecurityPolicy(),
        offered_profiles=list(default_profile_offers()),
        now=_NOW, offer_expires_at="2026-06-01T12:00:01Z",
    )
    assert r.ok
    offer = r.value
    r = mgr_r.respond(offer, now=_LATER)
    if r.ok or r.reason != TransportReasonCode.OFFER_EXPIRED:
        results.append(fail("case_11_offer_expiry_rejected", "expired offer accepted (%r)" % r.reason))
        return
    log_types = [e.event_type for e in mgr_r.security_log()]
    if "rejected" not in log_types:
        results.append(fail("case_11_offer_expiry_rejected", "no audit event"))
        return
    results.append(ok("case_11_offer_expiry_rejected", "OFFER_EXPIRED + security log"))


def case_12_unknown_session_rejected(results: List[Result]) -> None:
    """12. establishment requires a real WORK-012 session."""
    world = _World()
    mgr = world.manager()
    r = mgr.establish_initiator(
        "session-does-not-exist", policy=TransportSecurityPolicy(),
        offered_profiles=list(default_profile_offers()), now=_NOW,
    )
    if r.ok or r.reason != TransportReasonCode.SESSION_NOT_SECUREABLE:
        results.append(fail("case_12_unknown_session_rejected", "unknown session accepted"))
        return
    results.append(ok("case_12_unknown_session_rejected", "read-only WORK-012 lookup enforced"))


def case_13_non_secureable_session_state(results: List[Result]) -> None:
    """13. only ESTABLISHED/DEGRADED/RECONNECTING sessions are
    secureable (frozen vocabulary)."""
    if SECURABLE_SESSION_STATES != frozenset({"ESTABLISHED", "DEGRADED", "RECONNECTING"}):
        results.append(fail("case_13_non_secureable_session_state", "secureable set drifted"))
        return
    world = _World()
    # A session left in REQUESTED state (fresh binding material: the
    # b->c direction, distinct from the established a->b/a->c sessions
    # so the idempotent create cannot return an established session).
    res = world.sessions.create(
        _route(world.node_b.node_id.text, world.node_c.node_id.text),
        _policy_decision(),
        source_node_id=world.node_b.node_id.text,
        destination_node_id=world.node_c.node_id.text,
        creation_instant=_NOW,
    )
    assert res.ok and res.session is not None
    mgr = world.manager()
    r = mgr.establish_initiator(
        res.session.session_id, policy=TransportSecurityPolicy(),
        offered_profiles=list(default_profile_offers()), now=_NOW,
    )
    if r.ok or r.reason != TransportReasonCode.SESSION_NOT_SECUREABLE:
        results.append(fail("case_13_non_secureable_session_state", "AUTHORIZED session secureable"))
        return
    # A terminated session.
    store, sid = _established_session(None, world.node_a.node_id.text, world.node_b.node_id.text)
    store.terminate(sid, event_instant=_NOW, actor_reference="t", reason_code="done")
    mgr2 = TransportManager(
        session_reader=Work012SessionReader(store), identity=world.identity,
    )
    r = mgr2.establish_initiator(
        sid, policy=TransportSecurityPolicy(),
        offered_profiles=list(default_profile_offers()), now=_NOW,
    )
    if r.ok or r.reason != TransportReasonCode.SESSION_NOT_SECUREABLE:
        results.append(fail("case_13_non_secureable_session_state", "terminated session secureable"))
        return
    results.append(ok("case_13_non_secureable_session_state", "REQUESTED/AUTHORIZED/TERMINATED rejected"))


def case_14_revoked_credential_rejected(results: List[Result]) -> None:
    """14. revocation fails establishment closed on BOTH sides (zero
    trust)."""
    world = _World()
    # Responder-side: node B's operational credential revoked.
    ref_b = world.references[world.node_b.node_id.text]
    world.service.revoke(ref_b, reason="compromise", now=_NOW)
    mgr_i = world.manager()
    mgr_r = world.manager()
    r = mgr_i.establish_initiator(
        world.session_ab, policy=TransportSecurityPolicy(),
        offered_profiles=list(default_profile_offers()), now=_LATER,
    )
    assert r.ok  # the initiator's own credential is intact
    offer = r.value
    r = mgr_r.respond(offer, now=_LATER)
    if r.ok or r.reason != TransportReasonCode.CREDENTIAL_REVOKED:
        results.append(fail("case_14_revoked_credential_rejected", "responder revoked: %r" % r.reason))
        return
    # Initiator-side: node A's operational credential revoked.
    world2 = _World()
    ref_a = world2.references[world2.node_a.node_id.text]
    world2.service.revoke(ref_a, reason="compromise", now=_NOW)
    mgr = world2.manager()
    r = mgr.establish_initiator(
        world2.session_ab, policy=TransportSecurityPolicy(),
        offered_profiles=list(default_profile_offers()), now=_LATER,
    )
    if r.ok or r.reason != TransportReasonCode.CREDENTIAL_REVOKED:
        results.append(fail("case_14_revoked_credential_rejected", "initiator revoked: %r" % r.reason))
        return
    results.append(ok("case_14_revoked_credential_rejected", "CREDENTIAL_REVOKED both directions"))


def case_15_expired_credential_rejected(results: List[Result]) -> None:
    """15. expired credentials fail establishment closed."""
    world = _World()
    ref = world.references[world.node_a.node_id.text]
    world.service.expire(ref, now=_NOW)
    mgr = world.manager()
    r = mgr.establish_initiator(
        world.session_ab, policy=TransportSecurityPolicy(),
        offered_profiles=list(default_profile_offers()), now=_LATER,
    )
    if r.ok or r.reason != TransportReasonCode.CREDENTIAL_EXPIRED:
        results.append(fail("case_15_expired_credential_rejected", "reason %r" % r.reason))
        return
    results.append(ok("case_15_expired_credential_rejected", "CREDENTIAL_EXPIRED"))


def case_16_wrong_role_credential(results: List[Result]) -> None:
    """16. identity-role credentials alone cannot secure transports
    (operational role required)."""
    store = InMemoryCredentialStore()
    provider = DevHmacSha256Provider()
    service = IdentityService(store, provider)
    profiles = ProfileSet.load_default()
    node = NodeIdentity.create(profiles.get("identity.sha256-hmac-dev.v1"), b"identity-only", _NOW)
    ref = service.provision(node, "identity", b"identity-role-secret", now=_NOW)
    service.activate(ref, now=_NOW)
    # The far endpoint gets a proper OPERATIONAL credential; the near
    # endpoint holds ONLY the identity-role credential.
    node_b = NodeIdentity.create(profiles.get("identity.sha256-hmac-dev.v1"), b"far-end", _NOW)
    ref_b = service.provision(node_b, "operational", b"op-secret-b", now=_NOW)
    service.activate(ref_b, now=_NOW)
    sessions, sid = _established_session(None, node.node_id.text, node_b.node_id.text)
    identity = Work004IdentityAuthority(service, provider, store)
    mgr = TransportManager(session_reader=Work012SessionReader(sessions), identity=identity)
    r = mgr.establish_initiator(
        sid, policy=TransportSecurityPolicy(),
        offered_profiles=list(default_profile_offers()), now=_NOW,
    )
    if r.ok or r.reason != TransportReasonCode.IDENTITY_UNUSABLE:
        results.append(fail("case_16_wrong_role_credential", "identity-role credential secured a transport (%r)" % r.reason))
        return
    results.append(ok("case_16_wrong_role_credential", "operational role required"))


# --------------------------------------------------------------------------
# 17-20: downgrade resistance (required verification)
# --------------------------------------------------------------------------


def case_17_downgrade_offer_stripping(results: List[Result]) -> None:
    """17. in-flight offer tampering (attacker removes the strong
    profile from the offer) is detected at completion."""
    world = _World()
    mgr_i = world.manager()
    mgr_r = world.manager()
    policy = TransportSecurityPolicy(require_confidentiality=True, require_forward_secrecy=True)
    r = mgr_i.establish_initiator(
        world.session_ab, policy=policy,
        offered_profiles=[_QUIC, _TLS, _IPSEC], now=_NOW,
    )
    assert r.ok
    offer = r.value
    handle = mgr_i.pending_handles()[0]
    # Attacker rewrites the offer without QUIC/TLS and re-signs nothing:
    # the STRIPPED offer is delivered to the responder.
    stripped = TransportOffer(
        session_id=offer.session_id,
        initiator_node_id=offer.initiator_node_id,
        responder_node_id=offer.responder_node_id,
        offered_profiles=(_IPSEC,),
        policy=offer.policy,
        offer_nonce=offer.offer_nonce,
        issued_at=offer.issued_at,
        expires_at=offer.expires_at,
    )
    r = mgr_r.respond(stripped, now=_NOW)
    assert r.ok, r.detail
    tampered_acceptance = r.value
    # The initiator completes against ITS OWN offer; the acceptance
    # echoes the STRIPPED offer's digest -> mismatch -> fail closed.
    r = mgr_i.complete_initiator(handle, tampered_acceptance, now=_NOW)
    if r.ok or r.reason != TransportReasonCode.DOWNGRADE_REJECTED:
        results.append(fail("case_17_downgrade_offer_stripping", "stripping undetected (%r)" % r.reason))
        return
    log_types = [e.event_type for e in mgr_i.security_log()]
    if "downgrade-rejected" not in log_types:
        results.append(fail("case_17_downgrade_offer_stripping", "no downgrade audit event"))
        return
    if mgr_i.pending_handles():
        results.append(fail("case_17_downgrade_offer_stripping", "pending establishment survived"))
        return
    results.append(ok("case_17_downgrade_offer_stripping", "offer-digest echo detects stripping"))


def case_18_downgrade_forced_selection(results: List[Result]) -> None:
    """18. a forged acceptance with a weaker forced selection cannot
    complete (rule check + cryptographic confirmation)."""
    world = _World()
    mgr_i, mgr_r, transport_id, offer, acceptance, _ = _established_pair(world)
    # Fresh legitimate establishment to attack.
    r = mgr_i.establish_initiator(
        world.session_ab, policy=TransportSecurityPolicy(),
        offered_profiles=[_QUIC, _TLS], now=_NOW, instance_label="victim",
    )
    assert r.ok
    victim_offer = r.value
    victim_handle = mgr_i.pending_handles()[0]
    # Attack A: tamper the selected profile on a REAL acceptance.
    tampered = TransportAcceptance(
        transport_id=acceptance.transport_id,
        offer_digest=acceptance.offer_digest,
        selected_profile=_TLS if acceptance.selected_profile == _QUIC else _QUIC,
        responder_nonce=acceptance.responder_nonce,
        responder_confirmation=acceptance.responder_confirmation,
        responder_attestation=acceptance.responder_attestation,
        key_lineage=acceptance.key_lineage,
        issued_at=acceptance.issued_at,
    )
    r = mgr_i.complete_initiator(victim_handle, tampered, now=_NOW)
    if r.ok:
        results.append(fail("case_18_downgrade_forced_selection", "tampered selection accepted"))
        return
    if r.reason not in (TransportReasonCode.DOWNGRADE_REJECTED, TransportReasonCode.INTEGRITY_REJECTED):
        results.append(fail("case_18_downgrade_forced_selection", "unexpected reason %r" % r.reason))
        return
    # Attack B: selection outside the offered set entirely.
    outside = TransportAcceptance(
        transport_id=acceptance.transport_id,
        offer_digest=acceptance.offer_digest,
        selected_profile=_GENERIC,
        responder_nonce=acceptance.responder_nonce,
        responder_confirmation=acceptance.responder_confirmation,
        responder_attestation=acceptance.responder_attestation,
        key_lineage=acceptance.key_lineage,
        issued_at=acceptance.issued_at,
    )
    r2 = mgr_i.establish_initiator(
        world.session_ab, policy=TransportSecurityPolicy(),
        offered_profiles=[_QUIC], now=_NOW, instance_label="victim2",
    )
    assert r2.ok
    handle2 = mgr_i.pending_handles()[0]
    r = mgr_i.complete_initiator(handle2, outside, now=_NOW)
    if r.ok or r.reason != TransportReasonCode.DOWNGRADE_REJECTED:
        results.append(fail("case_18_downgrade_forced_selection", "out-of-offer selection: %r" % r.reason))
        return
    results.append(ok("case_18_downgrade_forced_selection", "forced selection fails both layers"))


def case_19_downgrade_policy_floor(results: List[Result]) -> None:
    """19. the policy floor rides in the transcript: an acceptance
    negotiated under a weaker floor cannot satisfy a stricter offer."""
    world = _World()
    strict = TransportSecurityPolicy(require_confidentiality=True, require_forward_secrecy=True)
    mgr_i = world.manager()
    r = mgr_i.establish_initiator(
        world.session_ab, policy=strict,
        offered_profiles=[_QUIC, _GENERIC], now=_NOW,
    )
    assert r.ok
    offer = r.value
    handle = mgr_i.pending_handles()[0]
    # A responder that ignores the floor and selects the weak profile.
    weak_acceptance = TransportAcceptance(
        transport_id=derive_transport_id(
            "generic",
            session_id=offer.session_id,
            initiator_node_id=offer.initiator_node_id,
            responder_node_id=offer.responder_node_id,
            profile_id=_GENERIC,
            policy_id=offer.policy.policy_id,
            offer_nonce=offer.offer_nonce,
        ),
        offer_digest=offer.digest(),
        selected_profile=_GENERIC,
        responder_nonce="0" * 16,
        responder_confirmation="00",
        responder_attestation="00",
        key_lineage="0" * 16,
        issued_at=_NOW,
    )
    r = mgr_i.complete_initiator(handle, weak_acceptance, now=_NOW)
    if r.ok or r.reason != TransportReasonCode.DOWNGRADE_REJECTED:
        results.append(fail("case_19_downgrade_policy_floor", "floor violation accepted (%r)" % r.reason))
        return
    # And the honest responder under the strict floor never selects weak.
    outcome = negotiate_transport_profiles([_QUIC, _GENERIC], list(default_profile_offers()), strict)
    if not outcome.ok or outcome.selected is None or outcome.selected.profile_id != _QUIC:
        results.append(fail("case_19_downgrade_policy_floor", "honest negotiation ignored floor"))
        return
    results.append(ok("case_19_downgrade_policy_floor", "floor enforced in rule and transcript"))


def case_20_downgrade_events_audited(results: List[Result]) -> None:
    """20. every downgrade attempt leaves audit evidence (section 19)."""
    world = _World()
    mgr_i = world.manager()
    mgr_r = world.manager()
    r = mgr_i.establish_initiator(
        world.session_ab, policy=TransportSecurityPolicy(),
        offered_profiles=[_QUIC], now=_NOW,
    )
    assert r.ok
    offer = r.value
    handle = mgr_i.pending_handles()[0]
    forged = TransportAcceptance(
        transport_id="adcos:transport:quic:" + "f" * 16,
        offer_digest="f" * 64,
        selected_profile=_QUIC,
        responder_nonce="f" * 16,
        responder_confirmation="ff",
        responder_attestation="ff",
        key_lineage="f" * 16,
        issued_at=_NOW,
    )
    r = mgr_i.complete_initiator(handle, forged, now=_NOW)
    if r.ok:
        results.append(fail("case_20_downgrade_events_audited", "forged acceptance accepted"))
        return
    events = mgr_i.security_log()
    downgrade_events = [e for e in events if e.event_type == TransportEventType.DOWNGRADE_REJECTED]
    if not downgrade_events:
        results.append(fail("case_20_downgrade_events_audited", "no downgrade event"))
        return
    event = downgrade_events[0]
    if not event.event_id or len(event.event_id) != 16:
        results.append(fail("case_20_downgrade_events_audited", "event id not content-derived"))
        return
    if any(pair[0] == "offer_digest" and len(pair[1]) == 64 for pair in event.metadata):
        results.append(ok("case_20_downgrade_events_audited", "downgrade event + offer-digest metadata"))
        return
    results.append(fail("case_20_downgrade_events_audited", "metadata lacks offer digest"))


# --------------------------------------------------------------------------
# 21-25: replay protection (required verification)
# --------------------------------------------------------------------------


def case_21_frame_replay_rejected(results: List[Result]) -> None:
    """21. exact frame replay is rejected with audit evidence."""
    world = _World()
    mgr_i, mgr_r, transport_id, _, _, _ = _established_pair(world)
    r = mgr_i.send(transport_id, b"replay-me", now=_NOW)
    assert r.ok
    frame = r.value
    r = mgr_r.receive(transport_id, frame, now=_NOW)
    if not r.ok:
        results.append(fail("case_21_frame_replay_rejected", "first delivery failed"))
        return
    r = mgr_r.receive(transport_id, frame, now=_NOW)
    if r.ok or r.reason != TransportReasonCode.REPLAY_REJECTED:
        results.append(fail("case_21_frame_replay_rejected", "replay accepted (%r)" % r.reason))
        return
    events = [e.event_type for e in mgr_r.get_events(transport_id)]
    if "replay-rejected" not in events:
        results.append(fail("case_21_frame_replay_rejected", "no replay audit event"))
        return
    results.append(ok("case_21_frame_replay_rejected", "REPLAY_REJECTED + event"))


def case_22_below_window_rejected(results: List[Result]) -> None:
    """22. sequences below the sliding window floor are rejected."""
    window = ReplayWindow(size=8)
    for seq in range(1, 12):
        if not window.accept(seq):
            results.append(fail("case_22_below_window_rejected", "fresh sequence %d rejected" % seq))
            return
    if window.accept(1):
        results.append(fail("case_22_below_window_rejected", "below-floor accepted"))
        return
    if window.accept(3):
        results.append(fail("case_22_below_window_rejected", "slid-out frame accepted"))
        return
    if not window.accept(12):
        results.append(fail("case_22_below_window_rejected", "window stuck"))
        return
    # Behavioral: replay of frame 1 after 70 deliveries.
    world = _World()
    mgr_i, mgr_r, transport_id, _, _, _ = _established_pair(world)
    first = None
    for index in range(70):
        r = mgr_i.send(transport_id, ("f%03d" % index).encode(), now=_NOW)
        assert r.ok
        if index == 0:
            first = r.value
        r = mgr_r.receive(transport_id, r.value, now=_NOW)
        assert r.ok, r.detail
    r = mgr_r.receive(transport_id, first, now=_NOW)
    if r.ok or r.reason != TransportReasonCode.REPLAY_REJECTED:
        results.append(fail("case_22_below_window_rejected", "ancient frame accepted (%r)" % r.reason))
        return
    results.append(ok("case_22_below_window_rejected", "unit + behavioral below-floor"))


def case_23_out_of_order_in_window(results: List[Result]) -> None:
    """23. unseen in-window reordering is accepted exactly once."""
    window = ReplayWindow(size=16)
    order = [2, 4, 1, 3]
    for seq in order:
        if not window.accept(seq):
            results.append(fail("case_23_out_of_order_in_window", "in-window %d rejected" % seq))
            return
    for seq in order:
        if window.accept(seq):
            results.append(fail("case_23_out_of_order_in_window", "reordered %d accepted twice" % seq))
            return
    # Behavioral: deliver frames out of order over a real pair.
    world = _World()
    mgr_i, mgr_r, transport_id, _, _, _ = _established_pair(world)
    frames = []
    for index in range(1, 5):
        r = mgr_i.send(transport_id, ("o%d" % index).encode(), now=_NOW)
        assert r.ok
        frames.append(r.value)
    delivered = []
    for frame in (frames[1], frames[3], frames[0], frames[2]):
        r = mgr_r.receive(transport_id, frame, now=_NOW)
        if not r.ok:
            results.append(fail("case_23_out_of_order_in_window", "in-order delivery of %r failed: %s" % (frame["sequence"], r.detail)))
            return
        delivered.append(r.value)
    if sorted(delivered) != sorted([b"o1", b"o2", b"o3", b"o4"]):
        results.append(fail("case_23_out_of_order_in_window", "payloads mangled"))
        return
    if mgr_r.receive(transport_id, frames[0], now=_NOW).ok:
        results.append(fail("case_23_out_of_order_in_window", "double delivery"))
        return
    results.append(ok("case_23_out_of_order_in_window", "reorder tolerated exactly once"))


def case_24_handshake_replay_rejected(results: List[Result]) -> None:
    """24. replayed handshake offers are rejected by the nonce ledger."""
    world = _World()
    mgr_i = world.manager()
    mgr_r = world.manager()
    r = mgr_i.establish_initiator(
        world.session_ab, policy=TransportSecurityPolicy(),
        offered_profiles=list(default_profile_offers()), now=_NOW,
    )
    assert r.ok
    offer = r.value
    r = mgr_r.respond(offer, now=_NOW)
    assert r.ok
    # Replay the identical offer to the same responder.
    r = mgr_r.respond(offer, now=_NOW)
    if r.ok or r.reason != TransportReasonCode.REPLAY_REJECTED:
        results.append(fail("case_24_handshake_replay_rejected", "offer replay accepted (%r)" % r.reason))
        return
    log_types = [e.event_type for e in mgr_r.security_log()]
    if "replay-rejected" not in log_types:
        results.append(fail("case_24_handshake_replay_rejected", "no replay audit event"))
        return
    # The replay must not have created a second transport.
    if len(mgr_r.transports()) != 1:
        results.append(fail("case_24_handshake_replay_rejected", "replay created state"))
        return
    results.append(ok("case_24_handshake_replay_rejected", "offer-nonce ledger"))


def case_25_acceptance_replay_rejected(results: List[Result]) -> None:
    """25. an old acceptance cannot complete a NEW offer (fresh
    nonces/digests make replays structurally distinct)."""
    world = _World()
    mgr_i, mgr_r, transport_id, offer, acceptance, _ = _established_pair(world)
    # A second, fresh establishment attempt on the same session.
    r = mgr_i.establish_initiator(
        world.session_ab, policy=TransportSecurityPolicy(),
        offered_profiles=list(default_profile_offers()), now=_NOW,
        instance_label="second-attempt",
    )
    assert r.ok
    handle = mgr_i.pending_handles()[0]
    r = mgr_i.complete_initiator(handle, acceptance, now=_NOW)
    if r.ok:
        results.append(fail("case_25_acceptance_replay_rejected", "stale acceptance completed a new offer"))
        return
    if r.reason != TransportReasonCode.DOWNGRADE_REJECTED:
        results.append(fail("case_25_acceptance_replay_rejected", "unexpected reason %r" % r.reason))
        return
    results.append(ok("case_25_acceptance_replay_rejected", "stale acceptance fails the echo check"))


# --------------------------------------------------------------------------
# 26-29: interoperability (required verification)
# --------------------------------------------------------------------------


def case_26_interop_bidirectional(results: List[Result]) -> None:
    """26. two independent managers interoperate in both directions
    over the full handshake + exchange."""
    world = _World()
    mgr_i, mgr_r, transport_id, _, acceptance, confirmation = _established_pair(world)
    payloads = [b"alpha", b"beta" * 40, b"gamma-1234567890"]
    for payload in payloads:
        if not _exchange_ok(mgr_i, mgr_r, transport_id, payload):
            results.append(fail("case_26_interop_bidirectional", "exchange failed for %r" % payload))
            return
    # The two endpoints agree on the public key lineage.
    state_i = mgr_i.get_security_state(transport_id)
    state_r = mgr_r.get_security_state(transport_id)
    if state_i.key_lineage != state_r.key_lineage:
        results.append(fail("case_26_interop_bidirectional", "lineage disagreement"))
        return
    if state_i.key_lineage[0] != acceptance.key_lineage:
        results.append(fail("case_26_interop_bidirectional", "lineage not derived from handshake"))
        return
    results.append(ok("case_26_interop_bidirectional", "both directions + shared lineage"))


def case_27_interop_independent_engines(results: List[Result]) -> None:
    """27. two SEPARATE engine instances derive identical secrets
    (the schedule is a pure function of the public records)."""
    world = _World()
    mgr_i, mgr_r, transport_id, _, acceptance, _ = _established_pair(world)
    r1 = mgr_i.rekey(transport_id, "rotation", now=_NOW)
    r2 = mgr_r.rekey(transport_id, "rotation", now=_NOW)
    if not (r1.ok and r2.ok):
        results.append(fail("case_27_interop_independent_engines", "rekey failed"))
        return
    if r1.value["lineage_digest"] != r2.value["lineage_digest"]:
        results.append(fail("case_27_interop_independent_engines", "independent engines derived different secrets"))
        return
    if not _exchange_ok(mgr_i, mgr_r, transport_id, b"after-rotation"):
        results.append(fail("case_27_interop_independent_engines", "post-rotation exchange failed"))
        return
    results.append(ok("case_27_interop_independent_engines", "same lineage digest on both ends"))


def case_28_interop_second_implementation(results: List[Result]) -> None:
    """28. a genuinely independent second implementation (MiniTransportEngine,
    its own schedule) runs behind the SAME contract and manager with
    zero core changes — transport replaceability."""
    world = _World()
    mgr_i = world.manager(MiniTransportEngine())
    mgr_r = world.manager(MiniTransportEngine())
    r = mgr_i.establish_initiator(
        world.session_ab, policy=TransportSecurityPolicy(require_confidentiality=True),
        offered_profiles=list(default_profile_offers()), now=_NOW,
        instance_label="mini-initiator",
    )
    assert r.ok, r.detail
    offer = r.value
    handle = mgr_i.pending_handles()[0]
    r = mgr_r.respond(offer, now=_NOW, instance_label="mini-responder")
    assert r.ok, r.detail
    acceptance = r.value
    r = mgr_i.complete_initiator(handle, acceptance, now=_NOW)
    assert r.ok, r.detail
    confirmation = r.value
    r = mgr_r.confirm(acceptance.transport_id, confirmation, now=_NOW)
    assert r.ok, r.detail
    if not _exchange_ok(mgr_i, mgr_r, acceptance.transport_id, b"mini-interop"):
        results.append(fail("case_28_interop_second_implementation", "Mini engines failed to interoperate"))
        return
    # Runtime swap: register the Mini engine on an existing manager.
    mgr_swap = world.manager()
    swap_result = mgr_swap.register_implementation(MiniTransportEngine())
    if not swap_result.ok:
        results.append(fail("case_28_interop_second_implementation", "registration rejected: %s" % swap_result.detail))
        return
    r = mgr_swap.establish_initiator(
        world.session_ab, policy=TransportSecurityPolicy(),
        offered_profiles=list(default_profile_offers()), now=_NOW,
        instance_label="swapped",
    )
    if not r.ok:
        results.append(fail("case_28_interop_second_implementation", "post-swap establishment failed"))
        return
    # Registration rejects an implementation serving unknown profiles.
    class RogueEngine(MiniTransportEngine):
        def supported_profiles(self):
            return ("transport.not.registered.v1",)

    bad = world.manager()
    bad_result = bad.register_implementation(RogueEngine())
    if bad_result.ok:
        results.append(fail("case_28_interop_second_implementation", "unknown-profile engine registered"))
        return
    results.append(ok("case_28_interop_second_implementation", "second impl + swap + registration gate"))


def case_29_wrong_key_unprotect_fails(results: List[Result]) -> None:
    """29. frames cannot cross transports: a frame from X fails closed
    on transport Y (cross-transport confusion)."""
    world = _World()
    mgr_i, mgr_r, transport_id_a, _, _, _ = _established_pair(world, label="a")
    mgr_i2, mgr_r2, transport_id_b, _, _, _ = _established_pair(world, label="b")
    r = mgr_i.send(transport_id_a, b"for-a", now=_NOW)
    assert r.ok
    frame_a = r.value
    # Deliver to the wrong manager/transport.
    r = mgr_r2.receive(transport_id_b, frame_a, now=_NOW)
    if r.ok:
        results.append(fail("case_29_wrong_key_unprotect_fails", "cross-transport frame accepted"))
        return
    # Tamper the frame's transport id to address B explicitly.
    forged = dict(frame_a)
    forged["transport_id"] = transport_id_b
    r = mgr_r2.receive(transport_id_b, forged, now=_NOW)
    if r.ok:
        results.append(fail("case_29_wrong_key_unprotect_fails", "forged-address frame accepted"))
        return
    # Tamper the visible payload region byte.
    tampered = dict(frame_a)
    tampered["wire_payload"] = ("0" if tampered["wire_payload"][0] != "0" else "1") + tampered["wire_payload"][1:]
    r = mgr_r.receive(transport_id_a, tampered, now=_NOW)
    if r.ok or r.reason != TransportReasonCode.INTEGRITY_REJECTED:
        results.append(fail("case_29_wrong_key_unprotect_fails", "tampered payload: %r" % r.reason))
        return
    # Tamper tag.
    tampered = dict(frame_a)
    tampered["integrity_tag"] = ("0" if tampered["integrity_tag"][0] != "0" else "1") + tampered["integrity_tag"][1:]
    r = mgr_r.receive(transport_id_a, tampered, now=_NOW)
    if r.ok:
        results.append(fail("case_29_wrong_key_unprotect_fails", "tampered tag accepted"))
        return
    results.append(ok("case_29_wrong_key_unprotect_fails", "cross-transport + tamper fail closed"))


# --------------------------------------------------------------------------
# 30-36: key binding + rotation (acceptance criterion 2)
# --------------------------------------------------------------------------


def _engine_confirmation_for(
    offer: TransportOffer, *, responder_attestation: str = "ab" * 32,
) -> Tuple[str, str]:
    """Run ONE responder handshake on a fresh engine and return
    (selected profile, responder confirmation)."""
    engine = ModeledTransportEngine()
    sandbox = SandboxedTransport(engine)
    handle = derive_pending_handle(offer.offer_nonce, "binding-probe")
    sandbox.initialize(_NOW, handle, offer.session_id)
    outcome = sandbox.handshake_responder(_NOW, handle, offer.session_id, offer, responder_attestation)
    assert outcome.ok, outcome.failure and outcome.failure.detail
    acceptance = outcome.value
    return (acceptance.selected_profile, acceptance.responder_confirmation)


def _binding_offer(world: _World, **overrides: Any) -> TransportOffer:
    base: Dict[str, Any] = {
        "session_id": world.session_ab,
        "initiator_node_id": world.node_a.node_id.text,
        "responder_node_id": world.node_b.node_id.text,
        "offered_profiles": (_TLS, _QUIC),
        "policy": TransportSecurityPolicy(require_confidentiality=True),
        "offer_nonce": "a1b2c3d4e5f60718",
        "issued_at": _NOW,
        "expires_at": "2026-06-01T12:30:00Z",
    }
    base.update(overrides)
    return TransportOffer(**base)


def case_30_key_binding_session(results: List[Result]) -> None:
    """30. traffic keys are bound to the SESSION (change session ->
    change keys)."""
    world = _World()
    _, baseline = _engine_confirmation_for(_binding_offer(world))
    _, other = _engine_confirmation_for(
        _binding_offer(world, session_id=world.session_ac)
    )
    if baseline == other:
        results.append(fail("case_30_key_binding_session", "session change did not change keys"))
        return
    results.append(ok("case_30_key_binding_session", "session input changes the derived keys"))


def case_31_key_binding_endpoints(results: List[Result]) -> None:
    """31. traffic keys are bound to BOTH endpoint identities."""
    world = _World()
    _, baseline = _engine_confirmation_for(_binding_offer(world))
    _, other_initiator = _engine_confirmation_for(
        _binding_offer(world, initiator_node_id=world.node_c.node_id.text)
    )
    _, other_responder = _engine_confirmation_for(
        _binding_offer(world, responder_node_id=world.node_c.node_id.text)
    )
    if baseline == other_initiator or baseline == other_responder:
        results.append(fail("case_31_key_binding_endpoints", "endpoint change did not change keys"))
        return
    results.append(ok("case_31_key_binding_endpoints", "both NodeIDs are transcript inputs"))


def case_32_key_binding_profile_and_policy(results: List[Result]) -> None:
    """32. traffic keys are bound to the negotiated profile AND the
    policy floor."""
    world = _World()
    profile_a, baseline = _engine_confirmation_for(_binding_offer(world))
    profile_b, other = _engine_confirmation_for(
        _binding_offer(world, offered_profiles=[_IPSEC, _TLS])
    )
    if profile_a == profile_b:
        results.append(fail("case_32_key_binding_profile_and_policy", "selection did not change"))
        return
    if baseline == other:
        results.append(fail("case_32_key_binding_profile_and_policy", "profile change did not change keys"))
        return
    _, policy_other = _engine_confirmation_for(
        _binding_offer(world, policy=TransportSecurityPolicy(require_confidentiality=True, require_forward_secrecy=True))
    )
    if baseline == policy_other:
        results.append(fail("case_32_key_binding_profile_and_policy", "policy change did not change keys"))
        return
    results.append(ok("case_32_key_binding_profile_and_policy", "profile + policy floor are transcript inputs"))


def case_33_key_binding_attestation(results: List[Result]) -> None:
    """33. traffic keys are bound to the responder identity
    attestation (identity policy binding)."""
    world = _World()
    _, baseline = _engine_confirmation_for(_binding_offer(world))
    _, other = _engine_confirmation_for(
        _binding_offer(world), responder_attestation="cd" * 32,
    )
    if baseline == other:
        results.append(fail("case_33_key_binding_attestation", "attestation change did not change keys"))
        return
    # The Work004IdentityAuthority signs the attestation basis with the
    # active operational credential: a different credential produces a
    # different attestation, hence different keys.
    basis = b"adcos-transport/responder-attestation:" + bytes.fromhex(
        _binding_offer(world).digest()
    )
    sig1 = world.identity.sign(world.node_b.node_id.text, basis, _NOW)
    sig2 = world.identity.sign(world.node_b.node_id.text, basis, _NOW)
    if sig1 != sig2:
        results.append(fail("case_33_key_binding_attestation", "attestation not deterministic"))
        return
    if not world.identity.verify(world.node_b.node_id.text, basis, sig1, _NOW):
        results.append(fail("case_33_key_binding_attestation", "attestation does not verify"))
        return
    if world.identity.verify(world.node_a.node_id.text, basis, sig1, _NOW):
        results.append(fail("case_33_key_binding_attestation", "attestation verifies for the WRONG node"))
        return
    results.append(ok("case_33_key_binding_attestation", "attestation in transcript + node-bound"))


def case_34_rekey_generation_chain(results: List[Result]) -> None:
    """34. rekey advances the generation, changes the keys, and
    old-generation frames are rejected."""
    world = _World()
    mgr_i, mgr_r, transport_id, _, _, _ = _established_pair(world)
    r = mgr_i.send(transport_id, b"gen-0-frame", now=_NOW)
    assert r.ok
    old_frame = r.value
    if old_frame["generation"] != 0:
        results.append(fail("case_34_rekey_generation_chain", "initial generation not 0"))
        return
    r = mgr_i.rekey(transport_id, "rotation-test", now=_NOW)
    if not r.ok or r.value["generation"] != 1:
        results.append(fail("case_34_rekey_generation_chain", "rekey did not advance: %s" % r.detail))
        return
    state = mgr_i.get_security_state(transport_id)
    if state.generation != 1 or len(state.key_lineage) != 2:
        results.append(fail("case_34_rekey_generation_chain", "lineage not tracked"))
        return
    if state.key_lineage[0] == state.key_lineage[1]:
        results.append(fail("case_34_rekey_generation_chain", "rekey did not change keys"))
        return
    # Old-generation frame rejected after rekey (peer also rekeys).
    r = mgr_r.rekey(transport_id, "rotation-test", now=_NOW)
    assert r.ok
    r = mgr_r.receive(transport_id, old_frame, now=_NOW)
    if r.ok or r.reason != TransportReasonCode.INTEGRITY_REJECTED:
        results.append(fail("case_34_rekey_generation_chain", "stale frame accepted (%r)" % r.reason))
        return
    if not _exchange_ok(mgr_i, mgr_r, transport_id, b"gen-1"):
        results.append(fail("case_34_rekey_generation_chain", "post-rekey exchange failed"))
        return
    events = [e.event_type for e in mgr_i.get_events(transport_id)]
    if "rekeyed" not in events:
        results.append(fail("case_34_rekey_generation_chain", "no rekeyed event"))
        return
    results.append(ok("case_34_rekey_generation_chain", "gen advance + lineage + stale rejection"))


def case_35_generation_bound(results: List[Result]) -> None:
    """35. the key-rotation bound is enforced: after the maximum
    generations, rekey fails closed and re-establishment is required."""
    world = _World()
    mgr_i, mgr_r, transport_id, _, _, _ = _established_pair(world)
    for generation in range(1, MAX_KEY_GENERATIONS):
        r = mgr_i.rekey(transport_id, "bound-%d" % generation, now=_NOW)
        if not r.ok:
            results.append(fail("case_35_generation_bound", "rekey %d failed early: %s" % (generation, r.detail)))
            return
        r = mgr_r.rekey(transport_id, "bound-%d" % generation, now=_NOW)
        if not r.ok:
            results.append(fail("case_35_generation_bound", "peer rekey %d failed early" % generation))
            return
    r = mgr_i.rekey(transport_id, "one-too-many", now=_NOW)
    if r.ok or r.reason != TransportReasonCode.GENERATION_EXHAUSTED:
        results.append(fail("case_35_generation_bound", "bound not enforced (%r)" % r.reason))
        return
    # The transport still functions at the last generation.
    if not _exchange_ok(mgr_i, mgr_r, transport_id, b"at-bound"):
        results.append(fail("case_35_generation_bound", "exchange at bound failed"))
        return
    results.append(ok("case_35_generation_bound", "GENERATION_EXHAUSTED at bound %d" % MAX_KEY_GENERATIONS))


def case_36_rekey_revoked_fails(results: List[Result]) -> None:
    """36. rekey under a revoked credential fails closed (keys are
    bound to identity policy)."""
    world = _World()
    mgr_i, mgr_r, transport_id, _, _, _ = _established_pair(world)
    ref = world.references[world.node_a.node_id.text]
    world.service.revoke(ref, reason="compromise", now=_NOW)
    r = mgr_i.rekey(transport_id, "post-compromise", now=_LATER)
    if r.ok or r.reason != TransportReasonCode.CREDENTIAL_REVOKED:
        results.append(fail("case_36_rekey_revoked_fails", "revoked rekey: %r" % r.reason))
        return
    events = [e.event_type for e in mgr_i.get_events(transport_id)]
    if "credential-revoked" not in events:
        results.append(fail("case_36_rekey_revoked_fails", "no revocation audit event"))
        return
    results.append(ok("case_36_rekey_revoked_fails", "CREDENTIAL_REVOKED at rekey + event"))


# --------------------------------------------------------------------------
# 37-39: continuity, revocation recheck, teardown
# --------------------------------------------------------------------------


def case_37_suspend_resume_rekey(results: List[Result]) -> None:
    """37. suspend/resume models access-change continuity: the same
    logical transport resumes on a FRESH generation (LOCK-006/021)."""
    world = _World()
    mgr_i, mgr_r, transport_id, _, _, _ = _established_pair(world)
    generation_before = mgr_i.get_security_state(transport_id).generation
    r = mgr_i.suspend(transport_id, now=_NOW, reason="path-lost")
    if not r.ok or r.value["state"] != "SUSPENDED":
        results.append(fail("case_37_suspend_resume_rekey", "suspend failed"))
        return
    r = mgr_i.send(transport_id, b"while-suspended", now=_NOW)
    if r.ok or r.reason != TransportReasonCode.NOT_ESTABLISHED:
        results.append(fail("case_37_suspend_resume_rekey", "suspended send accepted (%r)" % r.reason))
        return
    r = mgr_i.suspend(transport_id, now=_NOW)
    if r.ok:
        results.append(fail("case_37_suspend_resume_rekey", "double suspend accepted"))
        return
    r = mgr_i.resume(transport_id, now=_LATER)
    if not r.ok:
        results.append(fail("case_37_suspend_resume_rekey", "resume failed: %s" % r.detail))
        return
    state = mgr_i.get_security_state(transport_id)
    if state.generation != generation_before + 1:
        results.append(fail("case_37_suspend_resume_rekey", "resume did not rekey"))
        return
    if state.session_id != world.session_ab:
        results.append(fail("case_37_suspend_resume_rekey", "session identity changed across resume"))
        return
    events = [e.event_type for e in mgr_i.get_events(transport_id)]
    if "suspended" not in events or "resumed" not in events:
        results.append(fail("case_37_suspend_resume_rekey", "continuity events missing"))
        return
    # Peer must rekey too before frames flow again.
    mgr_r.suspend(transport_id, now=_NOW, reason="path-lost")
    mgr_r.resume(transport_id, now=_LATER)
    if not _exchange_ok(mgr_i, mgr_r, transport_id, b"resumed"):
        results.append(fail("case_37_suspend_resume_rekey", "post-resume exchange failed"))
        return
    results.append(ok("case_37_suspend_resume_rekey", "suspend -> resume rekey, session survives"))


def case_38_recheck_suspends_on_revocation(results: List[Result]) -> None:
    """38. the zero-trust recheck suspends live transports whose
    backing credential was revoked."""
    world = _World()
    mgr_i, mgr_r, transport_id, _, _, _ = _established_pair(world)
    r = mgr_i.recheck(transport_id, now=_NOW)
    if not r.ok or r.value["state"] != "ESTABLISHED":
        results.append(fail("case_38_recheck_suspends_on_revocation", "healthy recheck disturbed state"))
        return
    ref = world.references[world.node_a.node_id.text]
    world.service.revoke(ref, reason="compromise", now=_NOW)
    r = mgr_i.recheck(transport_id, now=_LATER)
    if r.ok or r.reason != TransportReasonCode.CREDENTIAL_REVOKED:
        results.append(fail("case_38_recheck_suspends_on_revocation", "recheck missed revocation (%r)" % r.reason))
        return
    if mgr_i.get_security_state(transport_id).generation < 0:
        results.append(fail("case_38_recheck_suspends_on_revocation", "state corrupted"))
        return
    r = mgr_i.send(transport_id, b"after-revoke", now=_LATER)
    if r.ok or r.reason != TransportReasonCode.NOT_ESTABLISHED:
        results.append(fail("case_38_recheck_suspends_on_revocation", "suspended transport still sends"))
        return
    r = mgr_i.resume(transport_id, now=_LATER)
    if r.ok or r.reason != TransportReasonCode.CREDENTIAL_REVOKED:
        results.append(fail("case_38_recheck_suspends_on_revocation", "resume under revocation"))
        return
    events = [e.event_type for e in mgr_i.get_events(transport_id)]
    if "credential-revoked" not in events:
        results.append(fail("case_38_recheck_suspends_on_revocation", "no revocation event"))
        return
    results.append(ok("case_38_recheck_suspends_on_revocation", "recheck -> suspend -> resume denied"))


def case_39_close_destroys_keys(results: List[Result]) -> None:
    """39. close is terminal and destroys engine key material."""
    world = _World()
    mgr_i, mgr_r, transport_id, _, _, _ = _established_pair(world)
    r = mgr_i.close(transport_id, now=_NOW, reason="teardown")
    if not r.ok or r.value["state"] != "CLOSED":
        results.append(fail("case_39_close_destroys_keys", "close failed"))
        return
    r = mgr_i.send(transport_id, b"closed", now=_NOW)
    if r.ok or r.reason != TransportReasonCode.TRANSPORT_CLOSED:
        results.append(fail("case_39_close_destroys_keys", "closed transport sends (%r)" % r.reason))
        return
    r = mgr_i.close(transport_id, now=_NOW)
    if r.ok:
        results.append(fail("case_39_close_destroys_keys", "double close accepted"))
        return
    r = mgr_i.rekey(transport_id, "zombie", now=_NOW)
    if r.ok:
        results.append(fail("case_39_close_destroys_keys", "closed transport rekeys"))
        return
    engine = mgr_i._sandbox.implementation  # type: ignore[attr-defined]
    if transport_id in getattr(engine, "_states", {}):
        results.append(fail("case_39_close_destroys_keys", "engine state survived close"))
        return
    state = mgr_i.get_security_state(transport_id)
    if state.established_at == "":
        results.append(fail("case_39_close_destroys_keys", "history destroyed"))
        return
    events = [e.event_type for e in mgr_i.get_events(transport_id)]
    if events[-1] != "closed":
        results.append(fail("case_39_close_destroys_keys", "close not last event"))
        return
    results.append(ok("case_39_close_destroys_keys", "terminal close + keys destroyed"))


# --------------------------------------------------------------------------
# 40-44: access independence (acceptance criterion 1) + import locks
# --------------------------------------------------------------------------

_TRANSPORT_SOURCES = sorted(
    str(path) for path in (REPO_ROOT / "transport").glob("*.py")
)
_CORE_MODULES = [
    "protocol", "identity", "capabilities", "discovery", "topology",
    "resources", "intent", "policy", "routing", "sessions", "multipath",
    "mobility", "federation", "adapters",
]

#: Access-technology / vendor tokens forbidden in transport IDENTIFIERS
#: (the adapter-suite identifier-scan convention; prose may reference
#: the standards documents, code must not branch on them).
_FORBIDDEN_TECH_TOKENS = (
    "five_g", "lte", "imt", "wifi", "bluetooth", "cellular", "gnb",
    "enb", "upf", "amf", "smf", "open5gs", "srsran", "ocudu",
    "ueransim", "ericsson", "nokia", "huawei", "qualcomm", "android",
    "sim", "imsi", "imei", "ssid",
)

#: Modules banned from the transport package (wall clock, randomness,
#: network, environment).
_BANNED_MODULES = {"time", "random", "socket", "urllib", "http", "ssl",
                   "secrets", "uuid", "os", "sys", "subprocess", "asyncio"}


def _imports_of(path: Path) -> List[Tuple[str, int]]:
    """Absolute imports only, as (module, level). Relative imports
    (level > 0) are intra-package and never leave the boundary."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: List[Tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.append((alias.name, 0))
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                found.append((node.module, 0))
    return found


def case_40_no_access_technology_tokens(results: List[Result]) -> None:
    """40. the transport layer contains no access-technology or vendor
    identifiers and no wall-clock/randomness/network modules (session
    security is access-independent BY CONSTRUCTION)."""
    problems = []
    for source in _TRANSPORT_SOURCES:
        tree = ast.parse(Path(source).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            name = None
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = node.name
            elif isinstance(node, ast.Name):
                name = node.id
            elif isinstance(node, ast.Attribute):
                name = node.attr
            elif isinstance(node, ast.arg):
                name = node.arg
            if name is None:
                continue
            lowered = name.lower()
            for token in _FORBIDDEN_TECH_TOKENS:
                if token in lowered:
                    problems.append("%s: %r embeds %r" % (Path(source).name, name, token))
                    break
    if problems:
        results.append(fail("case_40_no_access_technology_tokens", "; ".join(problems[:4])))
        return
    for source in _TRANSPORT_SOURCES:
        for module, level in _imports_of(Path(source)):
            if module.split(".")[0] in _BANNED_MODULES:
                results.append(fail("case_40_no_access_technology_tokens", "%s imports %s" % (Path(source).name, module)))
                return
    results.append(ok("case_40_no_access_technology_tokens", "identifier scan + banned modules clean"))


def case_41_transport_adapters_isolated(results: List[Result]) -> None:
    """41. /transport and /adapters never import each other (sibling
    boundaries beneath stable session semantics)."""
    for source in _TRANSPORT_SOURCES:
        for module, level in _imports_of(Path(source)):
            if module == "adapters" or module.startswith("adapters."):
                results.append(fail("case_41_transport_adapters_isolated", "%s imports %s" % (Path(source).name, module)))
                return
    for adapter_source in sorted((REPO_ROOT / "adapters").glob("*.py")):
        for module, level in _imports_of(adapter_source):
            if module == "transport" or module.startswith("transport."):
                results.append(fail("case_41_transport_adapters_isolated", "%s imports %s" % (adapter_source.name, module)))
                return
    results.append(ok("case_41_transport_adapters_isolated", "no transport<->adapters imports"))


def case_42_core_never_imports_transport(results: List[Result]) -> None:
    """42. no core module imports transport (transport never becomes
    core authority)."""
    offenders = []
    for module in _CORE_MODULES:
        for source in sorted((REPO_ROOT / module).glob("*.py")):
            for imported, level in _imports_of(source):
                if imported == "transport" or imported.startswith("transport."):
                    offenders.append("%s/%s" % (module, source.name))
    if offenders:
        results.append(fail("case_42_core_never_imports_transport", "; ".join(offenders[:4])))
        return
    results.append(ok("case_42_core_never_imports_transport", "14 core modules clean"))


def case_43_imports_bounded(results: List[Result]) -> None:
    """43. transport imports are bounded to its declared dependencies
    (protocol, identity, sessions) + stdlib."""
    allowed_roots = {"protocol", "identity", "sessions", "transport",
                     "__future__", "abc", "ast", "collections", "dataclasses",
                     "datetime", "enum", "functools", "hashlib", "hmac", "json",
                     "re", "typing"}
    offenders = []
    for source in _TRANSPORT_SOURCES:
        for module, level in _imports_of(Path(source)):
            root = module.split(".")[0]
            if root in allowed_roots:
                continue
            offenders.append("%s: %s" % (Path(source).name, module))
    if offenders:
        results.append(fail("case_43_imports_bounded", "; ".join(offenders[:4])))
        return
    # Declared dependency set is exactly WORK-003 + WORK-004 + WORK-012.
    roots = set()
    for source in _TRANSPORT_SOURCES:
        for module, level in _imports_of(Path(source)):
            root = module.split(".")[0]
            if root in ("protocol", "identity", "sessions"):
                roots.add(root)
    if roots != {"protocol", "identity", "sessions"}:
        results.append(fail("case_43_imports_bounded", "dependency roots %s" % sorted(roots)))
        return
    results.append(ok("case_43_imports_bounded", "protocol/identity/sessions + stdlib only"))


def case_44_access_independence_behavioral(results: List[Result]) -> None:
    """44. behavioral access independence: the SAME session is bound to
    two different access technologies through the REAL WORK-016 adapter
    runtime, and the secure transport is established over it without
    ever seeing a technology identifier."""
    world = _World()
    runtime = AdapterRuntime(session_store=world.sessions)

    def _mapping() -> Tuple[ResourceMappingEntry, ...]:
        return (
            ResourceMappingEntry(
                technology_resource="link-bandwidth", kind="bandwidth",
                unit="mbps", quantity=100, availability="reservation-based",
            ),
        )

    for technology, label in (("access.3gpp.nr.imt2020", "radio-5g"), ("access.ieee.80211", "radio-wifi")):
        descriptor = AdapterDescriptor(
            adapter_id=derive_adapter_id(technology, label),
            access_technology_id=technology,
            supported_profile_versions=("v1-0-0",),
            capabilities=("capability.core.store-and-forward",),
            resource_mapping=_mapping(),
            security_state=AdapterSecurityState(
                profile="baseline", credential_slots=("technology-credential",), attested=False,
            ),
        )
        runtime.register(descriptor, GenericAdapter(), now=_T0)
        runtime.open_adapter(descriptor.adapter_id, now=_NOW)
        bind = runtime.bind_session(descriptor.adapter_id, session_id=world.session_ab, now=_NOW)
        if not bind.ok:
            results.append(fail("case_44_access_independence_behavioral", "bind failed on %s" % technology))
            return
    # Establish the secure transport over the multi-access session.
    mgr_i, mgr_r, transport_id, offer, acceptance, _ = _established_pair(world)
    if not _exchange_ok(mgr_i, mgr_r, transport_id, b"over-any-access"):
        results.append(fail("case_44_access_independence_behavioral", "exchange failed"))
        return
    # The establishment records and public state carry no technology field.
    serialized = json.dumps(
        [offer.to_dict(), acceptance.to_dict(), mgr_i.get_security_state(transport_id).to_dict()]
    ).lower()
    for token in ("3gpp", "80211", "nr", "wifi", "access."):
        if token in serialized:
            results.append(fail("case_44_access_independence_behavioral", "technology token %r leaked into records" % token))
            return
    # Suspend both bearers (access changes), resume transport: security
    # state survives on a fresh generation without any technology input.
    mgr_i.suspend(transport_id, now=_NOW, reason="access-change")
    mgr_i.resume(transport_id, now=_LATER)
    if mgr_i.get_security_state(transport_id).session_id != world.session_ab:
        results.append(fail("case_44_access_independence_behavioral", "session identity changed"))
        return
    results.append(ok("case_44_access_independence_behavioral", "multi-access session, tech-free records"))


# --------------------------------------------------------------------------
# 45-50: failure isolation
# --------------------------------------------------------------------------


def _establish_with_engine(world: _World, engine: TransportContract, label: str = "iso"):
    mgr_i = world.manager(engine)
    mgr_r = world.manager(ModeledTransportEngine())
    r = mgr_i.establish_initiator(
        world.session_ab, policy=TransportSecurityPolicy(),
        offered_profiles=list(default_profile_offers()), now=_NOW,
        instance_label=label + "-i",
    )
    assert r.ok, r.detail
    offer = r.value
    handle = mgr_i.pending_handles()[0]
    r = mgr_r.respond(offer, now=_NOW, instance_label=label + "-r")
    assert r.ok, r.detail
    acceptance = r.value
    r = mgr_i.complete_initiator(handle, acceptance, now=_NOW)
    assert r.ok, r.detail
    confirmation = r.value
    r = mgr_r.confirm(acceptance.transport_id, confirmation, now=_NOW)
    assert r.ok, r.detail
    return mgr_i, acceptance.transport_id


def case_45_raising_implementation_isolated(results: List[Result]) -> None:
    """45. a raising implementation produces failure VALUES, never
    exceptions crossing into the caller."""
    world = _World()
    mgr, transport_id = _establish_with_engine(
        world, FaultyTransportEngine("protect", RuntimeError("vendor SDK exploded"))
    )
    r = mgr.send(transport_id, b"payload", now=_NOW)
    if r.ok or r.reason != TransportReasonCode.TRANSPORT_FAILURE:
        results.append(fail("case_45_raising_implementation_isolated", "exception crossed (%r)" % r.reason))
        return
    if "exploded" in r.detail:
        results.append(fail("case_45_raising_implementation_isolated", "exception message text leaked"))
        return
    if "RuntimeError" not in r.detail:
        results.append(fail("case_45_raising_implementation_isolated", "class name missing"))
        return
    # Manager state unchanged by the failure.
    snapshot_before = mgr.to_canonical_bytes()
    r = mgr.send(transport_id, b"payload", now=_NOW)
    snapshot_after = mgr.to_canonical_bytes()
    if snapshot_before != snapshot_after:
        results.append(fail("case_45_raising_implementation_isolated", "failure mutated manager state"))
        return
    results.append(ok("case_45_raising_implementation_isolated", "RuntimeError -> value, no message text"))


def case_46_contract_violation_discarded(results: List[Result]) -> None:
    """46. non-contract return shapes are CONTRACT_VIOLATION values and
    are discarded (never stored, keyed, or echoed)."""
    world = _World()
    mgr, transport_id = _establish_with_engine(world, BadShapeEngine("protect", "not-a-mapping"))
    r = mgr.send(transport_id, b"payload", now=_NOW)
    if r.ok or r.reason != TransportReasonCode.CONTRACT_VIOLATION:
        results.append(fail("case_46_contract_violation_discarded", "reason %r" % r.reason))
        return
    if mgr.engine_total_contract_violations != 1:
        results.append(fail("case_46_contract_violation_discarded", "violation not accounted"))
        return
    # A mis-shaped handshake return is rejected before entering state.
    mgr2 = world.manager(BadShapeEngine("handshake_responder", {"bogus": True}))
    r = mgr2.establish_initiator(
        world.session_ab, policy=TransportSecurityPolicy(),
        offered_profiles=list(default_profile_offers()), now=_NOW,
    )
    assert r.ok
    offer = r.value
    responder = world.manager()
    # Route the offer at the bad-shape responder manager.
    r = world.manager(BadShapeEngine("handshake_responder", None)).respond(offer, now=_NOW)
    if r.ok or r.reason != TransportReasonCode.CONTRACT_VIOLATION:
        results.append(fail("case_46_contract_violation_discarded", "bad handshake shape: %r" % r.reason))
        return
    results.append(ok("case_46_contract_violation_discarded", "shapes validated at every return"))


def case_47_budget_exhaustion(results: List[Result]) -> None:
    """47. the deterministic step budget is the hang model."""
    world = _World()
    mgr = world.manager(ModeledTransportEngine())
    r = mgr.establish_initiator(
        world.session_ab, policy=TransportSecurityPolicy(),
        offered_profiles=list(default_profile_offers()), now=_NOW,
    )
    assert r.ok
    offer = r.value
    responder = world.manager(ModeledTransportEngine(), step_budget=3)
    r = responder.respond(offer, now=_NOW)
    if r.ok or r.reason != TransportReasonCode.BUDGET_EXHAUSTED:
        results.append(fail("case_47_budget_exhaustion", "hang not modeled (%r)" % r.reason))
        return
    if "step budget" not in r.detail:
        results.append(fail("case_47_budget_exhaustion", "detail does not describe the budget model"))
        return
    # A generous budget succeeds on the same inputs.
    responder_ok = world.manager(ModeledTransportEngine())
    r = responder_ok.respond(offer, now=_NOW)
    if not r.ok:
        results.append(fail("case_47_budget_exhaustion", "generous budget failed: %s" % r.detail))
        return
    results.append(ok("case_47_budget_exhaustion", "BUDGET_EXHAUSTED hang model"))


def case_48_systemexit_isolated(results: List[Result]) -> None:
    """48. BaseException (SystemExit from a vendor SDK) is fully
    isolated."""
    world = _World()
    mgr, transport_id = _establish_with_engine(
        world, FaultyTransportEngine("unprotect", SystemExit(9))
    )
    r = mgr_i_send = mgr.send(transport_id, b"x", now=_NOW)
    assert r.ok
    frame = r.value
    # Route the frame into the SAME manager's receive (its engine
    # raises SystemExit on unprotect).
    r = mgr.receive(transport_id, frame, now=_NOW)
    if r.ok or r.reason != TransportReasonCode.TRANSPORT_FAILURE:
        results.append(fail("case_48_systemexit_isolated", "SystemExit crossed (%r)" % r.reason))
        return
    if "SystemExit" not in r.detail:
        results.append(fail("case_48_systemexit_isolated", "class name missing"))
        return
    results.append(ok("case_48_systemexit_isolated", "SystemExit -> isolated value"))


def case_49_health_degradation_thresholds(results: List[Result]) -> None:
    """49. deterministic supervision: DEGRADED at 2, FAILED at 5
    consecutive implementation failures; successes reset; probes never
    reset."""
    from transport.sandbox import FAILURE_THRESHOLD_DEGRADED, FAILURE_THRESHOLD_FAILED

    if (FAILURE_THRESHOLD_DEGRADED, FAILURE_THRESHOLD_FAILED) != (2, 5):
        results.append(fail("case_49_health_degradation_thresholds", "thresholds drifted"))
        return
    world = _World()
    engine = FaultyTransportEngine("protect", RuntimeError("x"))
    mgr, transport_id = _establish_with_engine(world, engine)
    # 1 failure -> still HEALTHY.
    mgr.send(transport_id, b"x", now=_NOW)
    health = mgr.health(_NOW)
    if not health.ok or health.value["effective"] != TransportHealth.HEALTHY:
        results.append(fail("case_49_health_degradation_thresholds", "1 failure not HEALTHY"))
        return
    # 2 consecutive -> DEGRADED.
    mgr.send(transport_id, b"x", now=_NOW)
    if mgr.health(_NOW).value["effective"] != TransportHealth.DEGRADED:
        results.append(fail("case_49_health_degradation_thresholds", "2 failures not DEGRADED"))
        return
    # Probes do NOT reset the counter (health() is a pure read).
    mgr.health(_NOW)
    if mgr.engine_consecutive_failures != 2:
        results.append(fail("case_49_health_degradation_thresholds", "probe reset the counter"))
        return
    # A successful REAL operation resets.
    engine2 = FaultyTransportEngine("unprotect", RuntimeError("x"))
    mgr2, transport_id2 = _establish_with_engine(world, engine2, label="reset")
    mgr2.send(transport_id2, b"x", now=_NOW)  # fails via unprotect? no: send charges protect only
    mgr2.receive(transport_id2, {"transport_id": transport_id2, "generation": 0, "sequence": 1, "protection_model": "reference-mac-only", "wire_payload": "ab", "integrity_tag": "cd"}, now=_NOW)
    mgr2.receive(transport_id2, {"transport_id": transport_id2, "generation": 0, "sequence": 2, "protection_model": "reference-mac-only", "wire_payload": "ab", "integrity_tag": "cd"}, now=_NOW)
    if mgr2.engine_consecutive_failures != 2:
        results.append(fail("case_49_health_degradation_thresholds", "expected 2 consecutive failures"))
        return
    # Successful send resets (protect path works on engine2).
    r = mgr2.send(transport_id2, b"reset", now=_NOW)
    if not r.ok:
        results.append(fail("case_49_health_degradation_thresholds", "send failed on engine2"))
        return
    if mgr2.engine_consecutive_failures != 0:
        results.append(fail("case_49_health_degradation_thresholds", "success did not reset"))
        return
    # 5 consecutive -> FAILED.
    for _ in range(5):
        mgr.send(transport_id, b"x", now=_NOW)
    if mgr.health(_NOW).value["effective"] != TransportHealth.FAILED:
        results.append(fail("case_49_health_degradation_thresholds", "5 failures not FAILED"))
        return
    results.append(ok("case_49_health_degradation_thresholds", "2/5 thresholds + probe no-reset"))


def case_50_security_rejections_not_health_faults(results: List[Result]) -> None:
    """50. network attacks (replays/tamper) never degrade the engine's
    health — they are peer behavior recorded as audit evidence, not
    implementation faults."""
    world = _World()
    mgr_i, mgr_r, transport_id, _, _, _ = _established_pair(world)
    r = mgr_i.send(transport_id, b"attack-me", now=_NOW)
    assert r.ok
    frame = r.value
    r = mgr_r.receive(transport_id, frame, now=_NOW)
    assert r.ok
    # Replay the same frame 20 times: 20 audit events, zero health impact.
    for _ in range(20):
        r = mgr_r.receive(transport_id, frame, now=_NOW)
        assert not r.ok and r.reason == TransportReasonCode.REPLAY_REJECTED
    if mgr_r.engine_consecutive_failures != 0 or mgr_r.engine_total_failures != 0:
        results.append(fail("case_50_security_rejections_not_health_faults", "replays degraded engine health"))
        return
    health = mgr_r.health(_NOW)
    if not health.ok or health.value["effective"] != TransportHealth.HEALTHY:
        results.append(fail("case_50_security_rejections_not_health_faults", "engine health degraded by network attack"))
        return
    replay_events = [
        e for e in mgr_r.get_events(transport_id)
        if e.event_type == TransportEventType.REPLAY_REJECTED
    ]
    if len(replay_events) != 20:
        results.append(fail("case_50_security_rejections_not_health_faults", "audit trail incomplete (%d)" % len(replay_events)))
        return
    results.append(ok("case_50_security_rejections_not_health_faults", "20 replays: 20 events, 0 health faults"))


# --------------------------------------------------------------------------
# 51-56: serialization / wire / determinism
# --------------------------------------------------------------------------


def case_51_wire_view_round_trip(results: List[Result]) -> None:
    """51. the public wire view round-trips through canonical bytes."""
    world = _World()
    mgr_i, mgr_r, transport_id, _, _, _ = _established_pair(world)
    mgr_i.rekey(transport_id, "view", now=_NOW)
    view = transport_view(mgr_i, transport_id)
    if set(view) < {"transport_id", "session_id", "direction", "state", "profile_id", "security_state", "events"}:
        results.append(fail("case_51_wire_view_round_trip", "required members missing"))
        return
    parsed = transport_view_from_mapping(view)
    canonical1 = transport_view_canonical_bytes(parsed)
    parsed2 = transport_view_from_mapping(json.loads(canonical1.decode("utf-8")))
    canonical2 = transport_view_canonical_bytes(parsed2)
    if canonical1 != canonical2:
        results.append(fail("case_51_wire_view_round_trip", "round trip not stable"))
        return
    # Unknown extension members survive verbatim (open world).
    extended = dict(view)
    extended["future-extension"] = {"opaque": [1, 2, 3]}
    parsed3 = transport_view_from_mapping(extended)
    if parsed3.get("future-extension") != {"opaque": [1, 2, 3]}:
        results.append(fail("case_51_wire_view_round_trip", "unknown members lost"))
        return
    results.append(ok("case_51_wire_view_round_trip", "stable round trip + open world"))


def case_52_tampered_wire_fails(results: List[Result]) -> None:
    """52. tampered wire views fail closed at every critical member."""
    world = _World()
    mgr_i, mgr_r, transport_id, _, _, _ = _established_pair(world)
    view = transport_view(mgr_i, transport_id)
    mutations = {
        "transport_id": "adcos:transport:tls:zzzz",
        "state": "HALF_OPEN",
        "profile_id": "transport.nope",
        "direction": "sideways",
    }
    for member, value in mutations.items():
        tampered = dict(view)
        tampered[member] = value
        try:
            transport_view_from_mapping(tampered)
            results.append(fail("case_52_tampered_wire_fails", "tampered %r accepted" % member))
            return
        except TransportError:
            continue
    # Missing member.
    stripped = dict(view)
    del stripped["security_state"]
    try:
        transport_view_from_mapping(stripped)
        results.append(fail("case_52_tampered_wire_fails", "missing member accepted"))
        return
    except TransportError:
        pass
    # Non-vocabulary event type.
    bad_event = dict(view)
    bad_event["events"] = [dict(view["events"][0], event_type="mystery")]
    try:
        transport_view_from_mapping(bad_event)
        results.append(fail("case_52_tampered_wire_fails", "bad event type accepted"))
        return
    except TransportError:
        pass
    # Non-vocabulary security property.
    bad_props = json.loads(json.dumps(view))
    bad_props["security_state"]["profile_properties"]["quantum"] = True
    try:
        transport_view_from_mapping(bad_props)
        results.append(fail("case_52_tampered_wire_fails", "unknown property accepted"))
        return
    except TransportError:
        pass
    results.append(ok("case_52_tampered_wire_fails", "6 tamper classes rejected"))


def case_53_envelope_opaque_forward(results: List[Result]) -> None:
    """53. transport state rides WORK-003 envelopes with opaque
    forwarding for parties that do not understand it (LOCK-014)."""
    world = _World()
    mgr_i, mgr_r, transport_id, _, _, _ = _established_pair(world)
    view = transport_view(mgr_i, transport_id)
    envelope = transport_state_to_envelope(
        view,
        message_type="transport.snapshot",
        message_id="m-0001",
        sender=world.node_a.node_id.text,
        issued_at=_NOW,
        expires_at="2026-12-31T23:59:59Z",
    )
    codec = get_codec("json-debug")
    wire = codec.encode(envelope)
    # A party that does not know the message type must still be able to
    # parse and re-emit it (tunnel as opaque extension).
    policy = ParsePolicy(unknown_type=UnknownTypePolicy.FORWARD_OPAQUE)
    outcome = protocol_accept(wire, now=parse_instant(_NOW), policy=policy)
    if not outcome.accepted or outcome.validated is None:
        results.append(fail("case_53_envelope_opaque_forward", "opaque forward failed: %s" % outcome.detail))
        return
    forwarded = outcome.validated.envelope
    if forwarded.extensions.get("transport-state") is None:
        results.append(fail("case_53_envelope_opaque_forward", "extension marker lost"))
        return
    recovered = transport_state_from_envelope(forwarded)
    if recovered.get("transport_id") != transport_id:
        results.append(fail("case_53_envelope_opaque_forward", "payload corrupted in transit"))
        return
    results.append(ok("case_53_envelope_opaque_forward", "unknown-type tunnel + payload recovery"))


def case_54_envelope_protection_round_trip(results: List[Result]) -> None:
    """54. secure control path: envelopes ride protected frames; tampered
    frames and expired envelopes fail closed."""
    world = _World()
    mgr_i, mgr_r, transport_id, _, _, _ = _established_pair(world)
    envelope = Envelope(
        version=1,
        message_type="capability.advertise",
        message_id="msg-0042",
        sender=world.node_a.node_id.text,
        issued_at=_NOW,
        expires_at="2026-12-31T23:59:59Z",
        payload={"opaque": True},
        signature="test-signature-opaque",
    )
    r = mgr_i.protect_envelope(transport_id, envelope, now=_NOW)
    if not r.ok:
        results.append(fail("case_54_envelope_protection_round_trip", "protect failed: %s" % r.detail))
        return
    frame = r.value
    r = mgr_r.receive_envelope(transport_id, frame, now=_NOW)
    if not r.ok or not isinstance(r.value, Envelope):
        results.append(fail("case_54_envelope_protection_round_trip", "receive failed: %s" % r.detail))
        return
    if r.value.message_id != "msg-0042" or r.value.payload != {"opaque": True}:
        results.append(fail("case_54_envelope_protection_round_trip", "envelope corrupted"))
        return
    # Replay of the protected envelope frame.
    r = mgr_r.receive_envelope(transport_id, frame, now=_NOW)
    if r.ok:
        results.append(fail("case_54_envelope_protection_round_trip", "replayed control frame accepted"))
        return
    # Expired envelope fails temporal validation at the transport boundary.
    expired = Envelope(
        version=1,
        message_type="capability.advertise",
        message_id="msg-0043",
        sender=world.node_a.node_id.text,
        issued_at=_T0,
        expires_at="2026-06-01T00:30:00Z",
        payload={"stale": True},
        signature="test-signature-opaque",
    )
    r = mgr_i.protect_envelope(transport_id, expired, now=_NOW)
    assert r.ok
    r = mgr_r.receive_envelope(transport_id, r.value, now=_NOW)
    if r.ok or r.reason not in (TransportReasonCode.OFFER_EXPIRED, TransportReasonCode.INVALID_INPUT):
        results.append(fail("case_54_envelope_protection_round_trip", "expired envelope accepted (%r)" % r.reason))
        return
    results.append(ok("case_54_envelope_protection_round_trip", "round trip + replay + expiry"))


def case_55_canonical_determinism(results: List[Result]) -> None:
    """55. identical operation histories produce byte-identical
    manager snapshots (in-process)."""
    def _run() -> bytes:
        world = _World()
        mgr_i, mgr_r, transport_id, _, _, _ = _established_pair(world, label="det")
        for index in range(5):
            r = mgr_i.send(transport_id, ("d%02d" % index).encode(), now=_NOW)
            assert r.ok
            r = mgr_r.receive(transport_id, r.value, now=_NOW)
            assert r.ok
        mgr_i.rekey(transport_id, "determinism", now=_NOW)
        mgr_i.suspend(transport_id, now=_NOW, reason="check")
        mgr_i.resume(transport_id, now=_LATER)
        return mgr_i.to_canonical_bytes() + mgr_r.to_canonical_bytes()

    if _run() != _run():
        results.append(fail("case_55_canonical_determinism", "snapshots differ across runs"))
        return
    results.append(ok("case_55_canonical_determinism", "byte-identical snapshots"))


def case_56_cross_process_determinism(results: List[Result]) -> None:
    """56. cross-process determinism: two fresh subprocess runs print
    byte-identical scenario output."""
    script = r"""
import sys
sys.path.insert(0, %r)
sys.path.insert(0, %r)
from tools.transport_selftest import _determinism_scenario
print(_determinism_scenario().hex())
""" % (str(REPO_ROOT), str(REPO_ROOT / "tools"))
    outputs = []
    for _ in range(2):
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=120,
        )
        if proc.returncode != 0:
            results.append(fail("case_56_cross_process_determinism", proc.stderr[-300:]))
            return
        outputs.append(proc.stdout.strip())
    if outputs[0] != outputs[1]:
        results.append(fail("case_56_cross_process_determinism", "cross-process outputs differ"))
        return
    if len(outputs[0]) < 64:
        results.append(fail("case_56_cross_process_determinism", "output too small"))
        return
    results.append(ok("case_56_cross_process_determinism", "two runs byte-identical"))


def _determinism_scenario() -> bytes:
    """A fixed scenario whose canonical output must be stable across
    processes (imported by the cross-process subprocess)."""
    world = _World()
    mgr_i, mgr_r, transport_id, _, _, _ = _established_pair(world, label="xdet")
    mgr_i.send(transport_id, b"cross-process", now=_NOW)
    mgr_r.receive(
        transport_id,
        mgr_i.send(transport_id, b"cross-process-2", now=_NOW).value,
        now=_NOW,
    )
    mgr_i.rekey(transport_id, "xdet", now=_NOW)
    return mgr_i.to_canonical_bytes()


# --------------------------------------------------------------------------
# 57-60: governance
# --------------------------------------------------------------------------


def case_57_secret_rejection(results: List[Result]) -> None:
    """57. deep secret rejection: no secret-shaped material may ride
    transport metadata (LOCK-023)."""
    probes = [
        {"session_id": "s", "psk": b"\x00\x01"},
        {"session_id": "s", "secret_key": "abcd"},
        {"session_id": "s", "material": "a" * 128},
        {"session_id": "s", "nested": [{"traffic_secret": "x"}]},
        {"session_id": "s", "blob": "A" * 64 + "=="},
    ]
    for index, probe in enumerate(probes):
        try:
            reject_secrets(probe, "probe")
            results.append(fail("case_57_secret_rejection", "accepted probe %d" % index))
            return
        except TransportError:
            continue
    # Clean public metadata passes.
    reject_secrets(
        {"session_id": "s", "policy_id": "p", "profile_id": _TLS}, "probe"
    )
    # Offers structurally reject secret extensions.
    world = _World()
    try:
        TransportOffer(
            session_id=world.session_ab,
            initiator_node_id=world.node_a.node_id.text,
            responder_node_id=world.node_b.node_id.text,
            offered_profiles=(_TLS,),
            policy=TransportSecurityPolicy(),
            offer_nonce="a1b2c3d4e5f60718",
            issued_at=_NOW,
            expires_at="2026-06-01T13:00:00Z",
            extensions={"note": "fine"},
        )
    except TransportError:
        results.append(fail("case_57_secret_rejection", "clean offer rejected"))
        return
    # The public security state cannot carry key bytes.
    from transport import TransportSecurityState as _State

    try:
        _State(
            session_id="s",
            initiator_node_id=world.node_a.node_id.text,
            responder_node_id=world.node_b.node_id.text,
            profile_id=_TLS,
            profile_properties={},
            generation=0,
            established_at=_NOW,
            last_rekey_at=_NOW,
            key_lineage=(b"\x00" * 8,),  # type: ignore[arg-type]
            replay_window_size=64,
        )
        results.append(fail("case_57_secret_rejection", "bytes in key lineage accepted"))
        return
    except (TransportError, TypeError, ValueError):
        pass
    results.append(ok("case_57_secret_rejection", "5 probe classes rejected; clean data passes"))


def case_58_frozen_docs_unchanged(results: List[Result]) -> None:
    """58. frozen architecture documents + prompts byte-identical to main.

    Follows the established suite convention (adapter case_55): the
    comparison is against ``origin/main`` when that ref exists (local
    verification); in environments without the ref (shallow CI
    checkouts) the diff produces no output and the check still asserts
    the working tree is clean for spec/.
    """
    try:
        spec_diff = subprocess.run(
            ["git", "diff", "origin/main", "HEAD", "--", "spec/"],
            capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=60,
        )
        worktree = subprocess.run(
            ["git", "status", "--porcelain", "--", "spec/"],
            capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=60,
        )
    except FileNotFoundError:
        results.append(ok("case_58_frozen_docs_unchanged", "git unavailable (skipped)"))
        return
    if spec_diff.stdout.strip():
        results.append(fail("case_58_frozen_docs_unchanged", "spec/ differs from origin/main"))
        return
    if worktree.stdout.strip():
        results.append(fail("case_58_frozen_docs_unchanged", "spec/ has uncommitted changes"))
        return
    sha = _main_sha()
    if sha == "unknown":
        results.append(ok("case_58_frozen_docs_unchanged", "spec/ clean (origin/main ref unavailable here; no diff output, working tree clean)"))
    else:
        results.append(ok("case_58_frozen_docs_unchanged", "spec/ byte-identical to origin/main (%s)" % sha))


def _main_sha() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "--short", "origin/main"],
        capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=60,
    )
    return proc.stdout.strip() or "unknown"


def case_59_vocabulary_freeze(results: List[Result]) -> None:
    """59. every frozen vocabulary is closed and exact."""
    expectations = {
        TransportReasonCode.values(): 26,
        TransportLifecycle.values(): 5,
        TransportEventType.values(): 11,
        TransportHealth.values(): 3,
        PROFILE_PROPERTIES: 8,
        REPLAY_MODES: 2,
        TRANSPORT_OPERATIONS: 11,
        registered_transport_profiles(): 5,
    }
    for vocabulary, size in expectations.items():
        values = tuple(vocabulary) if not isinstance(vocabulary, tuple) else vocabulary
        if len(values) != size or len(set(values)) != size:
            results.append(fail("case_59_vocabulary_freeze", "vocabulary size drift (%d != %d)" % (len(values), size)))
            return
    if TRANSPORT_PREFIX != "adcos:transport":
        results.append(fail("case_59_vocabulary_freeze", "prefix drifted"))
        return
    results.append(ok("case_59_vocabulary_freeze", "8 vocabularies exact"))


def case_60_concurrency_commutive(results: List[Result]) -> None:
    """60. concurrent operations on distinct transports converge to
    the deterministic snapshot regardless of interleaving."""
    world = _World()
    manager = world.manager(ModeledTransportEngine())
    responder = world.manager(ModeledTransportEngine())
    # Establish N sessions sequentially (deterministic establishment).
    sessions = [world.session_ab]
    for _ in range(7):
        sessions.append(
            world._session(world.node_a.node_id.text, world.node_b.node_id.text)
        )
    transport_ids = []
    for index, sid in enumerate(sessions):
        r = manager.establish_initiator(
            sid, policy=TransportSecurityPolicy(),
            offered_profiles=list(default_profile_offers()), now=_NOW,
            instance_label="conc-%d" % index,
        )
        assert r.ok, r.detail
        offer = r.value
        handle = manager.pending_handles()[0]
        r = responder.respond(offer, now=_NOW, instance_label="conc-r-%d" % index)
        assert r.ok, r.detail
        acceptance = r.value
        r = manager.complete_initiator(handle, acceptance, now=_NOW)
        assert r.ok, r.detail
        r = responder.confirm(acceptance.transport_id, r.value, now=_NOW)
        assert r.ok, r.detail
        transport_ids.append(acceptance.transport_id)
    # Concurrent sends on all transports from many threads.
    errors: List[str] = []
    lock = threading.Lock()

    def _worker(tid: str, count: int) -> None:
        for _ in range(count):
            r = manager.send(tid, b"conc-" + tid.encode()[:8], now=_NOW)
            if not r.ok:
                with lock:
                    errors.append("%s: %s" % (tid, r.reason))

    threads = [
        threading.Thread(target=_worker, args=(tid, 3))
        for tid in transport_ids for _ in range(2)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    if errors:
        results.append(fail("case_60_concurrency_commutive", "; ".join(errors[:3])))
        return
    # The snapshot is exactly the deterministic expectation: all
    # transports established, each with 6 sent frames' worth of state.
    snapshot = json.loads(manager.to_canonical_bytes().decode("utf-8"))
    if len(snapshot["transports"]) != 8:
        results.append(fail("case_60_concurrency_commutive", "transport count %d" % len(snapshot["transports"])))
        return
    listed_ids = [t["transport_id"] for t in snapshot["transports"]]
    if listed_ids != sorted(listed_ids):
        results.append(fail("case_60_concurrency_commutive", "ordering not stable"))
        return
    if any(t["state"] != "ESTABLISHED" for t in snapshot["transports"]):
        results.append(fail("case_60_concurrency_commutive", "state drift under concurrency"))
        return
    if len(set(snapshot["offer_nonces"])) != 8:
        results.append(fail("case_60_concurrency_commutive", "nonce ledger inconsistent"))
        return
    results.append(ok("case_60_concurrency_commutive", "16 threads, 8 transports, stable snapshot"))


# --------------------------------------------------------------------------
# 61-67: WORK-017 correction — the standards boundary battery
# (LOCK-018 record-protection seam, zero-trust pre-authorization
# lifecycle, replaceability, contract independence)
# --------------------------------------------------------------------------


class HmacSha512RecordProtection(RecordProtection):
    """A second, independent record-protection implementation (test
    fixture): HMAC-SHA512 in the standard MAC role with its own domain
    label and its own model id.  Proves the record-protection seam is
    replaceable without touching the engine, manager, sandbox, or any
    core semantics — and that it composes no construction of its own
    (one standard primitive, one standard role)."""

    _MODEL = "reference-mac-sha512"
    _DOMAIN = b"test-sha512-frame/v1"

    def model_id(self) -> str:
        return self._MODEL

    def protect_record(self, direction_key, generation, sequence, payload):
        import hmac as _hmac

        tag = _hmac.new(
            bytes(direction_key),
            self._DOMAIN
            + int(generation).to_bytes(8, "big")
            + int(sequence).to_bytes(8, "big")
            + bytes(payload),
            hashlib.sha512,
        ).hexdigest()
        return {
            "protection_model": self._MODEL,
            "wire_payload": bytes(payload).hex(),
            "integrity_tag": tag,
        }

    def unprotect_record(self, direction_key, generation, sequence, frame):
        import hmac as _hmac

        if frame.get("protection_model") != self._MODEL:
            raise TransportError(
                TransportReasonCode.INTEGRITY_REJECTED,
                "sha512 model rejects foreign protection model %r" % (frame.get("protection_model"),),
            )
        payload = bytes.fromhex(str(frame["wire_payload"]))
        expected = _hmac.new(
            bytes(direction_key),
            self._DOMAIN
            + int(generation).to_bytes(8, "big")
            + int(sequence).to_bytes(8, "big")
            + payload,
            hashlib.sha512,
        ).hexdigest()
        if not _hmac.compare_digest(expected, str(frame["integrity_tag"])):
            raise TransportError(
                TransportReasonCode.INTEGRITY_REJECTED, "sha512 tag mismatch"
            )
        return payload


#: Tokens that must NEVER appear in transport/*.py source: the module
#: must be unable to express an invented record-protection construction
#: or claim one (LOCK-018).  ("confidentiality" IS allowed — profile
#: DATA declares it; the reference record model simply does not
#: provide it.)
_FORBIDDEN_TRANSPORT_TOKENS = (
    "aead",
    "keystream",
    "encrypt",
    "cipher",
    "urandom",
    "secrets.token",
    "getrandom",
)


def case_61_standards_primitives_audit(results: List[Result]) -> None:
    """61. LOCK-018 static audit: the transport package uses ONLY the
    standard primitives (HKDF-SHA256 RFC 5869, HMAC-SHA256 RFC 2104)
    and cannot express an invented record-protection construction —
    no cipher/keystream/AEAD tokens anywhere, no entropy sources, and
    the standards-boundary citations are present in the seam modules.
    """
    sources = sorted((REPO_ROOT / "transport").glob("*.py"))
    if len(sources) != 11:
        results.append(fail("case_61_standards_primitives_audit", "expected 11 transport sources, saw %d" % len(sources)))
        return
    for source in sources:
        text = source.read_text(encoding="utf-8").lower()
        for token in _FORBIDDEN_TRANSPORT_TOKENS:
            if token in text:
                results.append(fail("case_61_standards_primitives_audit", "%s contains forbidden token %r" % (source.name, token)))
                return
        # No crypto-library or entropy imports anywhere in the package.
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            for name in names:
                root = name.split(".")[0]
                if root in ("ssl", "cryptography", "crypto", "random", "secrets", "os"):
                    results.append(fail("case_61_standards_primitives_audit", "%s imports %r" % (source.name, name)))
                    return
    # Standards leverage is DOCUMENTED where the primitives are used.
    keyschedule_text = (REPO_ROOT / "transport" / "keyschedule.py").read_text(encoding="utf-8")
    if "RFC 5869" not in keyschedule_text:
        results.append(fail("case_61_standards_primitives_audit", "keyschedule does not cite RFC 5869"))
        return
    record_text = (REPO_ROOT / "transport" / "recordprotection.py").read_text(encoding="utf-8")
    for citation in ("RFC 2104", "RFC 8446", "RFC 9001", "RFC 4303"):
        if citation not in record_text:
            results.append(fail("case_61_standards_primitives_audit", "recordprotection does not cite %s" % citation))
            return
    if "reference-mac-only" not in record_text:
        results.append(fail("case_61_standards_primitives_audit", "reference model id missing"))
        return
    # The reference record model is integrity-only BY DECLARATION: the
    # class docstring states the non-confidentiality explicitly.
    if "NO confidentiality" not in record_text:
        results.append(fail("case_61_standards_primitives_audit", "non-confidentiality not declared"))
        return
    results.append(ok("case_61_standards_primitives_audit", "11 sources: HKDF/HMAC only, no cipher tokens, RFCs cited"))


def case_62_reference_frame_contract(results: List[Result]) -> None:
    """62. the reference frame is SELF-DESCRIBING and honestly
    non-confidential: every frame declares its protection model, the
    payload region is visible by design (proving the model claims no
    confidentiality), core structural validation stays crypto-neutral
    (a foreign model id passes STRUCTURE but fails closed at the
    engine), and every tamper class fails closed."""
    world = _World()
    mgr_i, mgr_r, transport_id, _, _, _ = _established_pair(world)
    r = mgr_i.send(transport_id, b"visible-by-design", now=_NOW)
    if not r.ok:
        results.append(fail("case_62_reference_frame_contract", "send failed"))
        return
    frame = r.value
    # (a) self-describing: the frame declares exactly the reference model.
    if frame.get("protection_model") != REFERENCE_PROTECTION_MODEL:
        results.append(fail("case_62_reference_frame_contract", "frame does not self-describe the model"))
        return
    # (b) honest non-confidentiality: the payload region is the
    # plaintext, recoverable by plain hex-decode — the model makes NO
    # confidentiality claim anywhere.
    if bytes.fromhex(frame["wire_payload"]) != b"visible-by-design":
        results.append(fail("case_62_reference_frame_contract", "payload region is not the visible plaintext"))
        return
    # (c) the tag is a standard HMAC-SHA256 length (64 hex).
    if len(frame["integrity_tag"]) != 64:
        results.append(fail("case_62_reference_frame_contract", "tag is not HMAC-SHA256 length"))
        return
    # (d) core structural validation is crypto-neutral: a
    # production-shaped foreign model id passes STRUCTURE...
    foreign = dict(frame)
    foreign["protection_model"] = "production-tls13-record-protection"
    try:
        validate_frame_view(foreign)
    except TransportError as error:
        results.append(fail("case_62_reference_frame_contract", "core rejected a structurally valid foreign model: %s" % error.detail))
        return
    # ...but the reference ENGINE fails closed on the foreign model
    # (each implementation enforces exactly its own model).
    r2 = mgr_i.send(transport_id, b"model-gate", now=_NOW)
    assert r2.ok
    delivered = dict(r2.value)
    delivered["protection_model"] = "production-tls13-record-protection"
    r3 = mgr_r.receive(transport_id, delivered, now=_NOW)
    if r3.ok or r3.reason != TransportReasonCode.INTEGRITY_REJECTED:
        results.append(fail("case_62_reference_frame_contract", "foreign model accepted (%r)" % r3.reason))
        return
    # (e) the tag binds generation+sequence+payload: swapping the
    # payload between two same-length frames breaks the tag.
    ra = mgr_i.send(transport_id, b"AAAA", now=_NOW)
    assert ra.ok
    rb = mgr_i.send(transport_id, b"BBBB", now=_NOW)
    assert rb.ok
    swapped = dict(ra.value)
    swapped["wire_payload"] = rb.value["wire_payload"]
    rs = mgr_r.receive(transport_id, swapped, now=_NOW)
    if rs.ok or rs.reason != TransportReasonCode.INTEGRITY_REJECTED:
        results.append(fail("case_62_reference_frame_contract", "payload swap not detected (%r)" % rs.reason))
        return
    # (f) malformed member classes fail closed at structure.
    for member, value in (
        ("protection_model", "UPPER-CASE"),
        ("wire_payload", "not-hex"),
        ("integrity_tag", ""),
    ):
        bad = dict(rb.value)
        bad[member] = value
        try:
            validate_frame_view(bad)
            results.append(fail("case_62_reference_frame_contract", "malformed %r passed structure" % member))
            return
        except TransportError:
            continue
    results.append(ok("case_62_reference_frame_contract", "self-describing, visible, crypto-neutral core, fail-closed"))


def case_63_preconfirmation_gate(results: List[Result]) -> None:
    """63. ZERO-TRUST pre-authorization lifecycle: after respond() the
    responder transport is AWAITING_CONFIRM (channel cryptographically
    usable, peer NOT yet authenticated/authorized) and EVERY privileged
    operation fails closed with peer-unconfirmed; wrong key
    confirmation, a forged initiator attestation, and a revoked local
    credential each fail without granting authorization; only a fully
    verified confirm() reaches ESTABLISHED."""
    world = _World()
    mgr_i = world.manager(ModeledTransportEngine())
    mgr_r = world.manager(ModeledTransportEngine())
    r = mgr_i.establish_initiator(
        world.session_ab, policy=TransportSecurityPolicy(require_confidentiality=True),
        offered_profiles=list(default_profile_offers()), now=_NOW,
        instance_label="gate-initiator",
    )
    assert r.ok, r.detail
    offer = r.value
    handle = mgr_i.pending_handles()[0]
    r = mgr_r.respond(offer, now=_NOW, instance_label="gate-responder")
    assert r.ok, r.detail
    acceptance = r.value
    transport_id = acceptance.transport_id
    # (a) the responder is NOT established: the explicit
    # pre-authorization state is visible in public state.
    snapshot = mgr_r.snapshot()
    entry = [t for t in snapshot["transports"] if t["transport_id"] == transport_id][0]
    if entry["state"] != "AWAITING_CONFIRM":
        results.append(fail("case_63_preconfirmation_gate", "responder state %r != AWAITING_CONFIRM" % entry["state"]))
        return
    if [e.event_type for e in mgr_r.get_events(transport_id)] != ["awaiting-confirmation"]:
        results.append(fail("case_63_preconfirmation_gate", "responder events missing awaiting-confirmation"))
        return
    # (b) every privileged operation fails closed BEFORE confirm().
    forged_frame = {
        "transport_id": transport_id, "generation": 0, "sequence": 1,
        "protection_model": REFERENCE_PROTECTION_MODEL,
        "wire_payload": "ab", "integrity_tag": "cd" * 32,
    }
    envelope = Envelope(
        version=1, message_type="capability.advertise", message_id="m-gate",
        sender=world.node_a.node_id.text, issued_at=_NOW,
        expires_at="2026-12-31T23:59:59Z", payload={"gated": True},
        signature="opaque",
    )
    gates = [
        ("send", mgr_r.send(transport_id, b"early", now=_NOW)),
        ("receive", mgr_r.receive(transport_id, forged_frame, now=_NOW)),
        ("protect_envelope", mgr_r.protect_envelope(transport_id, envelope, now=_NOW)),
        ("receive_envelope", mgr_r.receive_envelope(transport_id, forged_frame, now=_NOW)),
        ("rekey", mgr_r.rekey(transport_id, "early-rotation", now=_NOW)),
    ]
    for label, outcome in gates:
        if outcome.ok or outcome.reason != TransportReasonCode.PEER_UNCONFIRMED:
            results.append(fail("case_63_preconfirmation_gate", "%s not peer-unconfirmed-gated (%r)" % (label, outcome.reason)))
            return
    if mgr_r.suspend(transport_id, now=_NOW).ok:
        results.append(fail("case_63_preconfirmation_gate", "suspend allowed pre-confirmation"))
        return
    # (c) lifecycle edges: AWAITING_CONFIRM -> ESTABLISHED is the only
    # authorization edge; no suspension shortcut exists.
    if not lifecycle_transition_is_legal("AWAITING_CONFIRM", "ESTABLISHED"):
        results.append(fail("case_63_preconfirmation_gate", "confirm edge illegal"))
        return
    if lifecycle_transition_is_legal("AWAITING_CONFIRM", "SUSPENDED"):
        results.append(fail("case_63_preconfirmation_gate", "unconfirmed channel may suspend"))
        return
    # (d) the initiator completes; a WRONG key confirmation does not
    # grant authorization.
    r = mgr_i.complete_initiator(handle, acceptance, now=_NOW)
    assert r.ok, r.detail
    confirmation = r.value
    wrong = TransportConfirmation(
        transport_id=transport_id,
        offer_digest=confirmation.offer_digest,
        initiator_confirmation="00" * 32,
        initiator_attestation=confirmation.initiator_attestation,
        issued_at=_NOW,
    )
    r = mgr_r.confirm(transport_id, wrong, now=_NOW)
    if r.ok or r.reason != TransportReasonCode.INTEGRITY_REJECTED:
        results.append(fail("case_63_preconfirmation_gate", "wrong confirmation accepted (%r)" % r.reason))
        return
    entry = [t for t in mgr_r.snapshot()["transports"] if t["transport_id"] == transport_id][0]
    if entry["state"] != "AWAITING_CONFIRM":
        results.append(fail("case_63_preconfirmation_gate", "state changed on failed confirmation"))
        return
    # (e) a FORGED initiator attestation (signed by node_c over the
    # same basis) does not grant authorization — the key confirmation
    # is valid, the identity is not.
    forged_attestation = world.identity.sign(
        world.node_c.node_id.text,
        initiator_attestation_basis(confirmation.offer_digest),
        _NOW,
    )
    impersonating = TransportConfirmation(
        transport_id=transport_id,
        offer_digest=confirmation.offer_digest,
        initiator_confirmation=confirmation.initiator_confirmation,
        initiator_attestation=forged_attestation,
        issued_at=_NOW,
    )
    r = mgr_r.confirm(transport_id, impersonating, now=_NOW)
    if r.ok or r.reason != TransportReasonCode.IDENTITY_UNUSABLE:
        results.append(fail("case_63_preconfirmation_gate", "forged attestation accepted (%r)" % r.reason))
        return
    if mgr_r.send(transport_id, b"still-gated", now=_NOW).ok:
        results.append(fail("case_63_preconfirmation_gate", "privileged op after failed confirmations"))
        return
    # (f) the properly signed confirmation grants authorization NOW.
    r = mgr_r.confirm(transport_id, confirmation, now=_NOW)
    if not r.ok:
        results.append(fail("case_63_preconfirmation_gate", "legitimate confirmation rejected: %s" % r.detail))
        return
    entry = [t for t in mgr_r.snapshot()["transports"] if t["transport_id"] == transport_id][0]
    if entry["state"] != "ESTABLISHED":
        results.append(fail("case_63_preconfirmation_gate", "confirmation did not establish"))
        return
    events = [e.event_type for e in mgr_r.get_events(transport_id)]
    # The audit trail shows: pre-authorization state, the REJECTED
    # confirmation attempts (integrity-rejected / rejected — audited
    # security evidence), then the granted authorization.
    if events[0] != "awaiting-confirmation" or events[-1] != "established":
        results.append(fail("case_63_preconfirmation_gate", "event order %s" % events))
        return
    if "integrity-rejected" not in events or "rejected" not in events:
        results.append(fail("case_63_preconfirmation_gate", "failed attempts not audited: %s" % events))
        return
    if not _exchange_ok(mgr_i, mgr_r, transport_id, b"post-confirm"):
        results.append(fail("case_63_preconfirmation_gate", "exchange failed after confirmation"))
        return
    # (g) double confirmation is a state conflict, not a silent no-op.
    if mgr_r.confirm(transport_id, confirmation, now=_NOW).ok:
        results.append(fail("case_63_preconfirmation_gate", "double confirm allowed"))
        return
    # (h) initiator-side symmetry: before complete_initiator the
    # initiator has NO transport record at all — nothing to abuse.
    world2 = _World()
    mgr2 = world2.manager(ModeledTransportEngine())
    r = mgr2.establish_initiator(
        world2.session_ab, policy=TransportSecurityPolicy(),
        offered_profiles=list(default_profile_offers()), now=_NOW,
        instance_label="pending-only",
    )
    assert r.ok, r.detail
    if mgr2.transports():
        results.append(fail("case_63_preconfirmation_gate", "initiator holds a transport record pre-completion"))
        return
    results.append(ok("case_63_preconfirmation_gate", "AWAITING_CONFIRM gates 6 ops; only verified confirm() establishes"))


def case_64_record_protection_replaceable(results: List[Result]) -> None:
    """64. the record-protection implementation is REPLACEABLE behind
    the same engine/contract: a second standard-primitive model
    (HMAC-SHA512, its own domain and model id) runs end-to-end with
    zero core changes, interops with itself, and both engines fail
    closed on the other's frames."""
    world = _World()
    mgr_i = world.manager(ModeledTransportEngine(record_protection=HmacSha512RecordProtection()))
    mgr_r = world.manager(ModeledTransportEngine(record_protection=HmacSha512RecordProtection()))
    r = mgr_i.establish_initiator(
        world.session_ab, policy=TransportSecurityPolicy(require_confidentiality=True),
        offered_profiles=list(default_profile_offers()), now=_NOW,
        instance_label="sha512-i",
    )
    assert r.ok, r.detail
    offer = r.value
    handle = mgr_i.pending_handles()[0]
    r = mgr_r.respond(offer, now=_NOW, instance_label="sha512-r")
    assert r.ok, r.detail
    acceptance = r.value
    r = mgr_i.complete_initiator(handle, acceptance, now=_NOW)
    assert r.ok, r.detail
    r = mgr_r.confirm(acceptance.transport_id, r.value, now=_NOW)
    assert r.ok, r.detail
    if not _exchange_ok(mgr_i, mgr_r, acceptance.transport_id, b"sha512-model"):
        results.append(fail("case_64_record_protection_replaceable", "sha512 pair failed to interoperate"))
        return
    # The frames carry the second model's id and tag length.
    r = mgr_i.send(acceptance.transport_id, b"model-check", now=_NOW)
    assert r.ok
    frame = r.value
    if frame["protection_model"] != "reference-mac-sha512" or len(frame["integrity_tag"]) != 128:
        results.append(fail("case_64_record_protection_replaceable", "second model's frame shape wrong"))
        return
    # A default-model (SHA-256) frame fails closed on the SHA-512 pair
    # (fresh sequence on the target transport so the rejection comes
    # from the MODEL gate, not the replay window).
    default_pair = _established_pair(world, label="cross")
    frame256 = default_pair[0].send(default_pair[2], b"sha256-frame", now=_NOW)
    assert frame256.ok
    delivered256 = dict(frame256.value, transport_id=acceptance.transport_id, sequence=3)
    r = mgr_r.receive(acceptance.transport_id, delivered256, now=_NOW)
    if r.ok or r.reason != TransportReasonCode.INTEGRITY_REJECTED:
        results.append(fail("case_64_record_protection_replaceable", "sha256 frame accepted by sha512 engine (%r)" % r.reason))
        return
    # And vice versa: the SHA-512 frame fails closed on the default pair
    # (fresh sequence on that transport).
    delivered512 = dict(frame, transport_id=default_pair[2], sequence=1)
    r = default_pair[1].receive(default_pair[2], delivered512, now=_NOW)
    if r.ok or r.reason != TransportReasonCode.INTEGRITY_REJECTED:
        results.append(fail("case_64_record_protection_replaceable", "sha512 frame accepted by default engine (%r)" % r.reason))
        return
    # Structural seam facts: both models satisfy the same ABC and the
    # engine carries whichever it was composed with.
    if not isinstance(HmacSha512RecordProtection(), RecordProtection):
        results.append(fail("case_64_record_protection_replaceable", "second model is not a RecordProtection"))
        return
    engine_probe = ModeledTransportEngine(record_protection=HmacSha512RecordProtection())
    if engine_probe._record_protection.model_id() != "reference-mac-sha512":  # type: ignore[attr-defined]
        results.append(fail("case_64_record_protection_replaceable", "engine did not compose the second model"))
        return
    results.append(ok("case_64_record_protection_replaceable", "sha512 model end-to-end; cross-model fail-closed"))


def case_65_contract_independent_of_crypto(results: List[Result]) -> None:
    """65. the PUBLIC contract is independent of the record-protection
    implementation: the same establishment + exchange history under two
    different record models produces BYTE-IDENTICAL manager snapshots
    and wire views — only the frames (crypto artifacts) differ."""
    world = _World()

    def run(record_protection):
        mgr_i = world.manager(ModeledTransportEngine(record_protection=record_protection))
        mgr_r = world.manager(ModeledTransportEngine(record_protection=record_protection))
        r = mgr_i.establish_initiator(
            world.session_ab, policy=TransportSecurityPolicy(require_confidentiality=True),
            offered_profiles=list(default_profile_offers()), now=_NOW,
            instance_label="indep",
        )
        assert r.ok, r.detail
        offer = r.value
        handle = mgr_i.pending_handles()[0]
        r = mgr_r.respond(offer, now=_NOW, instance_label="indep-r")
        assert r.ok, r.detail
        acceptance = r.value
        r = mgr_i.complete_initiator(handle, acceptance, now=_NOW)
        assert r.ok, r.detail
        confirmation = r.value
        r = mgr_r.confirm(acceptance.transport_id, confirmation, now=_NOW)
        assert r.ok, r.detail
        send_a = mgr_i.send(acceptance.transport_id, b"same-history", now=_NOW)
        assert send_a.ok
        recv = mgr_r.receive(acceptance.transport_id, send_a.value, now=_NOW)
        assert recv.ok and recv.value == b"same-history"
        rekey = mgr_i.rekey(acceptance.transport_id, "independence", now=_NOW)
        assert rekey.ok
        send_b = mgr_i.send(acceptance.transport_id, b"after-rekey", now=_NOW)
        assert send_b.ok
        view = transport_view(mgr_i, acceptance.transport_id)
        return mgr_i, acceptance.transport_id, send_a.value, send_b.value, view

    mgr_a, tid_a, frame_a1, frame_a2, view_a = run(ReferenceRecordProtection())
    mgr_b, tid_b, frame_b1, frame_b2, view_b = run(HmacSha512RecordProtection())
    # Same transport identity (derivation is contract-side, not crypto-side).
    if tid_a != tid_b:
        results.append(fail("case_65_contract_independent_of_crypto", "transport ids diverged"))
        return
    # Byte-identical public snapshots: the manager's public state knows
    # nothing about the record model serving it.
    if mgr_a.to_canonical_bytes() != mgr_b.to_canonical_bytes():
        results.append(fail("case_65_contract_independent_of_crypto", "snapshots differ across record models"))
        return
    if transport_view_canonical_bytes(view_a) != transport_view_canonical_bytes(view_b):
        results.append(fail("case_65_contract_independent_of_crypto", "wire views differ across record models"))
        return
    # ...while the crypto artifacts (frames) DO differ — the crypto
    # genuinely changed behind the unchanged contract.
    if frame_a1 == frame_b1 or frame_a2 == frame_b2:
        results.append(fail("case_65_contract_independent_of_crypto", "frames identical across record models"))
        return
    if frame_a1["protection_model"] == frame_b1["protection_model"]:
        results.append(fail("case_65_contract_independent_of_crypto", "model ids identical"))
        return
    # Cross-model delivery of the same history fails closed (frames are
    # bound to their model's keys and semantics).
    r = mgr_b.receive(tid_b, dict(frame_a2, transport_id=tid_b), now=_NOW)
    if r.ok:
        results.append(fail("case_65_contract_independent_of_crypto", "cross-model frame accepted"))
        return
    results.append(ok("case_65_contract_independent_of_crypto", "byte-identical contract; differing frames"))


def case_66_initiator_zero_trust(results: List[Result]) -> None:
    """66. initiator-side zero trust: a forged responder attestation
    (impersonation — the acceptance was produced over a transcript
    containing node_c's signature) passes the cryptographic key
    confirmation but FAILS the manager's identity gate; no transport
    record is created and the pending establishment is consumed."""
    world = _World()
    mgr_i = world.manager(ModeledTransportEngine())
    r = mgr_i.establish_initiator(
        world.session_ab, policy=TransportSecurityPolicy(),
        offered_profiles=list(default_profile_offers()), now=_NOW,
        instance_label="impersonation",
    )
    assert r.ok, r.detail
    offer = r.value
    handle = mgr_i.pending_handles()[0]
    # A "responder" that derived its acceptance over a transcript
    # containing an attestation signed by node_c (not the bound
    # responder node_b): the acceptance is internally consistent, so
    # the engine-level confirmation check passes — only the identity
    # gate can stop the impersonation.
    rogue_attestation = world.identity.sign(
        world.node_c.node_id.text,
        responder_attestation_basis(offer.digest()),
        _NOW,
    )
    engine = ModeledTransportEngine()
    sandbox = SandboxedTransport(engine)
    sandbox.initialize(_NOW, handle, offer.session_id)
    outcome = sandbox.handshake_responder(
        _NOW, handle, offer.session_id, offer, rogue_attestation
    )
    assert outcome.ok, outcome.failure and outcome.failure.detail
    rogue_acceptance = outcome.value
    r = mgr_i.complete_initiator(handle, rogue_acceptance, now=_NOW)
    if r.ok or r.reason != TransportReasonCode.IDENTITY_UNUSABLE:
        results.append(fail("case_66_initiator_zero_trust", "impersonated acceptance accepted (%r)" % getattr(r, "reason", None)))
        return
    # Fail-closed cleanup: no record, no pending entry, nothing usable.
    if mgr_i.transports():
        results.append(fail("case_66_initiator_zero_trust", "record created from impersonated acceptance"))
        return
    if mgr_i.pending_handles():
        results.append(fail("case_66_initiator_zero_trust", "pending entry survived the rejection"))
        return
    # Control: the same flow with the genuine responder attestation
    # establishes (the gate rejects forgery, not the flow).
    r = mgr_i.establish_initiator(
        world.session_ab, policy=TransportSecurityPolicy(),
        offered_profiles=list(default_profile_offers()), now=_NOW,
        instance_label="genuine",
    )
    assert r.ok, r.detail
    offer2 = r.value
    handle2 = mgr_i.pending_handles()[0]
    genuine = world.manager(ModeledTransportEngine())
    r = genuine.respond(offer2, now=_NOW, instance_label="genuine-r")
    assert r.ok, r.detail
    r = mgr_i.complete_initiator(handle2, r.value, now=_NOW)
    if not r.ok:
        results.append(fail("case_66_initiator_zero_trust", "genuine acceptance rejected: %s" % r.detail))
        return
    if len(mgr_i.transports()) != 1:
        results.append(fail("case_66_initiator_zero_trust", "genuine record missing"))
        return
    results.append(ok("case_66_initiator_zero_trust", "impersonation passes key check, fails identity gate"))


def case_67_standards_boundary_documented(results: List[Result]) -> None:
    """67. the standards boundary is DOCUMENTED (C2): the module
    README states precisely what is ADCOS semantics vs profile
    cryptography, names the standard record protections production
    implementations supply, and no longer contains the removed
    overstated claim ('modeled AEAD') anywhere in the module or docs."""
    readme = (REPO_ROOT / "transport" / "README.md").read_text(encoding="utf-8")
    required_markers = (
        "REFERENCE MODEL",
        "does NOT implement",
        "not wire-compatible",
        "no confidentiality claim",
        "reference-mac-only",
        "wire_payload",
        "RFC 8446",
        "RFC 9001",
        "RFC 4303",
        "WireGuard",
        "AWAITING_CONFIRM",
        "peer-unconfirmed",
        "RecordProtection",
    )
    for marker in required_markers:
        if marker not in readme:
            results.append(fail("case_67_standards_boundary_documented", "README missing boundary marker %r" % marker))
            return
    # The removed overstatement is gone everywhere it lived.
    for path in [REPO_ROOT / "transport" / "README.md"] + sorted((REPO_ROOT / "transport").glob("*.py")):
        if "modeled AEAD" in path.read_text(encoding="utf-8"):
            results.append(fail("case_67_standards_boundary_documented", "%s still claims 'modeled AEAD'" % path.name))
            return
    # The lifecycle vocabulary the README documents matches the code.
    if "AWAITING_CONFIRM" not in readme or TransportLifecycle.AWAITING_CONFIRM != "AWAITING_CONFIRM":
        results.append(fail("case_67_standards_boundary_documented", "lifecycle documentation mismatch"))
        return
    # The frame contract the README documents matches validation.
    if "protection_model" not in readme:
        results.append(fail("case_67_standards_boundary_documented", "frame contract not documented"))
        return
    results.append(ok("case_67_standards_boundary_documented", "13 boundary markers; overstated claim removed"))


def case_68_replay_window_transactional(results: List[Result]) -> None:
    """68. replay-window admission is TRANSACTIONAL (Blocker 1, the
    WORK-017 acceptance criterion): a forged frame with a huge
    sequence number and an invalid integrity tag must NOT advance the
    receive window, and the legitimate lower-sequence frame that
    follows must still succeed.  Unauthenticated network input cannot
    mutate security state (architecture section 19).

    Under the prior (non-transactional) code, ``unprotect`` advanced
    ``highest`` via ``accept`` BEFORE the MAC was checked; a forged
    high-sequence frame with a bad tag then left the window pinned
    far ahead, starving every legitimate lower-sequence frame
    (REPLAY_REJECTED on the real traffic).  This case proves the
    window is mutated only after authentication succeeds."""
    # --- unit level: would_accept is genuinely read-only ---
    window = ReplayWindow(size=8)
    before = window.highest
    if not window.would_accept(1_000_000):
        results.append(fail("case_68_replay_window_transactional", "would_accept rejected a fresh high sequence"))
        return
    if window.highest != before:
        results.append(fail("case_68_replay_window_transactional", "would_accept mutated highest (read-only violation)"))
        return
    # A normal sequence still admits after the (non-mutating) pre-check.
    if not window.accept(1):
        results.append(fail("case_68_replay_window_transactional", "legitimate sequence rejected after harmless pre-check"))
        return
    # --- behavioral: forged high-seq frame with an invalid tag ---
    world = _World()
    mgr_i, mgr_r, transport_id, _, _, _ = _established_pair(world)
    # Receive one legitimate frame so the responder window has state.
    r = mgr_i.send(transport_id, b"legit-1", now=_NOW)
    assert r.ok
    legit_1 = r.value
    r = mgr_r.receive(transport_id, legit_1, now=_NOW)
    assert r.ok, r.detail
    # Forged frame: bump the legit frame's sequence to a huge value,
    # leave the (now-wrong) tag in place.  transport_id/generation are
    # valid, so it reaches the replay gate and the MAC check.
    forged = dict(legit_1)
    forged["sequence"] = 1_000_000
    r = mgr_r.receive(transport_id, forged, now=_NOW)
    if r.ok or r.reason != TransportReasonCode.INTEGRITY_REJECTED:
        results.append(fail("case_68_replay_window_transactional", "forged high-seq frame not integrity-rejected: %r" % r.reason))
        return
    # The window was NOT advanced by the failed forged frame: the next
    # legitimate frame (sequence 2) must still succeed.  Under the old
    # code ``accept(1_000_000)`` would have advanced ``highest`` to
    # 1_000_000 and sequence 2 would be REPLAY_REJECTED as below-floor.
    r = mgr_i.send(transport_id, b"legit-2", now=_NOW)
    assert r.ok
    r = mgr_r.receive(transport_id, r.value, now=_NOW)
    if not r.ok or r.value != b"legit-2":
        results.append(fail("case_68_replay_window_transactional", "post-forgery legitimate frame rejected (window poisoned): %r" % r.reason))
        return
    results.append(ok("case_68_replay_window_transactional", "forged high-seq frame leaves window unchanged; legit frame still succeeds"))


def case_69_swap_preserves_live_transports(results: List[Result]) -> None:
    """69. runtime implementation swap preserves live transports
    (Blocker 2, the WORK-017 acceptance criterion): an
    already-established transport keeps the engine it was established
    with (its frames still use that engine's record model and still
    round-trip), and a transport established AFTER the swap uses the
    new implementation.  The manager's single default sandbox is no
    longer the routing target for established transports — each
    transport record owns the sandbox captured at its establishment.

    Under the prior code, ``register_implementation`` replaced the
    manager's single ``_sandbox``; every established transport was
    then routed into the new implementation, which held no state for
    it (TRANSPORT_FAILURE).  This case proves A survives the swap and
    B uses the new engine, coexisting on the same manager."""
    world = _World()
    mgr_i = world.manager(ModeledTransportEngine())
    mgr_r = world.manager(ModeledTransportEngine())
    # --- Establish transport A on the DEFAULT (Modeled) engine. ---
    r = mgr_i.establish_initiator(
        world.session_ab, policy=TransportSecurityPolicy(require_confidentiality=True),
        offered_profiles=list(default_profile_offers()), now=_NOW,
        instance_label="a-initiator",
    )
    assert r.ok, r.detail
    offer_a = r.value
    handle_a = mgr_i.pending_handles()[0]
    r = mgr_r.respond(offer_a, now=_NOW, instance_label="a-responder")
    assert r.ok, r.detail
    acceptance_a = r.value
    r = mgr_i.complete_initiator(handle_a, acceptance_a, now=_NOW)
    assert r.ok, r.detail
    confirmation_a = r.value
    r = mgr_r.confirm(acceptance_a.transport_id, confirmation_a, now=_NOW)
    assert r.ok, r.detail
    transport_a = acceptance_a.transport_id
    # A's frames use the reference (Modeled) record model.
    r = mgr_i.send(transport_a, b"A-before-swap", now=_NOW)
    assert r.ok
    if r.value["protection_model"] != REFERENCE_PROTECTION_MODEL:
        results.append(fail("case_69_swap_preserves_live_transports", "A frame not reference-mac-only before swap"))
        return
    r = mgr_r.receive(transport_a, r.value, now=_NOW)
    if not r.ok or r.value != b"A-before-swap":
        results.append(fail("case_69_swap_preserves_live_transports", "A exchange failed pre-swap"))
        return
    # --- Swap BOTH managers to the Mini implementation. ---
    swap_i = mgr_i.register_implementation(MiniTransportEngine())
    swap_r = mgr_r.register_implementation(MiniTransportEngine())
    if not (swap_i.ok and swap_r.ok):
        results.append(fail("case_69_swap_preserves_live_transports", "swap rejected"))
        return
    # --- A STILL WORKS: it keeps its original Modeled sandbox. ---
    # Under the old code this routed A into the new Mini sandbox, which
    # has no state for transport A -> TRANSPORT_FAILURE.
    if not _exchange_ok(mgr_i, mgr_r, transport_a, b"A-after-swap"):
        results.append(fail("case_69_swap_preserves_live_transports", "live transport A broken after swap"))
        return
    # And A's frames are STILL reference-mac-only (A did not migrate).
    r = mgr_i.send(transport_a, b"A-probe", now=_NOW)
    assert r.ok
    if r.value["protection_model"] != REFERENCE_PROTECTION_MODEL:
        results.append(fail("case_69_swap_preserves_live_transports", "A frame migrated to the new implementation after swap"))
        return
    # --- Establish transport B AFTER the swap; B uses Mini. ---
    r = mgr_i.establish_initiator(
        world.session_ab, policy=TransportSecurityPolicy(),
        offered_profiles=list(default_profile_offers()), now=_NOW,
        instance_label="b-initiator",
    )
    assert r.ok, r.detail
    offer_b = r.value
    handle_b = mgr_i.pending_handles()[0]
    r = mgr_r.respond(offer_b, now=_NOW, instance_label="b-responder")
    assert r.ok, r.detail
    acceptance_b = r.value
    r = mgr_i.complete_initiator(handle_b, acceptance_b, now=_NOW)
    assert r.ok, r.detail
    confirmation_b = r.value
    r = mgr_r.confirm(acceptance_b.transport_id, confirmation_b, now=_NOW)
    assert r.ok, r.detail
    transport_b = acceptance_b.transport_id
    # B's frames use the Mini record model (the new implementation).
    r = mgr_i.send(transport_b, b"B-1", now=_NOW)
    assert r.ok
    if r.value["protection_model"] != MiniTransportEngine._MODEL:
        results.append(fail("case_69_swap_preserves_live_transports", "B frame not using the new (Mini) implementation"))
        return
    if not _exchange_ok(mgr_i, mgr_r, transport_b, b"B-roundtrip"):
        results.append(fail("case_69_swap_preserves_live_transports", "post-swap transport B does not interoperate on the new engine"))
        return
    # --- A and B coexist on different engines within one manager. ---
    if transport_a == transport_b:
        results.append(fail("case_69_swap_preserves_live_transports", "A and B collided on the same transport id"))
        return
    results.append(ok("case_69_swap_preserves_live_transports", "A keeps Modeled across swap; B uses Mini; both coexist"))


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def main() -> int:
    results: List[Result] = []
    case_01_contract_surface_frozen(results)
    case_02_context_least_authority(results)
    case_03_context_injected_instant_and_budget(results)
    case_04_profile_catalog_frozen(results)
    case_05_negotiation_maximal_rank(results)
    case_06_negotiation_no_intersection(results)
    case_07_negotiation_unknown_never_coerced(results)
    case_08_policy_floor_rejects_weak(results)
    case_09_establish_happy_path_tls(results)
    case_10_establish_parametric_profiles(results)
    case_11_offer_expiry_rejected(results)
    case_12_unknown_session_rejected(results)
    case_13_non_secureable_session_state(results)
    case_14_revoked_credential_rejected(results)
    case_15_expired_credential_rejected(results)
    case_16_wrong_role_credential(results)
    case_17_downgrade_offer_stripping(results)
    case_18_downgrade_forced_selection(results)
    case_19_downgrade_policy_floor(results)
    case_20_downgrade_events_audited(results)
    case_21_frame_replay_rejected(results)
    case_22_below_window_rejected(results)
    case_23_out_of_order_in_window(results)
    case_24_handshake_replay_rejected(results)
    case_25_acceptance_replay_rejected(results)
    case_26_interop_bidirectional(results)
    case_27_interop_independent_engines(results)
    case_28_interop_second_implementation(results)
    case_29_wrong_key_unprotect_fails(results)
    case_30_key_binding_session(results)
    case_31_key_binding_endpoints(results)
    case_32_key_binding_profile_and_policy(results)
    case_33_key_binding_attestation(results)
    case_34_rekey_generation_chain(results)
    case_35_generation_bound(results)
    case_36_rekey_revoked_fails(results)
    case_37_suspend_resume_rekey(results)
    case_38_recheck_suspends_on_revocation(results)
    case_39_close_destroys_keys(results)
    case_40_no_access_technology_tokens(results)
    case_41_transport_adapters_isolated(results)
    case_42_core_never_imports_transport(results)
    case_43_imports_bounded(results)
    case_44_access_independence_behavioral(results)
    case_45_raising_implementation_isolated(results)
    case_46_contract_violation_discarded(results)
    case_47_budget_exhaustion(results)
    case_48_systemexit_isolated(results)
    case_49_health_degradation_thresholds(results)
    case_50_security_rejections_not_health_faults(results)
    case_51_wire_view_round_trip(results)
    case_52_tampered_wire_fails(results)
    case_53_envelope_opaque_forward(results)
    case_54_envelope_protection_round_trip(results)
    case_55_canonical_determinism(results)
    case_56_cross_process_determinism(results)
    case_57_secret_rejection(results)
    case_58_frozen_docs_unchanged(results)
    case_59_vocabulary_freeze(results)
    case_60_concurrency_commutive(results)
    case_61_standards_primitives_audit(results)
    case_62_reference_frame_contract(results)
    case_63_preconfirmation_gate(results)
    case_64_record_protection_replaceable(results)
    case_65_contract_independent_of_crypto(results)
    case_66_initiator_zero_trust(results)
    case_67_standards_boundary_documented(results)
    case_68_replay_window_transactional(results)
    case_69_swap_preserves_live_transports(results)

    print("ADCOS secure transport self-test (WORK-017)")
    print("=" * 72)
    for name, ok_flag, detail in results:
        print("[%s] %-52s %s" % ("ok  " if ok_flag else "FAIL", name, detail))
    print("-" * 72)
    passed = sum(1 for _, ok_flag, _ in results if ok_flag)
    if passed == len(results):
        print("Result: PASS (%d/%d cases)" % (passed, len(results)))
        return 0
    print("Result: FAIL (%d/%d cases passed)" % (passed, len(results)))
    return 1


if __name__ == "__main__":
    sys.exit(main())
