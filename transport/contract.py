"""ADCOS transport contract (WORK-017): the stable core-side seam.

The replaceable transport interface.  Transport IMPLEMENTATIONS
(:class:`TransportContract`) depend on the least-authority
:class:`TransportContext` facade — and on nothing else in the core.
The manager (transport.manager) mediates every call through the
sandbox (transport.sandbox): exception isolation, contract-shape
validation of every return value, deterministic step budget.  The core
never imports transport implementations, never branches on profile
identifiers, and never lets transport state become authoritative for
ADCOS core state (LOCK-016/LOCK-017 in the transport direction;
architecture section 25 rule 9 — no fixed transport).

Handshake flow (modeled on the SHAPE of the TLS 1.3 handshake —
offer/acceptance/confirmation with transcript-bound key derivation
and key confirmation — deterministic and offline):

1. The initiator's manager builds a :class:`TransportOffer` (full
   offered profile set + policy floor + content-derived nonce) and
   calls ``handshake_initiator`` on its engine under a local PENDING
   handle.
2. The responder's manager validates the offer (session secureable,
   endpoints, replay ledger) and calls ``handshake_responder``; the
   engine negotiates the maximal policy-satisfying mutually-known
   profile, mints the FINAL transport id, derives the master secret
   over the transcript basis, and returns the acceptance (offer-digest
   echo + selection + responder key confirmation + identity
   attestation).
3. The initiator's manager calls ``complete_initiator``; the engine
   verifies the offer-digest echo (in-flight offer tampering /
   downgrade detection 1), the selection eligibility (downgrade
   detection 2), re-derives and verifies the final transport id,
   derives the master secret, verifies the responder key confirmation
   (cryptographic downgrade/tamper detection 3), and returns the
   initiator confirmation.
4. The responder's manager calls ``accept_confirmation``; the engine
   verifies the initiator key confirmation (mutual key confirmation).

Also provides :class:`ModeledTransportEngine`, the deterministic
REFERENCE MODEL of the ADCOS transport contract.  It models the
contract's security semantics (negotiation, transcript-bound key
derivation over HKDF-SHA256 RFC 5869, key confirmation over
HMAC-SHA256 RFC 2104, replay windows, generation lifecycle) with a
composable record-protection object
(:class:`transport.recordprotection.RecordProtection` — the default
being the integrity-only, NON-confidential reference record model).
It is NOT a TLS 1.3, QUIC, IPsec, or WireGuard implementation: it
speaks none of those protocols, its frames are not wire-compatible
with any of them, and it makes no confidentiality claim.  Concrete
production transports (a real TLS 1.3 or QUIC library, an
IPsec/WireGuard daemon, each with its own standard record
protection) plug in behind the same ABC without modifying the
manager or any core semantics.
"""

from __future__ import annotations

import abc
import hashlib
from typing import Any, Dict, Mapping, Optional, Tuple

from .errors import TransportError, TransportReasonCode
from .keyschedule import (
    confirmation_tag,
    direction_keys,
    master_secret,
    public_generation_digest,
    rekey_secret,
)
from .model import (
    ReplayWindow,
    TransportAcceptance,
    TransportConfirmation,
    TransportHealth,
    TransportOffer,
    derive_transport_id,
    transcript_digest,
    transcript_digest_from_basis,
)
from .profiles import (
    TransportProfileSet,
    TransportSecurityPolicy,
    negotiate_transport_profiles,
)
from .recordprotection import (
    RecordProtection,
    ReferenceRecordProtection,
)
from .validation import (
    validate_frame_view,
    validate_nonempty_str,
)

#: Maximum key generations before mandatory re-establishment (key
#: rotation bound; the chained schedule never reuses a generation).
MAX_KEY_GENERATIONS = 8


# --------------------------------------------------------------------------
# Least-authority context facade
# --------------------------------------------------------------------------


class _BudgetExhausted(Exception):
    """Internal sentinel: the operation step budget is exhausted.

    Never crosses the sandbox boundary; the sandbox converts it into a
    BUDGET_EXHAUSTED failure value.  This is the deterministic model of
    a hung/overrunning transport operation — no wall-clock timeouts
    exist anywhere in the transport layer.
    """


class TransportContext:
    """The ONLY object the core hands to a transport implementation.

    Least authority (architecture P6): the context exposes the
    transport's own id, the session it serves, the injected operation
    instant, and a deterministic step budget.  It deliberately holds
    NO references to session stores, identity material, policy
    engines, topology, or the manager itself — a transport
    implementation cannot reach core state through the context
    (mechanically verified by the transport selftest).
    """

    __slots__ = ("_transport_id", "_session_id", "_instant", "_steps_left")

    _transport_id: str
    _session_id: str
    _instant: str
    _steps_left: int

    def __init__(
        self,
        transport_id: str,
        session_id: str,
        instant: str,
        step_budget: int,
    ) -> None:
        object.__setattr__(self, "_transport_id", transport_id)
        object.__setattr__(self, "_session_id", session_id)
        object.__setattr__(self, "_instant", instant)
        object.__setattr__(self, "_steps_left", step_budget)

    @property
    def transport_id(self) -> str:
        return self._transport_id

    @property
    def session_id(self) -> str:
        return self._session_id

    def now(self) -> str:
        """The injected instant of the current operation (never wall clock)."""
        return self._instant

    def charge(self, steps: int = 1) -> None:
        """Charge deterministic transport work against the step budget."""
        if isinstance(steps, bool) or not isinstance(steps, int):
            raise _BudgetExhausted()
        if steps < 0:
            raise _BudgetExhausted()
        object.__setattr__(self, "_steps_left", self._steps_left - steps)
        if self._steps_left < 0:
            raise _BudgetExhausted()

    def steps_left(self) -> int:
        """Remaining budget (introspection for tests/implementations)."""
        return self._steps_left

    def __setattr__(self, name: str, value: Any) -> None:
        raise TypeError(
            "TransportContext is immutable: transport implementations cannot "
            "inject state into the core facade"
        )


#: The attribute surface a transport implementation may use (the
#: sandbox and the selftest verify implementations receive nothing
#: beyond this).
CONTEXT_SURFACE = frozenset(
    {"transport_id", "session_id", "now", "charge", "steps_left"}
)


# --------------------------------------------------------------------------
# The stable transport contract
# --------------------------------------------------------------------------


class TransportContract(abc.ABC):
    """The stable interface every secure-transport implementation
    satisfies.

    Implementations are untrusted: the sandbox mediates every call,
    validates every return value against the contract shape, converts
    any exception (including ``BaseException``) into an isolated
    failure value, and enforces the deterministic step budget.  A
    contract method must never be called directly by core code — only
    through :class:`transport.sandbox.SandboxedTransport`.
    """

    __slots__ = ()

    #: Optional human label.  Informational only — never parsed, never
    #: branched on (no core state machine branches on profile names).
    label: str = ""

    @abc.abstractmethod
    def supported_profiles(self) -> Tuple[str, ...]:
        """Profile identifiers this implementation serves (data)."""

    @abc.abstractmethod
    def initialize(self, context: TransportContext) -> None:
        """Bring up per-transport engine state.  Return None on success."""

    @abc.abstractmethod
    def handshake_initiator(self, context: TransportContext, offer: TransportOffer) -> None:
        """Begin the initiator side of the modeled handshake (under the
        pending handle).  Return None on success."""

    @abc.abstractmethod
    def handshake_responder(
        self,
        context: TransportContext,
        offer: TransportOffer,
        *,
        responder_attestation: str,
        issued_at: str,
    ) -> TransportAcceptance:
        """Run the responder side: negotiate per the offer's policy floor,
        mint the final transport id, derive the shared secret over the
        transcript basis, and produce the acceptance record (moving the
        engine state from the pending handle to the final id)."""

    @abc.abstractmethod
    def complete_initiator(
        self,
        context: TransportContext,
        offer: TransportOffer,
        acceptance: TransportAcceptance,
        *,
        initiator_attestation: str,
        issued_at: str,
    ) -> TransportConfirmation:
        """Finish the initiator side: verify the acceptance echo, the
        selection eligibility, the final id derivation, and the
        responder key confirmation; derive the shared secret and produce
        the initiator confirmation (moving the engine state from the
        pending handle to the final id)."""

    @abc.abstractmethod
    def accept_confirmation(
        self,
        context: TransportContext,
        offer: TransportOffer,
        acceptance: TransportAcceptance,
        confirmation: TransportConfirmation,
    ) -> None:
        """Responder-side completion: verify the initiator's key
        confirmation.  Return None on success."""

    @abc.abstractmethod
    def protect(self, context: TransportContext, payload: bytes) -> Dict[str, object]:
        """Protect one frame payload; return the frame view mapping
        (transport_id, generation, sequence, plus the implementation's
        record-protection members — at minimum protection_model,
        wire_payload, integrity_tag)."""

    @abc.abstractmethod
    def unprotect(self, context: TransportContext, frame: Mapping[str, object]) -> bytes:
        """Verify one frame (protection model, integrity, generation,
        replay window) and return the payload bytes."""

    @abc.abstractmethod
    def rekey(self, context: TransportContext, cause: str) -> Dict[str, object]:
        """Advance the key generation (chained rotation); return the new
        generation info mapping (generation, lineage digest)."""

    @abc.abstractmethod
    def health(self) -> str:
        """Implementation-local health: HEALTHY, DEGRADED, or FAILED.

        Reported, never authoritative by itself (LOCK-017): the manager
        computes the effective health from mediated outcomes.
        """

    @abc.abstractmethod
    def close(self, context: TransportContext) -> None:
        """Bring the per-transport engine state down and destroy working
        key material.  Return None on success."""


#: The frozen contract operations, in interface order.
TRANSPORT_OPERATIONS: Tuple[str, ...] = (
    "supported_profiles",
    "initialize",
    "handshake_initiator",
    "handshake_responder",
    "complete_initiator",
    "accept_confirmation",
    "protect",
    "unprotect",
    "rekey",
    "health",
    "close",
)


# --------------------------------------------------------------------------
# The modeled built-in engine (TLS 1.3 / QUIC / tunnel / generic)
# --------------------------------------------------------------------------


class _EngineState:
    """Per-transport working state of the modeled engine.

    Working key material (master secret, directional keys) lives ONLY
    here — never in offers, acceptances, confirmations, events,
    public security state, or wire views (LOCK-023).  ``initialize``
    creates the entry; ``close`` erases it.
    """

    __slots__ = (
        "role",
        "offer",
        "master",
        "send_key",
        "recv_key",
        "generation",
        "send_sequence",
        "recv_window",
        "lineage",
    )

    def __init__(self) -> None:
        self.role: Optional[str] = None
        self.offer: Optional[TransportOffer] = None
        self.master: Optional[bytes] = None
        self.send_key: Optional[bytes] = None
        self.recv_key: Optional[bytes] = None
        self.generation = 0
        self.send_sequence = 0
        self.recv_window = ReplayWindow()
        self.lineage: list = []

    def destroy_keys(self) -> None:
        self.master = None
        self.send_key = None
        self.recv_key = None


class ModeledTransportEngine(TransportContract):
    """Deterministic reference model of the ADCOS transport contract.

    Serves every profile in its profile set (the reference key
    schedule is profile-bound through the transcript — selecting a
    different profile yields different keys).  This is a REFERENCE
    MODEL, not a protocol implementation: it proves the contract's
    security semantics (negotiation, binding, replay windows,
    downgrade detection, key lifecycle, isolation) for any profile;
    it does not implement TLS 1.3, QUIC, IPsec, or WireGuard
    cryptography and its frames are not wire-compatible with any
    external protocol.

    Record protection is DELEGATED to a composable
    :class:`RecordProtection` object (the default is the
    integrity-only, NON-confidential reference record model —
    HMAC-SHA256 RFC 2104 in its standard MAC role over the visible
    payload).  Production engines compose their profile's STANDARD
    record protection instead; nothing outside the engine changes.

    The construction is deterministic: the handshake "ephemeral"
    contributions are the content-derived offer/responder nonces, all
    instants are injected, and there is no randomness, wall clock, or
    network anywhere.
    """

    __slots__ = ("_states", "_profile_set", "_record_protection")

    #: Deterministic step charges per operation (budget model).
    STEP_CHARGES: Dict[str, int] = {
        "initialize": 2,
        "handshake_initiator": 6,
        "handshake_responder": 8,
        "complete_initiator": 8,
        "accept_confirmation": 4,
        "protect": 3,
        "unprotect": 3,
        "rekey": 4,
        "close": 2,
    }

    def __init__(
        self,
        profile_set: Optional[TransportProfileSet] = None,
        record_protection: Optional[RecordProtection] = None,
    ) -> None:
        self._states: Dict[str, _EngineState] = {}
        self._profile_set = profile_set or TransportProfileSet.load_default()
        self._record_protection: RecordProtection = (
            record_protection if record_protection is not None else ReferenceRecordProtection()
        )

    # -- helpers ---------------------------------------------------------

    def _charge(self, context: TransportContext, operation: str) -> None:
        context.charge(self.STEP_CHARGES.get(operation, 1))

    def _state(self, transport_id: str) -> _EngineState:
        state = self._states.get(transport_id)
        if state is None:
            raise TransportError(
                TransportReasonCode.UNKNOWN_TRANSPORT,
                "engine has no state for transport %s (initialize first)" % transport_id,
            )
        return state

    def _require_keys(self, transport_id: str) -> _EngineState:
        state = self._state(transport_id)
        if state.master is None or state.send_key is None or state.recv_key is None:
            raise TransportError(
                TransportReasonCode.NOT_ESTABLISHED,
                "transport %s has no working keys (handshake incomplete or closed)"
                % transport_id,
            )
        return state

    # -- contract --------------------------------------------------------

    def supported_profiles(self) -> Tuple[str, ...]:
        return tuple(sorted(self._profile_set.profile_ids()))

    def initialize(self, context: TransportContext) -> None:
        self._charge(context, "initialize")
        self._states[context.transport_id] = _EngineState()

    def handshake_initiator(self, context: TransportContext, offer: TransportOffer) -> None:
        self._charge(context, "handshake_initiator")
        state = self._state(context.transport_id)
        if state.role is not None:
            raise TransportError(
                TransportReasonCode.STATE_CONFLICT,
                "transport %s already started a handshake" % context.transport_id,
            )
        state.role = "initiator"
        state.offer = offer

    def handshake_responder(
        self,
        context: TransportContext,
        offer: TransportOffer,
        *,
        responder_attestation: str,
        issued_at: str,
    ) -> TransportAcceptance:
        self._charge(context, "handshake_responder")
        state = self._state(context.transport_id)
        if state.role is not None:
            raise TransportError(
                TransportReasonCode.STATE_CONFLICT,
                "transport %s already started a handshake" % context.transport_id,
            )
        outcome = negotiate_transport_profiles(
            offer.offered_profiles,
            self.supported_profiles(),
            offer.policy,
            profile_set=self._profile_set,
        )
        if not outcome.ok:
            raise TransportError(
                TransportReasonCode.NEGOTIATION_FAILED,
                "no mutually supported profile satisfies the policy floor "
                "(offered=%r)" % (sorted(set(offer.offered_profiles)),),
            )
        selected = outcome.selected
        assert selected is not None  # negotiation-outcome invariant
        transport_id = derive_transport_id(
            selected.family,
            session_id=offer.session_id,
            initiator_node_id=offer.initiator_node_id,
            responder_node_id=offer.responder_node_id,
            profile_id=selected.profile_id,
            policy_id=offer.policy.policy_id,
            offer_nonce=offer.offer_nonce,
        )
        responder_nonce = _responder_nonce(offer.offer_nonce, transport_id)
        # Master secret over the transcript BASIS (no key confirmation —
        # the TLS-1.3 Finished pattern; see model.transcript_digest).
        basis_digest = transcript_digest_from_basis(
            offer,
            transport_id=transport_id,
            offer_digest=offer.digest(),
            selected_profile=selected.profile_id,
            responder_nonce=responder_nonce,
            responder_attestation=responder_attestation,
            issued_at=issued_at,
        )
        master = master_secret(
            basis_digest,
            bytes.fromhex(offer.offer_nonce) + bytes.fromhex(responder_nonce),
        )
        acceptance = TransportAcceptance(
            transport_id=transport_id,
            offer_digest=offer.digest(),
            selected_profile=selected.profile_id,
            responder_nonce=responder_nonce,
            responder_confirmation=confirmation_tag(master, "responder"),
            responder_attestation=responder_attestation,
            key_lineage=public_generation_digest(master),
            issued_at=issued_at,
        )
        # Adopt the FINAL transport id: move the engine state from the
        # pending handle to the negotiated id.
        del self._states[context.transport_id]
        state.role = "responder"
        state.offer = offer
        state.master = master
        state.send_key, state.recv_key = direction_keys(master, "responder")
        state.generation = 0
        state.lineage = [public_generation_digest(master)]
        self._states[transport_id] = state
        return acceptance

    def complete_initiator(
        self,
        context: TransportContext,
        offer: TransportOffer,
        acceptance: TransportAcceptance,
        *,
        initiator_attestation: str,
        issued_at: str,
    ) -> TransportConfirmation:
        self._charge(context, "complete_initiator")
        state = self._state(context.transport_id)
        if state.role != "initiator" or state.offer is None:
            raise TransportError(
                TransportReasonCode.STATE_CONFLICT,
                "transport %s has no pending initiator handshake" % context.transport_id,
            )
        # Downgrade detection 1: the echoed offer digest must match OUR offer.
        if acceptance.offer_digest != state.offer.digest():
            raise TransportError(
                TransportReasonCode.DOWNGRADE_REJECTED,
                "acceptance echoes a different offer (digest mismatch) — "
                "in-flight offer tampering or replay",
            )
        # Downgrade detection 2: the selected profile must be one WE
        # offered, known, and satisfying OUR policy floor (a forced
        # weaker selection fails here even before the cryptographic
        # confirmation check).
        selected = self._profile_set.get(acceptance.selected_profile)
        if acceptance.selected_profile not in state.offer.offered_profiles or not selected.satisfies(state.offer.policy):
            raise TransportError(
                TransportReasonCode.DOWNGRADE_REJECTED,
                "selected profile %r was not offered or violates the policy "
                "floor — forced downgrade" % acceptance.selected_profile,
            )
        # The final transport id must be exactly the derivation over OUR
        # establishment inputs (tamper evidence on the id itself).
        expected_id = derive_transport_id(
            selected.family,
            session_id=state.offer.session_id,
            initiator_node_id=state.offer.initiator_node_id,
            responder_node_id=state.offer.responder_node_id,
            profile_id=selected.profile_id,
            policy_id=state.offer.policy.policy_id,
            offer_nonce=state.offer.offer_nonce,
        )
        if acceptance.transport_id != expected_id:
            raise TransportError(
                TransportReasonCode.INTEGRITY_REJECTED,
                "acceptance transport id does not match the derivation over "
                "the offered establishment inputs",
            )
        master = master_secret(
            transcript_digest(state.offer, acceptance),
            bytes.fromhex(state.offer.offer_nonce) + bytes.fromhex(acceptance.responder_nonce),
        )
        # Downgrade detection 3 (cryptographic): the responder key
        # confirmation proves the acceptance record was produced by a
        # party holding the transcript-derived secret; ANY tampering
        # with the records (offer, selection, nonces, attestation)
        # breaks it.
        if acceptance.responder_confirmation != confirmation_tag(master, "responder"):
            raise TransportError(
                TransportReasonCode.INTEGRITY_REJECTED,
                "responder key confirmation mismatch — tampered or forged "
                "acceptance record",
            )
        confirmation = TransportConfirmation(
            transport_id=acceptance.transport_id,
            offer_digest=state.offer.digest(),
            initiator_confirmation=confirmation_tag(master, "initiator"),
            initiator_attestation=initiator_attestation,
            issued_at=issued_at,
        )
        # Adopt the FINAL transport id (pending handle -> final id).
        del self._states[context.transport_id]
        state.master = master
        state.send_key, state.recv_key = direction_keys(master, "initiator")
        state.generation = 0
        state.lineage = [public_generation_digest(master)]
        self._states[acceptance.transport_id] = state
        return confirmation

    def accept_confirmation(
        self,
        context: TransportContext,
        offer: TransportOffer,
        acceptance: TransportAcceptance,
        confirmation: TransportConfirmation,
    ) -> None:
        self._charge(context, "accept_confirmation")
        state = self._state(context.transport_id)
        if state.role != "responder" or state.master is None:
            raise TransportError(
                TransportReasonCode.STATE_CONFLICT,
                "transport %s has no completed responder handshake" % context.transport_id,
            )
        if confirmation.offer_digest != offer.digest() or confirmation.transport_id != acceptance.transport_id:
            raise TransportError(
                TransportReasonCode.INTEGRITY_REJECTED,
                "confirmation does not match the accepted offer",
            )
        if confirmation.initiator_confirmation != confirmation_tag(state.master, "initiator"):
            raise TransportError(
                TransportReasonCode.INTEGRITY_REJECTED,
                "initiator key confirmation mismatch — wrong secret or "
                "tampered record",
            )

    def protect(self, context: TransportContext, payload: bytes) -> Dict[str, object]:
        self._charge(context, "protect")
        state = self._require_keys(context.transport_id)
        if not isinstance(payload, (bytes, bytearray)) or not payload:
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "frame payload must be non-empty bytes",
            )
        state.send_sequence += 1
        assert state.send_key is not None
        members = self._record_protection.protect_record(
            state.send_key, state.generation, state.send_sequence, bytes(payload)
        )
        frame: Dict[str, object] = {
            "transport_id": context.transport_id,
            "generation": state.generation,
            "sequence": state.send_sequence,
        }
        frame.update(members)
        return frame

    def unprotect(self, context: TransportContext, frame: Mapping[str, object]) -> bytes:
        self._charge(context, "unprotect")
        state = self._require_keys(context.transport_id)
        view = validate_frame_view(frame)
        if view["transport_id"] != context.transport_id:
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "frame is addressed to a different transport",
            )
        if view["generation"] != state.generation:
            raise TransportError(
                TransportReasonCode.INTEGRITY_REJECTED,
                "frame generation %d does not match current generation %d "
                "(stale or replayed across rekey)" % (view["generation"], state.generation),
            )
        sequence = view["sequence"]
        # Transactional replay admission (LOCK — replay-window
        # poisoning, the WORK-017 acceptance criterion): pre-check
        # admission WITHOUT mutating the window, authenticate the
        # record, and commit the sequence ONLY on success.  A forged
        # frame with a huge sequence number and an invalid tag can no
        # longer advance ``highest`` and starve legitimate
        # lower-sequence frames — unauthenticated network input cannot
        # mutate security state.  (Mirrors the TLS 1.3 record /
        # QUIC packet / IPsec ESP anti-replay discipline: the window
        # bit/sequence is set only after the record is authenticated.)
        if not state.recv_window.would_accept(sequence):
            raise TransportError(
                TransportReasonCode.REPLAY_REJECTED,
                "frame sequence %d is a replay or outside the anti-replay window" % sequence,
            )
        assert state.recv_key is not None
        # Delegation to the record-protection seam: the engine owns
        # generation/replay/sequence policy; the record model owns tag
        # verification and payload extraction (fail closed).  This raises
        # on any model/tag mismatch — and because the window has NOT
        # been mutated yet, a failed verification leaves the window
        # exactly as it was.
        payload = self._record_protection.unprotect_record(
            state.recv_key, state.generation, sequence, view
        )
        # Authentication succeeded: commit the sequence now.
        state.recv_window.accept(sequence)
        return payload

    def rekey(self, context: TransportContext, cause: str) -> Dict[str, object]:
        self._charge(context, "rekey")
        validate_nonempty_str(cause, "rekey cause")
        state = self._require_keys(context.transport_id)
        if state.generation + 1 >= MAX_KEY_GENERATIONS:
            raise TransportError(
                TransportReasonCode.GENERATION_EXHAUSTED,
                "transport %s reached the maximum key generation bound %d; "
                "re-establishment is required" % (context.transport_id, MAX_KEY_GENERATIONS),
            )
        assert state.master is not None
        state.master = rekey_secret(state.master, cause, state.generation + 1)
        state.generation += 1
        role = state.role or "initiator"
        state.send_key, state.recv_key = direction_keys(state.master, role)
        state.lineage.append(public_generation_digest(state.master))
        return {
            "generation": state.generation,
            "lineage_digest": state.lineage[-1],
        }

    def health(self) -> str:
        return TransportHealth.HEALTHY

    def close(self, context: TransportContext) -> None:
        self._charge(context, "close")
        state = self._states.pop(context.transport_id, None)
        if state is not None:
            state.destroy_keys()


def _responder_nonce(offer_nonce: str, transport_id: str) -> str:
    """Deterministic responder freshness contribution (content-derived
    from the offer nonce and the final transport id — the modeled
    ephemeral responder share)."""
    return hashlib.sha256(
        ("adcos-transport/responder-nonce:" + offer_nonce + ":" + transport_id).encode("utf-8")
    ).hexdigest()[:16]
