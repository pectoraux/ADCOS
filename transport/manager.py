"""ADCOS transport manager (WORK-017): the Agent's secure-transport
service.

Owns the establishment pipeline, frame exchange, key rotation, and
lifecycle of secure transport instances mapped onto WORK-012 logical
sessions.  Every engine call is mediated by the sandbox
(transport.sandbox); every public structure is secret-free; every
security rejection is recorded as audit evidence (architecture section
19).

Authority boundary (frozen):

- The manager is authoritative ONLY for the secure-channel state of
  the transports it manages — never for sessions (WORK-012 owns the
  logical session, accessed here READ-ONLY through the
  :class:`SessionReader` facade), never for identity (WORK-004 owns
  credentials, accessed through the :class:`IdentityAuthority`
  facade), never for policy, topology, or any access technology.
- Transport instances bind to sessions whose binding endpoints match
  the offer; the keys are bound to (session, both NodeIDs, negotiated
  profile, policy floor) through the transcript, and to identity
  through attestations signed with WORK-004 operational credentials.
- Establishments fail closed on unknown/suspended sessions, unusable
  credentials, expired offers, replayed offers/frames, tampered
  records, and downgrades.
"""

from __future__ import annotations

import abc
import json
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Dict, List, Mapping, Optional, Tuple

from protocol.canonicalization import CanonicalizationError, canonical_json_bytes
from protocol.envelope import Envelope, envelope_from_mapping
from protocol.temporal import TemporalError, check_temporal, parse_instant
from sessions.store import SessionStore

from .contract import ModeledTransportEngine, TransportContract
from .errors import TransportError, TransportReasonCode
from .model import (
    TransportAcceptance,
    TransportConfirmation,
    TransportEvent,
    TransportEventType,
    TransportLifecycle,
    TransportOffer,
    TransportSecurityState,
    derive_event_id,
    derive_offer_nonce,
    derive_pending_handle,
    lifecycle_transition_is_legal,
)
from .profiles import (
    TransportProfileSet,
    TransportSecurityPolicy,
)
from .sandbox import OperationOutcome, SandboxedTransport
from .validation import (
    reject_secrets,
    validate_instant,
    validate_nonempty_str,
    validate_policy,
    validate_profile_offers,
    validate_transport_id,
)

#: Session states under which a secure transport may be established,
#: rekeyed, or resumed (read-only WORK-012 vocabulary; mirrors the
#: WORK-016 bindable-states convention — RECONNECTING is included so a
#: mobility handover can rekey without tearing the logical session).
SECURABLE_SESSION_STATES = frozenset({"ESTABLISHED", "DEGRADED", "RECONNECTING"})

#: Default offer lifetime (seconds) when the caller does not inject an
#: explicit expiry instant.
DEFAULT_OFFER_LIFETIME_SECONDS = 300

#: Default per-instance label namespace separator role.
INITIATOR_LABEL = "initiator"
RESPONDER_LABEL = "responder"


def instant_plus(instant: str, seconds: int) -> str:
    """Deterministically add ``seconds`` to an RFC 3339 UTC instant."""
    base = parse_instant(instant)
    result = base + timedelta(seconds=seconds)
    return result.isoformat().replace("+00:00", "Z")


# --------------------------------------------------------------------------
# Read-only facades over accepted modules (least authority)
# --------------------------------------------------------------------------


class SessionReader(abc.ABC):
    """Read-only session lookup (the WORK-012 SessionStore surface the
    transport layer may see — ``get`` and nothing else)."""

    __slots__ = ()

    @abc.abstractmethod
    def get(self, session_id: str) -> Optional[Any]:
        """Return the session object or None (never mutates)."""


class Work012SessionReader(SessionReader):
    """Adapter over the real WORK-012 :class:`SessionStore`.

    The concrete store is validated by type: the WORK-012 SessionStore
    is the single session authority (no duplicate session authority is
    permitted), so read-only access is bound to the real type rather
    than an arbitrary duck-typed replacement.
    """

    __slots__ = ("_store",)

    def __init__(self, store: "SessionStore") -> None:
        if not isinstance(store, SessionStore):
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "session store must be a WORK-012 SessionStore (read-only use)",
            )
        self._store = store

    def get(self, session_id: str) -> Optional[Any]:
        return self._store.get(session_id)


class IdentityAuthority(abc.ABC):
    """The identity surface the transport layer may see.

    Fail-closed credential usability, transcript attestation signing,
    and attestation verification — all resolving secret material
    exclusively inside the WORK-004 credential store (LOCK-023).  A
    test double implements this same interface (the import-lock rule
    that test doubles satisfy the real interfaces).
    """

    __slots__ = ()

    @abc.abstractmethod
    def active_credential(self, node_id_text: str, role: str, now: str) -> Any:
        """The single ACTIVE, unexpired credential for (node, role).

        Raises TransportError(IDENTITY_UNUSABLE / CREDENTIAL_REVOKED /
        CREDENTIAL_EXPIRED) fail-closed."""

    @abc.abstractmethod
    def sign(self, node_id_text: str, data: bytes, now: str) -> str:
        """Sign ``data`` with the node's active operational credential
        (hex).  The secret never leaves the store."""

    @abc.abstractmethod
    def verify(self, node_id_text: str, data: bytes, signature_hex: str, now: str) -> bool:
        """Verify a signature against the node's active credential
        (fail closed when the credential is unusable — zero trust)."""


class Work004IdentityAuthority(IdentityAuthority):
    """Adapter over the real WORK-004 stack (IdentityService + provider +
    CredentialStore)."""

    __slots__ = ("_service", "_provider", "_store")

    def __init__(self, service: Any, provider: Any, store: Any) -> None:
        self._service = service
        self._provider = provider
        self._store = store

    def _require(self, node_id_text: str, role: str, now: str) -> Any:
        from identity.node_id import NodeIdError, parse_node_id

        try:
            node = parse_node_id(node_id_text)
        except NodeIdError as error:
            raise TransportError(
                TransportReasonCode.IDENTITY_UNUSABLE,
                "node id %r is not canonical: %s" % (node_id_text, error),
            ) from error
        try:
            return self._service.active_credential(node, role, now=now)
        except Exception as error:  # identity-layer fail-closed surface
            code = getattr(error, "code", "")
            records = []
            try:
                records = [
                    record
                    for record in self._service.records_for(node)
                    if record.role == role
                ]
            except Exception:  # pragma: no cover - defensive
                records = []
            if code == "expired":
                raise TransportError(
                    TransportReasonCode.CREDENTIAL_EXPIRED,
                    "credential for %s expired (identity layer: %s)"
                    % (node_id_text, code),
                ) from error
            statuses = [
                getattr(record, "status", None) and record.status.value
                for record in records
            ]
            if "revoked" in statuses:
                raise TransportError(
                    TransportReasonCode.CREDENTIAL_REVOKED,
                    "credential for %s is revoked; no active credential remains"
                    % node_id_text,
                ) from error
            if "expired" in statuses:
                raise TransportError(
                    TransportReasonCode.CREDENTIAL_EXPIRED,
                    "credential for %s is expired; no active credential remains"
                    % node_id_text,
                ) from error
            raise TransportError(
                TransportReasonCode.IDENTITY_UNUSABLE,
                "no usable %s credential for %s" % (role, node_id_text),
            ) from error

    def active_credential(self, node_id_text: str, role: str, now: str) -> Any:
        return self._require(node_id_text, role, now)

    def sign(self, node_id_text: str, data: bytes, now: str) -> str:
        record = self._require(node_id_text, "operational", now)
        signature = self._provider.sign(self._store, record.reference, data)
        return bytes(signature).hex()

    def verify(self, node_id_text: str, data: bytes, signature_hex: str, now: str) -> bool:
        try:
            record = self._require(node_id_text, "operational", now)
            signature = bytes.fromhex(signature_hex)
        except (TransportError, ValueError):
            return False
        try:
            return bool(
                self._provider.verify_with_credential(
                    self._store, record.reference, data, signature
                )
            )
        except Exception:
            return False


# --------------------------------------------------------------------------
# Result envelope
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class TransportOpResult:
    """Uniform result envelope for manager operations.

    ``ok`` True -> ``value`` carries the operation's public value
    (offer / acceptance / confirmation / frame / payload / generation
    info / session-authorized view).  ``ok`` False -> ``reason`` is a
    frozen :class:`TransportReasonCode` value with deterministic
    ``detail`` text.  Failures never mutate manager state.
    """

    ok: bool
    value: Any = None
    reason: str = ""
    detail: str = ""


# --------------------------------------------------------------------------
# Internal records
# --------------------------------------------------------------------------


class _PendingEntry:
    """An in-flight establishment (before the final transport id exists).

    Retains the owning sandbox captured at establishment time so a
    runtime implementation swap cannot split a pending handshake
    across two implementations (Blocker 2 — per-transport sandbox
    ownership)."""

    __slots__ = ("handle", "session_id", "offer", "events", "sandbox")

    def __init__(
        self, handle: str, session_id: str, offer: TransportOffer, sandbox: SandboxedTransport
    ) -> None:
        self.handle = handle
        self.session_id = session_id
        self.offer = offer
        self.events: List[TransportEvent] = []
        self.sandbox = sandbox


class _TransportRecord:
    """The manager's per-transport state.

    The public, structurally secret-free view is exposed by
    :meth:`security_state` and :meth:`TransportManager.snapshot`
    (neither serializes ``sandbox``); ``sandbox`` is internal
    routing metadata — the owning implementation captured at
    establishment time — so a runtime implementation swap routes
    NEW establishments to the new implementation while an
    already-established transport keeps the engine it was
    established with (Blocker 2 — per-transport sandbox ownership;
    the documented replaceability invariant made true)."""

    __slots__ = (
        "transport_id",
        "session_id",
        "direction",
        "state",
        "profile_id",
        "profile_properties",
        "offer",
        "acceptance",
        "established_at",
        "last_rekey_at",
        "generation",
        "lineage",
        "events",
        "sandbox",
    )

    def __init__(
        self,
        transport_id: str,
        session_id: str,
        direction: str,
        profile_id: str,
        profile_properties: Mapping[str, Any],
        offer: TransportOffer,
        acceptance: TransportAcceptance,
        established_at: str,
        sandbox: SandboxedTransport,
    ) -> None:
        self.transport_id = transport_id
        self.session_id = session_id
        self.direction = direction
        self.state = TransportLifecycle.CREATED
        self.profile_id = profile_id
        self.profile_properties = dict(profile_properties)
        self.offer = offer
        self.acceptance = acceptance
        self.established_at = established_at
        self.last_rekey_at = established_at
        self.generation = 0
        self.lineage: List[str] = []
        self.events: List[TransportEvent] = []
        self.sandbox = sandbox

    def security_state(self) -> TransportSecurityState:
        return TransportSecurityState(
            session_id=self.session_id,
            initiator_node_id=self.offer.initiator_node_id,
            responder_node_id=self.offer.responder_node_id,
            profile_id=self.profile_id,
            profile_properties=self.profile_properties,
            generation=self.generation,
            established_at=self.established_at,
            last_rekey_at=self.last_rekey_at,
            key_lineage=tuple(self.lineage),
            replay_window_size=64,
        )


# --------------------------------------------------------------------------
# Attestation bases (identity binding)
# --------------------------------------------------------------------------


def responder_attestation_basis(offer_digest: str) -> bytes:
    return b"adcos-transport/responder-attestation:" + bytes.fromhex(offer_digest)


def initiator_attestation_basis(offer_digest: str) -> bytes:
    return b"adcos-transport/initiator-attestation:" + bytes.fromhex(offer_digest)


# --------------------------------------------------------------------------
# The manager
# --------------------------------------------------------------------------


class TransportManager:
    """The Agent-side secure transport service.

    Construction injects the read-only session reader, the identity
    authority, and (optionally) the transport implementation behind the
    contract.  ``register_implementation`` swaps the implementation at
    runtime — transport replaceability behind the interface without
    modifying the manager or any core semantics (WORK-017 acceptance
    criterion 3; architecture section 25 rule 9).
    """

    def __init__(
        self,
        *,
        session_reader: SessionReader,
        identity: IdentityAuthority,
        implementation: Optional[TransportContract] = None,
        profile_set: Optional[TransportProfileSet] = None,
        step_budget: Optional[int] = None,
    ) -> None:
        if not isinstance(session_reader, SessionReader):
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "session_reader must satisfy the SessionReader facade",
            )
        if not isinstance(identity, IdentityAuthority):
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "identity must satisfy the IdentityAuthority facade",
            )
        self._profile_set = profile_set or TransportProfileSet.load_default()
        engine = implementation if implementation is not None else ModeledTransportEngine(self._profile_set)
        if step_budget is None:
            self._sandbox = SandboxedTransport(engine, profile_set=self._profile_set)
        else:
            self._sandbox = SandboxedTransport(
                engine, profile_set=self._profile_set, step_budget=step_budget
            )
        self._session_reader = session_reader
        self._identity = identity
        self._records: Dict[str, _TransportRecord] = {}
        self._pending: Dict[str, _PendingEntry] = {}
        self._offer_nonces: set = set()
        self._establishment_counter = 0
        self._security_log: List[TransportEvent] = []
        self._security_sequence = 0

    # ------------------------------------------------------------------
    # Registration / introspection
    # ------------------------------------------------------------------

    def register_implementation(
        self,
        implementation: TransportContract,
        *,
        now: Optional[str] = None,
    ) -> TransportOpResult:
        """Swap the DEFAULT transport implementation (replaceability).

        The new implementation's supported profiles must be known to
        the manager's profile set (data consistency, fail closed).
        This reassigns only the manager's default sandbox — the one
        NEW establishments are routed to.  It does NOT disturb
        existing transports or pending handshakes: each transport
        record and pending entry retains the owning sandbox it was
        established with (Blocker 2 — per-transport sandbox
        ownership), so an already-established transport keeps the
        engine it was established with and is never routed into the
        new implementation (which has no state for it).  New
        establishments use the new implementation.
        """
        if not isinstance(implementation, TransportContract):
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "implementation must satisfy the TransportContract ABC",
            )
        instant = now or "1970-01-01T00:00:00Z"
        probe = SandboxedTransport(implementation, profile_set=self._profile_set)
        outcome = probe.supported_profiles(instant)
        if not outcome.ok:
            return TransportOpResult(
                ok=False,
                reason=outcome.failure.reason if outcome.failure else TransportReasonCode.TRANSPORT_FAILURE,
                detail=outcome.failure.detail if outcome.failure else "supported_profiles probe failed",
            )
        profiles = outcome.value
        for identifier in profiles:
            if self._profile_set.classify(identifier) != "known":
                return TransportOpResult(
                    ok=False,
                    reason=TransportReasonCode.PROFILE_UNKNOWN,
                    detail="implementation serves profile %r unknown to the "
                    "manager's profile set" % (identifier,),
                )
        # Reassign the DEFAULT sandbox only (new establishments).
        # Existing _TransportRecord / _PendingEntry instances keep their
        # own captured sandbox — see _TransportRecord.sandbox and
        # _PendingEntry.sandbox.  The previous implementation is not
        # disturbed while any live transport still references it.
        self._sandbox = SandboxedTransport(implementation, profile_set=self._profile_set)
        return TransportOpResult(ok=True, value={"supported_profiles": tuple(profiles)})

    @property
    def implementation_label(self) -> str:
        return getattr(self._sandbox.implementation, "label", "") or type(
            self._sandbox.implementation
        ).__name__

    @property
    def engine_consecutive_failures(self) -> int:
        """Supervision introspection (deterministic health accounting)."""
        return self._sandbox.consecutive_failures

    @property
    def engine_total_failures(self) -> int:
        return self._sandbox.total_failures

    @property
    def engine_total_contract_violations(self) -> int:
        return self._sandbox.total_contract_violations

    def transports(self) -> Tuple[str, ...]:
        return tuple(sorted(self._records))

    def pending_handles(self) -> Tuple[str, ...]:
        return tuple(sorted(self._pending))

    def security_log(self) -> Tuple[TransportEvent, ...]:
        return tuple(self._security_log)

    def health(self, now: str) -> TransportOpResult:
        outcome = self._sandbox.health(now)
        if not outcome.ok:
            return TransportOpResult(
                ok=False,
                reason=outcome.failure.reason if outcome.failure else "",
                detail=outcome.failure.detail if outcome.failure else "",
            )
        return TransportOpResult(ok=True, value={"engine": outcome.value, "effective": self._sandbox.effective_health()})

    # ------------------------------------------------------------------
    # Session verification (read-only WORK-012 access)
    # ------------------------------------------------------------------

    def _verify_session(self, session_id: str, now: str) -> Any:
        session = self._session_reader.get(session_id)
        if session is None:
            raise TransportError(
                TransportReasonCode.SESSION_NOT_SECUREABLE,
                "session %s does not exist (read-only WORK-012 lookup)" % session_id,
            )
        state = getattr(session, "state", None)
        state_text = getattr(state, "value", state)
        if state_text not in SECURABLE_SESSION_STATES:
            raise TransportError(
                TransportReasonCode.SESSION_NOT_SECUREABLE,
                "session %s is %s; only %s sessions are secureable"
                % (session_id, state_text, sorted(SECURABLE_SESSION_STATES)),
            )
        return session

    @staticmethod
    def _session_endpoints(session: Any) -> Tuple[str, str]:
        binding = getattr(session, "binding", None)
        if binding is None:
            raise TransportError(
                TransportReasonCode.SESSION_NOT_SECUREABLE,
                "session object carries no creation binding",
            )
        return (binding.source_node_id, binding.destination_node_id)

    def _local_node(self, record: _TransportRecord) -> str:
        if record.direction == "initiator":
            return record.offer.initiator_node_id
        return record.offer.responder_node_id

    # ------------------------------------------------------------------
    # Security events (audit evidence — architecture section 19)
    # ------------------------------------------------------------------

    def _security_event(
        self,
        transport_id: str,
        event_type: str,
        now: str,
        reason_code: str,
        metadata: Tuple[Tuple[str, str], ...] = (),
    ) -> TransportEvent:
        self._security_sequence += 1
        event = TransportEvent(
            event_id=derive_event_id(
                transport_id=transport_id,
                sequence=self._security_sequence,
                event_type=event_type,
                event_instant=now,
            ),
            transport_id=transport_id,
            sequence=self._security_sequence,
            event_type=event_type,
            event_instant=now,
            reason_code=reason_code,
            metadata=metadata,
        )
        self._security_log.append(event)
        return event

    def _record_event(
        self,
        record: _TransportRecord,
        event_type: str,
        now: str,
        reason_code: str,
        metadata: Tuple[Tuple[str, str], ...] = (),
    ) -> TransportEvent:
        sequence = len(record.events) + 1
        event = TransportEvent(
            event_id=derive_event_id(
                transport_id=record.transport_id,
                sequence=sequence,
                event_type=event_type,
                event_instant=now,
            ),
            transport_id=record.transport_id,
            sequence=sequence,
            event_type=event_type,
            event_instant=now,
            reason_code=reason_code,
            metadata=metadata,
        )
        record.events.append(event)
        return event

    # ------------------------------------------------------------------
    # Establishment — initiator side
    # ------------------------------------------------------------------

    def establish_initiator(
        self,
        session_id: str,
        *,
        policy: TransportSecurityPolicy,
        offered_profiles: Any,
        now: str,
        instance_label: str = INITIATOR_LABEL,
        offer_expires_at: Optional[str] = None,
    ) -> TransportOpResult:
        """Build and locally start the initiator handshake.

        Returns the public :class:`TransportOffer` (to be delivered to
        the responder manager) as ``value``.  The pending handle is
        available via :meth:`pending_handles` for completion.
        """
        validate_instant(now, "now")
        validate_policy(policy)
        offers = validate_profile_offers(offered_profiles, "offered_profiles")
        validate_nonempty_str(instance_label, "instance_label")
        reject_secrets({"offered": list(offers)}, "offer inputs")
        try:
            session = self._verify_session(session_id, now)
        except TransportError as error:
            return TransportOpResult(ok=False, reason=error.reason, detail=error.detail)
        source, destination = self._session_endpoints(session)
        try:
            self._identity.active_credential(source, "operational", now)
        except TransportError as error:
            return TransportOpResult(ok=False, reason=error.reason, detail=error.detail)
        self._establishment_counter += 1
        nonce = derive_offer_nonce(
            session_id=session_id,
            initiator_node_id=source,
            responder_node_id=destination,
            establishment_counter=self._establishment_counter,
            instance_label=instance_label,
        )
        if nonce in self._offer_nonces:
            return TransportOpResult(
                ok=False,
                reason=TransportReasonCode.REPLAY_REJECTED,
                detail="derived offer nonce %s was already used (deterministic "
                "counter collision)" % nonce,
            )
        expires = offer_expires_at or instant_plus(now, DEFAULT_OFFER_LIFETIME_SECONDS)
        validate_instant(expires, "offer_expires_at")
        offer = TransportOffer(
            session_id=session_id,
            initiator_node_id=source,
            responder_node_id=destination,
            offered_profiles=offers,
            policy=policy,
            offer_nonce=nonce,
            issued_at=now,
            expires_at=expires,
        )
        handle = derive_pending_handle(nonce, instance_label)
        # Capture the owning sandbox NOW: a runtime implementation swap
        # between establish_initiator and complete_initiator must not
        # split this handshake across two implementations (Blocker 2).
        sandbox = self._sandbox
        outcome = sandbox.initialize(now, handle, session_id)
        if not outcome.ok:
            return self._pending_failure(outcome, handle, now)
        outcome = sandbox.handshake_initiator(now, handle, session_id, offer)
        if not outcome.ok:
            return self._pending_failure(outcome, handle, now)
        self._offer_nonces.add(nonce)
        self._pending[handle] = _PendingEntry(handle, session_id, offer, sandbox)
        return TransportOpResult(ok=True, value=offer)

    def complete_initiator(
        self,
        pending_handle: str,
        acceptance: TransportAcceptance,
        *,
        now: str,
    ) -> TransportOpResult:
        """Complete the initiator handshake with the responder's
        acceptance.  Returns the public :class:`TransportConfirmation`
        (to be delivered to the responder manager)."""
        validate_instant(now, "now")
        if not isinstance(acceptance, TransportAcceptance):
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "acceptance must be a TransportAcceptance",
            )
        entry = self._pending.get(pending_handle)
        if entry is None:
            return TransportOpResult(
                ok=False,
                reason=TransportReasonCode.UNKNOWN_TRANSPORT,
                detail="no pending establishment for handle %s" % pending_handle,
            )
        offer = entry.offer
        # Manager-side identity binding: the initiator attests over the
        # offer digest with its active operational credential.
        try:
            attestation = self._identity.sign(
                offer.initiator_node_id,
                initiator_attestation_basis(offer.digest()),
                now,
            )
        except TransportError as error:
            return TransportOpResult(ok=False, reason=error.reason, detail=error.detail)
        # Route through the pending entry's OWNING sandbox, not the
        # manager's current default — see establish_initiator (Blocker 2).
        outcome = entry.sandbox.complete_initiator(
            now, pending_handle, entry.session_id, offer, acceptance, attestation
        )
        if not outcome.ok:
            failure = outcome.failure
            event_type = (
                TransportEventType.DOWNGRADE_REJECTED
                if failure and failure.reason == TransportReasonCode.DOWNGRADE_REJECTED
                else TransportEventType.REJECTED
            )
            self._security_event(
                pending_handle,
                event_type,
                now,
                failure.reason if failure else "",
                (("offer_digest", offer.digest()),),
            )
            del self._pending[pending_handle]
            return TransportOpResult(
                ok=False,
                reason=failure.reason if failure else "",
                detail=failure.detail if failure else "",
            )
        confirmation = outcome.value
        # Verify the responder's identity attestation (zero trust: the
        # acceptance is only as good as the credential behind it).
        if not self._identity.verify(
            offer.responder_node_id,
            responder_attestation_basis(acceptance.offer_digest),
            acceptance.responder_attestation,
            now,
        ):
            self._security_event(
                pending_handle,
                TransportEventType.REJECTED,
                now,
                TransportReasonCode.IDENTITY_UNUSABLE,
                (("responder_node_id", offer.responder_node_id),),
            )
            del self._pending[pending_handle]
            return TransportOpResult(
                ok=False,
                reason=TransportReasonCode.IDENTITY_UNUSABLE,
                detail="responder attestation failed verification against %s"
                % offer.responder_node_id,
            )
        profile = self._profile_set.get(acceptance.selected_profile)
        record = _TransportRecord(
            transport_id=acceptance.transport_id,
            session_id=entry.session_id,
            direction="initiator",
            profile_id=acceptance.selected_profile,
            profile_properties=profile.properties_view(),
            offer=offer,
            acceptance=acceptance,
            established_at=now,
            sandbox=entry.sandbox,
        )
        record.state = TransportLifecycle.ESTABLISHED
        record.lineage.append(acceptance.key_lineage)
        if acceptance.transport_id in self._records:
            return TransportOpResult(
                ok=False,
                reason=TransportReasonCode.DUPLICATE_TRANSPORT,
                detail="transport %s already exists (duplicate establishment)"
                % acceptance.transport_id,
            )
        del self._pending[pending_handle]
        self._records[acceptance.transport_id] = record
        self._record_event(
            record,
            TransportEventType.ESTABLISHED,
            now,
            "established",
            (("profile", acceptance.selected_profile), ("generation", "0")),
        )
        return TransportOpResult(ok=True, value=confirmation)

    # ------------------------------------------------------------------
    # Establishment — responder side
    # ------------------------------------------------------------------

    def respond(
        self,
        offer: TransportOffer,
        *,
        now: str,
        instance_label: str = RESPONDER_LABEL,
    ) -> TransportOpResult:
        """Answer an offer: negotiate, derive keys, produce the public
        acceptance record (to be delivered back to the initiator)."""
        validate_instant(now, "now")
        if not isinstance(offer, TransportOffer):
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "offer must be a TransportOffer",
            )
        # Temporal gate (WORK-003 temporal contract applied to offers).
        try:
            temporal_code = check_temporal(offer.issued_at, offer.expires_at, parse_instant(now))
        except TemporalError as error:
            return TransportOpResult(
                ok=False,
                reason=TransportReasonCode.INVALID_INPUT,
                detail="offer temporal metadata is malformed: %s" % error,
            )
        if temporal_code == "expired":
            self._security_event(
                derive_pending_handle(offer.offer_nonce, instance_label),
                TransportEventType.REJECTED,
                now,
                TransportReasonCode.OFFER_EXPIRED,
                (("offer_nonce", offer.offer_nonce),),
            )
            return TransportOpResult(
                ok=False,
                reason=TransportReasonCode.OFFER_EXPIRED,
                detail="offer expired at %s (now=%s)" % (offer.expires_at, now),
            )
        if temporal_code is not None:
            return TransportOpResult(
                ok=False,
                reason=TransportReasonCode.INVALID_INPUT,
                detail="offer temporal metadata invalid (%s)" % temporal_code,
            )
        # Replay ledger: a seen offer nonce is a replayed handshake.
        if offer.offer_nonce in self._offer_nonces:
            handle = derive_pending_handle(offer.offer_nonce, instance_label)
            self._security_event(
                handle,
                TransportEventType.REPLAY_REJECTED,
                now,
                TransportReasonCode.REPLAY_REJECTED,
                (("offer_nonce", offer.offer_nonce),),
            )
            return TransportOpResult(
                ok=False,
                reason=TransportReasonCode.REPLAY_REJECTED,
                detail="offer nonce %s was already consumed (handshake replay)"
                % offer.offer_nonce,
            )
        # Session binding (read-only WORK-012).
        try:
            session = self._verify_session(offer.session_id, now)
        except TransportError as error:
            return TransportOpResult(ok=False, reason=error.reason, detail=error.detail)
        source, destination = self._session_endpoints(session)
        if (offer.initiator_node_id, offer.responder_node_id) != (source, destination):
            self._security_event(
                derive_pending_handle(offer.offer_nonce, instance_label),
                TransportEventType.REJECTED,
                now,
                TransportReasonCode.SESSION_NOT_SECUREABLE,
                (("offer_initiator", offer.initiator_node_id),),
            )
            return TransportOpResult(
                ok=False,
                reason=TransportReasonCode.SESSION_NOT_SECUREABLE,
                detail="offer endpoints do not match the session binding "
                "(%r/%r vs %r/%r)"
                % (offer.initiator_node_id, offer.responder_node_id, source, destination),
            )
        try:
            self._identity.active_credential(offer.responder_node_id, "operational", now)
        except TransportError as error:
            return TransportOpResult(ok=False, reason=error.reason, detail=error.detail)
        try:
            attestation = self._identity.sign(
                offer.responder_node_id,
                responder_attestation_basis(offer.digest()),
                now,
            )
        except TransportError as error:
            return TransportOpResult(ok=False, reason=error.reason, detail=error.detail)
        handle = derive_pending_handle(offer.offer_nonce, instance_label)
        # Capture the owning sandbox NOW: the responder record keeps
        # the engine it was established with across later swaps
        # (Blocker 2 — per-transport sandbox ownership).
        sandbox = self._sandbox
        outcome = sandbox.initialize(now, handle, offer.session_id)
        if not outcome.ok:
            return self._pending_failure(outcome, handle, now)
        outcome = sandbox.handshake_responder(
            now, handle, offer.session_id, offer, attestation
        )
        if not outcome.ok:
            failure = outcome.failure
            event_type = (
                TransportEventType.DOWNGRADE_REJECTED
                if failure and failure.reason == TransportReasonCode.DOWNGRADE_REJECTED
                else TransportEventType.REJECTED
            )
            self._security_event(handle, event_type, now, failure.reason if failure else "", ())
            return TransportOpResult(
                ok=False,
                reason=failure.reason if failure else "",
                detail=failure.detail if failure else "",
            )
        acceptance = outcome.value
        if acceptance.transport_id in self._records:
            return TransportOpResult(
                ok=False,
                reason=TransportReasonCode.DUPLICATE_TRANSPORT,
                detail="transport %s already exists (duplicate establishment)"
                % acceptance.transport_id,
            )
        profile = self._profile_set.get(acceptance.selected_profile)
        record = _TransportRecord(
            transport_id=acceptance.transport_id,
            session_id=offer.session_id,
            direction="responder",
            profile_id=acceptance.selected_profile,
            profile_properties=profile.properties_view(),
            offer=offer,
            acceptance=acceptance,
            established_at=now,
            sandbox=sandbox,
        )
        # Zero trust (LOCK-022 — WORK-017 correction): the responder
        # holds working keys from the acceptance on, but the initiator
        # is NOT yet authenticated.  "Channel cryptographically usable"
        # is deliberately NOT "peer authenticated/authorized": the
        # transport enters AWAITING_CONFIRM and every privileged
        # operation fails closed (peer-unconfirmed) until confirm()
        # verifies the initiator key confirmation AND identity
        # attestation.
        record.state = TransportLifecycle.AWAITING_CONFIRM
        record.lineage.append(acceptance.key_lineage)
        self._offer_nonces.add(offer.offer_nonce)
        self._records[acceptance.transport_id] = record
        self._record_event(
            record,
            TransportEventType.AWAITING_CONFIRM,
            now,
            "awaiting-confirmation",
            (("profile", acceptance.selected_profile), ("generation", "0")),
        )
        return TransportOpResult(ok=True, value=acceptance)

    def confirm(
        self,
        transport_id: str,
        confirmation: TransportConfirmation,
        *,
        now: str,
    ) -> TransportOpResult:
        """Responder-side completion: verify the initiator's key
        confirmation and identity attestation (fail closed), and only
        then grant authorization — AWAITING_CONFIRM -> ESTABLISHED."""
        validate_instant(now, "now")
        validate_transport_id(transport_id)
        if not isinstance(confirmation, TransportConfirmation):
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "confirmation must be a TransportConfirmation",
            )
        record = self._records.get(transport_id)
        if record is None:
            return TransportOpResult(
                ok=False,
                reason=TransportReasonCode.UNKNOWN_TRANSPORT,
                detail="no transport %s" % transport_id,
            )
        if record.direction != "responder":
            return TransportOpResult(
                ok=False,
                reason=TransportReasonCode.STATE_CONFLICT,
                detail="confirm() applies to responder-side transports",
            )
        if record.state != TransportLifecycle.AWAITING_CONFIRM:
            return TransportOpResult(
                ok=False,
                reason=TransportReasonCode.STATE_CONFLICT,
                detail="transport %s is %s; only AWAITING_CONFIRM transports "
                "are confirmable" % (transport_id, record.state),
            )
        offer = record.offer
        # Zero-trust recheck of the LOCAL credential: authorization is
        # granted only if the responder's own operational credential is
        # still usable at confirmation time (revocation between
        # acceptance and confirmation fails closed).
        try:
            self._identity.active_credential(offer.responder_node_id, "operational", now)
        except TransportError as error:
            self._record_event(
                record,
                TransportEventType.CREDENTIAL_REVOKED
                if error.reason == TransportReasonCode.CREDENTIAL_REVOKED
                else TransportEventType.REJECTED,
                now,
                error.reason,
                (),
            )
            return TransportOpResult(ok=False, reason=error.reason, detail=error.detail)
        # Route through the transport's OWNING sandbox (Blocker 2).
        outcome = record.sandbox.accept_confirmation(
            now, transport_id, record.session_id, offer, record.acceptance, confirmation
        )
        if not outcome.ok:
            failure = outcome.failure
            self._record_event(
                record,
                TransportEventType.INTEGRITY_REJECTED,
                now,
                failure.reason if failure else "",
                (),
            )
            return TransportOpResult(
                ok=False,
                reason=failure.reason if failure else "",
                detail=failure.detail if failure else "",
            )
        if not self._identity.verify(
            offer.initiator_node_id,
            initiator_attestation_basis(confirmation.offer_digest),
            confirmation.initiator_attestation,
            now,
        ):
            self._record_event(
                record,
                TransportEventType.REJECTED,
                now,
                TransportReasonCode.IDENTITY_UNUSABLE,
                (("initiator_node_id", offer.initiator_node_id),),
            )
            return TransportOpResult(
                ok=False,
                reason=TransportReasonCode.IDENTITY_UNUSABLE,
                detail="initiator attestation failed verification against %s"
                % offer.initiator_node_id,
            )
        # Mutual confirmation complete: authorization is granted NOW
        # (peer authenticated + key-confirmed + local credential live).
        record.state = TransportLifecycle.ESTABLISHED
        self._record_event(
            record,
            TransportEventType.ESTABLISHED,
            now,
            "established",
            (("profile", record.profile_id), ("generation", "0")),
        )
        return TransportOpResult(ok=True, value=None)

    # ------------------------------------------------------------------
    # Frame exchange
    # ------------------------------------------------------------------

    def _require_established(self, transport_id: str) -> _TransportRecord:
        record = self._records.get(transport_id)
        if record is None:
            raise TransportError(
                TransportReasonCode.UNKNOWN_TRANSPORT,
                "no transport %s" % transport_id,
            )
        if record.state == TransportLifecycle.CLOSED:
            raise TransportError(
                TransportReasonCode.TRANSPORT_CLOSED,
                "transport %s is closed (terminal)" % transport_id,
            )
        if record.state == TransportLifecycle.AWAITING_CONFIRM:
            # Zero-trust gate (LOCK-022): keys exist, the peer does not
            # count as authenticated/authorized yet — no privileged
            # ADCOS operation may execute in this state.
            raise TransportError(
                TransportReasonCode.PEER_UNCONFIRMED,
                "transport %s is AWAITING_CONFIRM: the peer is not yet "
                "authenticated/authorized, privileged operations are gated "
                "until confirm() succeeds" % transport_id,
            )
        if record.state != TransportLifecycle.ESTABLISHED:
            raise TransportError(
                TransportReasonCode.NOT_ESTABLISHED,
                "transport %s is %s" % (transport_id, record.state),
            )
        return record

    def send(self, transport_id: str, payload: bytes, *, now: str) -> TransportOpResult:
        """Protect and frame one payload (user path)."""
        validate_instant(now, "now")
        validate_transport_id(transport_id)
        try:
            record = self._require_established(transport_id)
        except TransportError as error:
            return TransportOpResult(ok=False, reason=error.reason, detail=error.detail)
        # Route through the transport's OWNING sandbox (Blocker 2): a
        # swapped default implementation never receives frames for a
        # transport it has no state for.
        outcome = record.sandbox.protect(now, transport_id, record.session_id, payload)
        if not outcome.ok:
            failure = outcome.failure
            return TransportOpResult(
                ok=False,
                reason=failure.reason if failure else "",
                detail=failure.detail if failure else "",
            )
        return TransportOpResult(ok=True, value=outcome.value)

    def receive(self, transport_id: str, frame: Mapping[str, object], *, now: str) -> TransportOpResult:
        """Verify and decode one inbound frame (fail closed on replay,
        integrity, or generation mismatch; every rejection is recorded
        as audit evidence)."""
        validate_instant(now, "now")
        validate_transport_id(transport_id)
        try:
            record = self._require_established(transport_id)
        except TransportError as error:
            return TransportOpResult(ok=False, reason=error.reason, detail=error.detail)
        # Route through the transport's OWNING sandbox (Blocker 2).
        outcome = record.sandbox.unprotect(now, transport_id, record.session_id, frame)
        if not outcome.ok:
            failure = outcome.failure
            reason = failure.reason if failure else ""
            event_type = (
                TransportEventType.REPLAY_REJECTED
                if reason == TransportReasonCode.REPLAY_REJECTED
                else TransportEventType.INTEGRITY_REJECTED
            )
            self._record_event(record, event_type, now, reason, ())
            return TransportOpResult(
                ok=False,
                reason=reason,
                detail=failure.detail if failure else "",
            )
        return TransportOpResult(ok=True, value=outcome.value)

    def protect_envelope(self, transport_id: str, envelope: Envelope, *, now: str) -> TransportOpResult:
        """Frame a protocol envelope over the secure control path.

        The frame payload is the envelope's canonical JSON bytes, so
        every security-critical field rides covered by the frame MAC —
        the message security profile of architecture section 7 rule 6
        at the transport boundary.
        """
        if not isinstance(envelope, Envelope):
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "envelope must be a WORK-003 Envelope",
            )
        try:
            payload = canonical_json_bytes(envelope.to_dict())
        except CanonicalizationError as error:
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "envelope is not canonically serializable: %s" % error,
            ) from error
        return self.send(transport_id, payload, now=now)

    def receive_envelope(self, transport_id: str, frame: Mapping[str, object], *, now: str) -> TransportOpResult:
        """Verify one inbound frame and reconstruct the protocol envelope.

        Fail closed on frame verification AND on envelope temporal
        validation (message expiration — architecture section 19)."""
        outcome = self.receive(transport_id, frame, now=now)
        if not outcome.ok:
            return outcome
        try:
            document = json.loads(outcome.value.decode("utf-8"))
            envelope = envelope_from_mapping(document)
        except (ValueError, UnicodeDecodeError) as error:
            return TransportOpResult(
                ok=False,
                reason=TransportReasonCode.INTEGRITY_REJECTED,
                detail="framed payload is not a valid envelope: %s" % error,
            )
        temporal_code = check_temporal(
            envelope.issued_at, envelope.expires_at, parse_instant(now)
        )
        if temporal_code is not None:
            return TransportOpResult(
                ok=False,
                reason=TransportReasonCode.OFFER_EXPIRED
                if temporal_code == "expired"
                else TransportReasonCode.INVALID_INPUT,
                detail="envelope temporal validation failed (%s)" % temporal_code,
            )
        return TransportOpResult(ok=True, value=envelope)

    # ------------------------------------------------------------------
    # Key rotation / continuity
    # ------------------------------------------------------------------

    def rekey(self, transport_id: str, cause: str, *, now: str) -> TransportOpResult:
        """Advance the key generation (chained rotation).

        Keys are bound to session/identity policy: a rekey under a
        revoked or expired local credential fails closed.
        """
        validate_instant(now, "now")
        validate_transport_id(transport_id)
        validate_nonempty_str(cause, "cause")
        try:
            record = self._require_established(transport_id)
        except TransportError as error:
            return TransportOpResult(ok=False, reason=error.reason, detail=error.detail)
        try:
            self._identity.active_credential(self._local_node(record), "operational", now)
        except TransportError as error:
            self._record_event(
                record,
                TransportEventType.CREDENTIAL_REVOKED
                if error.reason == TransportReasonCode.CREDENTIAL_REVOKED
                else TransportEventType.REJECTED,
                now,
                error.reason,
                (),
            )
            return TransportOpResult(ok=False, reason=error.reason, detail=error.detail)
        # Route through the transport's OWNING sandbox (Blocker 2).
        outcome = record.sandbox.rekey(now, transport_id, record.session_id, cause)
        if not outcome.ok:
            failure = outcome.failure
            return TransportOpResult(
                ok=False,
                reason=failure.reason if failure else "",
                detail=failure.detail if failure else "",
            )
        info = outcome.value
        record.generation = info["generation"]
        record.lineage.append(info["lineage_digest"])
        record.last_rekey_at = now
        self._record_event(
            record,
            TransportEventType.REKEYED,
            now,
            "rekeyed",
            (("cause", cause), ("generation", str(info["generation"]))),
        )
        return TransportOpResult(ok=True, value=dict(info))

    def suspend(self, transport_id: str, *, now: str, reason: str = "suspended") -> TransportOpResult:
        """Suspend the transport (underlying path/session lost while the
        logical session survives — LOCK-006/LOCK-021 continuity)."""
        validate_instant(now, "now")
        validate_transport_id(transport_id)
        record = self._records.get(transport_id)
        if record is None:
            return TransportOpResult(
                ok=False,
                reason=TransportReasonCode.UNKNOWN_TRANSPORT,
                detail="no transport %s" % transport_id,
            )
        if not lifecycle_transition_is_legal(record.state, TransportLifecycle.SUSPENDED) or record.state != TransportLifecycle.ESTABLISHED:
            return TransportOpResult(
                ok=False,
                reason=TransportReasonCode.STATE_CONFLICT,
                detail="transport %s is %s; only ESTABLISHED transports suspend"
                % (transport_id, record.state),
            )
        record.state = TransportLifecycle.SUSPENDED
        self._record_event(record, TransportEventType.SUSPENDED, now, reason, ())
        return TransportOpResult(ok=True, value={"state": record.state})

    def resume(self, transport_id: str, *, now: str, cause: str = "resume") -> TransportOpResult:
        """Resume a suspended transport: rekey to a fresh generation
        (a suspended generation is never reused) and return to
        ESTABLISHED."""
        validate_instant(now, "now")
        validate_transport_id(transport_id)
        record = self._records.get(transport_id)
        if record is None:
            return TransportOpResult(
                ok=False,
                reason=TransportReasonCode.UNKNOWN_TRANSPORT,
                detail="no transport %s" % transport_id,
            )
        if record.state != TransportLifecycle.SUSPENDED:
            return TransportOpResult(
                ok=False,
                reason=TransportReasonCode.STATE_CONFLICT,
                detail="transport %s is %s; only SUSPENDED transports resume"
                % (transport_id, record.state),
            )
        try:
            self._identity.active_credential(self._local_node(record), "operational", now)
        except TransportError as error:
            return TransportOpResult(ok=False, reason=error.reason, detail=error.detail)
        # Route through the transport's OWNING sandbox (Blocker 2).
        outcome = record.sandbox.rekey(now, transport_id, record.session_id, cause)
        if not outcome.ok:
            failure = outcome.failure
            return TransportOpResult(
                ok=False,
                reason=failure.reason if failure else "",
                detail=failure.detail if failure else "",
            )
        info = outcome.value
        record.state = TransportLifecycle.ESTABLISHED
        record.generation = info["generation"]
        record.lineage.append(info["lineage_digest"])
        record.last_rekey_at = now
        self._record_event(
            record,
            TransportEventType.RESUMED,
            now,
            "resumed",
            (("cause", cause), ("generation", str(info["generation"]))),
        )
        return TransportOpResult(ok=True, value=dict(info))

    def close(self, transport_id: str, *, now: str, reason: str = "closed") -> TransportOpResult:
        """Close the transport and destroy working key material
        (fail closed: state is terminal)."""
        validate_instant(now, "now")
        validate_transport_id(transport_id)
        record = self._records.get(transport_id)
        if record is None:
            return TransportOpResult(
                ok=False,
                reason=TransportReasonCode.UNKNOWN_TRANSPORT,
                detail="no transport %s" % transport_id,
            )
        if record.state == TransportLifecycle.CLOSED:
            return TransportOpResult(
                ok=False,
                reason=TransportReasonCode.TRANSPORT_CLOSED,
                detail="transport %s is already closed (terminal)" % transport_id,
            )
        # Route through the transport's OWNING sandbox (Blocker 2): close
        # destroys working key material in the engine that actually holds
        # this transport's state, which may be a previous implementation.
        outcome = record.sandbox.close(now, transport_id, record.session_id)
        if not outcome.ok:
            failure = outcome.failure
            return TransportOpResult(
                ok=False,
                reason=failure.reason if failure else "",
                detail=failure.detail if failure else "",
            )
        record.state = TransportLifecycle.CLOSED
        self._record_event(record, TransportEventType.CLOSED, now, reason, ())
        return TransportOpResult(ok=True, value={"state": record.state})

    def recheck(self, transport_id: str, *, now: str) -> TransportOpResult:
        """Zero-trust credential recheck: suspend a live transport whose
        local backing credential has been revoked or expired (fail
        closed for security — architecture section 25 rule 14)."""
        validate_instant(now, "now")
        validate_transport_id(transport_id)
        record = self._records.get(transport_id)
        if record is None:
            return TransportOpResult(
                ok=False,
                reason=TransportReasonCode.UNKNOWN_TRANSPORT,
                detail="no transport %s" % transport_id,
            )
        if record.state != TransportLifecycle.ESTABLISHED:
            return TransportOpResult(ok=True, value={"state": record.state})
        try:
            self._identity.active_credential(self._local_node(record), "operational", now)
        except TransportError as error:
            record.state = TransportLifecycle.SUSPENDED
            self._record_event(
                record,
                TransportEventType.CREDENTIAL_REVOKED
                if error.reason == TransportReasonCode.CREDENTIAL_REVOKED
                else TransportEventType.REJECTED,
                now,
                error.reason,
                (("local_node", self._local_node(record)),),
            )
            return TransportOpResult(
                ok=False,
                reason=error.reason,
                detail="transport suspended: %s" % error.detail,
            )
        return TransportOpResult(ok=True, value={"state": record.state})

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def get_security_state(self, transport_id: str) -> TransportSecurityState:
        record = self._records.get(transport_id)
        if record is None:
            raise TransportError(
                TransportReasonCode.UNKNOWN_TRANSPORT,
                "no transport %s" % transport_id,
            )
        return record.security_state()

    def get_events(self, transport_id: str) -> Tuple[TransportEvent, ...]:
        record = self._records.get(transport_id)
        if record is None:
            raise TransportError(
                TransportReasonCode.UNKNOWN_TRANSPORT,
                "no transport %s" % transport_id,
            )
        return tuple(record.events)

    def snapshot(self) -> Dict[str, Any]:
        """Deterministic public snapshot (structurally secret-free)."""
        records = []
        for transport_id in sorted(self._records):
            record = self._records[transport_id]
            records.append(
                {
                    "transport_id": record.transport_id,
                    "session_id": record.session_id,
                    "direction": record.direction,
                    "state": record.state,
                    "profile_id": record.profile_id,
                    "generation": record.generation,
                    "established_at": record.established_at,
                    "last_rekey_at": record.last_rekey_at,
                    "lineage": list(record.lineage),
                    "events": [event.to_dict() for event in record.events],
                }
            )
        return {
            "transports": records,
            "pending": sorted(self._pending),
            "establishment_counter": self._establishment_counter,
            "offer_nonces": sorted(self._offer_nonces),
            "security_log": [event.to_dict() for event in self._security_log],
            "engine": self.implementation_label,
        }

    def to_canonical_bytes(self) -> bytes:
        try:
            return canonical_json_bytes(self.snapshot())
        except CanonicalizationError as error:
            raise TransportError(
                TransportReasonCode.SERIALIZATION_INVALID,
                "snapshot is not canonically serializable: %s" % error,
            ) from error

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _pending_failure(self, outcome: OperationOutcome, handle: str, now: str) -> TransportOpResult:
        failure = outcome.failure
        self._security_event(
            handle,
            TransportEventType.REJECTED,
            now,
            failure.reason if failure else "",
            (),
        )
        return TransportOpResult(
            ok=False,
            reason=failure.reason if failure else "",
            detail=failure.detail if failure else "",
        )
