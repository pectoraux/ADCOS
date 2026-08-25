"""ADCOS transport domain model (WORK-017): identities, lifecycle,
handshake records, replay window, public security state, and events.

Secure transport instances are mapped onto ADCOS sessions (WORK-012)
under a negotiated transport profile (transport.profiles).  Instance
identity is content-derived and grammar-disjoint from both NodeID
(WORK-004) and adapter instance ids (WORK-016).  All instants are
injected RFC 3339 UTC values; all ids are content-derived over
WORK-003 canonical JSON; every public structure is structurally
secret-free (LOCK-023) — working key material lives only inside the
engine's key schedule, never in these objects.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

from protocol.canonicalization import CanonicalizationError, canonical_json_bytes

from .errors import TRANSPORT_PREFIX, TransportError, TransportReasonCode
from .profiles import TransportSecurityPolicy
from .validation import (
    validate_instant,
    validate_node_id_text,
    validate_nonempty_str,
    validate_profile_id,
    validate_profile_offers,
    validate_sequence,
    validate_transport_id,
)

# --------------------------------------------------------------------------
# Transport instance identity (disjoint from NodeID and adapter ids)
# --------------------------------------------------------------------------

_TRANSPORT_ID_RE = re.compile(
    r"^adcos:transport:((?:[a-z0-9][a-z0-9-]*\.)*[a-z0-9][a-z0-9-]*):([0-9a-f]{16})$"
)


class ParsedTransportId(Tuple[str, str]):
    """Parsed transport instance id: ``(family, instance_digest)``."""

    __slots__ = ()

    @property
    def family(self) -> str:
        return self[0]

    @property
    def instance_digest(self) -> str:
        return self[1]


def parse_transport_id(transport_id: object) -> ParsedTransportId:
    """Parse a transport instance id (fail closed on any other shape)."""
    if not isinstance(transport_id, str):
        raise TransportError(
            TransportReasonCode.TRANSPORT_ID_INVALID,
            "transport id must be a string",
        )
    match = _TRANSPORT_ID_RE.fullmatch(transport_id)
    if match is None:
        raise TransportError(
            TransportReasonCode.TRANSPORT_ID_INVALID,
            "transport id must match adcos:transport:<family>:<16 hex>",
        )
    return ParsedTransportId((match.group(1), match.group(2)))


def derive_transport_id(
    profile_family: str,
    *,
    session_id: str,
    initiator_node_id: str,
    responder_node_id: str,
    profile_id: str,
    policy_id: str,
    offer_nonce: str,
) -> str:
    """Deterministically derive the FINAL transport instance id.

    Content-derived over the establishment inputs (session, endpoints,
    negotiated profile, policy floor id, offer nonce) so both endpoints
    derive the identical id, the same establishment always yields the
    same id, and accidental duplicates collide visibly.  The responder
    mints the id once negotiation selects the profile; the initiator
    re-derives and verifies it at completion (the id itself is
    tamper-evident).  It is NOT derived from any identity key material:
    transport instance identity is distinct from node identity by
    construction (the WORK-016 adapter-id convention applied to
    transport).
    """
    if not isinstance(profile_family, str) or not re.fullmatch(
        r"(?:[a-z0-9][a-z0-9-]*\.)*[a-z0-9][a-z0-9-]*", profile_family
    ):
        raise TransportError(
            TransportReasonCode.INVALID_INPUT,
            "profile family %r must be dotted lowercase segments" % (profile_family,),
        )
    document = {
        "kind": "adcos.transport.instance",
        "profile_family": profile_family,
        "session_id": session_id,
        "initiator_node_id": initiator_node_id,
        "responder_node_id": responder_node_id,
        "profile_id": profile_id,
        "policy_id": policy_id,
        "offer_nonce": offer_nonce,
    }
    digest = hashlib.sha256(canonical_json_bytes(document)).hexdigest()[:16]
    return "%s:%s:%s" % (TRANSPORT_PREFIX, profile_family, digest)


def derive_pending_handle(offer_nonce: str, instance_label: str) -> str:
    """The local pending handle used to key engine state during the
    handshake, before the negotiated profile fixes the final id family.

    Grammar-valid (family ``pending``) but NEVER a final id: the digest
    binds only to the offer nonce and label, so a collision with a
    derived final id is computationally implausible and structurally
    visible.
    """
    if not isinstance(offer_nonce, str) or re.fullmatch(r"[0-9a-f]{16}", offer_nonce) is None:
        raise TransportError(
            TransportReasonCode.INVALID_INPUT,
            "offer_nonce must be 16 lowercase hex chars",
        )
    validate_nonempty_str(instance_label, "instance label")
    document = {
        "kind": "adcos.transport.pending",
        "offer_nonce": offer_nonce,
        "instance_label": instance_label,
    }
    digest = hashlib.sha256(canonical_json_bytes(document)).hexdigest()[:16]
    return "%s:pending:%s" % (TRANSPORT_PREFIX, digest)


def derive_offer_nonce(
    *,
    session_id: str,
    initiator_node_id: str,
    responder_node_id: str,
    establishment_counter: int,
    instance_label: str,
) -> str:
    """Deterministically derive the offer nonce.

    The nonce is the replay-resistant freshness contribution of the
    modeled handshake.  It is content-derived from the establishment
    inputs and the manager-local monotonic establishment counter —
    never from randomness or the wall clock (deterministic replay
    contract); real deployments inject true entropy inside the concrete
    implementation behind the same interface.
    """
    if isinstance(establishment_counter, bool) or not isinstance(establishment_counter, int):
        raise TransportError(
            TransportReasonCode.INVALID_INPUT,
            "establishment counter must be an integer",
        )
    if establishment_counter < 1:
        raise TransportError(
            TransportReasonCode.INVALID_INPUT,
            "establishment counter must be >= 1",
        )
    document = {
        "kind": "adcos.transport.offer-nonce",
        "session_id": session_id,
        "initiator_node_id": initiator_node_id,
        "responder_node_id": responder_node_id,
        "establishment_counter": establishment_counter,
        "instance_label": instance_label,
    }
    return hashlib.sha256(canonical_json_bytes(document)).hexdigest()[:16]


def derive_event_id(
    *,
    transport_id: str,
    sequence: int,
    event_type: str,
    event_instant: str,
) -> str:
    """Content-derived event id (WORK-016 event convention)."""
    document = {
        "kind": "adcos.transport.event",
        "transport_id": transport_id,
        "sequence": sequence,
        "event_type": event_type,
        "event_instant": event_instant,
    }
    return hashlib.sha256(canonical_json_bytes(document)).hexdigest()[:16]


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# Lifecycle / health / event vocabularies
# --------------------------------------------------------------------------


class TransportLifecycle:
    """Frozen lifecycle vocabulary.

    ``CLOSED`` is terminal.  ``AWAITING_CONFIRM`` is the responder-side
    pre-authorization state (WORK-017 correction, zero trust —
    LOCK-022): the handshake has produced working keys and the channel
    is cryptographically USABLE, but the initiator has not yet been
    authenticated — the responder holds the transport in
    ``AWAITING_CONFIRM`` and every privileged operation (send /
    receive / protect_envelope / receive_envelope / rekey) fails
    closed with ``peer-unconfirmed`` until :meth:`confirm` verifies
    the initiator key confirmation AND identity attestation.
    "Channel cryptographically usable" is thereby never conflated with
    "peer authenticated and authorized".  A transport is
    ``ESTABLISHED`` only after mutual confirmation on both sides;
    ``SUSPENDED`` models loss of the underlying carrying path (session
    suspension / mobility handover) while the logical ADCOS session
    survives (LOCK-006, LOCK-021); resume re-establishes keys (rekey
    on resume — never reuse a suspended generation).
    """

    CREATED = "CREATED"
    AWAITING_CONFIRM = "AWAITING_CONFIRM"
    ESTABLISHED = "ESTABLISHED"
    SUSPENDED = "SUSPENDED"
    CLOSED = "CLOSED"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.CREATED, cls.AWAITING_CONFIRM, cls.ESTABLISHED, cls.SUSPENDED, cls.CLOSED)


#: Legal lifecycle edges.  ESTABLISHED -> ESTABLISHED is the rekey
#: self-edge (generation advance without a state change).  The
#: responder enters AWAITING_CONFIRM at acceptance (keys exist, peer
#: unconfirmed) and may only reach ESTABLISHED through confirm();
#: there is deliberately no AWAITING_CONFIRM -> SUSPENDED edge — a
#: channel whose peer was never confirmed dies (CLOSED), it does not
#: survive as a suspended logical channel.
LIFECYCLE_TRANSITIONS: Dict[str, Tuple[str, ...]] = {
    TransportLifecycle.CREATED: (
        TransportLifecycle.ESTABLISHED,
        TransportLifecycle.AWAITING_CONFIRM,
        TransportLifecycle.CLOSED,
    ),
    TransportLifecycle.AWAITING_CONFIRM: (TransportLifecycle.ESTABLISHED, TransportLifecycle.CLOSED),
    TransportLifecycle.ESTABLISHED: (
        TransportLifecycle.ESTABLISHED,
        TransportLifecycle.SUSPENDED,
        TransportLifecycle.CLOSED,
    ),
    TransportLifecycle.SUSPENDED: (TransportLifecycle.ESTABLISHED, TransportLifecycle.CLOSED),
    TransportLifecycle.CLOSED: (),
}


def lifecycle_transition_is_legal(previous: str, new: str) -> bool:
    return new in LIFECYCLE_TRANSITIONS.get(previous, ())


class TransportHealth:
    """Transport-local health vocabulary (mediated, never authoritative
    alone — LOCK-017 in the transport direction)."""

    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.HEALTHY, cls.DEGRADED, cls.FAILED)


class TransportEventType:
    """Frozen append-only event vocabulary (audit evidence for security
    decisions — architecture section 19)."""

    ESTABLISHED = "established"
    AWAITING_CONFIRM = "awaiting-confirmation"
    REKEYED = "rekeyed"
    SUSPENDED = "suspended"
    RESUMED = "resumed"
    CLOSED = "closed"
    DOWNGRADE_REJECTED = "downgrade-rejected"
    REPLAY_REJECTED = "replay-rejected"
    INTEGRITY_REJECTED = "integrity-rejected"
    CREDENTIAL_REVOKED = "credential-revoked"
    REJECTED = "rejected"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.ESTABLISHED,
            cls.AWAITING_CONFIRM,
            cls.REKEYED,
            cls.SUSPENDED,
            cls.RESUMED,
            cls.CLOSED,
            cls.DOWNGRADE_REJECTED,
            cls.REPLAY_REJECTED,
            cls.INTEGRITY_REJECTED,
            cls.CREDENTIAL_REVOKED,
            cls.REJECTED,
        )


# --------------------------------------------------------------------------
# Replay window (sliding, deterministic, integer math only)
# --------------------------------------------------------------------------


class ReplayWindow:
    """A sliding anti-replay window over strictly monotonic sequences.

    Window semantics (the deterministic model of the TLS 1.3 record /
    QUIC packet / IPsec ESP anti-replay windows — architecture section
    19 replay protection):

    - a sequence greater than the highest seen ACCEPTS and advances
      the window (older entries slide out and are then rejected);
    - a sequence already seen REJECTS (exact replay);
    - a sequence at or below the window floor REJECTS (too old);
    - an unseen in-window sequence ACCEPTS exactly once (reordering
      tolerance).

    Transactional admission (LOCK — replay-window poisoning, the
    WORK-017 acceptance criterion): the window is the security state
    an unauthenticated network input MUST NOT mutate.  Callers
    authenticate the record FIRST (``would_accept`` pre-check, then
    integrity verification) and commit the sequence with ``accept``
    ONLY after authentication succeeds.  A forged record that fails
    integrity verification therefore never advances ``highest`` and
    cannot starve legitimate lower-sequence records (the attack
    surface the WORK-017 review required closed).
    """

    __slots__ = ("_size", "_highest", "_seen")

    def __init__(self, size: int = 64) -> None:
        if isinstance(size, bool) or not isinstance(size, int) or size < 1:
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "replay window size must be a positive integer",
            )
        self._size = size
        self._highest = -1
        self._seen: set = set()

    @property
    def size(self) -> int:
        return self._size

    @property
    def highest(self) -> int:
        return self._highest

    def would_accept(self, sequence: int) -> bool:
        """Read-only admission pre-check.

        Return whether ``sequence`` would be admitted by
        :meth:`accept` WITHOUT mutating the window.  Used for
        transactional replay admission: the caller pre-checks
        admission, authenticates the record, and only then commits
        via :meth:`accept`.  A forged record that fails
        authentication therefore never advances the window and
        cannot starve legitimate lower-sequence records (LOCK: the
        replay-window poisoning the WORK-017 review required closed).
        """
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "replay window sequence must be a non-negative integer",
            )
        if sequence > self._highest:
            return True
        if sequence in self._seen:
            return False
        if sequence <= self._highest - self._size:
            return False
        return True

    def accept(self, sequence: int) -> bool:
        """Check and COMMIT ``sequence`` (mutating).

        Returns True and advances the window when ``sequence`` is
        admissible; returns False (without mutating) on an exact
        replay or a below-floor sequence.  Callers that must keep
        the window untouched on authentication failure should
        pre-check with :meth:`would_accept` and call ``accept`` only
        AFTER the record is authenticated (transactional admission).
        """
        if not self.would_accept(sequence):
            return False
        if sequence > self._highest:
            self._highest = sequence
            self._seen.add(sequence)
            floor = self._highest - self._size
            if floor > 0:
                self._seen = {s for s in self._seen if s >= floor}
        else:
            self._seen.add(sequence)
        return True

    def view(self) -> Dict[str, int]:
        return {"size": self._size, "highest": self._highest}


# --------------------------------------------------------------------------
# Handshake records (public, structurally secret-free)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class TransportOffer:
    """The initiator's offer record (the modeled ClientHello).

    Carries the FULL offered profile set and the policy floor — both
    are covered by the transcript, which is the downgrade-protection
    basis: an in-flight attacker who removes stronger profiles from
    the offer changes the offer digest, and the initiator's
    completion check fails closed (DOWNGRADE_REJECTED).
    """

    session_id: str
    initiator_node_id: str
    responder_node_id: str
    offered_profiles: Tuple[str, ...]
    policy: TransportSecurityPolicy
    offer_nonce: str
    issued_at: str
    expires_at: str
    extensions: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        validate_nonempty_str(self.session_id, "offer.session_id")
        validate_node_id_text(self.initiator_node_id, "offer.initiator_node_id")
        validate_node_id_text(self.responder_node_id, "offer.responder_node_id")
        validate_profile_offers(self.offered_profiles, "offer.offered_profiles")
        if not isinstance(self.policy, TransportSecurityPolicy):
            raise TransportError(
                TransportReasonCode.POLICY_INVALID,
                "offer.policy must be a TransportSecurityPolicy",
            )
        if not isinstance(self.offer_nonce, str) or re.fullmatch(r"[0-9a-f]{16}", self.offer_nonce) is None:
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "offer.offer_nonce must be 16 lowercase hex chars",
            )
        validate_instant(self.issued_at, "offer.issued_at")
        validate_instant(self.expires_at, "offer.expires_at")
        if not isinstance(self.extensions, Mapping):
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "offer.extensions must be a string-valued mapping",
            )
        for key, value in self.extensions.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise TransportError(
                    TransportReasonCode.INVALID_INPUT,
                    "offer.extensions must map strings to strings",
                )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": "adcos.transport.offer",
            "session_id": self.session_id,
            "initiator_node_id": self.initiator_node_id,
            "responder_node_id": self.responder_node_id,
            "offered_profiles": list(self.offered_profiles),
            "policy": self.policy.transcript_view(),
            "offer_nonce": self.offer_nonce,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "extensions": dict(self.extensions),
        }

    def canonical_bytes(self) -> bytes:
        try:
            return canonical_json_bytes(self.to_dict())
        except CanonicalizationError as error:
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "offer is not canonically serializable: %s" % error,
            ) from error

    def digest(self) -> str:
        return sha256_hex(self.canonical_bytes())


@dataclass(frozen=True)
class TransportAcceptance:
    """The responder's acceptance record (the modeled ServerHello +
    Finished): selection, offer-digest echo, responder nonce, responder
    key confirmation, the responder's identity attestation over the
    transcript-so-far, and the PUBLIC generation-0 key-lineage digest.

    The offer-digest echo is the downgrade-detection basis; the key
    confirmation proves possession of the derived traffic secret; the
    attestation binds the acceptance to the responder's WORK-004
    operational credential (keys bound to identity policy); the
    key-lineage digest lets both endpoints record the SAME public
    generation-0 lineage (the confirmation MACs differ by role).
    """

    transport_id: str
    offer_digest: str
    selected_profile: str
    responder_nonce: str
    responder_confirmation: str
    responder_attestation: str
    key_lineage: str
    issued_at: str
    extensions: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        validate_transport_id(self.transport_id)
        if not isinstance(self.offer_digest, str) or re.fullmatch(r"[0-9a-f]{64}", self.offer_digest) is None:
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "acceptance.offer_digest must be 64 lowercase hex chars",
            )
        validate_profile_id(self.selected_profile)
        if not isinstance(self.responder_nonce, str) or re.fullmatch(r"[0-9a-f]{16}", self.responder_nonce) is None:
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "acceptance.responder_nonce must be 16 lowercase hex chars",
            )
        for member in ("responder_confirmation", "responder_attestation"):
            value = getattr(self, member)
            if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]+", value) is None or not value:
                raise TransportError(
                    TransportReasonCode.INVALID_INPUT,
                    "acceptance.%s must be a non-empty lowercase hex string" % member,
                )
        if not isinstance(self.key_lineage, str) or re.fullmatch(r"[0-9a-f]{16}", self.key_lineage) is None:
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "acceptance.key_lineage must be 16 lowercase hex chars",
            )
        validate_instant(self.issued_at, "acceptance.issued_at")
        if not isinstance(self.extensions, Mapping):
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "acceptance.extensions must be a string-valued mapping",
            )
        for key, value in self.extensions.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise TransportError(
                    TransportReasonCode.INVALID_INPUT,
                    "acceptance.extensions must map strings to strings",
                )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": "adcos.transport.acceptance",
            "transport_id": self.transport_id,
            "offer_digest": self.offer_digest,
            "selected_profile": self.selected_profile,
            "responder_nonce": self.responder_nonce,
            "responder_confirmation": self.responder_confirmation,
            "responder_attestation": self.responder_attestation,
            "key_lineage": self.key_lineage,
            "issued_at": self.issued_at,
            "extensions": dict(self.extensions),
        }

    def canonical_bytes(self) -> bytes:
        try:
            return canonical_json_bytes(self.to_dict())
        except CanonicalizationError as error:
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "acceptance is not canonically serializable: %s" % error,
            ) from error


@dataclass(frozen=True)
class TransportConfirmation:
    """The initiator's completion record (the modeled client Finished):
    initiator key confirmation + identity attestation over the full
    transcript."""

    transport_id: str
    offer_digest: str
    initiator_confirmation: str
    initiator_attestation: str
    issued_at: str

    def __post_init__(self) -> None:
        validate_transport_id(self.transport_id)
        if not isinstance(self.offer_digest, str) or re.fullmatch(r"[0-9a-f]{64}", self.offer_digest) is None:
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "confirmation.offer_digest must be 64 lowercase hex chars",
            )
        for member in ("initiator_confirmation", "initiator_attestation"):
            value = getattr(self, member)
            if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]+", value) is None or not value:
                raise TransportError(
                    TransportReasonCode.INVALID_INPUT,
                    "confirmation.%s must be a non-empty lowercase hex string" % member,
                )
        validate_instant(self.issued_at, "confirmation.issued_at")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": "adcos.transport.confirmation",
            "transport_id": self.transport_id,
            "offer_digest": self.offer_digest,
            "initiator_confirmation": self.initiator_confirmation,
            "initiator_attestation": self.initiator_attestation,
            "issued_at": self.issued_at,
        }

    def canonical_bytes(self) -> bytes:
        try:
            return canonical_json_bytes(self.to_dict())
        except CanonicalizationError as error:
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "confirmation is not canonically serializable: %s" % error,
            ) from error


def _acceptance_basis_document(
    transport_id: str,
    offer_digest: str,
    selected_profile: str,
    responder_nonce: str,
    responder_attestation: str,
    issued_at: str,
    extensions: Mapping[str, str],
) -> Dict[str, Any]:
    """The canonical acceptance BASIS document (no key confirmation)."""
    return {
        "kind": "adcos.transport.acceptance",
        "transport_id": transport_id,
        "offer_digest": offer_digest,
        "selected_profile": selected_profile,
        "responder_nonce": responder_nonce,
        "responder_attestation": responder_attestation,
        "issued_at": issued_at,
        "extensions": dict(extensions),
    }


def acceptance_basis_mapping(acceptance: "TransportAcceptance") -> Dict[str, Any]:
    """The acceptance projection used for KEY-DERIVATION transcript
    hashing: the acceptance WITHOUT the responder key confirmation.

    TLS-1.3 Finished-message pattern: the traffic secrets derive from
    the transcript up to (but not including) the key-confirmation
    values, which are themselves MACs over those secrets — so both
    endpoints compute identical masters without circularity, while the
    confirmation still proves possession of the transcript-derived
    secret.  The responder identity attestation IS in the basis (key
    binding to identity policy).
    """
    return _acceptance_basis_document(
        acceptance.transport_id,
        acceptance.offer_digest,
        acceptance.selected_profile,
        acceptance.responder_nonce,
        acceptance.responder_attestation,
        acceptance.issued_at,
        acceptance.extensions,
    )


def transcript_digest(
    offer: TransportOffer,
    acceptance: TransportAcceptance,
) -> str:
    """The key-derivation transcript digest: sha256 over the canonical
    concatenation of the offer record and the acceptance BASIS (see
    :func:`acceptance_basis_mapping`)."""
    try:
        material = offer.canonical_bytes() + b"\x00" + canonical_json_bytes(
            acceptance_basis_mapping(acceptance)
        )
    except CanonicalizationError as error:
        raise TransportError(
            TransportReasonCode.INVALID_INPUT,
            "transcript material is not canonically serializable: %s" % error,
        ) from error
    return sha256_hex(material)


def transcript_digest_from_basis(
    offer: TransportOffer,
    *,
    transport_id: str,
    offer_digest: str,
    selected_profile: str,
    responder_nonce: str,
    responder_attestation: str,
    issued_at: str,
    extensions: Optional[Mapping[str, str]] = None,
) -> str:
    """The key-derivation transcript digest computed BEFORE the final
    acceptance record exists (responder side): identical bytes to
    :func:`transcript_digest` over the completed record."""
    document = _acceptance_basis_document(
        transport_id,
        offer_digest,
        selected_profile,
        responder_nonce,
        responder_attestation,
        issued_at,
        extensions or {},
    )
    try:
        material = offer.canonical_bytes() + b"\x00" + canonical_json_bytes(document)
    except CanonicalizationError as error:
        raise TransportError(
            TransportReasonCode.INVALID_INPUT,
            "transcript material is not canonically serializable: %s" % error,
        ) from error
    return sha256_hex(material)


# --------------------------------------------------------------------------
# Events
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class TransportEvent:
    """Append-only transport history evidence.

    Every accepted lifecycle change and every security rejection
    produces exactly one event carrying a strictly-monotonic
    per-transport ``sequence``, the injected ``event_instant``, string
    ``reason_code``, and string-pair ``metadata`` (audit evidence for
    privileged/security decisions — architecture section 19).
    """

    event_id: str
    transport_id: str
    sequence: int
    event_type: str
    event_instant: str
    reason_code: str
    metadata: Tuple[Tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        validate_transport_id(self.transport_id)
        validate_sequence(self.sequence, "event.sequence")
        if self.event_type not in TransportEventType.values():
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "event type %r is not in the frozen vocabulary" % self.event_type,
            )
        validate_instant(self.event_instant, "event.event_instant")
        validate_nonempty_str(self.reason_code, "event.reason_code")
        if not isinstance(self.metadata, tuple):
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "event.metadata must be a tuple of string pairs",
            )
        for pair in self.metadata:
            if (
                not isinstance(pair, tuple)
                or len(pair) != 2
                or not isinstance(pair[0], str)
                or not isinstance(pair[1], str)
            ):
                raise TransportError(
                    TransportReasonCode.INVALID_INPUT,
                    "event.metadata must be a tuple of string pairs",
                )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "transport_id": self.transport_id,
            "sequence": self.sequence,
            "event_type": self.event_type,
            "event_instant": self.event_instant,
            "reason_code": self.reason_code,
            "metadata": [[key, value] for key, value in self.metadata],
        }


# --------------------------------------------------------------------------
# Public security state
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class TransportSecurityState:
    """The public, structurally secret-free security state of one
    transport instance.

    Working key material NEVER appears here: only the negotiated
    profile and its declared structural properties, the current key
    generation number, the PUBLIC key-lineage digests (one per
    generation, for audit), and the replay-window bounds.  This is the
    object that may be serialized, logged, or exposed to management —
    it is the adapter-security-state convention applied to transport.
    """

    session_id: str
    initiator_node_id: str
    responder_node_id: str
    profile_id: str
    profile_properties: Mapping[str, Any]
    generation: int
    established_at: str
    last_rekey_at: str
    key_lineage: Tuple[str, ...]
    replay_window_size: int

    def __post_init__(self) -> None:
        validate_nonempty_str(self.session_id, "state.session_id")
        validate_node_id_text(self.initiator_node_id, "state.initiator_node_id")
        validate_node_id_text(self.responder_node_id, "state.responder_node_id")
        validate_profile_id(self.profile_id)
        if not isinstance(self.profile_properties, Mapping):
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "state.profile_properties must be a mapping",
            )
        if isinstance(self.generation, bool) or not isinstance(self.generation, int) or self.generation < 0:
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "state.generation must be a non-negative integer",
            )
        validate_instant(self.established_at, "state.established_at")
        validate_instant(self.last_rekey_at, "state.last_rekey_at")
        if not isinstance(self.key_lineage, tuple):
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "state.key_lineage must be a tuple of public generation digests",
            )
        for digest in self.key_lineage:
            if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{16}", digest) is None:
                raise TransportError(
                    TransportReasonCode.INVALID_INPUT,
                    "state.key_lineage entries must be 16 lowercase hex chars",
                )
        if isinstance(self.replay_window_size, bool) or not isinstance(self.replay_window_size, int) or self.replay_window_size < 1:
            raise TransportError(
                TransportReasonCode.INVALID_INPUT,
                "state.replay_window_size must be a positive integer",
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "initiator_node_id": self.initiator_node_id,
            "responder_node_id": self.responder_node_id,
            "profile_id": self.profile_id,
            "profile_properties": dict(self.profile_properties),
            "generation": self.generation,
            "established_at": self.established_at,
            "last_rekey_at": self.last_rekey_at,
            "key_lineage": list(self.key_lineage),
            "replay_window_size": self.replay_window_size,
        }
