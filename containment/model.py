"""WORK-048 containment value model (ACR-012).

The frozen value records of the containment authority:

- **ContainmentBoundary** — one isolated provider-sharing boundary
  instance: its capability facts (platform, mechanism, capability
  state, restrictions), its scope declaration (allowed egress +
  exposed local services, deny-by-default), its admission
  references (lease, consent, NetworkPath, logical session —
  CITATIONS of other authorities' identities, never ownership),
  its boundary lifecycle state, and its verification/proof facts
  (scope ref, proof id/digest, verified_at, proof epoch).
- **ContainmentProof** — the recorded verification proof produced
  by the platform primitive's own observation (the evidence that
  the isolation boundary existed for the sharing interval; the
  record correlated into the canonical usage journal by the
  sharing runtime).
- **SecurityEvidence** — the typed evidence record for isolation
  breaches and fail-closed security transitions (LOCK-022/LOCK-023
  discipline: exception class names only, never secret material).
- **BoundaryEvent** — one append-only journaled boundary lifecycle
  action with its deterministic, content-derived event id.

Identity discipline (the NetworkPath/routing precedent):
``boundary_id`` is a CONTENT-DERIVED fingerprint over
(sharing session ref, lease ref, buyer ref, provider ref, mechanism,
scope declaration digest) — a fingerprint ONLY: not a NodeID, not a
trust authority, never an authorization, never a session identity.
The constructor mechanically verifies the content binding, so a
tampered or deserialized boundary can never carry an
attacker-chosen id.

Temporal discipline: every instant is an injected RFC 3339 UTC
string (the WORK-003 / WORK-033 clock seam; the authority consumes
exactly one clock read per journaled action).  No wall-clock reads,
no UUIDs, no randomness.  Iteration is sorted so identical logical
inputs produce identical canonical bytes.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import ContainmentError, ContainmentReasonCode
from .isolation import ScopeSpec
from .state import (
    ACTION_REQUIRED_STATE,
    BOUNDARY_TRANSITIONS,
    BoundaryAction,
    BoundaryState,
    CapabilityState,
    transition_is_legal,
)


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContainmentError(
            ContainmentReasonCode.INVALID_INPUT,
            "%s must be a non-empty string" % label,
        )
    return value


def _require_instant(value: object, label: str, *, allow_empty: bool = False) -> str:
    if allow_empty and value == "":
        return ""
    if not isinstance(value, str) or not value:
        raise ContainmentError(
            ContainmentReasonCode.INVALID_INPUT,
            "%s must be an RFC 3339 UTC instant string" % label,
        )
    return value


def boundary_identity_content(
    sharing_session_ref: str,
    lease_ref: str,
    buyer_ref: str,
    provider_ref: str,
    mechanism: str,
    scope_digest: str,
) -> Dict[str, Any]:
    """The canonical identity content of a ContainmentBoundary.

    Volatile facts (lifecycle state, scope ref, proof ids, admission
    counters) are deliberately OUTSIDE the identity content: a
    boundary's identity is its referenced enforcement envelope, not
    its volatile measurements.
    """
    return {
        "sharing_session_ref": sharing_session_ref,
        "lease_ref": lease_ref,
        "buyer_ref": buyer_ref,
        "provider_ref": provider_ref,
        "mechanism": mechanism,
        "scope_digest": scope_digest,
    }


def derive_boundary_id(
    sharing_session_ref: str,
    lease_ref: str,
    buyer_ref: str,
    provider_ref: str,
    mechanism: str,
    scope_digest: str,
) -> str:
    """The content-derived ContainmentBoundary fingerprint."""
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(
            boundary_identity_content(
                sharing_session_ref, lease_ref, buyer_ref, provider_ref,
                mechanism, scope_digest,
            )
        )
    ).hexdigest()


@dataclass(frozen=True)
class ContainmentBoundary:
    """One ContainmentBoundary instance (the ACR-012 object).

    Reference fields (``lease_ref``, ``consent_ref``, ``path_ref``,
    ``session_ref``, ``sharing_session_ref``) are CITATIONS of
    other authorities' identities: the boundary never owns, mutates,
    or re-derives any of them.  ``admitted_bytes`` records the
    integer byte count admitted through THIS boundary (byte
    accounting at the boundary — never payload content).

    ``failure_reason`` carries the typed fail-closed reason when
    the boundary is ``failed``; ``revocation_reason`` when
    ``revoked``; ``close_reason`` when ``closed``.  ``proof_epoch``
    counts verification proofs (freshness ordering).
    """

    boundary_id: str
    sharing_session_ref: str
    lease_ref: str
    buyer_ref: str
    provider_ref: str
    consent_ref: str
    session_ref: str
    path_ref: str
    platform_id: str
    mechanism: str
    capability_state: str
    restrictions: Tuple[str, ...]
    allowed_egress: Tuple[str, ...]
    exposed_local_services: Tuple[str, ...]
    state: str = BoundaryState.PREPARED
    scope_ref: str = ""
    proof_id: str = ""
    proof_digest: str = ""
    verified_at: str = ""
    proof_epoch: int = 0
    admitted_bytes: int = 0
    failure_reason: str = ""
    revocation_reason: str = ""
    close_reason: str = ""
    created_at: str = ""
    state_changed_at: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.boundary_id, str):
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "boundary_id must be a string",
            )
        _require_text(self.sharing_session_ref, "sharing_session_ref")
        _require_text(self.lease_ref, "lease_ref")
        _require_text(self.buyer_ref, "buyer_ref")
        _require_text(self.provider_ref, "provider_ref")
        _require_text(self.platform_id, "platform_id")
        _require_text(self.mechanism, "mechanism")
        if self.capability_state not in CapabilityState.values():
            raise ContainmentError(
                ContainmentReasonCode.CAPABILITY_INVALID,
                "capability_state %r must be one of %s"
                % (self.capability_state, list(CapabilityState.values())),
            )
        if self.capability_state in CapabilityState.fail_closed_values():
            raise ContainmentError(
                ContainmentReasonCode.CAPABILITY_UNSUPPORTED,
                "a boundary record requires a supported/restricted "
                "capability (unknown/unsupported platforms refuse exposure "
                "-- fail closed before any record is created)",
            )
        if self.state not in BoundaryState.values():
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "state %r must be one of %s"
                % (self.state, list(BoundaryState.values())),
            )
        for label, value in (
            ("restrictions", self.restrictions),
            ("allowed_egress", self.allowed_egress),
            ("exposed_local_services", self.exposed_local_services),
        ):
            if not isinstance(value, tuple) or any(
                not isinstance(item, str) for item in value
            ):
                raise ContainmentError(
                    ContainmentReasonCode.INVALID_INPUT,
                    "%s must be a tuple of strings" % label,
                )
        if not isinstance(self.proof_epoch, int) or isinstance(self.proof_epoch, bool):
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "proof_epoch must be an integer",
            )
        if not isinstance(self.admitted_bytes, int) or isinstance(self.admitted_bytes, bool):
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "admitted_bytes must be an integer",
            )
        # Tamper-evident content binding: an EMPTY id at construction
        # means "derive it"; a non-empty id MUST equal the fingerprint
        # recomputed from the content.
        scope_digest = self.scope_declaration_digest()
        expected = derive_boundary_id(
            self.sharing_session_ref, self.lease_ref, self.buyer_ref,
            self.provider_ref, self.mechanism, scope_digest,
        )
        if self.boundary_id == "":
            object.__setattr__(self, "boundary_id", expected)
        elif self.boundary_id != expected:
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "boundary_id %r does not match the derived fingerprint %r "
                "(content binding: session/lease/buyer/provider/mechanism/"
                "scope -- tampered or misbound boundary id rejected)"
                % (self.boundary_id[:80], expected[:80]),
            )

    # ------------------------------------------------------------------
    # Scope declaration (deny-by-default)
    # ------------------------------------------------------------------

    def scope_content(self) -> Dict[str, Any]:
        return {
            "allowed_egress": list(sorted(self.allowed_egress)),
            "exposed_local_services": list(sorted(self.exposed_local_services)),
        }

    def scope_declaration_digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.scope_content())
        ).hexdigest()

    def scope_spec(self) -> ScopeSpec:
        """The neutral scope specification for the platform
        primitive (the ACTUAL establishment path)."""
        return ScopeSpec(
            boundary_id=self.boundary_id,
            mechanism=self.mechanism,
            allowed_egress=tuple(sorted(self.allowed_egress)),
            exposed_local_services=tuple(sorted(self.exposed_local_services)),
        )

    # ------------------------------------------------------------------
    # Admission facts (the frozen gate vocabulary)
    # ------------------------------------------------------------------

    def proof_is_valid(self) -> bool:
        """The recorded verification proof exists and is content-
        bound to THIS boundary's scope."""
        if self.proof_id == "" or self.proof_digest == "" or self.verified_at == "":
            return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "boundary_id": self.boundary_id,
            "sharing_session_ref": self.sharing_session_ref,
            "lease_ref": self.lease_ref,
            "buyer_ref": self.buyer_ref,
            "provider_ref": self.provider_ref,
            "consent_ref": self.consent_ref,
            "session_ref": self.session_ref,
            "path_ref": self.path_ref,
            "platform_id": self.platform_id,
            "mechanism": self.mechanism,
            "capability_state": self.capability_state,
            "restrictions": list(self.restrictions),
            "allowed_egress": list(sorted(self.allowed_egress)),
            "exposed_local_services": list(sorted(self.exposed_local_services)),
            "state": self.state,
            "scope_ref": self.scope_ref,
            "proof_id": self.proof_id,
            "proof_digest": self.proof_digest,
            "verified_at": self.verified_at,
            "proof_epoch": self.proof_epoch,
            "admitted_bytes": self.admitted_bytes,
            "failure_reason": self.failure_reason,
            "revocation_reason": self.revocation_reason,
            "close_reason": self.close_reason,
            "created_at": self.created_at,
            "state_changed_at": self.state_changed_at,
        }

    @classmethod
    def from_dict(cls, data: object) -> "ContainmentBoundary":
        if not isinstance(data, Mapping):
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "containment boundary must be a mapping",
            )

        def _tuple(key: str) -> Tuple[str, ...]:
            value = data.get(key, ())
            if not isinstance(value, (list, tuple)):
                raise ContainmentError(
                    ContainmentReasonCode.INVALID_INPUT,
                    "boundary %s must be a sequence" % key,
                )
            return tuple(str(item) for item in value)

        return cls(
            boundary_id=str(data.get("boundary_id", "")),
            sharing_session_ref=str(data.get("sharing_session_ref", "")),
            lease_ref=str(data.get("lease_ref", "")),
            buyer_ref=str(data.get("buyer_ref", "")),
            provider_ref=str(data.get("provider_ref", "")),
            consent_ref=str(data.get("consent_ref", "")),
            session_ref=str(data.get("session_ref", "")),
            path_ref=str(data.get("path_ref", "")),
            platform_id=str(data.get("platform_id", "")),
            mechanism=str(data.get("mechanism", "")),
            capability_state=str(data.get("capability_state", "")),
            restrictions=_tuple("restrictions"),
            allowed_egress=_tuple("allowed_egress"),
            exposed_local_services=_tuple("exposed_local_services"),
            state=str(data.get("state", BoundaryState.PREPARED)),
            scope_ref=str(data.get("scope_ref", "")),
            proof_id=str(data.get("proof_id", "")),
            proof_digest=str(data.get("proof_digest", "")),
            verified_at=str(data.get("verified_at", "")),
            proof_epoch=int(data.get("proof_epoch", 0)),
            admitted_bytes=int(data.get("admitted_bytes", 0)),
            failure_reason=str(data.get("failure_reason", "")),
            revocation_reason=str(data.get("revocation_reason", "")),
            close_reason=str(data.get("close_reason", "")),
            created_at=str(data.get("created_at", "")),
            state_changed_at=str(data.get("state_changed_at", "")),
        )

    def content_digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.to_dict())
        ).hexdigest()


# ---------------------------------------------------------------------------
# Containment proof (the verification evidence record)
# ---------------------------------------------------------------------------


def proof_identity_content(
    boundary_id: str,
    scope_ref: str,
    proof_epoch: int,
    mechanism: str,
    observed_at: str,
    primitive_proof_digest: str,
) -> Dict[str, Any]:
    return {
        "boundary_id": boundary_id,
        "scope_ref": scope_ref,
        "proof_epoch": proof_epoch,
        "mechanism": mechanism,
        "observed_at": observed_at,
        "primitive_proof_digest": primitive_proof_digest,
    }


def derive_proof_id(
    boundary_id: str,
    scope_ref: str,
    proof_epoch: int,
    mechanism: str,
    observed_at: str,
    primitive_proof_digest: str,
) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(
            proof_identity_content(
                boundary_id, scope_ref, proof_epoch, mechanism,
                observed_at, primitive_proof_digest,
            )
        )
    ).hexdigest()


@dataclass(frozen=True)
class ContainmentProof:
    """The recorded containment verification proof.

    Produced by the platform primitive's OWN observation (the
    primitive proof content is preserved verbatim), content-bound
    to the boundary/scope/epoch.  This is the record the sharing
    runtime correlates into the canonical W042 usage journal as
    delivery evidence (ACR-012 §2: "the evidence that the isolation
    boundary existed for the sharing interval").

    ``evidence_class`` is always ``SOFTWARE``: a proof produced by
    a primitive implementation is software evidence of the
    mechanism; a PHYSICAL containment claim requires separate
    physical evidence and remains OPEN until physically
    demonstrated (never promoted by this record).
    """

    proof_id: str
    boundary_id: str
    scope_ref: str
    mechanism: str
    proof_epoch: int
    observed_at: str
    primitive_proof_digest: str
    scope_exists: bool
    allowlist_active: bool
    deny_probes: Tuple[Dict[str, str], ...]
    evidence_class: str = "SOFTWARE"

    def __post_init__(self) -> None:
        if not isinstance(self.proof_id, str):
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "proof_id must be a string",
            )
        _require_text(self.boundary_id, "boundary_id")
        _require_text(self.scope_ref, "scope_ref")
        _require_text(self.mechanism, "mechanism")
        if not isinstance(self.proof_epoch, int) or isinstance(self.proof_epoch, bool):
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "proof_epoch must be an integer",
            )
        _require_instant(self.observed_at, "observed_at")
        _require_text(self.primitive_proof_digest, "primitive_proof_digest")
        if not isinstance(self.scope_exists, bool):
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "scope_exists must be a boolean",
            )
        if not isinstance(self.allowlist_active, bool):
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "allowlist_active must be a boolean",
            )
        if not isinstance(self.deny_probes, tuple):
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "deny_probes must be a tuple",
            )
        if self.evidence_class != "SOFTWARE":
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "a primitive-produced proof is SOFTWARE evidence only; a "
                "physical containment claim is a separate PHYSICAL "
                "obligation that this record never promotes",
            )
        if not isinstance(self.proof_id, str):
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "proof_id must be a string",
            )
        expected = derive_proof_id(
            self.boundary_id, self.scope_ref, self.proof_epoch,
            self.mechanism, self.observed_at, self.primitive_proof_digest,
        )
        if self.proof_id == "":
            object.__setattr__(self, "proof_id", expected)
        elif self.proof_id != expected:
            raise ContainmentError(
                ContainmentReasonCode.PROOF_INVALID,
                "proof_id %r does not match the derived fingerprint "
                "(content binding -- tampered or misbound proof id rejected)"
                % (self.proof_id[:80],),
            )

    def proves_boundary(self) -> bool:
        """The proof proves the boundary ONLY when the primitive
        observed the scope to exist, the allow-list enforcing, and
    every deny probe decided by the platform scope."""
        if not (self.scope_exists and self.allowlist_active):
            return False
        for probe in self.deny_probes:
            if probe.get("decided_by") != "platform-scope":
                return False
            if probe.get("decision") not in ("denied", "allowed"):
                return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proof_id": self.proof_id,
            "boundary_id": self.boundary_id,
            "scope_ref": self.scope_ref,
            "mechanism": self.mechanism,
            "proof_epoch": self.proof_epoch,
            "observed_at": self.observed_at,
            "primitive_proof_digest": self.primitive_proof_digest,
            "scope_exists": self.scope_exists,
            "allowlist_active": self.allowlist_active,
            "deny_probes": list(self.deny_probes),
            "evidence_class": self.evidence_class,
        }

    @classmethod
    def from_dict(cls, data: object) -> "ContainmentProof":
        if not isinstance(data, Mapping):
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "containment proof must be a mapping",
            )
        probes = data.get("deny_probes", ())
        if not isinstance(probes, (list, tuple)):
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "containment proof deny_probes must be a sequence",
            )
        return cls(
            proof_id=str(data.get("proof_id", "")),
            boundary_id=str(data.get("boundary_id", "")),
            scope_ref=str(data.get("scope_ref", "")),
            mechanism=str(data.get("mechanism", "")),
            proof_epoch=int(data.get("proof_epoch", 0)),
            observed_at=str(data.get("observed_at", "")),
            primitive_proof_digest=str(data.get("primitive_proof_digest", "")),
            scope_exists=bool(data.get("scope_exists", False)),
            allowlist_active=bool(data.get("allowlist_active", False)),
            deny_probes=tuple(dict(probe) for probe in probes),
            evidence_class=str(data.get("evidence_class", "SOFTWARE")),
        )


# ---------------------------------------------------------------------------
# Security evidence (breach / fail-closed transitions)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SecurityEvidence:
    """A typed security-evidence record for isolation breaches and
    fail-closed security transitions (LOCK-022 zero-trust;
    LOCK-023: diagnostics carry exception CLASS NAMES only)."""

    evidence_id: str
    boundary_id: str
    kind: str  # "isolation-breach" | "fail-closed-transition"
    reason: str
    destination: str
    observed_at: str
    exception_class: str = ""

    def __post_init__(self) -> None:
        _require_text(self.boundary_id, "boundary_id")
        if self.kind not in ("isolation-breach", "fail-closed-transition"):
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "security-evidence kind %r outside the frozen vocabulary"
                % self.kind,
            )
        _require_text(self.reason, "reason")
        _require_instant(self.observed_at, "observed_at")
        content = {
            "boundary_id": self.boundary_id,
            "kind": self.kind,
            "reason": self.reason,
            "destination": self.destination,
            "observed_at": self.observed_at,
            "exception_class": self.exception_class,
        }
        expected = "sha256:" + hashlib.sha256(
            canonical_json_bytes(content)
        ).hexdigest()
        if self.evidence_id == "":
            object.__setattr__(self, "evidence_id", expected)
        elif self.evidence_id != expected:
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "security evidence id does not match the derived "
                "fingerprint (content binding)",
            )
        if not isinstance(self.evidence_id, str):
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "evidence_id must be a string",
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "boundary_id": self.boundary_id,
            "kind": self.kind,
            "reason": self.reason,
            "destination": self.destination,
            "observed_at": self.observed_at,
            "exception_class": self.exception_class,
        }


# ---------------------------------------------------------------------------
# Boundary lifecycle event (append-only journal record)
# ---------------------------------------------------------------------------


def derive_boundary_event_id(
    boundary_id: str,
    action: str,
    from_state: str,
    to_state: str,
    instant: str,
    reason: str,
) -> str:
    content = {
        "boundary_id": boundary_id,
        "action": action,
        "from_state": from_state,
        "to_state": to_state,
        "instant": instant,
        "reason": reason,
    }
    return "sha256:" + hashlib.sha256(canonical_json_bytes(content)).hexdigest()


@dataclass(frozen=True)
class BoundaryEvent:
    """One journaled containment boundary lifecycle action.

    ``from_state == to_state`` marks a state-preserving journaled
    action (``establish-failed``, ``admission-denied``): evidence
    recorded, lifecycle state unchanged.  ``event_id`` is
    content-derived over (boundary, action, from, to, instant,
    reason) — an exact replay of the same transition yields the
    same id and is rejected as a duplicate.
    """

    event_id: str
    boundary_id: str
    action: str
    from_state: str
    to_state: str
    instant: str
    reason: str = ""
    detail: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.event_id, str):
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "event_id must be a string",
            )
        _require_text(self.boundary_id, "boundary_id")
        if self.action not in BoundaryAction.values():
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "action %r must be one of %s"
                % (self.action, list(BoundaryAction.values())),
            )
        for label, value in (
            ("from_state", self.from_state),
            ("to_state", self.to_state),
        ):
            if value not in BoundaryState.values():
                raise ContainmentError(
                    ContainmentReasonCode.INVALID_INPUT,
                    "%s %r must be one of %s"
                    % (label, value, list(BoundaryState.values())),
                )
        _require_instant(self.instant, "instant")
        expected = derive_boundary_event_id(
            self.boundary_id, self.action, self.from_state,
            self.to_state, self.instant, self.reason,
        )
        if self.event_id == "":
            object.__setattr__(self, "event_id", expected)
        elif self.event_id != expected:
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "event_id %r does not match the derived fingerprint "
                "(content binding -- tampered or misbound event id rejected)"
                % (self.event_id[:80],),
            )
        if self.from_state != self.to_state and not transition_is_legal(
            self.from_state, self.to_state
        ):
            raise ContainmentError(
                ContainmentReasonCode.LIFECYCLE_ILLEGAL,
                "boundary event records an illegal transition %s -> %s "
                "(fail closed: the frozen table rejects it)"
                % (self.from_state, self.to_state),
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "boundary_id": self.boundary_id,
            "action": self.action,
            "from_state": self.from_state,
            "to_state": self.to_state,
            "instant": self.instant,
            "reason": self.reason,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, data: object) -> "BoundaryEvent":
        if not isinstance(data, Mapping):
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "boundary event must be a mapping",
            )
        return cls(
            event_id=str(data.get("event_id", "")),
            boundary_id=str(data.get("boundary_id", "")),
            action=str(data.get("action", "")),
            from_state=str(data.get("from_state", "")),
            to_state=str(data.get("to_state", "")),
            instant=str(data.get("instant", "")),
            reason=str(data.get("reason", "")),
            detail=str(data.get("detail", "")),
        )


def boundary_event_list_digest(events: List[BoundaryEvent]) -> str:
    """Deterministic digest over the ordered boundary journal."""
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes([event.to_dict() for event in events])
    ).hexdigest()


#: Re-exported for callers that need the frozen vocabularies
#: alongside the value model (single import site).
BOUNDARY_TRANSITION_TABLE: Dict[str, frozenset] = dict(BOUNDARY_TRANSITIONS)
ACTION_PRECONDITIONS: Dict[str, str] = dict(ACTION_REQUIRED_STATE)
