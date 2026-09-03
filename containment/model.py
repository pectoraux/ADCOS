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
from .isolation import (
    MANDATORY_DENIED_PROBE_DESTINATIONS,
    ScopeSpec,
    _envelope_floor_violations,
)
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
        # the deny-by-default floor: a boundary may NEVER declare
        # the control-plane/admin/private destinations reachable
        # (fail closed at record construction — a tampered or
        # deserialized envelope can never widen the floor)
        floor = _envelope_floor_violations(
            self.allowed_egress, self.exposed_local_services,
        )
        if floor:
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "the boundary envelope exposes deny-by-default floor "
                "destinations buyer traffic may never reach (%s); the "
                "boundary record is rejected fail closed" % list(floor),
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
        """The recorded verification proof exists, is content-bound
        to THIS boundary's scope, and carries a live proof epoch
        (epoch 0 = never proven).  Full SEMANTIC validation of the
        recorded proof material against this boundary's declared
        envelope is :meth:`ContainmentProof.proves_boundary` — the
        structural check here is only the first gate."""
        if self.proof_id == "" or self.proof_digest == "" or self.verified_at == "":
            return False
        if self.proof_epoch < 1:
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


def primitive_observation_material(
    scope_ref: str,
    scope_exists: bool,
    allowlist_active: bool,
    deny_probes: Tuple[Dict[str, str], ...],
    observed_at: str,
    mechanism: str,
) -> Dict[str, Any]:
    """The canonical content of the preserved primitive observation
    (the ACTUAL material the durable proof record preserves
    verbatim: the scope binding, the two observation booleans, the
    probe matrix, the observation instant, and the mechanism).

    This is EXACTLY the content the primitive's own
    :meth:`VerificationProof.proof_digest
    <containment.isolation.VerificationProof.proof_digest>` commits
    to: the durable record preserves those observation fields
    verbatim, so the digest of this content MUST equal the record's
    stored ``primitive_proof_digest`` — the digest is content-derived
    from the material, never a freely chosen value."""
    return {
        "scope_ref": scope_ref,
        "scope_exists": scope_exists,
        "allowlist_active": allowlist_active,
        "deny_probes": [
            {
                "destination": probe["destination"],
                "decision": probe["decision"],
                "decided_by": probe["decided_by"],
            }
            for probe in deny_probes
        ],
        "observed_at": observed_at,
        "mechanism": mechanism,
    }


def derive_primitive_material_digest(
    scope_ref: str,
    scope_exists: bool,
    allowlist_active: bool,
    deny_probes: Tuple[Dict[str, str], ...],
    observed_at: str,
    mechanism: str,
) -> str:
    """The INDEPENDENTLY content-derived digest of the actual
    preserved primitive observation fields.

    The tamper-evident chain of a durable proof record is
    ``material -> primitive_proof_digest -> proof_id``: EVERY link
    is recomputable from the record's own fields.  Construction,
    deserialization/restore, and the admission gate all require the
    stored ``primitive_proof_digest`` to equal this digest — a
    tampered durable snapshot cannot mutate the proof material and
    freely re-choose a digest (recomputing the proof id from it) to
    produce a self-consistent forged record."""
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(
            primitive_observation_material(
                scope_ref, scope_exists, allowlist_active,
                deny_probes, observed_at, mechanism,
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

    Tamper-evidence (the frozen integrity chain): the stored
    ``primitive_proof_digest`` MUST be the content-derived digest of
    the record's OWN preserved observation material
    (:meth:`primitive_material_digest`), and the ``proof_id`` MUST
    be derived over that digest — ``material -> digest -> proof_id``
    recomputed link by link at construction, deserialization, and
    the admission gate.  A tampered durable snapshot that mutates
    the proof material and recomputes BOTH the digest and the proof
    id (and the boundary's reference) still fails closed: a digest
    that is not the content-derived digest of the actual preserved
    material can never construct, restore, or admit.
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
        # the frozen primitive probe-record shape: every durable
        # probe entry is EXACTLY destination/decision/decided_by
        # with the mechanism's own decision vocabulary (the record
        # preserves the primitive's DenyProbe values verbatim)
        for probe in self.deny_probes:
            if not isinstance(probe, Mapping):
                raise ContainmentError(
                    ContainmentReasonCode.INVALID_INPUT,
                    "a deny-probe entry must be a mapping (the frozen "
                    "primitive probe record)",
                )
            if set(probe.keys()) != {"destination", "decision", "decided_by"}:
                raise ContainmentError(
                    ContainmentReasonCode.INVALID_INPUT,
                    "a deny-probe entry must carry exactly "
                    "destination/decision/decided_by (the frozen "
                    "primitive probe record shape)",
                )
            if (
                not isinstance(probe["destination"], str)
                or not probe["destination"]
            ):
                raise ContainmentError(
                    ContainmentReasonCode.INVALID_INPUT,
                    "a deny-probe destination must be a non-empty opaque "
                    "destination token",
                )
            if probe["decision"] not in ("denied", "allowed"):
                raise ContainmentError(
                    ContainmentReasonCode.INVALID_INPUT,
                    "a deny-probe decision must be denied|allowed",
                )
            if probe["decided_by"] != "platform-scope":
                raise ContainmentError(
                    ContainmentReasonCode.INVALID_INPUT,
                    "deny-probe decisions come from the platform scope only",
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
        # P0 (PR #139 review round 2): the stored primitive-proof
        # digest is NOT a free variable the proof id merely chains
        # to — it must be the INDEPENDENTLY content-derived digest
        # of the ACTUAL preserved primitive observation fields.  A
        # tampered durable snapshot cannot mutate the proof material
        # and freely choose a new digest (recomputing the proof id
        # from it, and updating the boundary's reference) to produce
        # a self-consistent forged record: the digest is rejected
        # fail closed here, at deserialization/restore, before the
        # id binding is even consulted.
        material_digest = self.primitive_material_digest()
        if self.primitive_proof_digest != material_digest:
            raise ContainmentError(
                ContainmentReasonCode.PROOF_INVALID,
                "the stored primitive-proof digest %s is not the "
                "content-derived digest of the preserved primitive "
                "observation material %s (the digest must be "
                "independently recomputable from the actual scope/"
                "observation/probe fields: a tampered or freely chosen "
                "digest cannot bind a proof id -- fail closed)"
                % (
                    self.primitive_proof_digest[:23],
                    material_digest[:23],
                ),
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

    def primitive_material_digest(self) -> str:
        """The INDEPENDENTLY content-derived digest of THIS record's
        actual preserved primitive observation fields.

        Construction, deserialization/restore, and the admission
        gate all require it to equal the stored
        ``primitive_proof_digest``: the digest is a commitment to the
        preserved material (scope binding, observation booleans,
        probe matrix, instant, mechanism), never an opaque value a
        tampered snapshot may freely re-choose."""
        return derive_primitive_material_digest(
            self.scope_ref, self.scope_exists, self.allowlist_active,
            self.deny_probes, self.observed_at, self.mechanism,
        )

    def proves_boundary(self, boundary: "ContainmentBoundary") -> bool:
        """The proof proves THIS boundary ONLY when it is fully
        bound to the boundary's exact declaration and the probe
        matrix semantically matches the declared envelope:

        - identity binding: the proof's ``boundary_id``, ``scope_ref``
          and ``mechanism`` ARE the boundary's (a proof of another
          boundary, another scope, or another mechanism proves
          nothing here), and the proof epoch is live;
        - the primitive OBSERVED the scope to exist and its egress
          allow-list enforcing;
        - every probe is decided by the platform scope, no
          destination is probed twice, and every decision MATCHES
          the declared semantics: a destination in the boundary's
          declared envelope (allowed egress + exposed local
          services) MUST be ``allowed``; every other probed
          destination MUST be ``denied``;
        - the probe matrix COVERS the declared envelope (an
          unprobed allowed destination proves nothing);
        - deny-by-default is DEMONSTRATED: every frozen
          mandatory-denied floor destination is probed ``denied``.

        A structurally valid proof (well-formed fields, valid
        content-derived id) with a lying, incomplete, or misbound
        probe matrix does NOT prove the boundary."""
        if not isinstance(boundary, ContainmentBoundary):
            return False
        # identity binding: THIS boundary, THIS scope, THIS mechanism
        if self.boundary_id != boundary.boundary_id:
            return False
        if boundary.scope_ref == "" or self.scope_ref != boundary.scope_ref:
            return False
        if self.mechanism != boundary.mechanism:
            return False
        if self.proof_epoch < 1:
            return False
        if not (self.scope_exists and self.allowlist_active):
            return False
        envelope = (
            set(boundary.allowed_egress)
            | set(boundary.exposed_local_services)
        )
        seen: set = set()
        for probe in self.deny_probes:
            if not isinstance(probe, Mapping):
                return False
            decided_by = probe.get("decided_by")
            decision = probe.get("decision")
            destination = probe.get("destination")
            if decided_by != "platform-scope":
                return False
            if decision not in ("denied", "allowed"):
                return False
            if not isinstance(destination, str) or not destination:
                return False
            if destination in seen:
                return False  # a duplicated probe is malformed evidence
            seen.add(destination)
            if destination in envelope:
                if decision != "allowed":
                    return False
            else:
                if decision != "denied":
                    return False
        # coverage: every declared-allowed destination is proved allowed
        if not envelope <= seen:
            return False
        # the deny floor: deny-by-default demonstrated by the mechanism
        for destination in MANDATORY_DENIED_PROBE_DESTINATIONS:
            if destination in envelope:
                return False  # an illegal envelope never proves (defensive)
            if destination not in seen:
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
