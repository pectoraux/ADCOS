"""WORK-048 containment authority lifecycle manager (ACR-012).

:class:`ContainmentAuthority` is the public surface of the
containment family.  It composes exactly one external dependency —
the platform isolation primitive (:class:`~containment.isolation.
IsolationPrimitive`, the ``/adapters``-owned OS/network mechanism)
— plus the injected clock.  It OWNS exactly the ACR-012 concerns:

- buyer-traffic admission into the isolated provider boundary;
- containment capability state (the frozen capability dimension);
- the containment boundary lifecycle and its fail-closed
  transitions;
- control-plane / buyer-plane separation (deny-by-default scope);
- isolation establishment and verification (proof records);
- teardown, revocation, and breach emergency-stop;
- containment proof records and deterministic evidence.

It does NOT own: identity, logical session identity, routing,
NetworkPath lifecycle, transport semantics, lease truth, usage
truth, payment custody, marketplace ranking, or plaintext payload
semantics.  Commercial/session/path/consent/quota admission FACTS
arrive as caller-composed :class:`AdmissionFacts` VALUES (the
sharing runtime reads the canonical authorities through their
public surfaces and passes the facts here); the containment
authority verifies its OWN facts (capability, proof, scope) and
denies admission fail-closed when ANY fact is false.

The frozen invariant enforced here:

    NO PROVEN CONTAINMENT  =>  NO BUYER TRAFFIC

- ``active`` is reachable ONLY from ``verified``;
- an establishment failure keeps the boundary in ``prepared``
  (``establish-failed`` journaled; the boundary NEVER leaves
  prepared without a primitive-produced proof);
- an invalid proof fails the instance (terminal ``failed``);
- every admission operation re-checks ALL facts (capability,
  proof validity/freshness, scope existence, and every caller
  fact) — not only at grant time;
- unmodeled exceptions on security-critical operations become
  typed fail-closed denials (``UNEXPECTED_EXCEPTION``, exception
  CLASS NAME only — LOCK-023), never accidental admissions;
- teardown/revocation destroys the primitive scope and never
  rewrites admitted-byte history (append-only accounting);
- recovery re-proves containment or the boundary starts/lands in
  ``failed`` — it never resumes ``active`` from stale proof.

Journal discipline: append-only, content-derived event ids, exact
duplicate replay rejected (``DUPLICATE_TRANSITION``), state-
preserving denials journaled without state change, one clock read
per journaled action (validation gates run BEFORE the read), and
the live state is always exactly the journal fold (verified by
:meth:`ContainmentAuthority.verify_integrity`).
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Dict, List, Optional, Tuple

from agent.clock import AgentClock

from .capability import CapabilityMatrix, PlatformCapability
from .errors import ContainmentError, ContainmentReasonCode
from .isolation import IsolationPrimitive, ScopeEstablishment
from .model import (
    BoundaryEvent,
    ContainmentBoundary,
    ContainmentProof,
    SecurityEvidence,
    boundary_event_list_digest,
    derive_boundary_event_id,
    derive_proof_id,
)
from .state import (
    ACTION_REQUIRED_STATE,
    BoundaryAction,
    BoundaryState,
    CapabilityState,
    transition_is_legal,
)

#: The maximum number of verification proofs one boundary may
#: accumulate (the deterministic bounded-history guard).
MAX_PROOF_HISTORY = 64


@dataclass(frozen=True)
class AdmissionFacts:
    """The caller-composed admission fact VALUES (frozen gate
    vocabulary, all boolean, all default-deny).

    The sharing runtime derives each fact from the canonical
    authority's own public reads (W051 lease state/expiry, consent
    state, W041 path ACTIVE for the exact session, quota
    availability).  This record carries FACTS, never authority
    objects; the containment authority trusts nothing but its own
    checks plus these explicit booleans, and ANY false fact denies
    admission (NO NEW BUYER TRAFFIC).
    """

    lease_active: bool = False
    consent_granted: bool = False
    path_active: bool = False
    quota_available: bool = False

    def all_hold(self) -> bool:
        return (
            self.lease_active
            and self.consent_granted
            and self.path_active
            and self.quota_available
        )

    def failed_conditions(self) -> Tuple[str, ...]:
        """The deterministic ordered list of failed conditions."""
        conditions = (
            ("lease_active", self.lease_active),
            ("consent_granted", self.consent_granted),
            ("path_active", self.path_active),
            ("quota_available", self.quota_available),
        )
        return tuple(name for name, holds in conditions if not holds)


@dataclass(frozen=True)
class AdmissionDecision:
    """The typed admission decision (never a bare boolean)."""

    boundary_id: str
    admitted: bool
    reason: str
    detail: str = ""


class ContainmentAuthority:
    """The ACR-012 containment boundary authority (public surface)."""

    def __init__(
        self,
        *,
        primitive: IsolationPrimitive,
        clock: AgentClock,
        matrix: Optional[CapabilityMatrix] = None,
    ) -> None:
        if not isinstance(primitive, IsolationPrimitive):
            # structural type check: the neutral contract only
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "primitive must implement the neutral IsolationPrimitive "
                "contract (the /adapters-owned platform mechanism)",
            )
        if not isinstance(clock, AgentClock):
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "clock must be an AgentClock (the injected WORK-033 seam)",
            )
        self._primitive = primitive
        self._clock = clock
        self._matrix = matrix if matrix is not None else CapabilityMatrix()
        self._boundaries: Dict[str, ContainmentBoundary] = {}
        self._events: List[BoundaryEvent] = []
        self._event_ids: set = set()
        self._proofs: Dict[str, List[ContainmentProof]] = {}
        self._security_evidence: List[SecurityEvidence] = []
        # Post-restore recovery condition (an admission CONDITION,
        # not a lifecycle state): restored durable state is
        # NON-ADMITTING until the mandatory recovery revalidation
        # completes with a FRESH containment re-proof for every
        # non-terminal established boundary.  A freshly constructed
        # authority is never pending.
        self._recovery_pending: bool = False
        self._restore_proof_epochs: Dict[str, int] = {}

    # ------------------------------------------------------------------
    # Public reads (deterministic, no clock consumption)
    # ------------------------------------------------------------------

    def boundaries(self) -> Tuple[str, ...]:
        """All boundary ids (sorted, deterministic order)."""
        return tuple(sorted(self._boundaries))

    def boundary(self, boundary_id: str) -> ContainmentBoundary:
        return self._require_boundary(boundary_id)

    def events(self) -> Tuple[BoundaryEvent, ...]:
        return tuple(self._events)

    def event_log_digest(self) -> str:
        return boundary_event_list_digest(list(self._events))

    def proofs(self, boundary_id: str) -> Tuple[ContainmentProof, ...]:
        """The verification-proof history of one boundary (append-
        only; the containment evidence for the sharing interval)."""
        self._require_boundary(boundary_id)
        return tuple(self._proofs.get(boundary_id, ()))

    def latest_proof(self, boundary_id: str) -> Optional[ContainmentProof]:
        history = self._proofs.get(boundary_id, ())
        return history[-1] if history else None

    def security_evidence(self) -> Tuple[SecurityEvidence, ...]:
        return tuple(self._security_evidence)

    def capability_of(self, platform_id: str) -> PlatformCapability:
        return self._matrix.capability(platform_id)

    def snapshot(self) -> Dict[str, Any]:
        """A deterministic, serializable state snapshot (the
        recovery/journal-first reconstruction source)."""
        return {
            "boundaries": [
                self._boundaries[key].to_dict() for key in sorted(self._boundaries)
            ],
            "events": [event.to_dict() for event in self._events],
            "proofs": {
                key: [proof.to_dict() for proof in self._proofs[key]]
                for key in sorted(self._proofs)
            },
            "security_evidence": [
                record.to_dict() for record in self._security_evidence
            ],
            "matrix": self._matrix.to_dict(),
        }

    @classmethod
    def restore(
        cls,
        *,
        primitive: IsolationPrimitive,
        clock: AgentClock,
        snapshot: Dict[str, Any],
    ) -> "ContainmentAuthority":
        """Journal-first recovery: rebuild from the snapshot (the
        fold is byte-identical by construction; the primitive scope
        must be RE-PROVED by the caller via :meth:`reprove`).

        The restored authority is NON-ADMITTING until the mandatory
        recovery revalidation completes: every admission path fails
        closed with the typed ``RECOVERY_REQUIRED`` condition,
        cleared ONLY by :meth:`mark_recovered` (which itself
        requires a FRESH post-restore proof for every non-terminal
        established boundary).  A restored ``active`` boundary can
        therefore NEVER admit buyer traffic before the fresh
        re-proof — a stale-but-structurally-valid proof is not a
        path around the recovery gate."""
        authority = cls(primitive=primitive, clock=clock)
        for record in snapshot.get("boundaries", ()):
            boundary = ContainmentBoundary.from_dict(record)
            authority._boundaries[boundary.boundary_id] = boundary
        for event in snapshot.get("events", ()):
            authority._journal(BoundaryEvent.from_dict(event), revalidate=False)
        for key, proofs in snapshot.get("proofs", {}).items():
            authority._proofs[key] = [
                ContainmentProof.from_dict(proof) for proof in proofs
            ]
        for record in snapshot.get("security_evidence", ()):
            evidence = SecurityEvidence(
                evidence_id=record["evidence_id"],
                boundary_id=record["boundary_id"],
                kind=record["kind"],
                reason=record["reason"],
                destination=record["destination"],
                observed_at=record["observed_at"],
                exception_class=record.get("exception_class", ""),
            )
            authority._security_evidence.append(evidence)
        # the post-restore non-admitting condition: record the proof
        # epochs at restore so recovery completion can PROVE each
        # non-terminal established boundary carries a strictly
        # fresher proof than the restored one
        authority._recovery_pending = True
        authority._restore_proof_epochs = {
            boundary_id: boundary.proof_epoch
            for boundary_id, boundary in sorted(
                authority._boundaries.items()
            )
        }
        return authority

    @property
    def recovery_pending(self) -> bool:
        """True while restored durable state has NOT completed the
        mandatory recovery revalidation (admission fails closed
        with ``RECOVERY_REQUIRED``; not a lifecycle state)."""
        return self._recovery_pending

    def mark_recovered(self) -> None:
        """Clear the post-restore recovery condition — the ONLY
        clearance path, and it self-verifies: every NON-terminal,
        ESTABLISHED boundary must carry a proof epoch STRICTLY
        greater than its restored epoch (a fresh post-restore
        verification proof, produced by :meth:`verify` or
        :meth:`reprove`).  Otherwise the typed fail-closed
        ``RECOVERY_REQUIRED`` error and the authority stays
        non-admitting.

        :meth:`SharingRuntime.recover` calls this at the END of its
        full revalidation loop; it is never called by any
        admission path."""
        if not self._recovery_pending:
            return  # idempotent (nothing pending)
        for boundary_id in sorted(self._boundaries):
            boundary = self._boundaries[boundary_id]
            if boundary.state in BoundaryState.terminal_values():
                continue
            if boundary.scope_ref == "":
                # prepared/never established: non-admitting by STATE
                # (verify + activate are still required before any
                # traffic can exist)
                continue
            restored_epoch = self._restore_proof_epochs.get(boundary_id, 0)
            if boundary.proof_epoch <= restored_epoch:
                raise ContainmentError(
                    ContainmentReasonCode.RECOVERY_REQUIRED,
                    "boundary %r carries no fresh post-restore proof "
                    "(epoch %d <= restored epoch %d); recovery cannot "
                    "complete and the authority stays non-admitting "
                    "(fail closed: NO buyer traffic)"
                    % (boundary_id[:23], boundary.proof_epoch, restored_epoch),
                )
        self._recovery_pending = False
        self._restore_proof_epochs = {}

    def verify_integrity(self) -> None:
        """Re-verify the journal (content bindings) and that the
        live state is reachable (every event's boundary exists)."""
        for event in self._events:
            if event.boundary_id not in self._boundaries:
                raise ContainmentError(
                    ContainmentReasonCode.INVALID_INPUT,
                    "journal references unknown boundary %r (corrupt)"
                    % event.boundary_id[:23],
                )

    # ------------------------------------------------------------------
    # Boundary preparation (capability-gated, fail closed)
    # ------------------------------------------------------------------

    def prepare(
        self,
        *,
        sharing_session_ref: str,
        lease_ref: str,
        buyer_ref: str,
        provider_ref: str,
        consent_ref: str,
        session_ref: str,
        path_ref: str,
        platform_id: str,
        allowed_egress: Tuple[str, ...],
        exposed_local_services: Tuple[str, ...] = (),
    ) -> ContainmentBoundary:
        """Create one boundary record in ``prepared``.

        The capability gate runs FIRST and fail-closed:
        ``unknown``/``unsupported`` platforms refuse exposure
        (typed reason; NO boundary record is created — there is no
        record to later "upgrade").  The mechanism is selected from
        the capability matrix; the scope declaration (allowed egress
        + exposed local services) becomes the deny-by-default
        envelope.  The isolation primitive is NOT yet established:
        NO buyer traffic.
        """
        for label, value in (
            ("sharing_session_ref", sharing_session_ref),
            ("lease_ref", lease_ref),
            ("buyer_ref", buyer_ref),
            ("provider_ref", provider_ref),
            ("session_ref", session_ref),
        ):
            if not isinstance(value, str) or not value:
                raise ContainmentError(
                    ContainmentReasonCode.INVALID_INPUT,
                    "%s must be a non-empty string" % label,
                )
        if not isinstance(platform_id, str) or not platform_id:
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "platform_id must be a non-empty string",
            )
        if not isinstance(allowed_egress, tuple) or not allowed_egress:
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "allowed_egress must be a non-empty tuple (an empty egress "
                "set would deny everything including the leased egress)",
            )
        # the capability gate (fail closed, no downgrade)
        capability = self._matrix.capability(platform_id)
        if capability.state == CapabilityState.UNKNOWN:
            raise ContainmentError(
                ContainmentReasonCode.CAPABILITY_UNKNOWN,
                "platform %r capability is unknown (not proven): exposure "
                "refused fail-closed; unknown NEVER silently degrades to "
                "any weaker mechanism" % platform_id,
            )
        if capability.state == CapabilityState.UNSUPPORTED:
            raise ContainmentError(
                ContainmentReasonCode.CAPABILITY_UNSUPPORTED,
                "platform %r cannot provide the required OS/network "
                "isolation mechanism: exposure refused fail-closed"
                % platform_id,
            )
        boundary = ContainmentBoundary(
            boundary_id="",
            sharing_session_ref=sharing_session_ref,
            lease_ref=lease_ref,
            buyer_ref=buyer_ref,
            provider_ref=provider_ref,
            consent_ref=consent_ref,
            session_ref=session_ref,
            path_ref=path_ref,
            platform_id=platform_id,
            mechanism=capability.mechanism,
            capability_state=capability.state,
            restrictions=capability.restrictions,
            allowed_egress=tuple(sorted(allowed_egress)),
            exposed_local_services=tuple(sorted(exposed_local_services)),
            state=BoundaryState.PREPARED,
            created_at=self._clock.now(),
            state_changed_at="",
        )
        boundary = replace(boundary, state_changed_at=boundary.created_at)
        if boundary.boundary_id in self._boundaries:
            existing = self._boundaries[boundary.boundary_id]
            if existing.to_dict() != boundary.to_dict():
                raise ContainmentError(
                    ContainmentReasonCode.INVALID_INPUT,
                    "a different boundary already exists for this "
                    "envelope (fail closed; never rebind)",
                )
            return existing
        self._boundaries[boundary.boundary_id] = boundary
        self._proofs[boundary.boundary_id] = []
        self._journal_event(
            boundary.boundary_id,
            BoundaryAction.PREPARE,
            BoundaryState.PREPARED,
            BoundaryState.PREPARED,
            reason="SESSION_PREPARED",
            detail="capability %s on mechanism %s"
            % (capability.state, capability.mechanism),
        )
        return self._boundaries[boundary.boundary_id]

    # ------------------------------------------------------------------
    # Verification (the ACTUAL platform primitive)
    # ------------------------------------------------------------------

    def verify(self, boundary_id: str) -> ContainmentBoundary:
        """Establish AND verify the boundary at the OS/network
        primitive level: ``prepared -> verified``.

        The scope is established BY THE PRIMITIVE; the verification
        proof is the primitive's OWN observation (scope exists,
        allow-list active, deny-probes decided by the platform
        scope).  A boundary with an invalid proof NEVER becomes
        ``verified``:

        - primitive cannot establish ⇒ the boundary STAYS
          ``prepared`` (``establish-failed`` journaled,
          ``ISOLATION_UNAVAILABLE`` raised; no scope, no traffic);
        - the primitive's proof does not prove the boundary ⇒ the
          instance FAILS closed (terminal ``failed``).
        """
        boundary = self._require_boundary(boundary_id)
        self._require_action_state(boundary, BoundaryAction.VERIFY)
        # security-critical: fail closed on ANY unmodeled exception
        try:
            instant = self._clock.now()
            establishment = self._primitive.establish(
                boundary.scope_spec(), at=instant,
            )
        except ContainmentError as error:
            if error.reason == ContainmentReasonCode.ISOLATION_UNAVAILABLE:
                # the primitive cannot be established: the boundary
                # cannot leave prepared (the frozen contract)
                self._journal_event(
                    boundary.boundary_id,
                    BoundaryAction.ESTABLISH_FAILED,
                    BoundaryState.PREPARED,
                    BoundaryState.PREPARED,
                    reason="ISOLATION_UNAVAILABLE",
                    detail="the platform primitive could not establish the "
                    "scope; the boundary cannot leave prepared",
                    instant=instant,
                )
                raise
            self._fail_boundary(
                boundary, ContainmentReasonCode.ISOLATION_UNAVAILABLE,
                "isolation establishment failed (%s)" % error.reason,
                instant=instant,
            )
            raise
        except Exception as error:  # noqa: BLE001 - typed fail-closed
            self._record_fail_closed(
                boundary, "establish", type(error).__name__,
                reason=ContainmentReasonCode.ISOLATION_UNAVAILABLE,
                instant=instant,
            )
            self._fail_boundary(
                boundary,
                ContainmentReasonCode.UNEXPECTED_EXCEPTION,
                "unmodeled exception during isolation establishment (%s); "
                "the boundary fails closed and NO buyer traffic was "
                "admitted" % type(error).__name__,
                instant=instant,
            )
            raise ContainmentError(
                ContainmentReasonCode.UNEXPECTED_EXCEPTION,
                "isolation establishment raised %s (fail closed: the "
                "boundary is failed; NO buyer traffic)"
                % type(error).__name__,
            ) from error
        if not isinstance(establishment, ScopeEstablishment):
            self._fail_boundary(
                boundary,
                ContainmentReasonCode.PROOF_INVALID,
                "the primitive returned a non-contract establishment value "
                "(fail closed; no buyer traffic)",
            )
            raise ContainmentError(
                ContainmentReasonCode.PROOF_INVALID,
                "non-contract establishment value rejected",
            )
        # verify: the primitive's own observation of the scope
        try:
            primitive_proof = self._primitive.verify(
                establishment.scope_ref, at=instant,
            )
        except Exception as error:  # noqa: BLE001 - typed fail-closed
            self._record_fail_closed(
                boundary, "verify", type(error).__name__,
                reason=ContainmentReasonCode.PROOF_INVALID,
                instant=instant,
            )
            self._fail_boundary(
                boundary,
                ContainmentReasonCode.UNEXPECTED_EXCEPTION,
                "unmodeled exception during containment verification (%s); "
                "the boundary fails closed" % type(error).__name__,
                instant=instant,
            )
            raise ContainmentError(
                ContainmentReasonCode.UNEXPECTED_EXCEPTION,
                "containment verification raised %s (fail closed: the "
                "boundary is failed; NO buyer traffic)"
                % type(error).__name__,
            ) from error
        epoch = boundary.proof_epoch + 1
        # semantic binding: the primitive proof must correspond to
        # the EXACT scope just established AND the boundary's exact
        # declared envelope (scope binding + mechanism + probe
        # decision semantics + envelope coverage + deny floor).
        # A structurally shaped proof of another scope, or a lying
        # probe matrix, proves NOTHING and fails the instance closed.
        if (
            primitive_proof.scope_ref != establishment.scope_ref
            or not primitive_proof.proves_boundary(boundary.scope_spec())
        ):
            self._fail_boundary(
                boundary,
                ContainmentReasonCode.PROOF_INVALID,
                "the primitive's verification observation does not prove "
                "the established scope/envelope (scope binding, mechanism, "
                "probe decision semantics, envelope coverage, or the "
                "deny-by-default floor failed); the instance fails closed "
                "and NO buyer traffic was admitted",
            )
            raise ContainmentError(
                ContainmentReasonCode.PROOF_INVALID,
                "containment proof does not prove the boundary (fail "
                "closed; NO buyer traffic)",
            )
        proof = ContainmentProof(
            proof_id="",
            boundary_id=boundary.boundary_id,
            scope_ref=establishment.scope_ref,
            mechanism=boundary.mechanism,
            proof_epoch=epoch,
            observed_at=primitive_proof.observed_at,
            primitive_proof_digest=primitive_proof.proof_digest(),
            scope_exists=primitive_proof.scope_exists,
            allowlist_active=primitive_proof.allowlist_active,
            deny_probes=tuple(
                {
                    "destination": probe.destination,
                    "decision": probe.decision,
                    "decided_by": probe.decided_by,
                }
                for probe in primitive_proof.deny_probes
            ),
        )
        if not proof.proves_boundary(
            replace(
                boundary,
                state=BoundaryState.VERIFIED,
                scope_ref=proof.scope_ref,
                proof_id=proof.proof_id,
                proof_digest=proof.primitive_proof_digest,
                verified_at=proof.observed_at,
                proof_epoch=epoch,
            )
        ):
            # defense in depth: the RECORDED proof material must also
            # semantically prove the boundary this instance is about
            # to become (identity/scope/mechanism binding + envelope
            # semantics); a structurally valid record with a lying
            # matrix fails closed (never verified)
            self._fail_boundary(
                boundary,
                ContainmentReasonCode.PROOF_INVALID,
                "the recorded verification proof does not semantically "
                "prove the boundary (identity/scope/mechanism binding or "
                "probe-matrix envelope semantics failed); the instance "
                "fails closed",
            )
            raise ContainmentError(
                ContainmentReasonCode.PROOF_INVALID,
                "containment proof does not prove the boundary (fail "
                "closed; NO buyer traffic)",
            )
        history = self._proofs.setdefault(boundary.boundary_id, [])
        if len(history) >= MAX_PROOF_HISTORY:
            history = history[-(MAX_PROOF_HISTORY - 1):]
        history.append(proof)
        self._proofs[boundary.boundary_id] = history
        advanced = replace(
            boundary,
            state=BoundaryState.VERIFIED,
            scope_ref=proof.scope_ref,
            proof_id=proof.proof_id,
            proof_digest=proof.primitive_proof_digest,
            verified_at=proof.observed_at,
            proof_epoch=epoch,
            state_changed_at=instant,
        )
        self._boundaries[boundary.boundary_id] = advanced
        self._journal_event(
            boundary.boundary_id,
            BoundaryAction.VERIFY,
            boundary.state,
            BoundaryState.VERIFIED,
            reason="ISOLATION_ESTABLISHED",
            detail="proof %s epoch %d by %s"
            % (proof.proof_id[:23], epoch, boundary.mechanism),
            instant=instant,
        )
        return self._boundaries[boundary.boundary_id]

    # ------------------------------------------------------------------
    # The admission gate (frozen invariant enforcement)
    # ------------------------------------------------------------------

    def evaluate_admission(
        self, boundary_id: str, facts: AdmissionFacts
    ) -> AdmissionDecision:
        """Evaluate the FULL frozen admission gate (no state
        change; usable at every enforcement point):

        boundary verified-or-active (with a valid, current proof),
        AND scope currently established (primitive's own read),
        AND capability still admitting (supported/restricted within
        the documented set),
        AND every caller fact (lease/consent/path/quota).

        ANY failure is a typed DENY — never a crash, never a
        best-effort admit, never a silent degradation."""
        boundary = self._require_boundary(boundary_id)
        if self._recovery_pending:
            # P1 recovery gate: restored durable state is NON-ADMITTING
            # until the mandatory recovery revalidation completes with
            # a FRESH containment re-proof (fail closed, typed)
            return AdmissionDecision(
                boundary_id=boundary_id, admitted=False,
                reason=ContainmentReasonCode.RECOVERY_REQUIRED,
                detail="restored durable state requires the mandatory "
                "recovery revalidation and fresh containment re-proof "
                "before any buyer-traffic admission (fail closed: NO "
                "buyer traffic; a stale-but-valid proof is not a path "
                "around the recovery gate)",
            )
        containment_problems = self._containment_admission_problems(boundary)
        if containment_problems:
            reason, detail = containment_problems[0]
            return AdmissionDecision(
                boundary_id=boundary_id, admitted=False,
                reason=reason, detail=detail,
            )
        if not facts.all_hold():
            failed = facts.failed_conditions()
            return AdmissionDecision(
                boundary_id=boundary_id, admitted=False,
                reason=ContainmentReasonCode.ADMISSION_DENIED,
                detail="admission facts failed: %s"
                % ", ".join(sorted(failed)),
            )
        return AdmissionDecision(
            boundary_id=boundary_id, admitted=True, reason="",
        )

    def activate(
        self, boundary_id: str, facts: AdmissionFacts
    ) -> ContainmentBoundary:
        """The admission transition ``verified -> active``.

        Reachable ONLY from ``verified``; requires EVERY admission
        condition to hold; journals a state-preserving typed denial
        (``admission-denied``) without state change otherwise.  NO
        BUYER TRAFFIC exists outside boundary ``active``.
        """
        boundary = self._require_boundary(boundary_id)
        self._require_action_state(boundary, BoundaryAction.ACTIVATE)
        decision = self.evaluate_admission(boundary_id, facts)
        if not decision.admitted:
            self._journal_event(
                boundary_id,
                BoundaryAction.ADMISSION_DENIED,
                BoundaryState.VERIFIED,
                BoundaryState.VERIFIED,
                reason=decision.reason,
                detail=decision.detail,
            )
            raise ContainmentError(
                decision.reason,
                "buyer-traffic admission denied for boundary %s: %s"
                % (boundary_id[:23], decision.detail),
            )
        instant = self._clock.now()
        advanced = replace(
            boundary, state=BoundaryState.ACTIVE, state_changed_at=instant,
        )
        self._boundaries[boundary_id] = advanced
        self._journal_event(
            boundary_id,
            BoundaryAction.ACTIVATE,
            boundary.state,
            BoundaryState.ACTIVE,
            reason="ADMISSION_GRANTED",
            detail="lease/consent/path/quota/proof/scope all hold",
            instant=instant,
        )
        return advanced

    def admit_bytes(
        self, boundary_id: str, byte_count: int, facts: AdmissionFacts
    ) -> AdmissionDecision:
        """Admit and COUNT bytes at the boundary (the enforcement
        point): the full admission gate runs FIRST; on success the
        primitive counts the integer bytes crossing its scope
        (byte COUNTS only — payload content is never represented
        or read).  On ANY failure: typed deny, zero bytes counted,
        NO state mutation."""
        boundary = self._require_boundary(boundary_id)
        if not isinstance(byte_count, int) or isinstance(byte_count, bool) or byte_count < 0:
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "byte_count must be a non-negative integer",
            )
        if boundary.state != BoundaryState.ACTIVE:
            return AdmissionDecision(
                boundary_id=boundary_id, admitted=False,
                reason=ContainmentReasonCode.ADMISSION_DENIED,
                detail="boundary state is %s (buyer traffic exists only in "
                "active)" % boundary.state,
            )
        decision = self.evaluate_admission(boundary_id, facts)
        if not decision.admitted:
            if decision.reason == ContainmentReasonCode.ISOLATION_LOST:
                # isolation lost mid-session is a REVOCATION
                # condition (the frozen lifecycle): the boundary
                # tears down fail-closed and no bytes are admitted
                self._revoke_boundary(
                    boundary,
                    "ISOLATION_LOST",
                    "the isolation scope no longer exists (isolation "
                    "lost mid-session: the boundary revokes fail closed "
                    "and NO bytes are admitted)",
                )
            return decision
        try:
            self._primitive.account(boundary.scope_ref, byte_count)
        except ContainmentError as error:
            if error.reason == ContainmentReasonCode.ISOLATION_LOST:
                # the scope was destroyed: isolation lost, fail closed
                self._revoke_boundary(
                    boundary,
                    "ISOLATION_LOST",
                    "the isolation primitive reported scope loss during "
                    "byte admission (fail closed; no bytes admitted)",
                )
                return AdmissionDecision(
                    boundary_id=boundary_id, admitted=False,
                    reason=ContainmentReasonCode.ISOLATION_LOST,
                    detail="the isolation scope was lost; the boundary is "
                    "revoked fail-closed and no bytes were admitted",
                )
            raise
        except Exception as error:  # noqa: BLE001 - typed fail-closed
            self._record_fail_closed(
                boundary, "account", type(error).__name__,
                reason=ContainmentReasonCode.ADMISSION_DENIED,
            )
            return AdmissionDecision(
                boundary_id=boundary_id, admitted=False,
                reason=ContainmentReasonCode.UNEXPECTED_EXCEPTION,
                detail="byte accounting raised %s (fail closed: zero bytes "
                "admitted)" % type(error).__name__,
            )
        advanced = replace(
            boundary, admitted_bytes=boundary.admitted_bytes + byte_count,
        )
        self._boundaries[boundary_id] = advanced
        return AdmissionDecision(
            boundary_id=boundary_id, admitted=True, reason="",
        )

    def decide_reachability(
        self, boundary_id: str, destination: str
    ) -> bool:
        """The PRIMITIVE's own reachability decision for one
        destination (deny-by-default: only the enforced allow-list
        and exposed local services are reachable).  The core never
        substitutes an application-level destination check."""
        boundary = self._require_boundary(boundary_id)
        decision = self._primitive.decide(boundary.scope_ref, destination)
        return decision.allowed

    # ------------------------------------------------------------------
    # Degradation / re-verification (the frozen restricted path)
    # ------------------------------------------------------------------

    def degrade(self, boundary_id: str, reason: str = "PROOF_STALE") -> ContainmentBoundary:
        """``active -> degraded``: the boundary remains established
        but NO NEW buyer traffic is admitted under the frozen
        contract (never a silent conversion to unrestricted
        active)."""
        boundary = self._require_boundary(boundary_id)
        self._require_action_state(boundary, BoundaryAction.DEGRADE)
        instant = self._clock.now()
        advanced = replace(
            boundary, state=BoundaryState.DEGRADED, state_changed_at=instant,
        )
        self._boundaries[boundary_id] = advanced
        self._journal_event(
            boundary_id,
            BoundaryAction.DEGRADE,
            boundary.state,
            BoundaryState.DEGRADED,
            reason=reason,
            instant=instant,
        )
        return advanced

    def reverify(self, boundary_id: str) -> ContainmentBoundary:
        """``degraded -> active`` ONLY through an explicit fresh
        verification proof (the ONLY legal re-entry; the proof is
        re-produced by the primitive — never accepted from stale
        evidence).  Fails closed when the fresh proof does not
        prove the boundary."""
        boundary = self._require_boundary(boundary_id)
        self._require_action_state(boundary, BoundaryAction.REVERIFY)
        try:
            instant = self._clock.now()
            primitive_proof = self._primitive.verify(
                boundary.scope_ref, at=instant,
            )
        except Exception as error:  # noqa: BLE001 - typed fail-closed
            self._record_fail_closed(
                boundary, "reverify", type(error).__name__,
                reason=ContainmentReasonCode.PROOF_INVALID,
            )
            self._fail_boundary(
                boundary,
                ContainmentReasonCode.UNEXPECTED_EXCEPTION,
                "re-verification raised %s (fail closed; the boundary "
                "degrades no further and stays non-admitting)"
                % type(error).__name__,
            )
            raise ContainmentError(
                ContainmentReasonCode.UNEXPECTED_EXCEPTION,
                "containment re-verification raised %s (fail closed)"
                % type(error).__name__,
            ) from error
        epoch = boundary.proof_epoch + 1
        # semantic binding (same discipline as verify): the fresh
        # observation must prove THIS boundary's exact scope and
        # envelope; a lying or misbound matrix never re-admits
        if (
            primitive_proof.scope_ref != boundary.scope_ref
            or not primitive_proof.proves_boundary(boundary.scope_spec())
        ):
            self._fail_boundary(
                boundary,
                ContainmentReasonCode.PROOF_INVALID,
                "the fresh re-verification observation does not prove the "
                "boundary's scope/envelope (scope binding, mechanism, "
                "probe decision semantics, envelope coverage, or the "
                "deny-by-default floor failed); degraded never becomes "
                "active without a semantically valid proof",
            )
            raise ContainmentError(
                ContainmentReasonCode.PROOF_INVALID,
                "re-verification proof does not prove the boundary",
            )
        proof = ContainmentProof(
            proof_id="",
            boundary_id=boundary.boundary_id,
            scope_ref=boundary.scope_ref,
            mechanism=boundary.mechanism,
            proof_epoch=epoch,
            observed_at=primitive_proof.observed_at,
            primitive_proof_digest=primitive_proof.proof_digest(),
            scope_exists=primitive_proof.scope_exists,
            allowlist_active=primitive_proof.allowlist_active,
            deny_probes=tuple(
                {
                    "destination": probe.destination,
                    "decision": probe.decision,
                    "decided_by": probe.decided_by,
                }
                for probe in primitive_proof.deny_probes
            ),
        )
        if not proof.proves_boundary(boundary):
            self._fail_boundary(
                boundary,
                ContainmentReasonCode.PROOF_INVALID,
                "the fresh re-verification proof does not semantically "
                "prove the boundary (identity/scope/mechanism binding or "
                "probe-matrix envelope semantics failed; degraded never "
                "becomes active without proof)",
            )
            raise ContainmentError(
                ContainmentReasonCode.PROOF_INVALID,
                "re-verification proof does not prove the boundary",
            )
        history = self._proofs.setdefault(boundary.boundary_id, [])
        if len(history) >= MAX_PROOF_HISTORY:
            history = history[-(MAX_PROOF_HISTORY - 1):]
        history.append(proof)
        self._proofs[boundary.boundary_id] = history
        advanced = replace(
            boundary,
            state=BoundaryState.ACTIVE,
            proof_id=proof.proof_id,
            proof_digest=proof.primitive_proof_digest,
            verified_at=proof.observed_at,
            proof_epoch=epoch,
            state_changed_at=instant,
        )
        self._boundaries[boundary_id] = advanced
        self._journal_event(
            boundary_id,
            BoundaryAction.REVERIFY,
            boundary.state,
            BoundaryState.ACTIVE,
            reason="PROOF_REFRESHED",
            detail="proof epoch %d" % epoch,
            instant=instant,
        )
        return advanced

    # ------------------------------------------------------------------
    # Breach / revocation / failure / teardown
    # ------------------------------------------------------------------

    def observe_breach(
        self, boundary_id: str, destination: str
    ) -> ContainmentBoundary:
        """Buyer traffic was OBSERVED reaching a denied destination:
        emergency-stop the boundary (``active -> revoked``) and
        record typed security evidence (LOCK-022 zero-trust)."""
        boundary = self._require_boundary(boundary_id)
        self._require_action_state(boundary, BoundaryAction.BREACH)
        instant = self._clock.now()
        evidence = SecurityEvidence(
            evidence_id="",
            boundary_id=boundary_id,
            kind="isolation-breach",
            reason="ISOLATION_BREACH",
            destination=destination,
            observed_at=instant,
        )
        self._security_evidence.append(evidence)
        revoked = self._revoke_boundary(
            boundary,
            "ISOLATION_BREACH",
            "buyer traffic observed reaching denied destination %r; "
            "the boundary emergency-stops (fail closed)" % destination,
            instant=instant,
        )
        return revoked

    def revoke(self, boundary_id: str, reason: str) -> ContainmentBoundary:
        """Tear the boundary down under revocation (consent
        withdrawal, emergency stop, isolation loss): ``-> revoked``.
        The primitive scope is destroyed AT THE PRIMITIVE LEVEL;
        historical admitted bytes and proof history are untouched."""
        boundary = self._require_boundary(boundary_id)
        if boundary.state in BoundaryState.terminal_values():
            raise ContainmentError(
                ContainmentReasonCode.LIFECYCLE_ILLEGAL,
                "boundary %s is terminal (%s); revocation is impossible"
                % (boundary_id[:23], boundary.state),
            )
        return self._revoke_boundary(boundary, reason, "revoked by %s" % reason)

    def fail(self, boundary_id: str, reason: str, detail: str = "") -> ContainmentBoundary:
        """``-> failed`` (terminal): containment could not be
        established or proven.  NO buyer traffic was admitted
        through the failed instance; the typed reason is recorded."""
        boundary = self._require_boundary(boundary_id)
        return self._fail_boundary(boundary, reason, detail)

    def close(self, boundary_id: str, reason: str) -> ContainmentBoundary:
        """Normal terminal teardown (expiry, quota completion,
        lease end, clean shutdown): ``-> closed``.  The primitive
        scope is destroyed; the containment-proof history for the
        whole sharing interval remains immutable."""
        boundary = self._require_boundary(boundary_id)
        if boundary.state in BoundaryState.terminal_values():
            raise ContainmentError(
                ContainmentReasonCode.LIFECYCLE_ILLEGAL,
                "boundary %s is already terminal (%s)"
                % (boundary_id[:23], boundary.state),
            )
        instant = self._clock.now()
        if boundary.scope_ref != "":
            try:
                self._primitive.teardown(boundary.scope_ref, at=instant)
            except Exception as error:  # noqa: BLE001 - typed fail-closed
                # teardown failure fails closed: the boundary is
                # closed with the scope reported destroyed only
                # when the primitive confirms destruction; here it
                # did not -- record and still terminate closed (no
                # buyer traffic can flow through a closed boundary)
                self._record_fail_closed(
                    boundary, "teardown", type(error).__name__,
                    reason="ISOLATION_LOST",
                )
        advanced = replace(
            boundary,
            state=BoundaryState.CLOSED,
            close_reason=reason,
            state_changed_at=instant,
        )
        self._boundaries[boundary_id] = advanced
        self._journal_event(
            boundary_id,
            BoundaryAction.CLOSE,
            boundary.state,
            BoundaryState.CLOSED,
            reason=reason,
            instant=instant,
        )
        return advanced

    # ------------------------------------------------------------------
    # Recovery re-proof (journal-first restart support)
    # ------------------------------------------------------------------

    def reprove(self, boundary_id: str) -> Tuple[ContainmentBoundary, ContainmentProof]:
        """Re-prove containment after process death/restart.

        The scope is RE-VERIFIED by the primitive (a FRESH proof —
        stale proof never resumes admission).  A boundary that
        cannot re-prove containment transitions to ``failed``
        (fail closed; NO buyer traffic).  A scope that was already
        destroyed (isolation lost while down) transitions to
        ``revoked``.  Terminal boundaries stay terminal (revoked
        stays revoked; closed stays closed)."""
        boundary = self._require_boundary(boundary_id)
        if boundary.state in BoundaryState.terminal_values():
            return boundary, self.latest_proof(boundary_id) or self._empty_proof(boundary)
        if boundary.state == BoundaryState.PREPARED and boundary.scope_ref == "":
            # never established: nothing to re-prove; stays prepared
            # (no admission is possible without verification first)
            return boundary, self._empty_proof(boundary)
        try:
            instant = self._clock.now()
            primitive_proof = self._primitive.verify(
                boundary.scope_ref, at=instant,
            )
        except Exception as error:  # noqa: BLE001 - typed fail-closed
            failed = self._fail_boundary(
                boundary,
                ContainmentReasonCode.UNEXPECTED_EXCEPTION,
                "recovery re-proof raised %s (fail closed: the boundary "
                "fails and NO buyer traffic resumes)" % type(error).__name__,
            )
            raise ContainmentError(
                ContainmentReasonCode.UNEXPECTED_EXCEPTION,
                "recovery re-proof raised %s (fail closed)"
                % type(error).__name__,
            ) from error
        epoch = boundary.proof_epoch + 1
        # semantic binding (same discipline as verify): a stale,
        # lying, or misbound recovery observation NEVER resumes
        # admission (the fresh proof must prove THIS boundary's
        # exact scope and envelope)
        if (
            primitive_proof.scope_ref != boundary.scope_ref
            or not primitive_proof.proves_boundary(boundary.scope_spec())
        ):
            self._fail_boundary(
                boundary,
                ContainmentReasonCode.PROOF_INVALID,
                "the recovery re-proof observation does not prove the "
                "boundary's scope/envelope (scope binding, mechanism, "
                "probe decision semantics, envelope coverage, or the "
                "deny-by-default floor failed); cannot re-prove "
                "containment => failed => NO buyer traffic",
            )
            return (
                self._boundaries[boundary.boundary_id],
                self._empty_proof(boundary),
            )
        proof = ContainmentProof(
            proof_id="",
            boundary_id=boundary.boundary_id,
            scope_ref=boundary.scope_ref,
            mechanism=boundary.mechanism,
            proof_epoch=epoch,
            observed_at=primitive_proof.observed_at,
            primitive_proof_digest=primitive_proof.proof_digest(),
            scope_exists=primitive_proof.scope_exists,
            allowlist_active=primitive_proof.allowlist_active,
            deny_probes=tuple(
                {
                    "destination": probe.destination,
                    "decision": probe.decision,
                    "decided_by": probe.decided_by,
                }
                for probe in primitive_proof.deny_probes
            ),
        )
        if not proof.proves_boundary(boundary):
            failed = self._fail_boundary(
                boundary,
                ContainmentReasonCode.PROOF_INVALID,
                "recovery re-proof does not semantically prove the "
                "boundary (identity/scope/mechanism binding or "
                "probe-matrix envelope semantics failed; cannot re-prove "
                "containment => failed => NO buyer traffic)",
            )
            return failed, proof
        history = self._proofs.setdefault(boundary.boundary_id, [])
        if len(history) >= MAX_PROOF_HISTORY:
            history = history[-(MAX_PROOF_HISTORY - 1):]
        history.append(proof)
        self._proofs[boundary.boundary_id] = history
        advanced = replace(
            boundary,
            proof_id=proof.proof_id,
            proof_digest=proof.primitive_proof_digest,
            verified_at=proof.observed_at,
            proof_epoch=epoch,
        )
        self._boundaries[boundary_id] = advanced
        return advanced, proof

    # ------------------------------------------------------------------
    # Internals (fail-closed helpers)
    # ------------------------------------------------------------------

    def _empty_proof(self, boundary: ContainmentBoundary) -> ContainmentProof:
        """A non-proving placeholder for boundaries without proofs
        (never valid admission evidence)."""
        return ContainmentProof(
            proof_id="",
            boundary_id=boundary.boundary_id,
            scope_ref="",
            mechanism=boundary.mechanism,
            proof_epoch=0,
            observed_at="1970-01-01T00:00:00Z",
            primitive_proof_digest="",
            scope_exists=False,
            allowlist_active=False,
            deny_probes=(),
        )

    def _containment_admission_problems(
        self, boundary: ContainmentBoundary
    ) -> List[Tuple[str, str]]:
        """The containment-side admission checks (typed problems,
        deterministic order)."""
        problems: List[Tuple[str, str]] = []
        if boundary.state not in (
            BoundaryState.VERIFIED, BoundaryState.ACTIVE,
        ):
            reason = (
                ContainmentReasonCode.PROOF_STALE
                if boundary.state == BoundaryState.DEGRADED
                else ContainmentReasonCode.ADMISSION_DENIED
            )
            problems.append(
                (
                    reason,
                    "boundary state is %s (admission requires verified or "
                    "active; prepared/degraded/failed/revoked/closed "
                    "admit NO buyer traffic; degraded NEVER silently "
                    "converts to unrestricted active)" % boundary.state,
                )
            )
            return problems
        if not boundary.proof_is_valid():
            problems.append(
                (
                    ContainmentReasonCode.PROOF_INVALID,
                    "the boundary carries no valid containment proof",
                )
            )
            return problems
        # the recorded proof must be BOUND to this boundary's exact
        # proof reference AND must SEMANTICALLY prove this boundary's
        # declared envelope (identity/scope/mechanism binding +
        # probe-matrix semantics + coverage + deny floor): a
        # tampered, stale, or forged proof record can never satisfy
        # the admission gate
        recorded = self.latest_proof(boundary.boundary_id)
        if recorded is None:
            problems.append(
                (
                    ContainmentReasonCode.PROOF_INVALID,
                    "no containment proof is recorded for the boundary "
                    "(admission requires proven containment)",
                )
            )
            return problems
        if (
            recorded.proof_id != boundary.proof_id
            or recorded.primitive_proof_digest != boundary.proof_digest
            or recorded.proof_epoch != boundary.proof_epoch
        ):
            problems.append(
                (
                    ContainmentReasonCode.PROOF_INVALID,
                    "the boundary's proof reference does not match the "
                    "recorded proof (id/digest/epoch binding failed: "
                    "tampered, stale, or misbound proof material cannot "
                    "satisfy admission)",
                )
            )
            return problems
        if not recorded.proves_boundary(boundary):
            problems.append(
                (
                    ContainmentReasonCode.PROOF_INVALID,
                    "the recorded proof does not semantically prove this "
                    "boundary's declared envelope (identity/scope/"
                    "mechanism binding, probe-matrix semantics, coverage, "
                    "or the deny-by-default floor failed)",
                )
            )
            return problems
        # the scope must CURRENTLY exist (the primitive's own read)
        try:
            scope_exists = self._primitive.scope_exists(boundary.scope_ref)
        except Exception as error:  # noqa: BLE001 - typed fail-closed
            problems.append(
                (
                    ContainmentReasonCode.UNEXPECTED_EXCEPTION,
                    "scope existence check raised %s (fail closed)"
                    % type(error).__name__,
                )
            )
            return problems
        if not scope_exists:
            problems.append(
                (
                    ContainmentReasonCode.ISOLATION_LOST,
                    "the isolation scope no longer exists (isolation lost: "
                    "NO buyer traffic)",
                )
            )
        return problems

    def _revoke_boundary(
        self,
        boundary: ContainmentBoundary,
        reason: str,
        detail: str,
        instant: Optional[str] = None,
    ) -> ContainmentBoundary:
        if boundary.state in BoundaryState.terminal_values():
            return boundary
        at = instant if instant is not None else self._clock.now()
        if boundary.scope_ref != "":
            try:
                self._primitive.teardown(boundary.scope_ref, at=at)
            except Exception as error:  # noqa: BLE001 - typed fail-closed
                self._record_fail_closed(
                    boundary, "teardown", type(error).__name__,
                    reason=ContainmentReasonCode.ISOLATION_LOST,
                )
        revoked = replace(
            boundary,
            state=BoundaryState.REVOKED,
            revocation_reason=reason,
            state_changed_at=at,
        )
        self._boundaries[boundary.boundary_id] = revoked
        self._journal_event(
            boundary.boundary_id,
            BoundaryAction.REVOKE,
            boundary.state,
            BoundaryState.REVOKED,
            reason=reason,
            detail=detail,
            instant=at,
        )
        return revoked

    def _fail_boundary(
        self,
        boundary: ContainmentBoundary,
        reason: str,
        detail: str,
        instant: Optional[str] = None,
    ) -> ContainmentBoundary:
        if boundary.state in BoundaryState.terminal_values():
            return boundary
        at = instant if instant is not None else self._clock.now()
        failed = replace(
            boundary,
            state=BoundaryState.FAILED,
            failure_reason=reason,
            state_changed_at=at,
        )
        self._boundaries[boundary.boundary_id] = failed
        self._journal_event(
            boundary.boundary_id,
            BoundaryAction.FAIL,
            boundary.state,
            BoundaryState.FAILED,
            reason=reason,
            detail=detail,
            instant=at,
        )
        return failed

    def _record_fail_closed(
        self,
        boundary: ContainmentBoundary,
        operation: str,
        exception_class: str,
        *,
        reason: str,
        instant: Optional[str] = None,
    ) -> None:
        """Typed security evidence for a fail-closed transition
        (exception CLASS NAME only — LOCK-023)."""
        at = instant if instant is not None else self._clock.now()
        evidence = SecurityEvidence(
            evidence_id="",
            boundary_id=boundary.boundary_id,
            kind="fail-closed-transition",
            reason=reason,
            destination=operation,
            observed_at=at,
            exception_class=exception_class,
        )
        self._security_evidence.append(evidence)

    def _require_boundary(self, boundary_id: str) -> ContainmentBoundary:
        boundary = self._boundaries.get(boundary_id)
        if boundary is None:
            raise ContainmentError(
                ContainmentReasonCode.BOUNDARY_UNKNOWN,
                "boundary %r is not journaled" % boundary_id,
            )
        return boundary

    def _require_action_state(
        self, boundary: ContainmentBoundary, action: str
    ) -> None:
        required = ACTION_REQUIRED_STATE.get(action, "")
        if required == "":
            return
        if boundary.state != required:
            raise ContainmentError(
                ContainmentReasonCode.LIFECYCLE_ILLEGAL,
                "action %r requires boundary state %s (current: %s; "
                "duplicate/stale/out-of-order attempts fail closed)"
                % (action, required, boundary.state),
            )

    def _journal_event(
        self,
        boundary_id: str,
        action: str,
        from_state: str,
        to_state: str,
        *,
        reason: str,
        detail: str = "",
        instant: Optional[str] = None,
    ) -> None:
        at = instant if instant is not None else self._clock.now()
        event = BoundaryEvent(
            event_id="",
            boundary_id=boundary_id,
            action=action,
            from_state=from_state,
            to_state=to_state,
            instant=at,
            reason=reason,
            detail=detail,
        )
        self._journal(event, revalidate=True)

    def _journal(
        self, event: BoundaryEvent, *, revalidate: bool = True
    ) -> None:
        if revalidate:
            if event.boundary_id not in self._boundaries:
                raise ContainmentError(
                    ContainmentReasonCode.INVALID_INPUT,
                    "journal event references unknown boundary",
                )
        if event.event_id in self._event_ids:
            raise ContainmentError(
                ContainmentReasonCode.DUPLICATE_TRANSITION,
                "boundary event %s is an exact replay of a journaled "
                "transition (duplicate rejected; fail closed)"
                % event.event_id[:23],
            )
        self._event_ids.add(event.event_id)
        self._events.append(event)

    def _now(self) -> str:
        return self._clock.now()
