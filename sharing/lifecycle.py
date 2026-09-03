"""WORK-048 provider sharing runtime (the composition engine).

:class:`SharingRuntime` is the public surface of the sharing
family: the LOCAL ENFORCEMENT MECHANISM of WORK-048.  It composes
the canonical authorities through their PUBLIC surfaces ONLY and
owns none of their state:

- **W051 CommercialCore** (lease truth): read-only reads of the
  transaction projection (state, expiry, session/path/buyer
  bindings).  The runtime never mints, mutates, or settles leases,
  never drives a commercial command, and never becomes a
  commercial ledger.  A missing, expired, revoked, malformed, or
  unprovable lease fails closed.
- **W041 NetworkPathManager** (path lifecycle): paths are
  validated, bound, probed, activated, handed over, and retired
  ONLY through the manager's public machinery.  The runtime never
  computes routes, never creates a parallel path abstraction,
  never marks an unvalidated path active, and never manufactures
  PATH_ACTIVE: a sharing session becomes traffic-bearing only when
  bound to an actually-ACTIVE W041 NetworkPath.
- **ACR-012 ContainmentAuthority** (buyer-traffic containment):
  exactly one ContainmentBoundary per sharing session, driven
  through the containment authority's public lifecycle
  (prepare/verify/activate/degrade/reverify/revoke/close/reprove).
  NO PROVEN CONTAINMENT => NO BUYER TRAFFIC.
- **W048-local**: the consent registry, the quota/capacity ledger,
  the sharing-session state machine, and the append-only sharing
  journal (enforcement records; usage truth stays with W052).
- **W052 UsageLedger** (usage truth): usage evidence is EMITTED
  INTO the canonical journal with deterministic, content-derived
  correlation ids (:mod:`sharing.usage`); duplicates reconcile
  through the ledger's own durable dedup; the runtime keeps no
  competing ledger.

The two state machines (sharing session and containment boundary)
are DISTINCT objects that coordinate transitions without ever
merging: ``sharing.active`` does NOT itself prove
``ContainmentBoundary.active`` — both must satisfy their own
authority rules.

Admission gate (frozen; re-checked at EVERY enforcement point):

    lease active
    AND provider consent granted
    AND NetworkPath valid/active for the exact logical session
    AND quota available
    AND capability supported/restricted within constraints
    AND containment proof valid
    AND isolation currently established
        =>
    buyer traffic permitted (boundary active)

Any failure is a typed fail-closed denial (no crash, no
best-effort admit, no silent degradation); unmodeled exceptions on
security-critical admission operations become
``sharing-unexpected-exception`` denials.  Teardown/revocation
never rewrites historical usage (append-only accounting; W042
journal discipline).

Recovery is journal-first: durable state is restored from the
deterministic snapshot, then the lease, consent, NetworkPath, and
quota are revalidated and containment is RE-PROVED — a boundary
that cannot re-prove containment lands ``failed`` and its session
is revoked (NO buyer traffic resumes from stale proof).  Revoked
stays revoked; expired stays expired; historical usage remains
immutable.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Dict, List, Optional, Tuple

from agent.clock import AgentClock
from commercial.lifecycle import CommercialCore
from commercial.errors import CommercialError
from commercial.model import CommercialState
from containment.errors import ContainmentError, ContainmentReasonCode
from containment.lifecycle import (
    AdmissionFacts,
    ContainmentAuthority,
)
from networkpath.errors import NetworkPathError
from networkpath.lifecycle import NetworkPathManager
from networkpath.state import NetworkPathState

from .consent import ConsentRegistry
from .errors import SharingError, SharingReasonCode
from .model import (
    ProviderConsent,
    SharingEvent,
    SharingScope,
    SharingSession,
    sharing_event_list_digest,
)
from .quota import ProviderEnvelope, QuotaLedger
from .state import SharingAction, SharingSessionState, transition_is_legal
from .timeutil import epoch_seconds
from .usage import emit_usage_evidence

#: The W051 commercial states inside which the lease is LIVE for
#: sharing (the delivery window: delivery started and usage
#: accruing).  Pre-delivery states (reservation/lease) do not
#: authorize buyer traffic; post-delivery and compensating states
#: end it.  This is a READ-ONLY projection of W051 truth (the
#: states are CommercialCore's own frozen vocabulary).
LEASE_DELIVERY_ACTIVE_STATES: Tuple[str, ...] = (
    CommercialState.DELIVERY_STARTED,
    CommercialState.USAGE_ACCRUING,
)

#: The provenance recorded on sharing-journal commercial citations.
SHARING_RUNTIME_SOURCE = "provider-sharing-runtime"


class SharingRuntime:
    """The W048 provider sharing runtime (public surface)."""

    def __init__(
        self,
        *,
        core: CommercialCore,
        paths: NetworkPathManager,
        containment: ContainmentAuthority,
        clock: AgentClock,
        envelopes: Tuple[ProviderEnvelope, ...] = (),
    ) -> None:
        if not isinstance(core, CommercialCore):
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "core must be a CommercialCore (the W051 lease authority, "
                "composed read-only)",
            )
        if not isinstance(paths, NetworkPathManager):
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "paths must be a NetworkPathManager (the W041 path "
                "lifecycle authority, composed through its machinery)",
            )
        if not isinstance(containment, ContainmentAuthority):
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "containment must be a ContainmentAuthority (the ACR-012 "
                "containment authority)",
            )
        if not isinstance(clock, AgentClock):
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "clock must be an AgentClock (the injected WORK-033 seam)",
            )
        self._core = core
        self._paths = paths
        self._containment = containment
        self._clock = clock
        self._sessions: Dict[str, SharingSession] = {}
        self._events: List[SharingEvent] = []
        self._event_ids: set = set()
        self._consents = ConsentRegistry()
        self._quota = QuotaLedger(envelopes)
        # Post-restore recovery condition (an admission CONDITION,
        # not a lifecycle state): a RESTORED runtime is non-admitting
        # until :meth:`recover` completes the mandatory revalidation
        # (lease/consent/path/quota re-read + FRESH containment
        # re-proof).  A freshly constructed runtime is never pending.
        self._recovery_pending: bool = False

    # ------------------------------------------------------------------
    # Public reads (deterministic, no clock consumption)
    # ------------------------------------------------------------------

    def sessions(self) -> Tuple[str, ...]:
        return tuple(sorted(self._sessions))

    def session(self, sharing_session_id: str) -> SharingSession:
        return self._require_session(sharing_session_id)

    def events(self) -> Tuple[SharingEvent, ...]:
        return tuple(self._events)

    def event_log_digest(self) -> str:
        return sharing_event_list_digest(list(self._events))

    def consents(self) -> Tuple[str, ...]:
        return self._consents.consents()

    def consent(self, consent_id: str) -> ProviderConsent:
        return self._consents.consent(consent_id)

    def quota_ledger(self) -> QuotaLedger:
        return self._quota

    def snapshot(self) -> Dict[str, Any]:
        """The deterministic durable-state document (the recovery
        source: sessions, journal, consent registry, quota ledger)."""
        return {
            "sessions": [
                self._sessions[key].to_dict() for key in sorted(self._sessions)
            ],
            "events": [event.to_dict() for event in self._events],
            "consents": self._consents.snapshot(),
            "quota": self._quota.snapshot(),
        }

    @classmethod
    def restore(
        cls,
        *,
        core: CommercialCore,
        paths: NetworkPathManager,
        containment: ContainmentAuthority,
        clock: AgentClock,
        snapshot: Dict[str, Any],
    ) -> "SharingRuntime":
        """Journal-first reconstruction of the durable enforcement
        state (byte-identical by construction; authorities are
        re-injected fresh and revalidated by :meth:`recover`).

        The restored runtime is NON-ADMITTING until :meth:`recover`
        completes: every traffic-admitting path (authorize, activate,
        account, resume, path change) fails closed with the typed
        ``RECOVERY_REQUIRED`` condition.  Restored ``active`` state
        can therefore NEVER reach admission before the mandatory
        fresh recovery re-proof — even though the restored proof
        material may be structurally valid."""
        runtime = cls(
            core=core, paths=paths, containment=containment, clock=clock,
        )
        from .quota import QuotaLedger

        runtime._quota = QuotaLedger.restore(snapshot.get("quota", {}))
        for record in snapshot.get("sessions", ()):
            session = SharingSession.from_dict(record)
            runtime._sessions[session.sharing_session_id] = session
        for event in snapshot.get("events", ()):
            runtime._journal(SharingEvent.from_dict(event))
        runtime._consents = ConsentRegistry.restore(
            snapshot.get("consents", {})
        )
        runtime._recovery_pending = True
        return runtime

    @property
    def recovery_pending(self) -> bool:
        """True while restored durable state has NOT completed the
        mandatory recovery revalidation (all traffic-admitting paths
        fail closed with ``RECOVERY_REQUIRED``; not a lifecycle
        state)."""
        return self._recovery_pending

    def _require_not_recovering(self, operation: str) -> None:
        """The post-restore admission gate: restored durable state
        is non-admitting until :meth:`recover` completes (fail
        closed, typed; the recovery re-proof is mandatory — a
        structurally valid restored proof is not a substitute)."""
        if self._recovery_pending:
            raise SharingError(
                SharingReasonCode.RECOVERY_REQUIRED,
                "restored durable state requires recovery before %r "
                "(lease/consent/path/quota revalidation + FRESH "
                "containment re-proof; fail closed: NO buyer traffic "
                "until recovery completes)" % operation,
            )

    # ------------------------------------------------------------------
    # Prepare (lease truth + envelope + capability; fail closed)
    # ------------------------------------------------------------------

    def prepare_sharing_session(
        self,
        *,
        lease_ref: str,
        buyer_ref: str,
        provider_ref: str,
        session_ref: str,
        path_ref: str,
        scope: SharingScope,
        platform_id: Optional[str] = None,
    ) -> SharingSession:
        """Prepare one sharing session (the local enforcement
        record + its containment boundary).

        Gates (fail closed, in order):
        1. lease truth (W051 read-only): the transaction exists, is
           inside the live delivery window, is bound to the exact
           logical session, cites the exact NetworkPath, and names
           the exact buyer; its expiry has not passed;
        2. time quota: the scope's expiry instant is in the future;
        3. capacity reservation: the scope's byte quota fits the
           provider's declared envelope (OVER_RESERVATION rejected);
        4. concurrent-buyer admission (deterministic, no
           displacement);
        5. containment capability (ACR-012: unknown/unsupported
           platforms refuse exposure).

        NO buyer traffic: the session is ``prepared`` and the
        boundary is ``prepared`` (the isolation primitive is NOT
        yet established)."""
        return self._prepare_impl(
            lease_ref=lease_ref,
            buyer_ref=buyer_ref,
            provider_ref=provider_ref,
            session_ref=session_ref,
            path_ref=path_ref,
            scope=scope,
            platform_id=platform_id,
        )

    def _prepare_impl(
        self,
        *,
        lease_ref: str,
        buyer_ref: str,
        provider_ref: str,
        session_ref: str,
        path_ref: str,
        scope: SharingScope,
        platform_id: Optional[str] = None,
    ) -> SharingSession:
        if not isinstance(scope, SharingScope):
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "scope must be a SharingScope",
            )
        # 1. lease truth (read-only W051 projection)
        self._require_lease_active(
            lease_ref=lease_ref, buyer_ref=buyer_ref,
            session_ref=session_ref, path_ref=path_ref,
        )
        # 1b. the cited NetworkPath must be KNOWN to the W041
        # machinery (read-only existence check; the path's own
        # state gate runs at authorize)
        try:
            self._paths.path(path_ref)
        except NetworkPathError as error:
            raise SharingError(
                SharingReasonCode.PATH_NOT_ACTIVE,
                "the W041 machinery does not know the cited path %r (%s); "
                "an unknown path never prepares a sharing session"
                % (path_ref[:23], error.reason),
            ) from error
        # 2. time quota sanity (an already-expired scope cannot prepare)
        now = self._clock.now()
        if epoch_seconds(scope.time_quota_expiry) <= epoch_seconds(now):
            raise SharingError(
                SharingReasonCode.QUOTA_EXHAUSTED,
                "the scope's time quota already expired at %s (fail closed "
                "at prepare; no exposure)" % scope.time_quota_expiry,
            )
        consent = self._consents.register(
            provider_ref=provider_ref,
            lease_ref=lease_ref,
            buyer_ref=buyer_ref,
            scope_digest=scope.scope_digest(),
        )
        session = SharingSession(
            sharing_session_id="",
            lease_ref=lease_ref,
            buyer_ref=buyer_ref,
            provider_ref=provider_ref,
            session_ref=session_ref,
            consent_ref=consent.consent_id,
            scope=scope,
            state=SharingSessionState.PREPARED,
            path_ref=path_ref,
            reserved_bytes=scope.byte_quota,
            created_at=now,
            state_changed_at="",
        )
        session = replace(session, state_changed_at=now)
        if session.sharing_session_id in self._sessions:
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "an identical sharing session already exists (fail closed; "
                "never rebind)",
            )
        # 3. capacity reservation (OVER_RESERVATION rejected here)
        self._quota.reserve(
            provider_ref=provider_ref,
            sharing_session_id=session.sharing_session_id,
            buyer_ref=buyer_ref,
            requested_bytes=scope.byte_quota,
        )
        # 4. deterministic concurrent-buyer admission
        buyer_previously_admitted = (
            buyer_ref in self._quota.admitted_buyers(provider_ref)
        )
        try:
            self._quota.admit_buyer(
                provider_ref=provider_ref,
                sharing_session_id=session.sharing_session_id,
                buyer_ref=buyer_ref,
            )
        except SharingError:
            self._quota.release_reservation(
                provider_ref=provider_ref,
                sharing_session_id=session.sharing_session_id,
            )
            raise
        # 5. containment capability gate + boundary preparation
        #    (ACR-012: unknown/unsupported refuse exposure HERE;
        #    the platform id defaults to the provider ref and may
        #    be the W050-advisory platform key)
        try:
            boundary = self._containment.prepare(
                sharing_session_ref=session.sharing_session_id,
                lease_ref=lease_ref,
                buyer_ref=buyer_ref,
                provider_ref=provider_ref,
                consent_ref=consent.consent_id,
                session_ref=session_ref,
                path_ref=path_ref,
                platform_id=platform_id if platform_id is not None else provider_ref,
                allowed_egress=scope.exposed_egress,
                exposed_local_services=scope.exposed_local_services,
            )
        except ContainmentError as error:
            # capability/containment failure: release THIS attempt's
            # local reservation and fail closed atomically (no
            # session record; a buyer already admitted under ANOTHER
            # session is never evicted by a failed prepare)
            self._quota.release_reservation(
                provider_ref=provider_ref,
                sharing_session_id=session.sharing_session_id,
            )
            if not buyer_previously_admitted:
                self._quota.release_buyer(
                    provider_ref=provider_ref, buyer_ref=buyer_ref,
                )
            raise SharingError(
                SharingReasonCode.CONTAINMENT_DENIED,
                "the containment authority refused to prepare the boundary "
                "(%s: %s); exposure refused fail-closed"
                % (error.reason, error.message[:140]),
            ) from error
        session = replace(session, boundary_ref=boundary.boundary_id)
        self._sessions[session.sharing_session_id] = session
        self._journal_event(
            session.sharing_session_id,
            SharingAction.PREPARE,
            SharingSessionState.PREPARED,
            SharingSessionState.PREPARED,
            reason="SESSION_PREPARED",
            detail="lease %s scope %d bytes" % (lease_ref[:23], scope.byte_quota),
            instant=now,
        )
        return session

    # ------------------------------------------------------------------
    # NetworkPath composition (W041 machinery only)
    # ------------------------------------------------------------------

    def bind_network_path(
        self, sharing_session_id: str, network_path_id: str
    ) -> SharingSession:
        """Drive the W041 public machinery (validate -> bind ->
        probe) for one candidate path, idempotently per the W041
        action preconditions.  The runtime NEVER marks a path
        active itself: activation is W041's ``activate`` (driven at
        :meth:`activate_sharing_session`)."""
        session = self._require_session(sharing_session_id)
        if session.state != SharingSessionState.PREPARED:
            raise SharingError(
                SharingReasonCode.LIFECYCLE_ILLEGAL,
                "path binding happens while the session is prepared "
                "(current: %s)" % session.state,
            )
        try:
            path = self._paths.path(network_path_id)
            if path.state == NetworkPathState.DISCOVERED:
                self._paths.validate(network_path_id)
                path = self._paths.path(network_path_id)
            if path.state == NetworkPathState.VALIDATED:
                self._paths.bind(network_path_id, session.session_ref)
                path = self._paths.path(network_path_id)
            if (
                path.state == NetworkPathState.BOUND
                and path.probe_digest == ""
            ):
                self._paths.probe(network_path_id)
        except NetworkPathError as error:
            raise SharingError(
                SharingReasonCode.PATH_NOT_ACTIVE,
                "the W041 machinery rejected the path chain for %r (%s: %s); "
                "an unvalidated candidate NEVER becomes active"
                % (network_path_id[:23], error.reason, error.message[:120]),
            ) from error
        session = replace(session, path_ref=network_path_id)
        self._sessions[sharing_session_id] = session
        return session

    # ------------------------------------------------------------------
    # Authorize (consent + lease + isolation establishment)
    # ------------------------------------------------------------------

    def authorize_sharing_session(
        self, sharing_session_id: str
    ) -> SharingSession:
        """``prepared -> authorized``.

        In order (all fail closed; the session STAYS ``prepared``
        on failure — the frozen contract: an unestablishable
        isolation primitive means the session cannot leave
        prepared):
        1. the containment boundary is ACTUALLY established and
           verified (the primitive's own proof — NO buyer traffic
           yet in ``verified``);
        2. provider consent is explicitly granted (scope-bound to
           this lease/buyer);
        3. the lease is still active (W051 truth re-read);
        4. the NetworkPath is validated/bound (W041 truth).

        Restored durable state must complete :meth:`recover` first
        (the typed ``RECOVERY_REQUIRED`` gate)."""
        self._require_not_recovering("authorize_sharing_session")
        session = self._require_session(sharing_session_id)
        if session.state != SharingSessionState.PREPARED:
            raise SharingError(
                SharingReasonCode.LIFECYCLE_ILLEGAL,
                "authorization requires state prepared (current: %s)"
                % session.state,
            )
        now = self._clock.now()
        # 1. isolation establishment (the boundary cannot leave
        #    prepared without the primitive's own proof; a failure
        #    here keeps the SESSION in prepared too).  Idempotent:
        #    a boundary already verified/active (an earlier
        #    authorize attempt, or recovery) is not re-driven.
        boundary = self._containment.boundary(session.boundary_ref)
        if boundary.state == "prepared":
            try:
                self._containment.verify(session.boundary_ref)
            except ContainmentError as error:
                raise SharingError(
                    SharingReasonCode.CONTAINMENT_DENIED,
                    "containment verification failed (%s: %s); the session "
                    "cannot leave prepared and NO buyer traffic is admitted"
                    % (error.reason, error.message[:140]),
                ) from error
        elif boundary.state not in ("verified", "active"):
            raise SharingError(
                SharingReasonCode.CONTAINMENT_DENIED,
                "the containment boundary is %s (a failed/revoked/closed "
                "boundary cannot authorize exposure; fail closed)"
                % boundary.state,
            )
        # 2. explicit provider consent (scope-bound)
        if not self._consents.is_granted(session.consent_ref):
            raise SharingError(
                SharingReasonCode.CONSENT_REQUIRED,
                "explicit provider consent is required before exposure "
                "(consent %r is not granted)" % session.consent_ref[:23],
            )
        # 3. lease truth re-read
        self._require_lease_active(
            lease_ref=session.lease_ref, buyer_ref=session.buyer_ref,
            session_ref=session.session_ref, path_ref=session.path_ref,
        )
        # 4. path valid/active (W041 truth: a VALIDATED/BOUND
        #    candidate or an already-ACTIVE path — the marketplace
        #    flow activates the path before the lease's delivery
        #    window opens)
        try:
            path = self._paths.path(session.path_ref)
        except NetworkPathError as error:
            raise SharingError(
                SharingReasonCode.PATH_NOT_ACTIVE,
                "the W041 machinery does not know the cited path (%s)"
                % error.reason,
            ) from error
        if path.state not in (
            NetworkPathState.VALIDATED, NetworkPathState.BOUND,
            NetworkPathState.ACTIVE,
        ):
            raise SharingError(
                SharingReasonCode.PATH_NOT_ACTIVE,
                "the cited NetworkPath is %s (authorization requires a "
                "validated/bound/active path; an unvalidated candidate "
                "never becomes active)" % path.state,
            )
        advanced = replace(
            session, state=SharingSessionState.AUTHORIZED,
            state_changed_at=now,
        )
        self._sessions[sharing_session_id] = advanced
        self._journal_event(
            sharing_session_id,
            SharingAction.AUTHORIZE,
            SharingSessionState.PREPARED,
            SharingSessionState.AUTHORIZED,
            reason="CONSENT_GRANTED",
            detail="lease active; path %s; boundary verified"
            % path.state,
            instant=now,
        )
        return advanced

    # ------------------------------------------------------------------
    # Activate (W041 path activation + the full admission gate)
    # ------------------------------------------------------------------

    def activate_sharing_session(
        self, sharing_session_id: str
    ) -> SharingSession:
        """``authorized -> active``: buyer traffic becomes
        permitted ONLY when the FULL admission gate holds.

        The W041 machinery activates the path (PATH_ACTIVE is
        W041's fact, driven through its public surface); the
        containment authority's admission gate then evaluates every
        frozen condition (lease/consent/path/quota facts +
        capability + proof + scope).  Any failure: typed raise, the
        session stays ``authorized``, the boundary stays
        ``verified`` — NO buyer traffic.

        Restored durable state must complete :meth:`recover` first
        (the typed ``RECOVERY_REQUIRED`` gate)."""
        self._require_not_recovering("activate_sharing_session")
        session = self._require_session(sharing_session_id)
        if session.state != SharingSessionState.AUTHORIZED:
            raise SharingError(
                SharingReasonCode.LIFECYCLE_ILLEGAL,
                "activation requires state authorized (current: %s)"
                % session.state,
            )
        now = self._clock.now()
        # W041 owns PATH_ACTIVE: drive the machinery for a BOUND
        # candidate (never the fact itself); an already-ACTIVE path
        # (the marketplace flow) is verified, not re-driven
        try:
            path = self._paths.path(session.path_ref)
            if path.state == NetworkPathState.BOUND:
                self._paths.activate(session.path_ref)
            elif path.state != NetworkPathState.ACTIVE:
                raise SharingError(
                    SharingReasonCode.PATH_NOT_ACTIVE,
                    "the cited NetworkPath is %s (activation requires a "
                    "BOUND candidate or an ACTIVE path; the sharing "
                    "session never manufactures PATH_ACTIVE)" % path.state,
                )
            active = self._paths.active_path_id(session.session_ref)
            if active != session.path_ref:
                raise SharingError(
                    SharingReasonCode.PATH_NOT_ACTIVE,
                    "the W041 machinery reports path %r active for the "
                    "logical session, not the cited path (fail closed)"
                    % (active or "none",),
                )
        except NetworkPathError as error:
            raise SharingError(
                SharingReasonCode.PATH_NOT_ACTIVE,
                "the W041 machinery refused path activation (%s: %s); a "
                "sharing session never manufactures PATH_ACTIVE"
                % (error.reason, error.message[:120]),
            ) from error
        facts = self._admission_facts(session)
        try:
            self._containment.activate(session.boundary_ref, facts)
        except ContainmentError as error:
            raise SharingError(
                SharingReasonCode.CONTAINMENT_DENIED,
                "the containment admission gate denied buyer traffic (%s: "
                "%s); the session stays authorized and NO buyer traffic "
                "flows" % (error.reason, error.message[:140]),
            ) from error
        advanced = replace(
            session, state=SharingSessionState.ACTIVE,
            state_changed_at=now,
        )
        self._sessions[sharing_session_id] = advanced
        self._journal_event(
            sharing_session_id,
            SharingAction.ACTIVATE,
            SharingSessionState.AUTHORIZED,
            SharingSessionState.ACTIVE,
            reason="PATH_ACTIVATED",
            detail="W041 ACTIVE + containment admission granted",
            instant=now,
        )
        return advanced

    # ------------------------------------------------------------------
    # Traffic accounting (every enforcement point re-checks all)
    # ------------------------------------------------------------------

    def account_traffic(
        self, sharing_session_id: str, byte_count: int
    ) -> Tuple[SharingSession, int]:
        """Account ``byte_count`` bytes of buyer traffic at the
        boundary — an ATOMIC enforcement operation.

        Every accounting point re-validates the FULL admission
        state (fail closed, typed): session active; restored-state
        recovery completed; time quota; lease truth; consent; W041
        path ACTIVE for the exact logical session; byte-quota
        AVAILABILITY (check-only); the containment boundary gate
        (proof + scope + facts) — and only when containment
        CONFIRMS the admission does the local quota counter COMMIT
        (append-only) and the session's ``accounted_bytes`` advance.
        A containment denial therefore leaves the quota LEDGER, the
        session counter, the boundary counter, and the primitive
        counter all UNCHANGED: rejected bytes never consume quota.
        The usage-evidence emission happens separately (explicit,
        idempotent) via :meth:`emit_usage_evidence`."""
        self._require_not_recovering("account_traffic")
        session = self._require_session(sharing_session_id)
        if not isinstance(byte_count, int) or isinstance(byte_count, bool) or byte_count < 0:
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "byte_count must be a non-negative integer (byte counts "
                "only; payload content is never inspected)",
            )
        if session.state != SharingSessionState.ACTIVE:
            raise SharingError(
                SharingReasonCode.LIFECYCLE_ILLEGAL,
                "buyer traffic exists only in session active (current: %s)"
                % session.state,
            )
        # 1. time quota (deterministic pure-integer comparison)
        now = self._clock.now()
        if epoch_seconds(now) >= epoch_seconds(session.scope.time_quota_expiry):
            expired = self._expire_session(
                session, "TIME_QUOTA_REACHED", now=now,
            )
            raise SharingError(
                SharingReasonCode.QUOTA_EXHAUSTED,
                "the time quota expired at %s (session expired; no bytes "
                "admitted)" % session.scope.time_quota_expiry,
            )
        # 2. lease truth re-read (W051 read-only)
        lease_problem = self._lease_problem(session)
        if lease_problem is not None:
            reason_text, is_expiry = lease_problem
            token = "LEASE_EXPIRED" if is_expiry else "LEASE_NO_LONGER_ACTIVE"
            if is_expiry:
                self._expire_session(session, token, now=now)
            else:
                self._revoke_session(session, token, now=now)
            raise SharingError(
                SharingReasonCode.LEASE_EXPIRED
                if is_expiry else SharingReasonCode.LEASE_NOT_ACTIVE,
                "the lease is no longer active for sharing (%s); no bytes "
                "admitted" % reason_text,
            )
        # 3. consent re-read (every enforcement point)
        consent = self._consents.consent(session.consent_ref)
        if consent.state == "withdrawn":
            self._revoke_session(session, "CONSENT_WITHDRAWN", now=now)
            raise SharingError(
                SharingReasonCode.CONSENT_WITHDRAWN,
                "consent was withdrawn: new buyer traffic stops "
                "immediately (no bytes admitted)",
            )
        if consent.state == "emergency_stopped":
            self._revoke_session(session, "EMERGENCY_STOP", now=now)
            raise SharingError(
                SharingReasonCode.EMERGENCY_STOP,
                "the provider emergency stop fired (no bytes admitted)",
            )
        # 4. W041 path truth (the exact path ACTIVE for the exact session)
        path_problem = self._path_problem(session)
        if path_problem is not None:
            self._revoke_session(session, "PATH_LOST", now=now)
            raise SharingError(
                SharingReasonCode.PATH_LOST,
                "the W041 NetworkPath is no longer active for the logical "
                "session (%s); the session is revoked PATH_LOST and no "
                "bytes are admitted" % path_problem,
            )
        # 5. byte-quota AVAILABILITY (check-only: NO counter
        #    mutation — the local quota ledger commits ONLY after
        #    containment admission confirms the bytes actually
        #    crossed the boundary; rejected bytes never consume
        #    quota)
        try:
            self._quota.check_byte_quota(
                sharing_session_id=sharing_session_id,
                byte_quota=session.scope.byte_quota,
                additional_bytes=byte_count,
            )
        except SharingError as error:
            if error.reason == SharingReasonCode.QUOTA_EXHAUSTED:
                self._expire_session(session, "BYTE_QUOTA_REACHED", now=now)
            raise
        # 6. the containment boundary gate (proof + scope + facts):
        #    the primitive counts the bytes ONLY when every
        #    condition holds; a denial leaves ALL accounting
        #    untouched (atomic admission — quota commits below)
        facts = self._admission_facts(session)
        try:
            decision = self._containment.admit_bytes(
                session.boundary_ref, byte_count, facts
            )
        except ContainmentError as error:
            self._revoke_if_boundary_terminal(session, error.reason, now=now)
            raise SharingError(
                SharingReasonCode.CONTAINMENT_DENIED,
                "the containment boundary refused byte admission (%s: %s)"
                % (error.reason, error.message[:140]),
            ) from error
        if not decision.admitted:
            self._revoke_if_boundary_terminal(
                session, decision.reason, now=now,
            )
            raise SharingError(
                SharingReasonCode.CONTAINMENT_DENIED,
                "the containment boundary denied byte admission (%s: %s)"
                % (decision.reason, decision.detail[:140]),
            )
        # 7. quota COMMIT (only after confirmed admission; the
        #    check ran at step 5 over the same counter, so this
        #    appends deterministically — the defensive failure
        #    path below fails closed WITHOUT rewriting the
        #    already-admitted boundary history)
        try:
            total = self._quota.account(
                sharing_session_id=sharing_session_id,
                byte_quota=session.scope.byte_quota,
                byte_count=byte_count,
            )
        except SharingError as error:
            if error.reason == SharingReasonCode.QUOTA_EXHAUSTED:
                # defensive (single-threaded deterministic): the
                # availability check passed; treat any commit-time
                # exhaustion the same fail-closed way
                self._expire_session(session, "BYTE_QUOTA_REACHED", now=now)
                raise
            self._revoke_session(session, "QUOTA_UNVERIFIABLE", now=now)
            raise SharingError(
                SharingReasonCode.QUOTA_UNVERIFIABLE,
                "the quota counter became unverifiable after containment "
                "admission; the session revokes fail-closed and the "
                "admitted-bytes history at the boundary is never rewritten "
                "(append-only accounting)",
            ) from error
        # 8. session record advance (the committed total)
        epoch = session.accounting_epochs + 1
        advanced = replace(
            session,
            accounted_bytes=total,
            accounting_epochs=epoch,
            last_accounted_at=now,
        )
        self._sessions[sharing_session_id] = advanced
        self._journal_event(
            sharing_session_id,
            SharingAction.ACCOUNT,
            SharingSessionState.ACTIVE,
            SharingSessionState.ACTIVE,
            reason="BYTE_QUOTA_OK",
            detail="epoch %d: %d bytes (total %d / %d)"
            % (epoch, byte_count, total, session.scope.byte_quota),
            instant=now,
        )
        return advanced, total

    def emit_usage_evidence(
        self,
        sharing_session_id: str,
        *,
        ledger: Any,
    ) -> Any:
        """Emit the current accounting epoch's usage evidence INTO
        the canonical W052 ledger (idempotent; see
        :func:`sharing.usage.emit_usage_evidence`).  The ledger is
        injected by the composed CALLER, constructed with an
        evidence index built from public reads (the containment
        proofs are the delivery evidence)."""
        session = self._require_session(sharing_session_id)
        if session.accounting_epochs <= 0 or session.accounted_bytes <= 0:
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "no accounted usage to emit for session %r"
                % sharing_session_id[:23],
            )
        if session.last_accounted_at == "":
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "the accounting instant is missing (deterministic "
                "emission requires the epoch's recorded instant)",
            )
        proof = self._containment.latest_proof(session.boundary_ref)
        if proof is None or proof.proof_id == "":
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "no containment proof available as delivery evidence",
            )
        # the emission instant is the EPOCH'S OWN recorded accounting
        # instant: an exact replay of the same epoch derives the same
        # command bytes and the ledger's durable dedup reconciles it
        # as a no-op (byte-identical idempotency).  The path
        # correlation is the LEASE-RECORDED path (the canonical W052
        # correlation discipline).
        return emit_usage_evidence(
            ledger=ledger,
            session=session,
            epoch=session.accounting_epochs,
            quantity=session.accounted_bytes,
            observed_at=session.last_accounted_at,
            evidence_ref=proof.proof_id,
            path_ref=self._lease_recorded_path(session),
        )

    # ------------------------------------------------------------------
    # Consent grant / breach reporting (public surfaces)
    # ------------------------------------------------------------------

    def grant_consent(
        self, sharing_session_id: str, *, cause: str = "PROVIDER_GRANTED"
    ) -> ProviderConsent:
        """Grant the session's provider consent explicitly (the
        append-only ``not_granted -> granted`` transition)."""
        session = self._require_session(sharing_session_id)
        now = self._clock.now()
        return self._consents.grant(
            session.consent_ref, cause=cause, instant=now,
        )

    def report_isolation_breach(
        self, sharing_session_id: str, destination: str
    ) -> SharingSession:
        """Report buyer traffic OBSERVED reaching a denied destination:
        the containment boundary emergency-stops (isolation breach;
        LOCK-022/LOCK-023 security evidence recorded) and the session
        is revoked fail-closed."""
        session = self._require_session(sharing_session_id)
        now = self._clock.now()
        try:
            self._containment.observe_breach(
                session.boundary_ref, destination,
            )
        except ContainmentError as error:
            raise SharingError(
                SharingReasonCode.CONTAINMENT_DENIED,
                "the containment authority refused the breach report (%s)"
                % error.reason,
            ) from error
        return self._revoke_session(session, "ISOLATION_BREACH", now=now)

    # ------------------------------------------------------------------
    # Pause / resume (provider pause; full re-check on resume)
    # ------------------------------------------------------------------

    def pause_sharing_session(
        self, sharing_session_id: str, cause: str = "PROVIDER_PAUSE"
    ) -> SharingSession:
        """``active -> paused``: no new buyer traffic.  The
        containment boundary degrades in coordination (its own
        authority transition; the two state machines stay
        distinct)."""
        session = self._require_session(sharing_session_id)
        if session.state != SharingSessionState.ACTIVE:
            raise SharingError(
                SharingReasonCode.LIFECYCLE_ILLEGAL,
                "pause requires state active (current: %s)" % session.state,
            )
        now = self._clock.now()
        try:
            self._containment.degrade(
                session.boundary_ref, reason="SESSION_PAUSED"
            )
        except ContainmentError as error:
            raise SharingError(
                SharingReasonCode.CONTAINMENT_DENIED,
                "the containment authority refused degradation (%s)"
                % error.reason,
            ) from error
        advanced = replace(
            session, state=SharingSessionState.PAUSED, state_changed_at=now,
        )
        self._sessions[sharing_session_id] = advanced
        self._journal_event(
            sharing_session_id,
            SharingAction.PAUSE,
            SharingSessionState.ACTIVE,
            SharingSessionState.PAUSED,
            reason=cause,
            instant=now,
        )
        return advanced

    def resume_sharing_session(
        self, sharing_session_id: str
    ) -> SharingSession:
        """``paused -> active`` ONLY through a full re-check (the
        boundary must be re-verified with a FRESH proof — never a
        silent conversion — and consent/lease/path/quota must hold
        again).

        Restored durable state must complete :meth:`recover` first
        (the typed ``RECOVERY_REQUIRED`` gate: a restored paused
        session never resumes admission before the fresh recovery
        re-proof)."""
        self._require_not_recovering("resume_sharing_session")
        session = self._require_session(sharing_session_id)
        if session.state != SharingSessionState.PAUSED:
            raise SharingError(
                SharingReasonCode.LIFECYCLE_ILLEGAL,
                "resume requires state paused (current: %s)" % session.state,
            )
        now = self._clock.now()
        # fresh containment proof (degraded -> active only via
        # explicit re-verification)
        try:
            self._containment.reverify(session.boundary_ref)
        except ContainmentError as error:
            raise SharingError(
                SharingReasonCode.CONTAINMENT_DENIED,
                "containment re-verification failed on resume (%s: %s); "
                "the session stays paused and no buyer traffic flows"
                % (error.reason, error.message[:120]),
            ) from error
        facts = self._admission_facts(session)
        if not facts.all_hold():
            failed = facts.failed_conditions()
            raise SharingError(
                SharingReasonCode.CONTAINMENT_DENIED,
                "resume re-check failed (%s); the session stays paused"
                % ", ".join(sorted(failed)),
            )
        advanced = replace(
            session, state=SharingSessionState.ACTIVE, state_changed_at=now,
        )
        self._sessions[sharing_session_id] = advanced
        self._journal_event(
            sharing_session_id,
            SharingAction.RESUME,
            SharingSessionState.PAUSED,
            SharingSessionState.ACTIVE,
            reason="PROVIDER_RESUME",
            detail="consent/lease/path/quota re-checked; fresh proof",
            instant=now,
        )
        return advanced

    # ------------------------------------------------------------------
    # Consent withdrawal / provider emergency stop
    # ------------------------------------------------------------------

    def withdraw_consent(
        self,
        sharing_session_id: str,
        *,
        cause: str = "PROVIDER_WITHDREW",
        ledger: Any = None,
    ) -> SharingSession:
        """Withdraw consent: new buyer traffic stops IMMEDIATELY;
        the session is revoked, the boundary torn down (revoked),
        the reservation released.  Historical usage is untouched;
        the final usage emission happens only when a ledger is
        provided."""
        session = self._require_session(sharing_session_id)
        now = self._clock.now()
        self._consents.withdraw(
            session.consent_ref, cause=cause, instant=now,
        )
        return self._revoke_session(
            session, "CONSENT_WITHDRAWN", now=now, ledger=ledger,
        )

    def emergency_stop(
        self,
        sharing_session_id: str,
        *,
        cause: str = "PROVIDER_EMERGENCY_STOP",
        ledger: Any = None,
    ) -> SharingSession:
        """The provider kill switch: ``active -> revoked``
        immediately; buyer exposure terminated; isolation torn
        down; final usage evidence emitted (when a ledger is
        provided); historical usage preserved; deterministic
        security evidence recorded."""
        session = self._require_session(sharing_session_id)
        now = self._clock.now()
        self._consents.emergency_stop(
            session.consent_ref, cause=cause, instant=now,
        )
        return self._revoke_session(
            session, "EMERGENCY_STOP", now=now, ledger=ledger,
        )

    # ------------------------------------------------------------------
    # Path loss / path change (W041-composed)
    # ------------------------------------------------------------------

    def notify_path_lost(
        self,
        sharing_session_id: str,
        *,
        candidate_path_id: Optional[str] = None,
    ) -> SharingSession:
        """Handle W041 path loss deterministically:

        - with a VALIDATING candidate: the session PAUSES (the
          explicitly authorized recovery behavior; ``session_id``
          stable; the candidate never becomes active merely because
          it exists);
        - without a candidate (or a candidate the W041 machinery
          rejects): the session is REVOKED ``PATH_LOST`` (buyer
          traffic stops; isolation torn down)."""
        session = self._require_session(sharing_session_id)
        if session.state not in (
            SharingSessionState.ACTIVE, SharingSessionState.PAUSED,
        ):
            raise SharingError(
                SharingReasonCode.LIFECYCLE_ILLEGAL,
                "path-loss handling requires an active/paused session "
                "(current: %s)" % session.state,
            )
        now = self._clock.now()
        if candidate_path_id is not None:
            # attempt the candidate chain through the W041 machinery
            # (validate -> bind -> probe): the candidate is never
            # active merely because it exists
            try:
                candidate = self._paths.path(candidate_path_id)
                if candidate.state == NetworkPathState.DISCOVERED:
                    self._paths.validate(candidate_path_id)
                    candidate = self._paths.path(candidate_path_id)
                if candidate.state == NetworkPathState.VALIDATED:
                    self._paths.bind(candidate_path_id, session.session_ref)
                    candidate = self._paths.path(candidate_path_id)
                if (
                    candidate.state == NetworkPathState.BOUND
                    and candidate.probe_digest == ""
                ):
                    self._paths.probe(candidate_path_id)
                paused = replace(
                    session,
                    state=SharingSessionState.PAUSED,
                    state_changed_at=now,
                )
                self._sessions[sharing_session_id] = paused
                self._journal_event(
                    sharing_session_id,
                    SharingAction.PATH_LOST,
                    session.state,
                    SharingSessionState.PAUSED,
                    reason="PATH_LOST",
                    detail="paused while candidate %s validates"
                    % candidate_path_id[:23],
                    instant=now,
                )
                return paused
            except NetworkPathError:
                # the candidate chain failed: fall through to revoke
                pass
        return self._revoke_session(session, "PATH_LOST", now=now)

    def change_path(
        self, sharing_session_id: str, candidate_path_id: str
    ) -> SharingSession:
        """Path change through the W041 handover machinery
        (validate -> bind -> probe -> activate candidate -> retire
        old LAST).  The logical ``session_id`` is STABLE across the
        change (the session authority owns it); the sharing session
        stays active only if the W041 machinery proves the new path
        ACTIVE for the exact logical session.

        Restored durable state must complete :meth:`recover` first
        (the typed ``RECOVERY_REQUIRED`` gate)."""
        self._require_not_recovering("change_path")
        session = self._require_session(sharing_session_id)
        if session.state != SharingSessionState.ACTIVE:
            raise SharingError(
                SharingReasonCode.LIFECYCLE_ILLEGAL,
                "path change requires an active session (current: %s)"
                % session.state,
            )
        now = self._clock.now()
        try:
            self._paths.handover(session.session_ref, candidate_path_id)
        except NetworkPathError as error:
            raise SharingError(
                SharingReasonCode.PATH_NOT_ACTIVE,
                "the W041 handover machinery rejected the candidate (%s: "
                "%s); the OLD active path is preserved and the session "
                "continues on it" % (error.reason, error.message[:120]),
            ) from error
        active = self._paths.active_path_id(session.session_ref)
        if active != candidate_path_id:
            raise SharingError(
                SharingReasonCode.PATH_NOT_ACTIVE,
                "the W041 machinery does not report the candidate ACTIVE "
                "for the logical session (active: %r); fail closed"
                % active,
            )
        advanced = replace(
            session, path_ref=candidate_path_id, state_changed_at=now,
        )
        self._sessions[sharing_session_id] = advanced
        self._journal_event(
            sharing_session_id,
            SharingAction.PATH_CHANGE,
            SharingSessionState.ACTIVE,
            SharingSessionState.ACTIVE,
            reason="PATH_CHANGED",
            detail="W041 handover to %s; session_id stable"
            % candidate_path_id[:23],
            instant=now,
        )
        return advanced

    # ------------------------------------------------------------------
    # Close (normal terminal teardown)
    # ------------------------------------------------------------------

    def close_sharing_session(
        self,
        sharing_session_id: str,
        *,
        ledger: Any = None,
    ) -> SharingSession:
        """Final teardown: ``expired/revoked/active -> closed``.

        The containment boundary is closed (proof history
        retained), the reservation/buyer released, and the final
        usage evidence emitted when a ledger is provided.  The
        closed session and its history are immutable."""
        session = self._require_session(sharing_session_id)
        if session.state == SharingSessionState.CLOSED:
            return session
        now = self._clock.now()
        if session.state in (
            SharingSessionState.ACTIVE, SharingSessionState.PAUSED,
        ):
            # clean shutdown of a live session: teardown first
            self._teardown_boundary(session, "SESSION_CLOSED")
        elif session.state == SharingSessionState.EXPIRED:
            self._teardown_boundary(session, "TIME_QUOTA_REACHED")
        elif session.state == SharingSessionState.REVOKED:
            self._teardown_boundary(session, session.termination_reason or "REVOKED")
        if ledger is not None and session.accounted_bytes > 0:
            self._emit_final_usage(session, ledger, now)
        advanced = replace(
            session, state=SharingSessionState.CLOSED, state_changed_at=now,
        )
        self._sessions[sharing_session_id] = advanced
        self._release_local_envelope(session)
        self._journal_event(
            sharing_session_id,
            SharingAction.CLOSE,
            session.state,
            SharingSessionState.CLOSED,
            reason="SESSION_CLOSED",
            detail="final teardown; history immutable",
            instant=now,
        )
        return advanced

    # ------------------------------------------------------------------
    # Recovery (journal-first; re-prove or fail closed)
    # ------------------------------------------------------------------

    def recover(self) -> Dict[str, Any]:
        """Post-restart revalidation of the restored durable state:

        for every session (revoked stays revoked; expired stays
        expired; closed stays closed):
        1. revalidate the lease (W051 read-only);
        2. revalidate consent;
        3. revalidate the NetworkPath (W041 read-only);
        4. revalidate the accounting-consistency invariant (the
           durable session counter == the local quota-ledger
           counter, and the boundary's admitted counter never
           trails the session's — the atomic admission discipline;
           tampered/divergent accounting revokes fail closed);
        5. RE-PROVE containment (a FRESH primitive verification —
           never stale proof).

        A boundary that cannot re-prove containment lands ``failed``
        and its session is revoked (NO buyer traffic resumes).  A
        session whose lease/consent/path/quota no longer hold is
        expired/revoked with its typed reason.  At the END of the
        loop the containment authority's recovery condition clears
        (it self-verifies every non-terminal established boundary
        carries a fresh post-restore proof) and THIS runtime's
        ``RECOVERY_REQUIRED`` condition clears — the only clearance
        path.  A raised error leaves both conditions SET (fail
        closed: restored state stays non-admitting).  Returns the
        deterministic recovery report."""
        report: Dict[str, Any] = {}
        now = self._clock.now()
        for sharing_session_id in self.sessions():
            session = self._sessions[sharing_session_id]
            if session.state in (
                SharingSessionState.REVOKED,
                SharingSessionState.EXPIRED,
                SharingSessionState.CLOSED,
            ):
                report[sharing_session_id] = "unchanged:%s" % session.state
                continue
            # 1-4: authority revalidation
            lease_problem = self._lease_problem(session)
            if lease_problem is not None:
                reason_text, is_expiry = lease_problem
                token = "LEASE_EXPIRED" if is_expiry else "LEASE_NO_LONGER_ACTIVE"
                if is_expiry:
                    self._expire_session(session, token, now=now)
                else:
                    self._revoke_session(session, token, now=now)
                report[sharing_session_id] = "expired-or-revoked:%s" % token
                continue
            if not self._consents.is_granted(session.consent_ref):
                self._revoke_session(session, "CONSENT_WITHDRAWN", now=now)
                report[sharing_session_id] = "revoked:CONSENT_WITHDRAWN"
                continue
            path_problem = self._path_problem(session)
            if path_problem is not None and session.state == SharingSessionState.ACTIVE:
                self._revoke_session(session, "PATH_LOST", now=now)
                report[sharing_session_id] = "revoked:PATH_LOST"
                continue
            # 4. accounting-consistency invariant (the atomic
            #    admission discipline): the durable session counter
            #    MUST equal the local quota-ledger counter, and the
            #    boundary's admitted counter MUST never trail the
            #    session's (a boundary cannot have admitted fewer
            #    bytes than were accounted).  Divergent or
            #    unverifiable accounting revokes fail closed.
            try:
                ledger_bytes = self._quota.accounted_bytes(
                    sharing_session_id
                )
            except SharingError:
                self._revoke_session(
                    session, "QUOTA_UNVERIFIABLE", now=now,
                )
                report[sharing_session_id] = "revoked:QUOTA_UNVERIFIABLE"
                continue
            try:
                boundary_record = self._containment.boundary(
                    session.boundary_ref
                )
            except ContainmentError:
                self._revoke_session(
                    session, "BOUNDARY_UNKNOWN", now=now,
                )
                report[sharing_session_id] = "revoked:BOUNDARY_UNKNOWN"
                continue
            if (
                ledger_bytes != session.accounted_bytes
                or boundary_record.admitted_bytes < session.accounted_bytes
            ):
                self._revoke_session(
                    session, "ACCOUNTING_INCONSISTENT", now=now,
                )
                report[sharing_session_id] = (
                    "revoked:ACCOUNTING_INCONSISTENT"
                )
                continue
            # 5: re-prove containment (fresh proof or fail closed)
            try:
                boundary, proof = self._containment.reprove(
                    session.boundary_ref
                )
            except ContainmentError as error:
                self._revoke_session(
                    session, "ISOLATION_UNPROVABLE", now=now,
                )
                report[sharing_session_id] = "revoked:ISOLATION_UNPROVABLE"
                continue
            if boundary.state == ContainmentBoundaryFailed:
                self._revoke_session(
                    session, "ISOLATION_UNPROVABLE", now=now,
                )
                report[sharing_session_id] = "revoked:ISOLATION_UNPROVABLE"
                continue
            if proof is not None and not proof.proves_boundary(boundary):
                self._revoke_session(
                    session, "ISOLATION_UNPROVABLE", now=now,
                )
                report[sharing_session_id] = "revoked:ISOLATION_UNPROVABLE"
                continue
            if session.state == SharingSessionState.ACTIVE:
                # enforcement resumes ONLY under a fresh proof and
                # a currently-admitting boundary
                facts = self._admission_facts(session)
                if not facts.all_hold():
                    self._revoke_session(
                        session, "ADMISSION_LOST", now=now,
                    )
                    report[sharing_session_id] = "revoked:ADMISSION_LOST"
                    continue
            report[sharing_session_id] = "revalidated:%s" % session.state
        # recovery completion — the ONLY clearance path: the
        # containment authority self-verifies that every
        # non-terminal established boundary carries a FRESH
        # post-restore proof (mark_recovered raises otherwise and
        # BOTH conditions stay set: restored state stays
        # non-admitting, fail closed)
        self._containment.mark_recovered()
        self._recovery_pending = False
        return report

    # ------------------------------------------------------------------
    # Internals: authority reads (read-only; typed re-wraps)
    # ------------------------------------------------------------------

    def _require_lease_active(
        self,
        *,
        lease_ref: str,
        buyer_ref: str,
        session_ref: str,
        path_ref: str,
    ) -> None:
        problem = self._lease_problem_for(
            lease_ref=lease_ref, buyer_ref=buyer_ref,
            session_ref=session_ref, path_ref=path_ref,
        )
        if problem is not None:
            reason, is_expiry = problem
            raise SharingError(
                SharingReasonCode.LEASE_EXPIRED
                if is_expiry
                else SharingReasonCode.LEASE_NOT_ACTIVE,
                "the W051 lease truth does not authorize sharing (%s); "
                "fail closed: no exposure" % reason,
            )

    def _lease_problem(self, session: SharingSession):
        return self._lease_problem_for(
            lease_ref=session.lease_ref, buyer_ref=session.buyer_ref,
            session_ref=session.session_ref, path_ref=session.path_ref,
        )

    def _lease_problem_for(
        self,
        *,
        lease_ref: str,
        buyer_ref: str,
        session_ref: str,
        path_ref: str,
    ):
        """Read the W051 lease truth (read-only) and return the
        typed problem (reason, is_expiry) or None when the lease is
        active.  W051 owns lease truth; this read NEVER mutates
        it."""
        if not isinstance(lease_ref, str) or not lease_ref:
            return ("lease reference is missing", False)
        try:
            projection = self._core.transaction(lease_ref)
        except CommercialError as error:
            return (
                "the W051 transaction is not readable (%s)"
                % error.reason,
                False,
            )
        except Exception as error:  # noqa: BLE001 - typed fail-closed
            return (
                "the W051 transaction read raised %s (fail closed)"
                % type(error).__name__,
                False,
            )
        if projection.state not in LEASE_DELIVERY_ACTIVE_STATES:
            return (
                "transaction state is %s (outside the live delivery window "
                "%s)" % (projection.state, list(LEASE_DELIVERY_ACTIVE_STATES)),
                projection.state == CommercialState.EXPIRED,
            )
        if projection.session_ref != session_ref:
            return (
                "the lease is authorized for logical session %r, not %r"
                % (projection.session_ref[:23], session_ref[:23]),
                False,
            )
        intent_buyer = projection.intent.get("buyer", "")
        if intent_buyer != buyer_ref:
            return (
                "the lease names buyer %r, not %r"
                % (intent_buyer, buyer_ref),
                False,
            )
        if projection.expires_at != "" and epoch_seconds(
            self._clock.now()
        ) >= epoch_seconds(projection.expires_at):
            return ("the lease expiry %s has passed" % projection.expires_at, True)
        return None

    def _lease_recorded_path(self, session: SharingSession) -> str:
        """The lease's recorded path correlation (W051 read-only):
        the canonical W052 usage correlation discipline binds usage
        citations to the commercial transaction's OWN recorded
        session/path.  The LIVE carrying path is W041 enforcement
        truth (checked against the W041 machinery at every
        admission point) — a different fact from this citation."""
        try:
            return self._core.transaction(session.lease_ref).path_ref
        except Exception:  # noqa: BLE001 - fail closed to empty
            return ""

    def _path_problem(self, session: SharingSession):
        """Read the W041 path truth (read-only): the exact path must
        be ACTIVE for the exact logical session.  Returns the typed
        problem text or None."""
        try:
            path = self._paths.path(session.path_ref)
        except NetworkPathError:
            return "the cited NetworkPath is not known to the W041 machinery"
        except Exception as error:  # noqa: BLE001 - typed fail-closed
            return "the W041 path read raised %s" % type(error).__name__
        if path.state != NetworkPathState.ACTIVE:
            return "the cited NetworkPath is %s" % path.state
        active = self._paths.active_path_id(session.session_ref)
        if active != session.path_ref:
            return (
                "the W041 machinery reports path %r active for the logical "
                "session, not the cited path" % (active or "none",)
            )
        return None

    def _admission_facts(self, session: SharingSession) -> AdmissionFacts:
        """Assemble the caller-side admission FACTS from the
        canonical authorities' public reads (the containment
        authority verifies its OWN facts and these booleans)."""
        lease_problem = self._lease_problem(session)
        consent_ok = self._consents.is_granted(session.consent_ref)
        path_problem = self._path_problem(session)
        quota_ok = self._quota_available(session)
        return AdmissionFacts(
            lease_active=lease_problem is None,
            consent_granted=consent_ok,
            path_active=path_problem is None,
            quota_available=quota_ok,
        )

    def _quota_available(self, session: SharingSession) -> bool:
        """Quota availability (fail closed: an unverifiable counter
        is NOT available)."""
        try:
            now = self._clock.now()
            if epoch_seconds(now) >= epoch_seconds(
                session.scope.time_quota_expiry
            ):
                return False
            self._quota.check_byte_quota(
                sharing_session_id=session.sharing_session_id,
                byte_quota=session.scope.byte_quota,
                additional_bytes=0,
            )
            return True
        except SharingError:
            return False

    # ------------------------------------------------------------------
    # Internals: terminal transitions
    # ------------------------------------------------------------------

    def _revoke_if_boundary_terminal(
        self, session: SharingSession, containment_reason: str, *, now: str
    ) -> None:
        """When the containment boundary landed in a terminal state
        during byte admission (isolation lost / breach / failure), the
        session revokes fail-closed with the mapped frozen reason."""
        try:
            boundary = self._containment.boundary(session.boundary_ref)
        except ContainmentError:
            return
        if boundary.state not in ("failed", "revoked", "closed"):
            return
        if session.state in (
            SharingSessionState.REVOKED, SharingSessionState.CLOSED,
            SharingSessionState.EXPIRED,
        ):
            return
        reason = "ISOLATION_LOST"
        if "breach" in containment_reason:
            reason = "ISOLATION_BREACH"
        elif "lost" in containment_reason:
            reason = "ISOLATION_LOST"
        elif "proof" in containment_reason or "unexpected" in containment_reason:
            reason = "ISOLATION_UNPROVABLE"
        self._revoke_session(session, reason, now=now)

    def _expire_session(
        self, session: SharingSession, reason: str, *, now: str
    ) -> SharingSession:
        if session.state in (
            SharingSessionState.EXPIRED, SharingSessionState.CLOSED,
        ):
            return session
        self._teardown_boundary(session, reason)
        advanced = replace(
            session,
            state=SharingSessionState.EXPIRED,
            termination_reason=reason,
            state_changed_at=now,
        )
        self._sessions[session.sharing_session_id] = advanced
        self._release_local_envelope(session)
        self._journal_event(
            session.sharing_session_id,
            SharingAction.EXPIRE,
            session.state,
            SharingSessionState.EXPIRED,
            reason=reason,
            detail="quota/expiry teardown; historical usage untouched",
            instant=now,
        )
        return advanced

    def _revoke_session(
        self,
        session: SharingSession,
        reason: str,
        *,
        now: str,
        ledger: Any = None,
    ) -> SharingSession:
        if session.state in (
            SharingSessionState.REVOKED, SharingSessionState.CLOSED,
        ):
            return session
        self._teardown_boundary(session, reason)
        if ledger is not None and session.accounted_bytes > 0:
            self._emit_final_usage(session, ledger, now)
        advanced = replace(
            session,
            state=SharingSessionState.REVOKED,
            termination_reason=reason,
            state_changed_at=now,
        )
        self._sessions[session.sharing_session_id] = advanced
        self._release_local_envelope(session)
        self._journal_event(
            session.sharing_session_id,
            SharingAction.REVOKE,
            session.state,
            SharingSessionState.REVOKED,
            reason=reason,
            detail="revocation teardown; historical usage never rewritten",
            instant=now,
        )
        return advanced

    def _teardown_boundary(self, session: SharingSession, reason: str) -> None:
        """Tear the isolation down AT THE PRIMITIVE LEVEL through
        the containment authority (fail closed; history kept)."""
        try:
            boundary = self._containment.boundary(session.boundary_ref)
        except ContainmentError:
            return
        if boundary.state in ("failed", "revoked", "closed"):
            return
        if session.state in (
            SharingSessionState.EXPIRED, SharingSessionState.REVOKED,
        ) or reason in (
            "CONSENT_WITHDRAWN", "EMERGENCY_STOP", "PATH_LOST",
            "ISOLATION_LOST", "ISOLATION_BREACH", "ISOLATION_UNPROVABLE",
        ):
            try:
                self._containment.revoke(session.boundary_ref, reason)
            except ContainmentError:
                try:
                    self._containment.close(session.boundary_ref, reason)
                except ContainmentError:
                    pass
            return
        try:
            self._containment.close(session.boundary_ref, reason)
        except ContainmentError:
            pass

    def _emit_final_usage(
        self, session: SharingSession, ledger: Any, now: str
    ) -> None:
        """The final usage emission at teardown/revocation (the
        historical facts emitted up to now; usage truth stays with
        the canonical W052 ledger).  The emission instant is the
        epoch's own recorded accounting instant (deterministic,
        replay-idempotent); the path correlation is the lease's
        recorded path."""
        proof = self._containment.latest_proof(session.boundary_ref)
        if proof is None or proof.proof_id == "":
            return
        if session.last_accounted_at == "":
            return
        try:
            emit_usage_evidence(
                ledger=ledger,
                session=session,
                epoch=session.accounting_epochs,
                quantity=session.accounted_bytes,
                observed_at=session.last_accounted_at,
                evidence_ref=proof.proof_id,
                path_ref=self._lease_recorded_path(session),
            )
        except SharingError:
            # emission failure never blocks the fail-closed teardown
            # (the accounting epoch remains emittable on retry; the
            # ledger is the authority and its dedup reconciles)
            pass

    def _release_local_envelope(self, session: SharingSession) -> None:
        self._quota.release_reservation(
            provider_ref=session.provider_ref,
            sharing_session_id=session.sharing_session_id,
        )
        self._quota.release_buyer(
            provider_ref=session.provider_ref, buyer_ref=session.buyer_ref,
        )

    # ------------------------------------------------------------------
    # Internals: journal + lookups
    # ------------------------------------------------------------------

    def _require_session(self, sharing_session_id: str) -> SharingSession:
        session = self._sessions.get(sharing_session_id)
        if session is None:
            raise SharingError(
                SharingReasonCode.SESSION_UNKNOWN,
                "sharing session %r is not journaled" % sharing_session_id,
            )
        return session

    def _journal_event(
        self,
        sharing_session_id: str,
        action: str,
        from_state: str,
        to_state: str,
        *,
        reason: str,
        detail: str = "",
        instant: Optional[str] = None,
    ) -> None:
        at = instant if instant is not None else self._clock.now()
        event = SharingEvent(
            event_id="",
            sharing_session_id=sharing_session_id,
            action=action,
            from_state=from_state,
            to_state=to_state,
            instant=at,
            reason=reason,
            detail=detail,
        )
        self._journal(event)

    def _journal(self, event: SharingEvent) -> None:
        if event.sharing_session_id not in self._sessions:
            raise SharingError(
                SharingReasonCode.INVALID_INPUT,
                "journal event references an unknown sharing session",
            )
        if event.event_id in self._event_ids:
            raise SharingError(
                SharingReasonCode.DUPLICATE_TRANSITION,
                "sharing event %s is an exact replay of a journaled "
                "transition (duplicate rejected; fail closed)"
                % event.event_id[:23],
            )
        self._event_ids.add(event.event_id)
        self._events.append(event)

    def _now(self) -> str:
        return self._clock.now()


#: The containment boundary failed state (import-site constant for
#: the recovery comparison; the containment vocabulary is frozen).
ContainmentBoundaryFailed = "failed"
