"""WORK-049 provider-mode client runtime.

The provider-mode client is the user-facing
CONTROL/PROJECTION surface for the W048 provider sharing runtime
(consent UX, configuration, status, stop/revoke controls,
presentation, handoff).  It is a CLIENT/CONTROLLER for the
canonical machinery — it NEVER recreates W048 containment,
isolation, quota, or provider-traffic enforcement, and the ACR-012
invariant is absolute:

    NO PROVEN CONTAINMENT  =>  NO BUYER TRAFFIC

(no client surface can bypass or soften it).

The frozen provider client lifecycle (client-local projection/
UX-control/handoff states ONLY — never replacements for the W048
canonical sharing-session lifecycle):

    UNAVAILABLE -> CAPABILITY_CHECKED -> READY -> CONSENT_REQUIRED
    -> CONSENTED -> HANDOFF_REQUESTED -> ACTIVE -> PAUSED
    -> REVOKED / EXPIRED / STOPPED -> CLOSED

Mapping onto the canonical W048 chain (driven through the
runtime's public surface, never reimplemented):

    prepare_sharing_session -> CONSENT_REQUIRED
    grant_consent           -> CONSENTED
    authorize_sharing_session -> HANDOFF_REQUESTED
    activate_sharing_session  -> ACTIVE (projection only)
    pause/resume            -> PAUSED/ACTIVE
    withdraw_consent        -> REVOKED
    emergency_stop          -> STOPPED
    lease/quota expiry      -> EXPIRED
    close_sharing_session   -> CLOSED

Emergency stop (frozen semantics): REQUEST STOP / ENFORCE LOCAL
SAFETY -> canonical provider-sharing termination -> W048
enforcement -> traffic termination.  The local detach is the
fail-safe leg; the canonical termination is the authority; the
STOPPED state is entered only after the canonical terminal fact
is verified (never a boolean flip that leaves W048 active).
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from .capability import (
    AdapterCapabilitySnapshot,
    CapabilityDecision,
    evaluate_capability,
)
from .errors import ClientError, ClientReasonCode, FailClosedResolution
from .events import ClientEvent, EventTaxonomy
from .gateway import CanonicalGateway, GatewayRead
from .model import ClientContext, ConsentFacts, ReasonRef, RequestRecord
from .privacy import present_consent_facts
from .projection import Freshness, StatusSnapshot
from .runtime import ClientRuntime
from .state import (
    PROVIDER_CLIENT_TRANSITIONS,
    ProviderClientState,
    transition_is_legal,
)

#: canonical states the W048 consent vocabulary reports as granted
_CONSENT_GRANTED = "granted"


def _sharing_reason(error: Exception) -> ReasonRef:
    """Preserve one canonical W048 reason verbatim."""
    return ReasonRef(
        code=str(getattr(error, "reason", "sharing-error")),
        source="sharing",
        severity="error",
    )


class ProviderClient:
    """The provider-mode client runtime (one sharing session).

    The consent presentation's economic result is a PROJECTION of
    canonical commercial truth (P1-2 correction): it is derived
    at presentation time from the canonical W051 transaction's
    own offer record, read through the gateway's bounded lease
    read — there is NO caller-supplied economic-terms input, so
    arbitrary client text can never diverge the presentation
    from the canonical economics.
    """

    MODE = "provider"

    def __init__(
        self,
        *,
        runtime: ClientRuntime,
        sharing: Any,
    ) -> None:
        if not isinstance(runtime, ClientRuntime):
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "the provider client requires a ClientRuntime",
            )
        # the injected W048 sharing runtime (the canonical
        # provider-side control plane; the client drives its public
        # surface and NEVER reimplements it)
        if sharing is None:
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "the provider client requires the injected W048 sharing "
                "runtime (the canonical control plane)",
            )
        self._runtime = runtime
        self._sharing = sharing
        self._state = ProviderClientState.UNAVAILABLE
        self._sharing_session_id = ""
        self._consent_ref = ""
        self._path_ref = ""
        self._capability: Optional[AdapterCapabilitySnapshot] = None
        self._capability_decision = ""
        self._canonical_state = ""
        self._termination_reason = ""

    # ------------------------------------------------------------------
    # reads
    # ------------------------------------------------------------------

    @property
    def state(self) -> str:
        return self._state

    @property
    def sharing_session_id(self) -> str:
        return self._sharing_session_id

    @property
    def capability_decision(self) -> str:
        return self._capability_decision

    def _now(self) -> str:
        return self._runtime.gateway.read_clock()

    def _require_legal(self, to_state: str, action: str) -> None:
        if not transition_is_legal(
            PROVIDER_CLIENT_TRANSITIONS, self._state, to_state
        ):
            raise ClientError(
                ClientReasonCode.LIFECYCLE_ILLEGAL,
                "provider client %s is illegal from %s (%s)"
                % (to_state, self._state, action),
            )

    def _transition(self, to_state: str) -> None:
        self._require_legal(to_state, "transition")
        self._state = to_state

    def _record(
        self, action: str, subject: str, outcome: str, *, resolution: str = "", reason: str = ""
    ) -> RequestRecord:
        record = RequestRecord(
            request_id=self._runtime.request_id(self.MODE, action, subject),
            mode=self.MODE,
            action=action,
            subject=subject,
            outcome=outcome,
            resolution=resolution,
            reason=reason,
            issued_at=self._now(),
            outcome_at=self._now(),
        )
        self._runtime.record_request(record)
        return record

    def _emit(
        self,
        kind: str,
        taxonomy: str,
        subject: str,
        detail: Tuple[Tuple[str, str], ...] = (),
        *,
        canonical_source: str = "",
        canonical_reason: Optional[ReasonRef] = None,
    ) -> None:
        self._runtime.emit(
            ClientEvent(
                kind=kind,
                taxonomy=taxonomy,
                subject=subject,
                observed_at=self._now(),
                detail=detail,
                canonical_source=canonical_source,
                canonical_reason=canonical_reason,
            )
        )

    def _require_operating(self, action: str) -> None:
        """A terminal client refuses every mutating action (revoked/
        expired/stopped/closed never silently return to the
        operating set — including idempotent replays)."""
        terminal = {
            ProviderClientState.REVOKED,
            ProviderClientState.EXPIRED,
            ProviderClientState.STOPPED,
            ProviderClientState.CLOSED,
        }
        if self._state in terminal:
            raise ClientError(
                ClientReasonCode.LIFECYCLE_ILLEGAL,
                "provider client %s is terminal; %s is refused (no "
                "resurrection, including idempotent replays)"
                % (self._state, action),
            )

    def _require_online(self, action: str) -> None:
        """Mutating requests require the canonical surface: while
        offline NOTHING is requested (never fabricated success; the
        refusal is journaled as a LOCAL_FAILURE)."""
        if not self._runtime.gateway.reachable:
            self._emit(
                "provider.share_started" if action in (
                    "authorize", "activate", "resume",
                ) else "provider.consent_requested" if action in (
                    "prepare", "grant",
                ) else "provider.share_stopped",
                EventTaxonomy.LOCAL_FAILURE,
                self._sharing_session_id or self._runtime.context.platform_id,
                (("offline", action),),
            )
            raise ClientError(
                ClientReasonCode.OFFLINE,
                "the canonical authority surface is unreachable: the %s "
                "request is refused (fail closed; nothing is fabricated)"
                % action,
                resolution=FailClosedResolution.UNKNOWN,
            )

    def _wrap_sharing_error(self, error: Exception, action: str) -> ClientError:
        """Wrap one canonical W048 denial with the canonical reason
        preserved VERBATIM (code + source + severity — presentation
        may translate to UX text but never alters the triple)."""
        wrapped = ClientError(
            ClientReasonCode.CANONICAL_DENIED,
            "the canonical provider-sharing machinery denied %s (%s: %s)"
            % (action, getattr(error, "reason", "sharing-error"), error),
            resolution=FailClosedResolution.DENY,
            canonical_reason=_sharing_reason(error),
        )
        return wrapped

    # -- sensitive-replay revalidation (P1-4) ---------------------------

    def _revalidated_session_state(
        self, action: str, allowed: Tuple[str, ...]
    ) -> GatewayRead:
        """Re-read the canonical sharing session and fail closed
        unless it is provider-bound and in ``allowed``.

        A recorded performed outcome is LOCAL state, not canonical
        truth: before a sensitive replay (or any activation-critical
        accept) returns success, the canonical session is re-read
        through the gateway, verified bound to THIS provider, and
        required to still hold one of the ``allowed`` states.  A
        forged or stale performed record whose canonical state has
        changed fails closed — the record alone can never prove the
        operation still holds (P1-4 correction; the typed denial
        preserves the canonical reason verbatim — the frozen event
        vocabulary is not extended)."""
        read = self._runtime.canonical_read(
            self._runtime.gateway.read_sharing_session(
                self._sharing_session_id
            ),
            expect={"provider_ref": self._runtime.context.user_ref},
        )
        if read.state not in allowed:
            raise ClientError(
                ClientReasonCode.CANONICAL_DENIED,
                "the recorded %s outcome is stale: the canonical sharing "
                "session state is %r (allowed: %s) — the local record is "
                "not canonical truth and the replay fails closed"
                % (action, read.state, "/".join(allowed)),
                resolution=FailClosedResolution.DENY,
                canonical_reason=ReasonRef(
                    code="sharing-session-state-%s" % read.state,
                    source="sharing",
                    severity="error",
                ),
            )
        return read

    # ------------------------------------------------------------------
    # UNAVAILABLE -> CAPABILITY_CHECKED -> READY
    # ------------------------------------------------------------------

    def check_capability(self) -> AdapterCapabilitySnapshot:
        """The explicit platform capability check (fail closed).

        UNKNOWN/UNSUPPORTED refuse exposure (the client stays
        UNAVAILABLE and a LOCAL_FAILURE is journaled); RESTRICTED
        is constrained operation only; SUPPORTED is eligibility
        subject to canonical checks.  No platform assumption is
        made — the adapter report is the only source."""
        self._require_legal(ProviderClientState.CAPABILITY_CHECKED, "capability")
        snapshot = self._runtime.adapter_capabilities()
        result = evaluate_capability(snapshot, "provider")
        self._capability = snapshot
        self._capability_decision = result.decision
        self._emit(
            "provider.capability_changed",
            EventTaxonomy.LOCAL_UI_EVENT,
            self._runtime.context.platform_id,
            (
                ("platform_id", snapshot.platform_id),
                ("provider_support", snapshot.provider_support),
                ("decision", result.decision),
            ),
        )
        if result.decision == CapabilityDecision.DENIED:
            self._emit(
                "provider.capability_changed",
                EventTaxonomy.LOCAL_FAILURE,
                self._runtime.context.platform_id,
                (("denial", result.detail),),
            )
            self._record(
                "capability", snapshot.platform_id, "denied",
                resolution=FailClosedResolution.DENY,
                reason=ClientReasonCode.CAPABILITY_DENIED,
            )
            raise ClientError(
                ClientReasonCode.CAPABILITY_DENIED,
                result.detail,
                resolution=FailClosedResolution.DENY,
            )
        self._transition(ProviderClientState.CAPABILITY_CHECKED)
        self._record("capability", snapshot.platform_id, "performed")
        return snapshot

    def become_ready(self) -> None:
        """Bind the canonical control-plane context (READY)."""
        self._require_legal(ProviderClientState.READY, "ready")
        # the canonical read window must answer (the sharing
        # runtime wiring is verified through the gateway clock
        # seam; no canonical truth is fabricated here)
        self._runtime.gateway.read_clock()
        self._transition(ProviderClientState.READY)

    # ------------------------------------------------------------------
    # READY -> CONSENT_REQUIRED (canonical prepare + consent facts)
    # ------------------------------------------------------------------

    def prepare_sharing(
        self,
        *,
        lease_ref: str,
        buyer_ref: str,
        provider_ref: str,
        session_ref: str,
        path_ref: str,
        scope: Any,
    ) -> ConsentFacts:
        """Drive the canonical W048 prepare (the client NEVER
        prepares enforcement itself) and present the frozen
        consent facts.

        The scope is the provider's DECLARED sharing envelope (a
        canonical ``SharingScope``); prepare fails closed on the
        canonical gates (lease window, quota, capacity,
        capability) — the client surfaces the canonical denial
        verbatim and stays READY."""
        self._require_operating("prepare")
        self._require_online("prepare")
        subject = "%s/%s" % (lease_ref, buyer_ref)
        request_id = self._runtime.request_id(self.MODE, "prepare", subject)
        replay = self._runtime.require_not_recorded_performed(
            request_id, "prepare"
        )
        if replay is not None:
            if replay.outcome == "denied":
                raise ClientError(
                    ClientReasonCode.CANONICAL_DENIED,
                    "prepare was already canonically denied (%s)" % replay.reason,
                )
            # P1-4: the canonical session already exists (exact
            # replay) — re-present the consent facts from the
            # canonical record re-read through the gateway and
            # verified bound to THIS provider (the local record
            # alone is never the presentation authority)
            read = self._runtime.canonical_read(
                self._runtime.gateway.read_sharing_session(
                    self._sharing_session_id
                ),
                expect={"provider_ref": self._runtime.context.user_ref},
            )
            session = self._sharing.session(self._sharing_session_id)
            return self._consent_facts_for(session, read)
        self._require_legal(ProviderClientState.CONSENT_REQUIRED, "prepare")
        try:
            session = self._sharing.prepare_sharing_session(
                lease_ref=lease_ref,
                buyer_ref=buyer_ref,
                provider_ref=provider_ref,
                session_ref=session_ref,
                path_ref=path_ref,
                scope=scope,
                platform_id=self._runtime.context.platform_id,
            )
        except Exception as error:  # typed canonical denials only
            self._record(
                "prepare", subject, "denied",
                resolution=FailClosedResolution.DENY,
                reason=str(getattr(error, "reason", "sharing-error")),
            )
            self._emit(
                "provider.consent_requested",
                EventTaxonomy.LOCAL_FAILURE,
                subject,
                (("denial", str(getattr(error, "reason", "sharing-error"))),),
                            )
            raise self._wrap_sharing_error(error, "prepare") from error
        self._sharing_session_id = session.sharing_session_id
        self._consent_ref = session.consent_ref
        self._path_ref = session.path_ref
        self._canonical_state = str(session.state)
        self._record("prepare", subject, "performed")
        self._emit(
            "provider.consent_requested",
            EventTaxonomy.LOCAL_REQUEST_EVENT,
            self._sharing_session_id,
            (("canonical_state", str(session.state)),),
        )
        self._project_canonical("prepared")
        self._transition(ProviderClientState.CONSENT_REQUIRED)
        return self._consent_facts_for(
            session,
            self._runtime.canonical_read(
                self._runtime.gateway.read_sharing_session(
                    self._sharing_session_id
                ),
                expect={"provider_ref": self._runtime.context.user_ref},
            ),
        )

    def _consent_facts_for(
        self, session: Any, read: GatewayRead
    ) -> ConsentFacts:
        """The frozen consent presentation, filled from canonical
        citations ONLY (scope facts, canonically-sourced commercial
        terms, the canonical current state).

        P1-2 correction: the expected economic result is PROJECTED
        from the canonical W051 transaction's own offer record —
        read through the gateway's bounded lease read for the
        session's lease, buyer-bound to the session's buyer — and
        is never free-form client input.  When the canonical
        economics cannot be read (or carry no offer terms), the
        presentation is REFUSED fail-closed (UNKNOWN): consent is
        never requested over unknown economics."""
        scope = session.scope
        lease_read = self._runtime.canonical_read(
            self._runtime.gateway.read_lease(session.lease_ref),
            expect={"buyer_ref": session.buyer_ref},
        )
        offer_terms = lease_read.binding("offer_terms")
        if not offer_terms or offer_terms == "{}":
            raise ClientError(
                ClientReasonCode.STALE_STATE,
                "the canonical commercial terms for lease %r are "
                "unavailable (the W051 record carries no offer terms): "
                "the economics are UNKNOWN and the consent presentation "
                "is refused (fail closed — never invented)"
                % session.lease_ref,
                resolution=FailClosedResolution.UNKNOWN,
                canonical_reason=ReasonRef(
                    code="commercial-offer-terms-missing",
                    source="commercial",
                    severity="error",
                ),
            )
        return present_consent_facts(
            exposed_egress=scope.exposed_egress,
            time_quota_expiry=scope.time_quota_expiry,
            buyer_ref=session.buyer_ref,
            quota_bytes=scope.byte_quota,
            max_concurrent_buyers=scope.max_concurrent_buyers,
            commercial_terms=(
                "canonical W051 offer terms %s cited by lease %s "
                "(canonical commercial state %s; projected from the "
                "canonical transaction record — never client-supplied)"
                % (offer_terms, session.lease_ref, lease_read.state)
            ),
            canonical_state=str(read.state),
            canonical_source_refs=(
                "sharing:%s" % session.sharing_session_id,
                "commercial:%s" % session.lease_ref,
            ),
        )

    # ------------------------------------------------------------------
    # CONSENT_REQUIRED -> CONSENTED (canonical consent)
    # ------------------------------------------------------------------

    def grant_consent(self) -> None:
        """Request consent through the CANONICAL W048 consent
        machinery (the UI cannot fabricate consent).  CONSENTED is
        entered only when the canonical consent record reads
        ``granted`` (fail closed)."""
        self._require_operating("grant")
        self._require_online("grant")
        subject = self._sharing_session_id
        request_id = self._runtime.request_id(self.MODE, "grant_consent", subject)
        replay = self._runtime.require_not_recorded_performed(
            request_id, "grant_consent"
        )
        if replay is not None:
            if replay.outcome == "denied":
                raise ClientError(
                    ClientReasonCode.CANONICAL_DENIED,
                    "consent grant was already canonically denied",
                )
            # P1-4: the idempotent replay is accepted only after
            # the canonical consent record is re-read and still
            # holds granted (the local record alone is not proof)
            self._revalidated_consent_state("grant_consent")
            return
        self._require_legal(ProviderClientState.CONSENTED, "grant")
        try:
            consent = self._sharing.grant_consent(subject)
        except Exception as error:
            self._record(
                "grant_consent", subject, "denied",
                resolution=FailClosedResolution.DENY,
                reason=str(getattr(error, "reason", "sharing-error")),
            )
            self._emit(
                "provider.consent_granted",
                EventTaxonomy.LOCAL_FAILURE,
                subject,
                (("denial", str(getattr(error, "reason", "sharing-error"))),),
                            )
            raise self._wrap_sharing_error(error, "consent grant") from error
        canonical_state = str(consent.state)
        if canonical_state != _CONSENT_GRANTED:
            # fail closed: a canonical non-granted consent never
            # becomes a client CONSENTED
            self._record(
                "grant_consent", subject, "denied",
                resolution=FailClosedResolution.DENY,
                reason="consent-state-%s" % canonical_state,
            )
            raise ClientError(
                ClientReasonCode.CANONICAL_DENIED,
                "the canonical consent state is %r, not granted (fail "
                "closed: no UI-only consent)" % canonical_state,
                resolution=FailClosedResolution.DENY,
                canonical_reason=ReasonRef(
                    code="sharing-consent-state-%s" % canonical_state,
                    source="sharing",
                    severity="error",
                ),
            )
        self._record("grant_consent", subject, "performed")
        self._emit(
            "provider.consent_granted",
            EventTaxonomy.LOCAL_REQUEST_EVENT,
            subject,
            (("canonical_consent", canonical_state),),
        )
        self._project_canonical("consent-granted")
        self._transition(ProviderClientState.CONSENTED)

    def _revalidated_consent_state(self, action: str) -> GatewayRead:
        """P1-4: re-read the canonical consent record and fail
        closed unless it is provider-bound and still granted — a
        recorded grant outcome is local state, never proof that
        the canonical consent still holds (the typed denial
        preserves the canonical reason verbatim)."""
        read = self._runtime.canonical_read(
            self._runtime.gateway.read_consent(self._consent_ref),
            expect={"provider_ref": self._runtime.context.user_ref},
        )
        if read.state != _CONSENT_GRANTED:
            raise ClientError(
                ClientReasonCode.CANONICAL_DENIED,
                "the recorded %s outcome is stale: the canonical consent "
                "state is %r, not granted — the local record is not "
                "canonical truth and the replay fails closed"
                % (action, read.state),
                resolution=FailClosedResolution.DENY,
                canonical_reason=ReasonRef(
                    code="sharing-consent-state-%s" % read.state,
                    source="sharing",
                    severity="error",
                ),
            )
        return read

    # ------------------------------------------------------------------
    # CONSENTED -> HANDOFF_REQUESTED -> ACTIVE (canonical handoff)
    # ------------------------------------------------------------------

    def request_handoff(self) -> None:
        """Drive the canonical W048 authorization (the handoff to
        enforcement).  The client NEVER authorizes enforcement
        itself."""
        self._require_operating("authorize")
        self._require_online("authorize")
        subject = self._sharing_session_id
        request_id = self._runtime.request_id(self.MODE, "authorize", subject)
        replay = self._runtime.require_not_recorded_performed(
            request_id, "authorize"
        )
        if replay is not None:
            if replay.outcome == "denied":
                raise ClientError(
                    ClientReasonCode.CANONICAL_DENIED,
                    "authorization was already canonically denied (%s)"
                    % replay.reason,
                )
            # P1-4: the recorded authorization is revalidated
            # against the canonical session state before the
            # replay is accepted
            self._revalidated_session_state(
                "authorize", ("authorized", "active", "paused")
            )
            return
        self._require_legal(ProviderClientState.HANDOFF_REQUESTED, "authorize")
        try:
            session = self._sharing.authorize_sharing_session(subject)
        except Exception as error:
            self._record(
                "authorize", subject, "denied",
                resolution=FailClosedResolution.DENY,
                reason=str(getattr(error, "reason", "sharing-error")),
            )
            self._emit(
                "provider.share_started",
                EventTaxonomy.LOCAL_FAILURE,
                subject,
                (("denial", str(getattr(error, "reason", "sharing-error"))),),
                            )
            raise self._wrap_sharing_error(error, "authorize") from error
        self._canonical_state = str(session.state)
        self._record("authorize", subject, "performed")
        self._emit(
            "provider.share_started",
            EventTaxonomy.LOCAL_REQUEST_EVENT,
            subject,
            (("canonical_state", str(session.state)),),
        )
        self._project_canonical(str(session.state))
        self._transition(ProviderClientState.HANDOFF_REQUESTED)

    def activate(self) -> None:
        """Drive the canonical W048 activation (containment
        admission).  Local ACTIVE is a PROJECTION ONLY: it is
        entered solely when the canonical sharing session reads
        ``active`` — never evidence by itself that connectivity
        exists."""
        self._require_operating("activate")
        self._require_online("activate")
        subject = self._sharing_session_id
        request_id = self._runtime.request_id(self.MODE, "activate", subject)
        replay = self._runtime.require_not_recorded_performed(
            request_id, "activate"
        )
        if replay is not None:
            if replay.outcome == "denied":
                raise ClientError(
                    ClientReasonCode.CANONICAL_DENIED,
                    "activation was already canonically denied (%s)"
                    % replay.reason,
                )
            # P1-4: activation-critical — the recorded activation is
            # revalidated against the canonical ACTIVE state before
            # the replay is accepted
            self._revalidated_session_state("activate", ("active",))
            return
        self._require_legal(ProviderClientState.ACTIVE, "activate")
        try:
            session = self._sharing.activate_sharing_session(subject)
        except Exception as error:
            self._record(
                "activate", subject, "denied",
                resolution=FailClosedResolution.DENY,
                reason=str(getattr(error, "reason", "sharing-error")),
            )
            raise self._wrap_sharing_error(error, "activate") from error
        self._canonical_state = str(session.state)
        if str(session.state) != "active":
            # fail closed: canonical non-active never projects ACTIVE
            self._record(
                "activate", subject, "denied",
                resolution=FailClosedResolution.DENY,
                reason="session-state-%s" % session.state,
            )
            raise ClientError(
                ClientReasonCode.CANONICAL_DENIED,
                "the canonical sharing session is %r, not active (fail "
                "closed: local ACTIVE is a projection of canonical truth "
                "only)" % session.state,
                resolution=FailClosedResolution.DENY,
                canonical_reason=ReasonRef(
                    code="sharing-session-state-%s" % session.state,
                    source="sharing",
                    severity="error",
                ),
            )
        self._record("activate", subject, "performed")
        self._project_canonical(str(session.state))
        self._transition(ProviderClientState.ACTIVE)

    # ------------------------------------------------------------------
    # ACTIVE <-> PAUSED (canonical pause/resume)
    # ------------------------------------------------------------------

    def pause(self) -> None:
        """Drive the canonical W048 pause."""
        self._require_operating("pause")
        self._require_online("pause")
        subject = self._sharing_session_id
        request_id = self._runtime.request_id(self.MODE, "pause", subject)
        replay = self._runtime.require_not_recorded_performed(
            request_id, "pause"
        )
        if replay is not None:
            # P1-4: the recorded pause is revalidated against the
            # canonical paused state before the replay is accepted
            self._revalidated_session_state("pause", ("paused",))
            return
        self._require_legal(ProviderClientState.PAUSED, "pause")
        try:
            session = self._sharing.pause_sharing_session(subject)
        except Exception as error:
            raise self._wrap_sharing_error(error, "pause") from error
        self._canonical_state = str(session.state)
        self._record("pause", subject, "performed")
        self._project_canonical(str(session.state))
        self._transition(ProviderClientState.PAUSED)

    def resume(self) -> None:
        """Drive the canonical W048 resume (full canonical
        re-check inside W048); local ACTIVE returns only when the
        canonical session reads active again."""
        self._require_operating("resume")
        self._require_online("resume")
        subject = self._sharing_session_id
        request_id = self._runtime.request_id(self.MODE, "resume", subject)
        replay = self._runtime.require_not_recorded_performed(
            request_id, "resume"
        )
        if replay is not None and replay.outcome == "denied":
            raise ClientError(
                ClientReasonCode.CANONICAL_DENIED,
                "resume was canonically denied (%s)" % replay.reason,
            )
        self._require_legal(ProviderClientState.ACTIVE, "resume")
        try:
            session = self._sharing.resume_sharing_session(subject)
        except Exception as error:
            self._record(
                "resume", subject, "denied",
                resolution=FailClosedResolution.DENY,
                reason=str(getattr(error, "reason", "sharing-error")),
            )
            raise self._wrap_sharing_error(error, "resume") from error
        self._canonical_state = str(session.state)
        if str(session.state) != "active":
            raise ClientError(
                ClientReasonCode.CANONICAL_DENIED,
                "the canonical sharing session resumed to %r (fail closed; "
                "local ACTIVE requires canonical active)" % session.state,
                resolution=FailClosedResolution.DENY,
            )
        self._record("resume", subject, "performed")
        self._project_canonical(str(session.state))
        self._transition(ProviderClientState.ACTIVE)

    # ------------------------------------------------------------------
    # withdrawal / emergency stop / canonical terminal observation
    # ------------------------------------------------------------------

    def withdraw_consent(self) -> None:
        """Withdraw consent THROUGH the canonical machinery (no
        soft revoke: new buyer traffic stops immediately at W048;
        the client verifies the canonical terminal state)."""
        self._require_operating("withdraw")
        self._require_online("withdraw")
        subject = self._sharing_session_id
        request_id = self._runtime.request_id(
            self.MODE, "withdraw_consent", subject
        )
        replay = self._runtime.require_not_recorded_performed(
            request_id, "withdraw_consent"
        )
        if replay is not None:
            return
        self._require_legal(ProviderClientState.REVOKED, "withdraw")
        try:
            session = self._sharing.withdraw_consent(subject)
        except Exception as error:
            raise self._wrap_sharing_error(error, "withdraw") from error
        self._canonical_state = str(session.state)
        self._termination_reason = str(session.termination_reason)
        self._record("withdraw_consent", subject, "performed")
        self._emit(
            "provider.consent_revoked",
            EventTaxonomy.LOCAL_REQUEST_EVENT,
            subject,
            (("canonical_state", str(session.state)),),
        )
        self._emit(
            "provider.share_stopped",
            EventTaxonomy.OBSERVED_CANONICAL_EVENT,
            subject,
            (("termination_reason", str(session.termination_reason)),),
            canonical_source="sharing",
            canonical_reason=ReasonRef(
                code="sharing-%s" % str(session.termination_reason).lower(),
                source="sharing",
                severity="error",
            ),
        )
        self._project_canonical(str(session.state))
        self._transition(ProviderClientState.REVOKED)

    def emergency_stop(self) -> None:
        """The immediate stop control (frozen semantics).

        REQUEST STOP / ENFORCE LOCAL SAFETY
            -> canonical provider-sharing termination
            -> W048 enforcement
            -> traffic termination

        The LOCAL fail-safe leg (adapter network detach) runs
        FIRST; the canonical termination request follows; the
        STOPPED state is entered only after the canonical terminal
        fact (revoked / EMERGENCY_STOP) is VERIFIED through the
        canonical read — never a boolean flip or a hidden UI that
        leaves W048 active."""
        self._require_operating("emergency-stop")
        self._require_online("emergency-stop")
        subject = self._sharing_session_id
        request_id = self._runtime.request_id(
            self.MODE, "emergency_stop", subject
        )
        replay = self._runtime.require_not_recorded_performed(
            request_id, "emergency_stop"
        )
        if replay is not None:
            return
        self._require_legal(ProviderClientState.STOPPED, "emergency-stop")
        # 1. the local fail-safe (platform mechanism via the
        #    adapter boundary; a local action, never authority)
        if self._path_ref:
            self._runtime.adapter.network_detach(self._path_ref)
        # 2. the canonical termination (W048 is the authority)
        try:
            session = self._sharing.emergency_stop(subject)
        except Exception as error:
            self._record(
                "emergency_stop", subject, "denied",
                resolution=FailClosedResolution.STOP,
                reason=str(getattr(error, "reason", "sharing-error")),
            )
            self._emit(
                "provider.share_stopped",
                EventTaxonomy.LOCAL_FAILURE,
                subject,
                (("denial", str(getattr(error, "reason", "sharing-error"))),),
                            )
            raise self._wrap_sharing_error(error, "emergency stop") from error
        # 3. verify the canonical terminal fact (fail closed)
        canonical = self._runtime.canonical_read(
            self._runtime.gateway.read_sharing_session(subject),
            expect={"provider_ref": self._runtime.context.user_ref},
        )
        if canonical.state != "revoked":
            self._record(
                "emergency_stop", subject, "denied",
                resolution=FailClosedResolution.STOP,
                reason="canonical-state-%s" % canonical.state,
            )
            raise ClientError(
                ClientReasonCode.STALE_STATE,
                "the canonical provider-sharing state after the emergency "
                "stop is %r, not revoked (the stop is NOT verified; fail "
                "closed)" % canonical.state,
                resolution=FailClosedResolution.STOP,
            )
        self._canonical_state = canonical.state
        self._termination_reason = str(session.termination_reason)
        self._record("emergency_stop", subject, "performed")
        self._emit(
            "provider.share_stopped",
            EventTaxonomy.OBSERVED_CANONICAL_EVENT,
            subject,
            (("canonical_state", canonical.state),
             ("termination_reason", str(session.termination_reason))),
            canonical_source="sharing",
            canonical_reason=ReasonRef(
                code="sharing-%s" % str(session.termination_reason).lower(),
                source="sharing",
                severity="error",
            ),
        )
        self._runtime.adapter.notification("provider.share_stopped")
        self._project_canonical(canonical.state)
        self._transition(ProviderClientState.STOPPED)

    def notify_path_lost(self, *, candidate_path_id: Optional[str] = None) -> None:
        """Drive the canonical W048 path-loss handling (the client
        reports the symptom; W048 decides pause/revoke)."""
        if self._state not in (
            ProviderClientState.ACTIVE, ProviderClientState.PAUSED,
        ):
            raise ClientError(
                ClientReasonCode.LIFECYCLE_ILLEGAL,
                "path-loss reporting requires an active/paused provider "
                "client (current: %s)" % self._state,
            )
        try:
            session = self._sharing.notify_path_lost(
                self._sharing_session_id, candidate_path_id=candidate_path_id
            )
        except Exception as error:
            raise self._wrap_sharing_error(error, "path loss") from error
        self._canonical_state = str(session.state)
        self._project_canonical(str(session.state))
        if str(session.state) == "paused":
            self._transition(ProviderClientState.PAUSED)
        elif str(session.state) == "revoked":
            self._transition(ProviderClientState.REVOKED)

    # ------------------------------------------------------------------
    # status projection / offline / reconcile
    # ------------------------------------------------------------------

    def _project_canonical(self, state: str) -> None:
        if not self._sharing_session_id:
            return
        self._runtime.project(
            StatusSnapshot(
                subject="provider:%s" % self._sharing_session_id,
                state=state,
                freshness=Freshness.CANONICAL_STATE,
                observed_at=self._now(),
                canonical_source="sharing",
            )
        )

    def refresh_status(self) -> StatusSnapshot:
        """Project the CURRENT canonical status (never the local
        projection as truth).  Offline: the cached projection is
        demoted STALE (never presented as current); terminal
        canonical states transition the client lifecycle (revoked/
        expired/stopped -> the matching client state)."""
        subject = "provider:%s" % self._sharing_session_id
        if not self._sharing_session_id:
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "no sharing session is bound to this provider client",
            )
        read = self._runtime.gateway.read_sharing_session(
            self._sharing_session_id
        )
        read = self._runtime.canonical_read(
            read, expect={"provider_ref": self._runtime.context.user_ref}
        )
        self._canonical_state = read.state
        snapshot = StatusSnapshot(
            subject=subject,
            state=read.state,
            freshness=Freshness.CANONICAL_STATE,
            observed_at=read.observed_at,
            canonical_source="sharing",
        )
        self._runtime.project(snapshot)
        self._project_terminal_from_canonical(read)
        return snapshot

    def _project_terminal_from_canonical(self, read: GatewayRead) -> None:
        """Apply terminal canonical truths to the client lifecycle
        (canonical revocation/expiry observed through the read
        window; never a local resurrection)."""
        if read.state in ("revoked", "expired", "closed"):
            reason = read.binding("termination_reason")
            target = {
                "revoked": ProviderClientState.REVOKED,
                "expired": ProviderClientState.EXPIRED,
                "closed": ProviderClientState.CLOSED,
            }[read.state]
            if transition_is_legal(
                PROVIDER_CLIENT_TRANSITIONS, self._state, target
            ):
                self._termination_reason = reason
                kind = (
                    "provider.share_stopped"
                    if read.state == "revoked"
                    else "provider.share_stopped"
                )
                self._emit(
                    kind,
                    EventTaxonomy.OBSERVED_CANONICAL_EVENT,
                    self._sharing_session_id,
                    (("canonical_state", read.state), ("termination_reason", reason)),
                    canonical_source="sharing",
                    canonical_reason=ReasonRef(
                        code="sharing-session-%s" % read.state,
                        source="sharing",
                        severity="error",
                    ),
                )
                self._transition(target)

    def reconcile(self) -> StatusSnapshot:
        """The reconnect reconciliation (frozen sequence):
        reconcile authoritative state -> accept canonical truth ->
        apply local projection -> (for provider mode the canonical
        sharing runtime keeps enforcing across reconnects; the
        client re-projects; a terminal canonical truth transitions
        the lifecycle — never a local resume)."""
        return self.refresh_status()

    # ------------------------------------------------------------------
    # CLOSED
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Drive the canonical W048 close."""
        # close is the ONE sanctioned action from the revoked family
        # (REVOKED/EXPIRED/STOPPED -> CLOSED); only CLOSED itself
        # refuses (strictly terminal)
        if self._state == ProviderClientState.CLOSED:
            raise ClientError(
                ClientReasonCode.LIFECYCLE_ILLEGAL,
                "provider client CLOSED is strictly terminal",
            )
        self._require_online("close")
        subject = self._sharing_session_id
        request_id = self._runtime.request_id(self.MODE, "close", subject)
        replay = self._runtime.require_not_recorded_performed(
            request_id, "close"
        )
        if replay is not None:
            # P1-4: the recorded close is revalidated against the
            # canonical terminal family before the replay is
            # accepted
            self._revalidated_session_state(
                "close", ("revoked", "expired", "closed")
            )
            return
        self._require_legal(ProviderClientState.CLOSED, "close")
        try:
            session = self._sharing.close_sharing_session(subject)
        except Exception as error:
            raise self._wrap_sharing_error(error, "close") from error
        self._record("close", subject, "performed")
        self._project_canonical(str(session.state))
        self._transition(ProviderClientState.CLOSED)

    # ------------------------------------------------------------------
    # snapshot / restore (restart)
    # ------------------------------------------------------------------

    def snapshot(self) -> Dict[str, Any]:
        """The provider-mode local snapshot (restart input; the
        restored lifecycle state is STALE until reconciled)."""
        return {
            "state": self._state,
            "sharing_session_id": self._sharing_session_id,
            "consent_ref": self._consent_ref,
            "path_ref": self._path_ref,
            "capability_decision": self._capability_decision,
            "canonical_state": self._canonical_state,
            "termination_reason": self._termination_reason,
        }

    def restore(self, data: object) -> None:
        """Restore the provider-mode local state (the restart
        path).  The restored state is CLIENT-LOCAL ONLY: before
        any operating action the caller MUST reconcile against
        canonical truth (a restored ACTIVE is never resume
        authority)."""
        if not isinstance(data, dict):
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "provider snapshot must be a map",
            )
        state = str(data.get("state", ""))
        if state not in ProviderClientState.values():
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "restored provider state %r is outside the frozen "
                "vocabulary" % (state,),
            )
        self._state = state
        self._sharing_session_id = str(data.get("sharing_session_id", ""))
        self._consent_ref = str(data.get("consent_ref", ""))
        self._path_ref = str(data.get("path_ref", ""))
        self._capability_decision = str(data.get("capability_decision", ""))
        self._canonical_state = str(data.get("canonical_state", ""))
        self._termination_reason = str(data.get("termination_reason", ""))

    def resume_after_restart(self) -> StatusSnapshot:
        """The post-restart gate: a restored lifecycle state is
        STALE by construction; production status is re-read from
        the canonical authorities before ANY operating action, and
        a terminal canonical truth ends the session (no local
        resume from a restored ACTIVE)."""
        if not self._sharing_session_id:
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "no sharing session bound (nothing to resume)",
            )
        snapshot = self.refresh_status()
        return snapshot
