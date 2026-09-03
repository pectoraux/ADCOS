"""WORK-049 buyer-mode client runtime.

The buyer-mode client is the user-facing
PARTICIPATION/PROJECTION surface for buyer connectivity: it
requests offers from the W047 marketplace discovery authority
(THE only source of presentable candidates), presents them
privacy-bounded, drives the canonical authorization/lease chain
through the W047 coordination seams (which drive W051), hands
the selected candidate to the W041 NetworkPath machinery
(activation belongs EXCLUSIVELY to W041 — the client never
activates a path), attaches locally through the platform
adapter, and projects status from canonical truth.

The frozen buyer client lifecycle (client-local projections/
control states ONLY — never alternate lease, session, or
NetworkPath states):

    IDLE -> DISCOVERING -> OFFER_SELECTED -> AUTHORIZATION_PENDING
    -> LEASE_CONFIRMED -> PATH_HANDOFF_PENDING -> ATTACHING
    -> ACTIVE -> DEGRADED / RECONNECTING
    -> EXPIRED / REVOKED / FAILED -> CLOSED

Invariants (frozen):

- a local ``LEASE_CONFIRMED`` CANNOT be created by UI optimism:
  it is entered only when the canonical commercial state
  confirms the lease (fail-closed verification through the
  gateway);
- a local ``ACTIVE`` is never proof that connectivity exists;
  production connectivity is true only when the canonical
  authorities (W041 path state + W051 delivery state) report
  the required active state;
- reconnect reconciles canonical truth and resumes ONLY if the
  canonical authorities permit — never automatically because
  previous local state said ACTIVE.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from .capability import (
    CapabilityDecision,
    evaluate_capability,
)
from .errors import ClientError, ClientReasonCode, FailClosedResolution
from .events import ClientEvent, EventTaxonomy
from .gateway import GatewayRead
from .model import OfferView, ReasonRef, RequestRecord
from .privacy import present_offer
from .projection import Freshness, StatusSnapshot
from .runtime import ClientRuntime
from .state import (
    BUYER_CLIENT_TRANSITIONS,
    BuyerClientState,
    transition_is_legal,
)

#: canonical commercial states that confirm the lease (the W051
#: lease truth; RESERVATION_HELD is the canonical lease-hold —
#: everything beyond it only strengthens the confirmation)
_LEASE_CONFIRMING_STATES = (
    "RESERVATION_HELD",
    "SESSION_AUTHORIZED",
    "PATH_ACTIVE",
    "DELIVERY_STARTED",
    "USAGE_ACCRUING",
)

#: canonical commercial states supporting an ACTIVE buyer
#: projection (connectivity truth stays with W041; the commercial
#: record must support active delivery)
_DELIVERY_SUPPORTED_STATES = (
    "PATH_ACTIVE",
    "DELIVERY_STARTED",
    "USAGE_ACCRUING",
)


def _marketplace_reason(error: Exception) -> ReasonRef:
    return ReasonRef(
        code=str(getattr(error, "reason", "marketplace-error")),
        source="marketplace",
        severity="error",
    )


class BuyerClient:
    """The buyer-mode client runtime (one purchase/participation)."""

    MODE = "buyer"

    def __init__(
        self,
        *,
        runtime: ClientRuntime,
        marketplace: Any,
        core: Any,
        paths: Any,
        session_id: str,
        jurisdiction: str = "gh",
    ) -> None:
        if not isinstance(runtime, ClientRuntime):
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "the buyer client requires a ClientRuntime",
            )
        if marketplace is None or core is None or paths is None:
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "the buyer client requires the injected W047 marketplace "
                "service, W051 core, and W041 NetworkPath machinery "
                "(composition through their public contracts)",
            )
        if not isinstance(session_id, str) or not session_id:
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "the buyer client references the canonical logical session "
                "id (never mints one)",
            )
        self._runtime = runtime
        self._marketplace = marketplace
        self._core = core
        self._paths = paths
        self._session_id = session_id
        self._jurisdiction = jurisdiction
        self._state = BuyerClientState.IDLE
        self._query: Optional[Any] = None
        self._presented: Tuple[OfferView, ...] = ()
        self._selected_key: Tuple[str, str] = ("", "")
        self._proposal: Optional[Any] = None
        self._coordination: Optional[Any] = None
        self._outcome: Optional[Any] = None
        self._restored_transaction_id = ""
        self._path_id = ""
        self._canonical_lease_state = ""
        self._canonical_path_state = ""
        self._failure_reason = ""

    # ------------------------------------------------------------------
    # reads
    # ------------------------------------------------------------------

    @property
    def state(self) -> str:
        return self._state

    @property
    def presented_offers(self) -> Tuple[OfferView, ...]:
        return self._presented

    @property
    def transaction_id(self) -> str:
        if self._coordination is not None:
            return str(self._coordination.transaction_id)
        return self._restored_transaction_id

    @property
    def path_id(self) -> str:
        return self._path_id

    def _now(self) -> str:
        return self._runtime.gateway.read_clock()

    def _require_legal(self, to_state: str, action: str) -> None:
        if not transition_is_legal(
            BUYER_CLIENT_TRANSITIONS, self._state, to_state
        ):
            raise ClientError(
                ClientReasonCode.LIFECYCLE_ILLEGAL,
                "buyer client %s is illegal from %s (%s)"
                % (to_state, self._state, action),
            )

    def _transition(self, to_state: str) -> None:
        self._require_legal(to_state, "transition")
        self._state = to_state

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

    def _fail(self, reason: str, message: str, *, canonical: Optional[ReasonRef] = None) -> ClientError:
        self._failure_reason = reason
        if transition_is_legal(
            BUYER_CLIENT_TRANSITIONS, self._state, BuyerClientState.FAILED
        ):
            # the LOCAL_FAILURE event stays local-class (the
            # canonical reason is preserved on the raised error —
            # never promoted onto a local-class event)
            self._emit(
                "buyer.failed",
                EventTaxonomy.LOCAL_FAILURE,
                self._subject(),
                (("reason", reason),),
            )
            self._state = BuyerClientState.FAILED
        return ClientError(
            ClientReasonCode.CANONICAL_DENIED,
            message,
            resolution=FailClosedResolution.DENY,
            canonical_reason=canonical,
        )

    def _require_operating(self, action: str) -> None:
        """A terminal buyer refuses every mutating action (expired/
        revoked/failed/closed never silently return to the
        operating set — including idempotent replays)."""
        terminal = {
            BuyerClientState.EXPIRED,
            BuyerClientState.REVOKED,
            BuyerClientState.FAILED,
            BuyerClientState.CLOSED,
        }
        if self._state in terminal:
            raise ClientError(
                ClientReasonCode.LIFECYCLE_ILLEGAL,
                "buyer client %s is terminal; %s is refused (no "
                "resurrection, including idempotent replays)"
                % (self._state, action),
            )

    def _require_online(self, action: str) -> None:
        """Mutating requests require the canonical surface: while
        offline NOTHING is requested (never fabricated success; the
        refusal is journaled as a LOCAL_FAILURE)."""
        if not self._runtime.gateway.reachable:
            self._emit(
                "buyer.failed",
                EventTaxonomy.LOCAL_FAILURE,
                self._subject(),
                (("offline", action),),
            )
            raise ClientError(
                ClientReasonCode.OFFLINE,
                "the canonical authority surface is unreachable: the %s "
                "request is refused (fail closed; nothing is fabricated)"
                % action,
                resolution=FailClosedResolution.UNKNOWN,
            )

    def _subject(self) -> str:
        if self._coordination is not None:
            return str(self._coordination.transaction_id)
        if self._selected_key != ("", ""):
            return "%s/%s" % self._selected_key
        return self._session_id

    # -- activation-critical binding + replay revalidation ----------------

    def _bound_lease_read(
        self, *, session_bound: bool
    ) -> GatewayRead:
        """Read the canonical lease bound to THIS context (P0-2).

        The lease read is verified against the client's buyer
        principal; when ``session_bound`` (the activation-critical
        gates — attach/reconnect), the lease must ADDITIONALLY be
        bound to this client's canonical logical session id: a
        lease belonging to another session or principal is a
        misbound contract and fails closed (BINDING_MISMATCH;
        local ACTIVE is never entered over it)."""
        expect: Dict[str, str] = {
            "buyer_ref": self._runtime.context.user_ref
        }
        if session_bound:
            expect["session_ref"] = self._session_id
        read = self._runtime.gateway.read_lease(self.transaction_id)
        return self._runtime.canonical_read(read, expect=expect)

    def _bound_path_read(self) -> GatewayRead:
        """Read the canonical NetworkPath bound to THIS client's
        canonical logical session (P0-2): an ACTIVE path that
        belongs to another session is a misbound contract — it
        can never support this client's local ACTIVE."""
        read = self._runtime.gateway.read_path(self._path_id)
        return self._runtime.canonical_read(
            read, expect={"session_ref": self._session_id}
        )

    # ------------------------------------------------------------------
    # IDLE -> DISCOVERING -> OFFER_SELECTED
    # ------------------------------------------------------------------

    def start_discovery(self, query: Any) -> Tuple[OfferView, ...]:
        """Start discovery through the W047 authority (the ONLY
        source of presentable offers; the buyer's location is the
        canonical BOUNDED cell representation carried by the query
        — the client never holds exact coordinates).

        The buyer capability gate is evaluated first (fail
        closed).  Returns the privacy-bounded presentation of the
        ranked candidates."""
        self._require_legal(BuyerClientState.DISCOVERING, "discovery")
        snapshot = self._runtime.adapter_capabilities()
        gate = evaluate_capability(snapshot, "buyer")
        if gate.decision == CapabilityDecision.DENIED:
            self._emit(
                "buyer.discovery_started",
                EventTaxonomy.LOCAL_FAILURE,
                self._runtime.context.platform_id,
                (("denial", gate.detail),),
            )
            raise ClientError(
                ClientReasonCode.CAPABILITY_DENIED,
                gate.detail,
                resolution=FailClosedResolution.DENY,
            )
        self._query = query
        subject = "discovery:%s" % self._runtime.context.user_ref
        try:
            result = self._marketplace.discover(query=query)
        except Exception as error:
            self._emit(
                "buyer.discovery_started",
                EventTaxonomy.LOCAL_FAILURE,
                subject,
                (("denial", str(getattr(error, "reason", "marketplace-error"))),),
            )
            raise ClientError(
                ClientReasonCode.CANONICAL_DENIED,
                "the canonical discovery authority denied the query (%s)"
                % error,
                resolution=FailClosedResolution.DENY,
                canonical_reason=_marketplace_reason(error),
            ) from error
        ranked = list(result.ranked)
        if not ranked:
            # fail closed: no fabricated candidates; the client
            # returns to IDLE (nothing was selected)
            self._emit(
                "buyer.discovery_started",
                EventTaxonomy.LOCAL_FAILURE,
                subject,
                (("excluded", str(len(result.excluded))),),
            )
            if self._state == BuyerClientState.DISCOVERING:
                self._transition(BuyerClientState.IDLE)
            raise ClientError(
                ClientReasonCode.CANONICAL_DENIED,
                "no eligible candidate survived the canonical discovery "
                "filters (fail closed; nothing is fabricated)",
                resolution=FailClosedResolution.DENY,
            )
        self._emit(
            "buyer.discovery_started",
            EventTaxonomy.LOCAL_REQUEST_EVENT,
            subject,
            (("ranked", str(len(ranked))),),
        )
        self._presented = tuple(
            self._privacy_view(candidate) for candidate in ranked
        )
        self._record("discovery", subject, "performed")
        self._transition(BuyerClientState.DISCOVERING)
        return self._presented

    def _privacy_view(self, candidate: Any) -> OfferView:
        """The privacy-bounded view of one canonical candidate
        (bounded coverage cell; canonical price/quality facts;
        minimum precision — the canonical proximity contract is
        composed, never recomputed)."""
        offer = candidate.candidate.offer
        coverage_cell = ""
        if getattr(offer, "coverage", None):
            first = sorted(
                offer.coverage, key=lambda bound: bound.cell_id
            )[0]
            coverage_cell = str(first.precision_level)
        return present_offer(
            offer_id=offer.offer_id,
            provider_id=offer.provider_id,
            currency=offer.currency,
            price_minor=offer.price_minor,
            billing_mode=offer.billing_mode,
            metered=bool(offer.metered),
            access_type=offer.access_type,
            latency_ms=int(offer.advertised.latency_ms),
            throughput_kbps=int(offer.advertised.throughput_kbps),
            coverage_cell=coverage_cell,
        )

    def select_offer(self, offer_key: Tuple[str, str]) -> OfferView:
        """The user's explicit selection among the PRESENTED
        candidates (a local UI intent; the canonical proposal is
        composed by the W047 selection authority at request
        time)."""
        self._require_legal(BuyerClientState.OFFER_SELECTED, "selection")
        match = None
        for view in self._presented:
            if (view.provider_id, view.offer_id) == tuple(offer_key):
                match = view
                break
        if match is None:
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "the selected offer %r is not among the presented "
                "privacy-bounded candidates (fail closed)" % (offer_key,),
            )
        self._selected_key = tuple(offer_key)
        self._emit(
            "buyer.offer_selected",
            EventTaxonomy.LOCAL_UI_EVENT,
            "%s/%s" % tuple(offer_key),
            (("offer_id", match.offer_id),),
        )
        self._record("selection", "%s/%s" % tuple(offer_key), "performed")
        self._transition(BuyerClientState.OFFER_SELECTED)
        return match

    # ------------------------------------------------------------------
    # OFFER_SELECTED -> AUTHORIZATION_PENDING -> LEASE_CONFIRMED
    # ------------------------------------------------------------------

    def request_authorization(self) -> str:
        """Drive the canonical authorization through the W047
        coordination seam (which drives W051
        submit_intent/select_offer/hold_reservation with
        deterministic command ids — the client issues NO direct
        commercial commands and holds no commercial journal).

        AUTHORIZATION_PENDING is entered when the coordination
        request is issued; the canonical commercial state is read
        back through the gateway (canonical lease confirmation is
        a separate fail-closed step)."""
        if self._query is None or self._selected_key == ("", ""):
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "authorization requires a discovery query and a selected "
                "offer",
            )
        self._require_operating("coordinate")
        self._require_online("coordinate")
        subject = "%s/%s" % self._selected_key
        request_id = self._runtime.request_id(
            self.MODE, "coordinate", subject
        )
        replay = self._runtime.require_not_recorded_performed(
            request_id, "coordinate"
        )
        if replay is not None:
            if replay.outcome == "denied":
                raise ClientError(
                    ClientReasonCode.CANONICAL_DENIED,
                    "coordination was already canonically denied (%s)"
                    % replay.reason,
                )
            # P1-4: the idempotent replay is accepted only after
            # the canonical coordination is re-read and verified
            # bound to THIS buyer (the local record alone is not
            # proof that the canonical transaction exists)
            try:
                self._bound_lease_read(session_bound=False)
            except ClientError as error:
                raise self._fail(
                    "coordinate-replay-unverifiable-%s" % error.reason,
                    "the recorded coordination outcome is stale: the "
                    "canonical lease read failed closed (%s) — the local "
                    "record is not canonical truth and the replay fails "
                    "closed" % error.message,
                ) from error
            # the idempotent replay: the canonical coordination
            # already happened
            return str(self.transaction_id)
        self._require_legal(
            BuyerClientState.AUTHORIZATION_PENDING, "authorization"
        )
        # re-verify the canonical lease truth BEFORE the operating
        # action (a restored/forged LEASE_CONFIRMED is stale data;
        # the canonical read is the only gate — Q1 fail closed)
        if self._coordination is not None:
            try:
                lease_read = self._bound_lease_read(session_bound=False)
            except ClientError as error:
                canonical = (
                    error.canonical_reason
                    if isinstance(error.canonical_reason, ReasonRef)
                    else None
                )
                raise self._fail(
                    "lease-unverifiable-%s" % error.reason,
                    "the canonical lease read for the operating action "
                    "failed closed (%s) — the state is UNKNOWN and never "
                    "fabricated" % error.message,
                    canonical=canonical,
                ) from error
            if lease_read.state not in _LEASE_CONFIRMING_STATES:
                raise self._fail(
                    "lease-not-confirmed-%s" % lease_read.state,
                    "the canonical commercial state is %r (fail closed: "
                    "the operating action requires a canonically "
                    "confirmed lease — never a restored/forged local "
                    "LEASE_CONFIRMED)" % lease_read.state,
                )
        try:
            proposal = self._marketplace.propose(query=self._query)
        except Exception as error:
            raise self._fail(
                str(getattr(error, "reason", "marketplace-error")),
                "the canonical selection authority rejected the proposal "
                "composition (%s)" % error,
                canonical=_marketplace_reason(error),
            ) from error
        chain = list(proposal.chain)
        if tuple(self._selected_key) not in [tuple(key) for key in chain]:
            raise self._fail(
                "selection-outside-canonical-chain",
                "the user's selected offer is not in the canonical "
                "selection chain (the canonical ranking governs; the user "
                "must re-select within the presented ranking)",
            )
        self._proposal = proposal
        self._emit(
            "buyer.authorization_pending",
            EventTaxonomy.LOCAL_REQUEST_EVENT,
            subject,
            (("proposal_id", proposal.proposal_id),),
        )
        self._transition(BuyerClientState.AUTHORIZATION_PENDING)
        try:
            coordination = self._marketplace.coordinate_reservation(
                proposal=proposal,
                core=self._core,
                buyer_id=self._runtime.context.user_ref,
                jurisdiction=self._jurisdiction,
            )
        except Exception as error:
            reason = _marketplace_reason(error)
            self._record(
                "coordinate", subject, "denied",
                resolution=FailClosedResolution.DENY,
                reason=reason.code,
            )
            raise self._fail(
                reason.code,
                "the canonical commercial coordination was rejected (%s)"
                % error,
                canonical=reason,
            ) from error
        self._coordination = coordination
        self._record("coordinate", subject, "performed")
        return str(coordination.transaction_id)

    def confirm_lease(self) -> str:
        """Confirm the lease from CANONICAL commercial truth (the
        fail-closed LEASE_CONFIRMED gate).

        A local LEASE_CONFIRMED is entered ONLY when the canonical
        W051 transaction state is one of the lease-confirming
        states — UI optimism, payment success, or a forged local
        record can NEVER reach this state (the canonical read is
        the only gate)."""
        self._require_legal(BuyerClientState.LEASE_CONFIRMED, "lease-confirm")
        if self._coordination is None:
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "lease confirmation requires an issued coordination",
            )
        transaction_id = str(self._coordination.transaction_id)
        read = self._bound_lease_read(session_bound=False)
        self._canonical_lease_state = read.state
        if read.state not in _LEASE_CONFIRMING_STATES:
            raise self._fail(
                "lease-not-confirmed-%s" % read.state,
                "the canonical commercial state is %r (fail closed: a "
                "local LEASE_CONFIRMED requires canonical commercial "
                "confirmation — never UI optimism)" % read.state,
            )
        self._emit(
            "buyer.lease_confirmed",
            EventTaxonomy.OBSERVED_CANONICAL_EVENT,
            transaction_id,
            (("canonical_state", read.state),),
            canonical_source="commercial",
            canonical_reason=ReasonRef(
                code="commercial-state-%s" % read.state,
                source="commercial",
                severity="info",
            ),
        )
        self._record("lease-confirm", transaction_id, "performed")
        self._runtime.project(
            StatusSnapshot(
                subject="buyer-lease:%s" % transaction_id,
                state=read.state,
                freshness=Freshness.CANONICAL_STATE,
                observed_at=read.observed_at,
                canonical_source="commercial",
            )
        )
        self._transition(BuyerClientState.LEASE_CONFIRMED)
        return read.state

    # ------------------------------------------------------------------
    # LEASE_CONFIRMED -> PATH_HANDOFF_PENDING -> ATTACHING -> ACTIVE
    # ------------------------------------------------------------------

    def request_path_handoff(self) -> str:
        """Hand the canonical proposal to the W041 NetworkPath
        machinery (through the W047 handoff seam, which drives the
        machinery's own validate/bind/probe/activate chain — the
        client NEVER activates a path and NEVER introduces a
        client-local path object)."""
        if self._proposal is None and not self.transaction_id:
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "path handoff requires the canonical proposal",
            )
        self._require_operating("handoff")
        self._require_online("handoff")
        subject = self.transaction_id or self._session_id
        request_id = self._runtime.request_id(self.MODE, "handoff", subject)
        replay = self._runtime.require_not_recorded_performed(
            request_id, "handoff"
        )
        if replay is not None:
            if replay.outcome == "denied":
                raise ClientError(
                    ClientReasonCode.CANONICAL_DENIED,
                    "the path handoff was already denied (%s)" % replay.reason,
                )
            # P1-4: the recorded handoff is revalidated against the
            # canonical state before the replay is accepted: the
            # lease must still exist buyer-bound and the accepted
            # path must still exist and be bound to THIS session
            try:
                self._bound_lease_read(session_bound=False)
                if self._path_id:
                    self._bound_path_read()
            except ClientError as error:
                raise self._fail(
                    "handoff-replay-unverifiable-%s" % error.reason,
                    "the recorded handoff outcome is stale: the canonical "
                    "read failed closed (%s) — the local record is not "
                    "canonical truth and the replay fails closed"
                    % error.message,
                ) from error
            # the idempotent replay: the machinery already accepted
            # the handoff
            return self._path_id
        # re-verify the canonical lease truth BEFORE the operating
        # action (a restored/forged LEASE_CONFIRMED is stale data;
        # the canonical read is the only gate — Q1 fail closed)
        if self.transaction_id:
            try:
                lease_read = self._bound_lease_read(session_bound=False)
            except ClientError as error:
                # the canonical read failed (unknown/unverifiable
                # transaction): DENY the activation, land FAILED,
                # preserve any canonical reason verbatim
                canonical = (
                    error.canonical_reason
                    if isinstance(error.canonical_reason, ReasonRef)
                    else None
                )
                raise self._fail(
                    "lease-unverifiable-%s" % error.reason,
                    "the canonical lease read for the operating action "
                    "failed closed (%s) — the state is UNKNOWN and never "
                    "fabricated" % error.message,
                    canonical=canonical,
                ) from error
            if lease_read.state not in _LEASE_CONFIRMING_STATES:
                raise self._fail(
                    "lease-not-confirmed-%s" % lease_read.state,
                    "the canonical commercial state is %r (fail closed: "
                    "the path handoff requires a canonically confirmed "
                    "lease — never a restored/forged local "
                    "LEASE_CONFIRMED)" % lease_read.state,
                )
        self._require_legal(
            BuyerClientState.PATH_HANDOFF_PENDING, "path-handoff"
        )
        self._transition(BuyerClientState.PATH_HANDOFF_PENDING)
        self._emit(
            "buyer.attach_started",
            EventTaxonomy.LOCAL_REQUEST_EVENT,
            subject,
            (("stage", "canonical-handoff"),),
        )
        try:
            outcome = self._marketplace.handoff_to_networkpath(
                proposal=self._proposal,
                manager=self._paths,
                session_id=self._session_id,
            )
        except Exception as error:
            reason = _marketplace_reason(error)
            self._record(
                "handoff", subject, "denied",
                resolution=FailClosedResolution.DENY,
                reason=reason.code,
            )
            raise self._fail(
                reason.code,
                "the W041 NetworkPath machinery rejected every candidate "
                "(%s) — the client never activates a path itself" % error,
                canonical=reason,
            ) from error
        self._outcome = outcome
        self._path_id = str(outcome.network_path_id)
        self._record("handoff", subject, "performed")
        self._transition(BuyerClientState.ATTACHING)
        return self._path_id

    def attach(self) -> None:
        """Attach locally (through the platform adapter) and
        verify the ACTIVE projection from canonical truth.

        Order (frozen): the canonical machinery has ALREADY
        validated/activated the path (the handoff); the local
        adapter attach is a LOCAL action; the canonical commercial
        path activation is recorded through the W047 seam; the
        client enters ACTIVE only when the canonical path state
        reads ACTIVE and the canonical commercial state supports
        delivery (fail closed on every unverified condition)."""
        self._require_operating("attach")
        self._require_online("attach")
        subject = self.transaction_id or self._session_id
        request_id = self._runtime.request_id(self.MODE, "attach", subject)
        replay = self._runtime.require_not_recorded_performed(
            request_id, "attach"
        )
        if replay is not None:
            if replay.outcome == "denied":
                raise ClientError(
                    ClientReasonCode.CANONICAL_DENIED,
                    "the attach was already denied (%s)" % replay.reason,
                )
            # P1-4: ACTIVATION-CRITICAL — a recorded performed
            # attach is local state, never proof that production
            # connectivity still holds: the replay is accepted only
            # after the full canonical gate is re-verified (the
            # path bound to THIS session and ACTIVE, the lease
            # bound to THIS buyer+session and delivery-supported)
            self._require_attach_gate("attach-replay")
            return
        self._require_legal(BuyerClientState.ACTIVE, "attach")
        if self._outcome is None or not self._path_id:
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "attachment requires a completed canonical handoff",
            )
        # 1. the local platform attach (adapter boundary; failed
        #    platform handoff => deny activation)
        attach_result = self._runtime.adapter.network_attach(self._path_id)
        if not attach_result.ok:
            self._record(
                "attach", subject, "denied",
                resolution=FailClosedResolution.DENY,
                reason="adapter-attach-failed",
            )
            raise self._fail(
                "adapter-attach-failed",
                "the platform adapter failed the local attach (%s): "
                "activation denied (fail closed)" % attach_result.detail,
            )
        # 2. the canonical commercial path activation (W047 seam
        #    driving W051 authorize_session/activate_path against
        #    the PROVEN W041 ACTIVE state)
        try:
            self._coordination = self._marketplace.record_path_activation(
                coordination=self._coordination,
                core=self._core,
                manager=self._paths,
                outcome=self._outcome,
                session_id=self._session_id,
                actor=self._runtime.context.user_ref,
            )
        except Exception as error:
            reason = _marketplace_reason(error)
            self._runtime.adapter.network_detach(self._path_id)
            self._record(
                "attach", subject, "denied",
                resolution=FailClosedResolution.DENY,
                reason=reason.code,
            )
            raise self._fail(
                reason.code,
                "the canonical path-activation record was rejected (%s); "
                "the local attach was rolled back (fail closed)" % error,
                canonical=reason,
            ) from error
        # 3. the canonical verification (path bound to THIS session
        #    and ACTIVE + lease bound to THIS buyer+session and
        #    delivery-supported) — the ONLY gate to local ACTIVE
        #    (P0-2: every activation-critical read is strictly
        #    context/session-bound)
        path_read, lease_read = self._require_attach_gate("attach")
        self._canonical_lease_state = lease_read.state
        self._canonical_path_state = path_read.state
        self._emit(
            "buyer.connected",
            EventTaxonomy.OBSERVED_CANONICAL_EVENT,
            self.transaction_id,
            (("path_state", path_read.state),
             ("commercial_state", lease_read.state)),
            canonical_source="networkpath",
            canonical_reason=ReasonRef(
                code="networkpath-state-ACTIVE",
                source="networkpath",
                severity="info",
            ),
        )
        self._record("attach", subject, "performed")
        self._runtime.project(
            StatusSnapshot(
                subject="buyer-path:%s" % self._path_id,
                state=path_read.state,
                freshness=Freshness.CANONICAL_STATE,
                observed_at=path_read.observed_at,
                canonical_source="networkpath",
            )
        )
        self._transition(BuyerClientState.ACTIVE)

    def _require_attach_gate(
        self, action: str
    ) -> Tuple[GatewayRead, GatewayRead]:
        """The full P0-2 activation-critical gate (fail closed on
        every unverified or misbound condition): the canonical
        NetworkPath must be bound to THIS client's canonical
        logical session AND read ACTIVE, and the canonical
        commercial lease must be bound to THIS buyer AND session
        AND support active delivery.  A cross-session or
        misbound contract can never satisfy this gate; every
        failure rolls the local attach back (fail-safe detach)
        before failing closed.  Returns the (path, lease) reads
        on success."""
        try:
            path_read = self._bound_path_read()
        except ClientError as error:
            self._runtime.adapter.network_detach(self._path_id)
            raise self._fail(
                "path-unbound-%s" % error.reason,
                "the canonical NetworkPath read for %r failed closed (%s): "
                "an unbound or cross-session path can never support this "
                "client's local ACTIVE (fail closed; local attach rolled "
                "back)" % (self._path_id, error.message),
                canonical=(
                    error.canonical_reason
                    if isinstance(error.canonical_reason, ReasonRef)
                    else None
                ),
            ) from error
        if path_read.state != "ACTIVE":
            self._runtime.adapter.network_detach(self._path_id)
            raise self._fail(
                "path-not-active-%s" % path_read.state,
                "the canonical NetworkPath state is %r (fail closed: local "
                "ACTIVE is a projection of canonical connectivity only)"
                % path_read.state,
            )
        try:
            lease_read = self._bound_lease_read(session_bound=True)
        except ClientError as error:
            self._runtime.adapter.network_detach(self._path_id)
            raise self._fail(
                "lease-unbound-%s" % error.reason,
                "the canonical commercial lease read failed closed (%s): a "
                "lease that is not bound to this buyer and this client's "
                "canonical session can never support local ACTIVE (fail "
                "closed; local attach rolled back)" % error.message,
                canonical=(
                    error.canonical_reason
                    if isinstance(error.canonical_reason, ReasonRef)
                    else None
                ),
            ) from error
        if lease_read.state not in _DELIVERY_SUPPORTED_STATES:
            self._runtime.adapter.network_detach(self._path_id)
            raise self._fail(
                "delivery-unsupported-%s" % lease_read.state,
                "the canonical commercial state %r does not support active "
                "delivery (fail closed)" % lease_read.state,
            )
        return path_read, lease_read

    # ------------------------------------------------------------------
    # ACTIVE -> DEGRADED / RECONNECTING (offline/reconnect semantics)
    # ------------------------------------------------------------------

    def observe_path_loss(self) -> None:
        """Observe a local connectivity symptom (a LOCAL
        OBSERVATION — never canonical truth).  The client moves to
        DEGRADED and the cached canonical projections are demoted
        STALE; no canonical state is fabricated."""
        if self._state not in (
            BuyerClientState.ACTIVE, BuyerClientState.DEGRADED,
        ):
            raise ClientError(
                ClientReasonCode.LIFECYCLE_ILLEGAL,
                "path-loss observation requires an ACTIVE/DEGRADED buyer "
                "(current: %s)" % self._state,
            )
        self._emit(
            "buyer.degraded",
            EventTaxonomy.LOCAL_UI_EVENT,
            self._subject(),
            (("observation", "local-connectivity-symptom"),),
        )
        self._runtime.cache.mark_stale(observed_at=self._now())
        self._transition(BuyerClientState.DEGRADED)

    def reconnect(self) -> StatusSnapshot:
        """The frozen reconnect sequence:

        reconcile authoritative state -> accept canonical truth ->
        apply local projection -> resume ONLY if the canonical
        authorities permit.

        A prior local ACTIVE is NEVER resume authority: the
        canonical path state and the canonical commercial state
        are re-read, and the client resumes to ACTIVE only when
        BOTH still support it; a terminal canonical truth
        transitions the lifecycle to EXPIRED/REVOKED/FAILED
        (revoked/expired state can never be resurrected locally)."""
        if self._state not in (
            BuyerClientState.ACTIVE,
            BuyerClientState.DEGRADED,
            BuyerClientState.RECONNECTING,
        ):
            raise ClientError(
                ClientReasonCode.LIFECYCLE_ILLEGAL,
                "reconnect requires an ACTIVE/DEGRADED/RECONNECTING "
                "buyer (current: %s)" % self._state,
            )
        if self._state != BuyerClientState.RECONNECTING:
            self._emit(
                "buyer.reconnecting",
                EventTaxonomy.LOCAL_REQUEST_EVENT,
                self._subject(),
                (("stage", "canonical-reconcile"),),
            )
            self._transition(BuyerClientState.RECONNECTING)
        # reconcile (fail closed on every unreadable condition)
        if not self._path_id or not self.transaction_id:
            raise self._fail(
                "reconcile-missing-refs",
                "the reconciling buyer lacks the canonical path/lease "
                "references (fail closed; never fabricated)",
            )
        # P0-2: the reconciling reads are strictly bound to THIS
        # buyer and THIS client's canonical logical session (a
        # misbound contract can never drive the resume decision)
        path_read = self._bound_path_read()
        lease_read = self._bound_lease_read(session_bound=True)
        self._canonical_path_state = path_read.state
        self._canonical_lease_state = lease_read.state
        # terminal canonical truths first (never resurrected)
        if lease_read.state in ("EXPIRED", "CANCELLED", "NON_DELIVERED"):
            self._emit(
                "buyer.expired",
                EventTaxonomy.OBSERVED_CANONICAL_EVENT,
                self.transaction_id,
                (("canonical_state", lease_read.state),),
                canonical_source="commercial",
                canonical_reason=ReasonRef(
                    code="commercial-state-%s" % lease_read.state,
                    source="commercial",
                    severity="error",
                ),
            )
            self._transition(BuyerClientState.EXPIRED)
        elif lease_read.state == "PATH_FAILED":
            self._emit(
                "buyer.failed",
                EventTaxonomy.OBSERVED_CANONICAL_EVENT,
                self.transaction_id,
                (("canonical_state", lease_read.state),),
                canonical_source="commercial",
                canonical_reason=ReasonRef(
                    code="commercial-state-PATH_FAILED",
                    source="commercial",
                    severity="error",
                ),
            )
            self._transition(BuyerClientState.FAILED)
        elif path_read.state == "RETIRED":
            self._emit(
                "buyer.failed",
                EventTaxonomy.OBSERVED_CANONICAL_EVENT,
                self.path_id,
                (("canonical_state", path_read.state),),
                canonical_source="networkpath",
                canonical_reason=ReasonRef(
                    code="networkpath-state-RETIRED",
                    source="networkpath",
                    severity="error",
                ),
            )
            self._transition(BuyerClientState.FAILED)
        elif (
            path_read.state == "ACTIVE"
            and lease_read.state in _DELIVERY_SUPPORTED_STATES
        ):
            # canonical authorities permit the resume
            self._runtime.project(
                StatusSnapshot(
                    subject="buyer-path:%s" % self._path_id,
                    state=path_read.state,
                    freshness=Freshness.CANONICAL_STATE,
                    observed_at=path_read.observed_at,
                    canonical_source="networkpath",
                )
            )
            self._runtime.project(
                StatusSnapshot(
                    subject="buyer-lease:%s" % self.transaction_id,
                    state=lease_read.state,
                    freshness=Freshness.CANONICAL_STATE,
                    observed_at=lease_read.observed_at,
                    canonical_source="commercial",
                )
            )
            self._transition(BuyerClientState.ACTIVE)
        else:
            # canonical truth known but not active: stay degraded
            # (the canonical state governs; never fabricated)
            self._runtime.project(
                StatusSnapshot(
                    subject="buyer-path:%s" % self._path_id,
                    state=path_read.state,
                    freshness=Freshness.CANONICAL_STATE,
                    observed_at=path_read.observed_at,
                    canonical_source="networkpath",
                )
            )
            self._transition(BuyerClientState.DEGRADED)
        snapshot = StatusSnapshot(
            subject="buyer:%s" % self._subject(),
            state=self._state,
            freshness=Freshness.CANONICAL_STATE,
            observed_at=path_read.observed_at,
            canonical_source="networkpath",
        )
        self._runtime.project(snapshot)
        return snapshot

    # ------------------------------------------------------------------
    # canonical terminal observation / close
    # ------------------------------------------------------------------

    def refresh_status(self) -> StatusSnapshot:
        """Project the current canonical buyer status (lease +
        path).  Terminal canonical truths transition the lifecycle
        (never a local resurrection)."""
        if not self.transaction_id:
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "no canonical transaction is bound to this buyer client",
            )
        # P0-2: the status projection is also buyer-bound (a lease
        # naming another principal is never projected as this
        # buyer's status)
        lease_read = self._bound_lease_read(session_bound=False)
        self._canonical_lease_state = lease_read.state
        self._runtime.project(
            StatusSnapshot(
                subject="buyer-lease:%s" % self.transaction_id,
                state=lease_read.state,
                freshness=Freshness.CANONICAL_STATE,
                observed_at=lease_read.observed_at,
                canonical_source="commercial",
            )
        )
        if lease_read.state in ("EXPIRED", "CANCELLED", "NON_DELIVERED"):
            if transition_is_legal(
                BUYER_CLIENT_TRANSITIONS,
                self._state,
                BuyerClientState.EXPIRED,
            ):
                self._emit(
                    "buyer.expired",
                    EventTaxonomy.OBSERVED_CANONICAL_EVENT,
                    self.transaction_id,
                    (("canonical_state", lease_read.state),),
                    canonical_source="commercial",
                    canonical_reason=ReasonRef(
                        code="commercial-state-%s" % lease_read.state,
                        source="commercial",
                        severity="error",
                    ),
                )
                self._transition(BuyerClientState.EXPIRED)
        if self._path_id:
            # P0-2: the path status projection is session-bound
            path_read = self._bound_path_read()
            self._canonical_path_state = path_read.state
            self._runtime.project(
                StatusSnapshot(
                    subject="buyer-path:%s" % self._path_id,
                    state=path_read.state,
                    freshness=Freshness.CANONICAL_STATE,
                    observed_at=path_read.observed_at,
                    canonical_source="networkpath",
                )
            )
        return self._runtime.cache.get(
            "buyer-lease:%s" % self.transaction_id
        ) or StatusSnapshot(
            subject="buyer-lease:%s" % self.transaction_id,
            state=lease_read.state,
            freshness=Freshness.CANONICAL_STATE,
            observed_at=lease_read.observed_at,
            canonical_source="commercial",
        )

    def close(self) -> None:
        """Close the buyer participation (local lifecycle
        terminal)."""
        # close is the sanctioned action from every non-CLOSED state
        if self._state == BuyerClientState.CLOSED:
            raise ClientError(
                ClientReasonCode.LIFECYCLE_ILLEGAL,
                "buyer client CLOSED is strictly terminal",
            )
        if self._path_id:
            self._runtime.adapter.network_detach(self._path_id)
        self._transition(BuyerClientState.CLOSED)

    # ------------------------------------------------------------------
    # snapshot / restore (restart)
    # ------------------------------------------------------------------

    def snapshot(self) -> Dict[str, Any]:
        """The buyer-mode local snapshot (restart input; restored
        lifecycle state is STALE until reconciled)."""
        return {
            "state": self._state,
            "session_id": self._session_id,
            "selected_key": list(self._selected_key),
            "transaction_id": self.transaction_id,
            "path_id": self._path_id,
            "canonical_lease_state": self._canonical_lease_state,
            "canonical_path_state": self._canonical_path_state,
            "failure_reason": self._failure_reason,
        }

    def restore(self, data: object) -> None:
        """Restore the buyer-mode local state (the restart path).

        A restored ACTIVE is CLIENT-LOCAL STALE DATA: the caller
        MUST run :meth:`resume_after_restart` (canonical
        reconciliation) before any operating action — production
        connectivity resumes only on fresh canonical authority
        confirmation."""
        if not isinstance(data, dict):
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "buyer snapshot must be a map",
            )
        state = str(data.get("state", ""))
        if state not in BuyerClientState.values():
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "restored buyer state %r is outside the frozen vocabulary"
                % (state,),
            )
        self._state = state
        self._session_id = str(data.get("session_id", self._session_id))
        self._restored_transaction_id = str(data.get("transaction_id", ""))
        selected = data.get("selected_key", ["", ""])
        self._selected_key = (
            (str(selected[0]), str(selected[1]))
            if isinstance(selected, list) and len(selected) == 2
            else ("", "")
        )
        self._path_id = str(data.get("path_id", ""))
        self._canonical_lease_state = str(data.get("canonical_lease_state", ""))
        self._canonical_path_state = str(data.get("canonical_path_state", ""))
        self._failure_reason = str(data.get("failure_reason", ""))

    def resume_after_restart(self) -> str:
        """The post-restart gate: reconcile the restored local
        state against canonical truth BEFORE any operating action.

        Returns the reconciled lifecycle state.  A restored ACTIVE
        NEVER auto-resumes production connectivity: the canonical
        path/commercial states are re-read and the client lands
        exactly where the canonical truth says it should be
        (terminal truths end the session; a non-active canonical
        state degrades; only a fully supported canonical state
        resumes ACTIVE)."""
        if not self.transaction_id and not self._path_id:
            return self._state
        if self._state == BuyerClientState.ACTIVE:
            # force the reconcile path: the restored ACTIVE is
            # stale data, never resume authority
            self._state = BuyerClientState.RECONNECTING
        if self._state in (
            BuyerClientState.RECONNECTING,
            BuyerClientState.DEGRADED,
            BuyerClientState.ACTIVE,
        ):
            return self.reconnect().state
        if self._state == BuyerClientState.EXPIRED:
            return self._state
        return self._state
