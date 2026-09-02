"""WORK-046 developer platform request boundary (the gateway).

The single request-admission path of the developer API (the
W046 frozen contract's interface boundary):

    authenticate (constant-time, environment-bound)
      -> resolve the API version (deterministic policy)
      -> rate limit (per application, non-mutating)
      -> authorize the scoped capability
      -> for mutations: the DURABLE idempotency ledger
      -> adapt to the canonical subsystem (typed public
         command surfaces ONLY) or the developerapi-owned
         resource projection
      -> append the atomic journal record (persist-then-ack)
         -- the FINALITY POINT: the canonical mutation result
         and its response are final from here
      -> append the DURABLE webhook observation obligation
         (the delivery obligation survives a process crash;
         contained: a failure here can never change the
         response)
      -> return the canonical response envelope
      -> webhook queue writes + delivery attempts STRICTLY
         AFTER the response is final and fully contained: a
         webhook queue or delivery failure may affect only
         webhook observability/retry state, never the
         response -- and never the loss of the durable
         obligation to observe

Authority discipline (the frozen boundary -- battery-pinned
structurally by the import audit and the cross-authority call
audit):

- The gateway composes the accepted commercial-plane
  authorities through their PUBLIC surfaces ONLY:
  :class:`commercial.lifecycle.CommercialCore` (``submit_intent``
  / ``hold_reservation`` for the two sanctioned
  developer-mutating commercial operations; the public reads
  otherwise), :class:`usage.lifecycle.UsageLedger` (public reads
  only -- usage truth is never developer-writable), and
  :class:`allocation.lifecycle.AllocationLedger`
  (``register_policy`` for economic-policy configuration; the
  public reads otherwise).

- The gateway NEVER imports or touches the identity, session,
  NetworkPath, routing, transport, packet, payment, or
  eligibility authorities.  There is no authority object,
  client, or private accessor for any of them anywhere in the
  developerapi family: the commercial core is injected ALREADY
  COMPOSED by the platform (its reference index was built from
  the connectivity authorities' public surfaces by the platform
  composer, outside this package).

- API success NEVER implies physical connectivity success: the
  lifecycle observation resource keeps the distinct statements
  distinct (commercial state vs. connectivity vs. physical
  evidence), and no response fabricates or promotes physical
  evidence (battery-pinned).

- Webhook emission is OBSERVATION ONLY: events are built from
  public reads, queued before delivery, and delivered through
  the injectable transport seam; delivery state never feeds
  back into any business state.  The observation phase runs
  strictly AFTER the mutation's finality point and is fully
  contained: a webhook queue or delivery persistence failure
  can never turn an admitted mutation into an API failure,
  never alter the canonical mutation result, never cause a
  duplicate canonical mutation, never invalidate idempotency,
  and never act as a hidden transaction coordinator for the
  commercial plane (battery case 42 failure-injects exactly
  this).  The DELIVERY OBLIGATION, however, is a durable
  operational obligation of the observation channel itself:
  it is persisted BEFORE the API response is returned and
  survives a process crash, so a queue-write failure (or a
  crash between the obligation and the queue phase) loses
  nothing -- restart recovery re-queues the still-missing
  endpoints exactly once (battery case 43 failure-injects
  the crash).  The delivery STATE stays observational; the
  delivery OBLIGATION is durable.  That distinction is the
  whole reliability contract.

Durability (the idempotency contract): every mutation's
request+response is ONE atomic journal record (the durable
ledger).  Duplicates replay the canonical prior response
byte-identically; conflicting reuse fails closed; the ledger
survives restart (journal-first recovery).  The crash window
between an adapted authority's append and the boundary record
is handled honestly: the derived api command id makes the
canonical subsystem's own durable idempotency return the
DUPLICATE outcome, and the boundary reconstructs the canonical
prior result from the subsystem's PUBLIC journal reads (never
re-executing the mutation).

The platform administration surface (credential issuance,
endpoint secret derivation, transaction observation emission,
due-delivery processing) is explicit and separated from the
request path: it is how the platform operator provisions and
operates the boundary, never an HTTP route.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from agent.clock import AgentClock

from protocol.canonicalization import canonical_json_bytes

from commercial.errors import CommercialError
from commercial.lifecycle import CommercialCore
from usage.errors import UsageLedgerError
from usage.lifecycle import UsageLedger
from allocation.errors import AllocationError
from allocation.lifecycle import AllocationLedger

from . import webhooks as webhook_platform
from .credentials import (
    ApplicationCredential,
    Capability,
    IssuedCredential,
    derive_application_id,
    derive_credential_secret,
    require_capability,
    secret_digest,
    verify_credential,
)
from .environments import Environment, evidence_class, require_environment
from .errors import DeveloperApiError, DeveloperApiReasonCode
from .identifiers import (
    derive_api_command_id,
    derive_request_id,
    derive_resource_id,
)
from .journal import (
    ApiStore,
    ApiIndex,
    AppendOnlyApiJournal,
    CredentialRecord,
    MutationRecord,
    WebhookAttemptRecord,
    WebhookObligationRecord,
    WebhookQueueRecord,
    derive_request_digest,
    fold_index,
)
from .pagination import normalize_filters, paginate
from .ratelimit import RateDecision, RateLimiter
from .schema import (
    API_VERSION_HEADER,
    ApiVersionSpec,
    canonical_response_bytes,
    resolve_version,
)

#: The transport seam: (endpoint_id, url, payload, headers) ->
#: (delivered, response_code).  Deterministic, offline, injected.
DeliveryTransport = Callable[
    [str, str, Mapping[str, Any], Mapping[str, str]], Tuple[bool, int]
]

#: The states a transaction must have reached for its lease
#: (reservation) projection to exist.
_LEASE_STATES = frozenset({
    "RESERVATION_HELD",
    "SESSION_AUTHORIZED",
    "PATH_ACTIVE",
    "DELIVERY_STARTED",
    "USAGE_ACCRUING",
    "DELIVERY_COMPLETED",
    "BILLABLE_FINAL",
    "SETTLEMENT_PENDING",
    "SETTLED",
    "CANCELLED",
    "EXPIRED",
    "PATH_FAILED",
    "NON_DELIVERED",
})

#: The honest lifecycle statement set (never collapsed): the
#: API reports the canonical COMMERCIAL state and explicitly
#: does NOT claim connectivity or physical evidence.
_LIFECYCLE_STATEMENTS = (
    "api_request_accepted",
    "commercial_intent_persisted",
    "reservation_created",
    "lease_created",
    "provider_eligibility_determined_by_w045_authority",
    "connectivity_requested",
    "connectivity_operational_per_networkpath_authority",
    "physical_connectivity_observed",
)


@dataclass(frozen=True)
class ApiRequest:
    """One developer API request (the transport-independent
    representation the SDK reproduces for parity)."""

    method: str
    route: str
    body: Mapping[str, Any]
    api_version: str = ""
    idempotency_key: str = ""
    application_id: str = ""
    secret: str = ""

    def __post_init__(self) -> None:
        if self.method not in ("GET", "POST"):
            raise DeveloperApiError(
                DeveloperApiReasonCode.INVALID_INPUT,
                "method %r must be GET or POST" % self.method,
            )
        if not isinstance(self.route, str) or not self.route:
            raise DeveloperApiError(
                DeveloperApiReasonCode.INVALID_INPUT,
                "route must be a non-empty string",
            )
        if not isinstance(self.body, Mapping):
            raise DeveloperApiError(
                DeveloperApiReasonCode.INVALID_INPUT,
                "body must be a mapping",
            )

    def canonical_body(self) -> Dict[str, Any]:
        return dict(self.body)


@dataclass(frozen=True)
class ApiResponse:
    """One developer API response (canonical body + headers)."""

    status: int
    body: Mapping[str, Any]
    headers: Mapping[str, str]

    def canonical_body_bytes(self) -> bytes:
        return canonical_response_bytes(self.body)

    def data(self) -> Any:
        return dict(self.body).get("data")

    def error(self) -> Any:
        return dict(self.body).get("error")


@dataclass(frozen=True)
class RouteSpec:
    """One declared route: operation, required capability,
    whether it mutates (idempotency required), and its request
    schema role (validated against the request's own API
    version schema set)."""

    operation: str
    capability: str
    mutation: bool = False
    schema_role: str = ""


#: The frozen route table (the versioned REST surface, native
#: ADCOS terminology: offers, intents, reservations/leases,
#: usage, billing, economic policies, webhook endpoints,
#: deliveries, the self credential record).
ROUTES: Dict[Tuple[str, str], RouteSpec] = {
    ("GET", "application"): RouteSpec(
        "application_self", "", False, ""
    ),
    ("GET", "offers"): RouteSpec(
        "offers_list", Capability.OFFERS_READ, False, ""
    ),
    ("POST", "offers"): RouteSpec(
        "offer_publish", Capability.OFFERS_WRITE, True, "offer"
    ),
    ("GET", "offers/{}"): RouteSpec(
        "offer_get", Capability.OFFERS_READ, False, ""
    ),
    ("GET", "intents"): RouteSpec(
        "intents_list", Capability.INTENTS_READ, False, ""
    ),
    ("POST", "intents"): RouteSpec(
        "intent_create", Capability.INTENTS_WRITE, True, "intent_request"
    ),
    ("GET", "intents/{}"): RouteSpec(
        "intent_get", Capability.INTENTS_READ, False, ""
    ),
    ("GET", "intents/{}/lifecycle"): RouteSpec(
        "intent_lifecycle", Capability.INTENTS_READ, False, ""
    ),
    ("POST", "intents/{}/reservations"): RouteSpec(
        "reservation_create", Capability.LEASES_WRITE, True,
        "reservation_request",
    ),
    ("GET", "reservations"): RouteSpec(
        "reservations_list", Capability.LEASES_READ, False, ""
    ),
    ("GET", "reservations/{}"): RouteSpec(
        "reservation_get", Capability.LEASES_READ, False, ""
    ),
    ("GET", "usage"): RouteSpec(
        "usage_list", Capability.USAGE_READ, False, ""
    ),
    ("GET", "usage/{}"): RouteSpec(
        "usage_get", Capability.USAGE_READ, False, ""
    ),
    ("GET", "billing"): RouteSpec(
        "billing_list", Capability.BILLING_READ, False, ""
    ),
    ("GET", "economic-policies"): RouteSpec(
        "policies_list", Capability.ECONOMIC_POLICY_READ, False, ""
    ),
    ("POST", "economic-policies"): RouteSpec(
        "policy_register", Capability.ECONOMIC_POLICY_WRITE, True,
        "economic_policy",
    ),
    ("GET", "economic-policies/{}/{}"): RouteSpec(
        "policy_get", Capability.ECONOMIC_POLICY_READ, False, ""
    ),
    ("GET", "webhook-endpoints"): RouteSpec(
        "endpoints_list", Capability.WEBHOOKS_READ, False, ""
    ),
    ("POST", "webhook-endpoints"): RouteSpec(
        "endpoint_register", Capability.WEBHOOKS_WRITE, True,
        "webhook_endpoint",
    ),
    ("GET", "webhook-endpoints/{}"): RouteSpec(
        "endpoint_get", Capability.WEBHOOKS_READ, False, ""
    ),
    ("GET", "webhook-endpoints/{}/deliveries"): RouteSpec(
        "deliveries_list", Capability.WEBHOOKS_READ, False, ""
    ),
}


def match_route(method: str, route: str) -> Tuple[RouteSpec, List[str]]:
    """Match one request route against the versioned route
    table.

    The route MUST be ``/api/{version}/{resource...}``; the
    version is unambiguous (the route prefix and the version
    header must agree -- enforced by the caller before this
    match).  Unknown routes fail closed ``route-unknown``."""
    if not route.startswith("/"):
        raise DeveloperApiError(
            DeveloperApiReasonCode.INVALID_INPUT,
            "route must start with '/'",
        )
    parts = [part for part in route.split("/") if part]
    if len(parts) < 2 or parts[0] != "api":
        raise DeveloperApiError(
            DeveloperApiReasonCode.ROUTE_UNKNOWN,
            "route %r is not under the /api/{version}/ namespace"
            % route,
        )
    resolve_version(parts[1])  # fail closed on an unresolvable version
    target = parts[2:]
    for (route_method, route_pattern), spec in sorted(ROUTES.items()):
        if route_method != method:
            continue
        pattern_parts = route_pattern.split("/")
        if len(pattern_parts) != len(target):
            continue
        positional: List[str] = []
        matched = True
        for pattern_part, target_part in zip(pattern_parts, target):
            if pattern_part == "{}":
                positional.append(target_part)
            elif pattern_part != target_part:
                matched = False
                break
        if matched:
            return spec, positional
    raise DeveloperApiError(
        DeveloperApiReasonCode.ROUTE_UNKNOWN,
        "no %s route matches %r (declared: %s)"
        % (method, route, sorted({r[1] for r in ROUTES if r[0] == method})),
    )


class DeveloperApiService:
    """The developer platform request boundary (frozen public
    surface).

    Construct fresh over an EMPTY store; recover a persisted
    store with :meth:`load` (journal-first recovery: the fold
    IS the state).  One instance is bound to exactly ONE
    environment and holds exactly ONE journal.
    """

    def __init__(
        self,
        *,
        environment: str,
        core: CommercialCore,
        usage: UsageLedger,
        allocation: AllocationLedger,
        store: ApiStore,
        clock: AgentClock,
        issuance_key: bytes,
        rate_limiter: Optional[RateLimiter] = None,
        delivery_transports: Optional[Mapping[str, DeliveryTransport]] = None,
    ) -> None:
        self._environment = require_environment(environment)
        if not isinstance(core, CommercialCore):
            raise DeveloperApiError(
                DeveloperApiReasonCode.INVALID_INPUT,
                "the developer API requires a CommercialCore (the "
                "WORK-051 canonical commercial authority, injected "
                "already-composed by the platform)",
            )
        if not isinstance(usage, UsageLedger):
            raise DeveloperApiError(
                DeveloperApiReasonCode.INVALID_INPUT,
                "the developer API requires a UsageLedger (the "
                "WORK-052 canonical usage authority)",
            )
        if not isinstance(allocation, AllocationLedger):
            raise DeveloperApiError(
                DeveloperApiReasonCode.INVALID_INPUT,
                "the developer API requires an AllocationLedger (the "
                "WORK-053 canonical economic allocation authority)",
            )
        if not isinstance(clock, AgentClock):
            raise DeveloperApiError(
                DeveloperApiReasonCode.INVALID_INPUT,
                "the developer API requires an AgentClock (the WORK-033 "
                "seam; the boundary never reads a wall clock)",
            )
        if not isinstance(issuance_key, (bytes, bytearray)) or not issuance_key:
            raise DeveloperApiError(
                DeveloperApiReasonCode.INVALID_INPUT,
                "the developer API requires a platform issuance key",
            )
        self._core = core
        self._usage = usage
        self._allocation = allocation
        self._clock = clock
        self._issuance_key = bytes(issuance_key)
        self._rate_limiter = rate_limiter
        self._transports: Dict[str, DeliveryTransport] = dict(
            delivery_transports or {}
        )
        self._journal = AppendOnlyApiJournal(store=store)
        if self._journal.tail_sequence() != 0:
            raise DeveloperApiError(
                DeveloperApiReasonCode.INVALID_INPUT,
                "fresh construction requires an EMPTY store; use "
                "DeveloperApiService.load for journal-first recovery",
            )
        self._index = ApiIndex()
        # Post-finality webhook containment state (health data
        # ONLY -- never business state).  The DURABLE recovery
        # truth for webhook observations is the journal's
        # obligation records (folded into the index at load);
        # this in-process buffer is the honest residual for the
        # one case the journal cannot cover: an observation
        # whose OBLIGATION WRITE itself failed is retained here
        # for best-effort in-process recovery through the
        # delivery pump (the journal is the only durable medium;
        # if the process crashes before the store heals, that
        # observation is lost -- recorded as an incident, never
        # silently).  Both buffers are process-local; the
        # incidents are health data only.
        self._pending_emissions: List[Callable[[], int]] = []
        self._observation_incidents: List[Dict[str, Any]] = []

    # -----------------------------------------------------------------
    # Journal-first recovery
    # -----------------------------------------------------------------

    @classmethod
    def load(
        cls,
        *,
        environment: str,
        core: CommercialCore,
        usage: UsageLedger,
        allocation: AllocationLedger,
        store: ApiStore,
        clock: AgentClock,
        issuance_key: bytes,
        rate_limiter: Optional[RateLimiter] = None,
        delivery_transports: Optional[Mapping[str, DeliveryTransport]] = None,
    ) -> "DeveloperApiService":
        """Rebuild the boundary from the persisted journal bytes
        (byte-identical replay; construction is recovery)."""
        service = cls(
            environment=environment,
            core=core,
            usage=usage,
            allocation=allocation,
            store=_FreshStoreView(store),
            clock=clock,
            issuance_key=issuance_key,
            rate_limiter=rate_limiter,
            delivery_transports=delivery_transports,
        )
        # replay the real store through the real journal
        service._journal = AppendOnlyApiJournal(store=store)
        service._index = fold_index(service._journal.records())
        return service

    # -----------------------------------------------------------------
    # Public reads (boundary state, diagnostics)
    # -----------------------------------------------------------------

    def environment(self) -> str:
        return self._environment

    def journal_records(self) -> Tuple[Any, ...]:
        return self._journal.records()

    def journal_digest(self) -> str:
        return self._journal.journal_digest()

    def index(self) -> ApiIndex:
        return self._index

    def verify_integrity(self) -> None:
        """Re-verify the journal fold (tamper evidence): the
        live index must be exactly the journal fold."""
        folded = fold_index(self._journal.records())
        if sorted(folded.mutations) != sorted(self._index.mutations):
            raise DeveloperApiError(
                DeveloperApiReasonCode.JOURNAL_CORRUPT,
                "live idempotency ledger diverges from the journal fold",
            )
        if sorted(folded.credentials) != sorted(self._index.credentials):
            raise DeveloperApiError(
                DeveloperApiReasonCode.JOURNAL_CORRUPT,
                "live credential registry diverges from the journal fold",
            )
        if sorted(folded.obligations) != sorted(self._index.obligations):
            raise DeveloperApiError(
                DeveloperApiReasonCode.JOURNAL_CORRUPT,
                "live webhook obligation index diverges from the "
                "journal fold",
            )
        if sorted(folded.deliveries) != sorted(self._index.deliveries):
            raise DeveloperApiError(
                DeveloperApiReasonCode.JOURNAL_CORRUPT,
                "live delivery index diverges from the journal fold",
            )

    # -----------------------------------------------------------------
    # Platform administration surface (never an HTTP route)
    # -----------------------------------------------------------------

    def issue_application_credential(
        self,
        *,
        developer_id: str,
        application_name: str,
        capabilities: Tuple[str, ...],
        valid_until: str,
        key_material: str,
        actor: str,
    ) -> IssuedCredential:
        """Provision one developer application credential.

        The platform's out-of-band issuance surface: the secret
        is derived deterministically from the issuance key,
        returned ONCE here, and only its DIGEST is journaled
        (secret hygiene is battery-audited)."""
        for label, value in (
            ("developer_id", developer_id),
            ("application_name", application_name),
            ("valid_until", valid_until),
            ("key_material", key_material),
            ("actor", actor),
        ):
            if not isinstance(value, str) or not value:
                raise DeveloperApiError(
                    DeveloperApiReasonCode.INVALID_INPUT,
                    "%s must be a non-empty string" % label,
                )
        application_id = derive_application_id(
            self._environment, developer_id, application_name, key_material
        )
        if application_id in self._index.credentials:
            raise DeveloperApiError(
                DeveloperApiReasonCode.INVALID_INPUT,
                "application %r is already issued in environment %r"
                % (application_id, self._environment),
            )
        secret = derive_credential_secret(self._issuance_key, application_id)
        issued_at = self._clock.now()
        record = CredentialRecord.build(
            sequence=self._journal.tail_sequence() + 1,
            prev_record_id=self._journal.tail_record_id(),
            action="credential-issue",
            application_id=application_id,
            developer_id=developer_id,
            application_name=application_name,
            environment=self._environment,
            capabilities=tuple(capabilities),
            status="active",
            valid_until=valid_until,
            issued_at=issued_at,
            secret_digest=secret_digest(secret),
        )
        self._journal.append(record)
        self._index.apply(record)
        credential = ApplicationCredential(
            application_id=application_id,
            developer_id=developer_id,
            application_name=application_name,
            environment=self._environment,
            capabilities=tuple(capabilities),
            status="active",
            valid_until=valid_until,
            issued_at=issued_at,
            secret_digest=secret_digest(secret),
        )
        return IssuedCredential(record=credential, secret=secret)

    def revoke_application_credential(
        self, *, application_id: str, actor: str
    ) -> None:
        """Revoke one application credential (terminal)."""
        if application_id not in self._index.credentials:
            raise DeveloperApiError(
                DeveloperApiReasonCode.RESOURCE_UNKNOWN,
                "application %r is not issued in this environment"
                % application_id,
            )
        record = CredentialRecord.build(
            sequence=self._journal.tail_sequence() + 1,
            prev_record_id=self._journal.tail_record_id(),
            action="credential-revoke",
            application_id=application_id,
            developer_id=self._index.credentials[application_id][
                "developer_id"
            ],
            revoked_at=self._clock.now(),
        )
        self._journal.append(record)
        self._index.apply(record)

    def endpoint_signing_secret(self, endpoint_id: str) -> str:
        """The platform-side signing secret of one webhook
        endpoint (deterministically re-derived; never journaled;
        delivered to the developer through the platform's secure
        channel, never through an API response)."""
        endpoint = self._index.endpoints.get(endpoint_id)
        if endpoint is None:
            raise DeveloperApiError(
                DeveloperApiReasonCode.RESOURCE_UNKNOWN,
                "webhook endpoint %r is not registered" % endpoint_id,
            )
        return webhook_platform.derive_endpoint_signing_secret(
            self._issuance_key, endpoint_id
        )

    def observe_transaction(self, transaction_id: str) -> int:
        """Emit the lifecycle observation webhook for one
        commercial transaction (platform-side surface).

        Reads the canonical CURRENT public projection and emits
        ``connectivity_transaction.state_changed`` when the
        transaction advanced beyond the last observed version.
        Returns the number of new deliveries queued.  The
        webhook system reports what ADCOS already knows; it
        never decides what ADCOS knows."""
        transaction = self._core.transaction(transaction_id)
        latest_event_id = self._latest_core_event_id(transaction_id)
        if not latest_event_id:
            latest_event_id = transaction.to_dict().get(
                "transaction_id", ""
            )
        return self._emit_event(
            event_type="connectivity_transaction.state_changed",
            event_id=latest_event_id,
            occurred_at=transaction.to_dict().get("last_instant", ""),
            resource_kind="intent",
            resource_id=transaction_id,
            resource_version=transaction.to_dict().get("event_count", 1),
            correlation="",
            data=self._intent_resource(transaction_id),
        )

    def process_due_deliveries(self) -> int:
        """Attempt every due webhook delivery (deterministic
        order: delivery id ascending).

        The DURABLE outstanding observation obligations are
        flushed FIRST (obligation-recovery: every obligation
        whose queue phase did not complete -- whether because a
        queue write failed in-process or because the process
        crashed between the obligation and the queue phase -- is
        re-queued for its still-missing endpoints; the delivery
        identity dedupe makes the flush exactly-once), then the
        in-process residual observations, then the delivery
        pass.  A still-failing store keeps the obligation
        outstanding and records an incident; an observation
        failure never surfaces as an API failure and never
        re-executes the canonical mutation.

        Due = pending (never attempted) OR failed with a
        scheduled next attempt that has arrived AND schedule
        capacity remaining.  Delivered is terminal.  Returns the
        number of attempts performed."""
        self._flush_outstanding_obligations()
        self._retry_pending_emissions()
        now = self._clock.now()
        performed = 0
        for delivery_id in sorted(self._index.deliveries):
            state = self._index.deliveries[delivery_id]
            if state.last_status == "delivered":
                continue
            if state.attempts >= webhook_platform.MAX_DELIVERY_ATTEMPTS:
                continue
            if state.attempts > 0:
                if not state.next_attempt_at:
                    continue
                if state.next_attempt_at > now:
                    continue
            self._attempt_delivery(delivery_id, now)
            performed += 1
        return performed

    def pending_webhook_obligations(self) -> Tuple[Mapping[str, Any], ...]:
        """The durable webhook observation obligations still
        outstanding (platform-side, never an HTTP route).

        An obligation is outstanding exactly when at least one
        of its target endpoints does not yet hold the queue
        record for its event -- the satisfaction condition is
        DERIVED from the journal fold (never separately stored),
        so the live view, a restarted view, and a replayed view
        agree by construction.  One entry per outstanding
        obligation: its identity, the full observation payload
        members, and the endpoints still pending.  This is the
        surface a restarted service (and the delivery pump)
        recovers the observation channel from -- operational
        observation-channel state, never business state."""
        out: List[Dict[str, Any]] = []
        for obligation_id in sorted(self._index.obligations):
            record = self._index.obligations[obligation_id]
            missing = [
                endpoint_id
                for endpoint_id in record.endpoints
                if webhook_platform.derive_delivery_id(
                    endpoint_id, record.event_id
                )
                not in self._index.deliveries
            ]
            if not missing:
                continue
            entry = record.to_dict()
            del entry["sequence"]
            del entry["record_id"]
            entry["pending_endpoints"] = tuple(missing)
            out.append(entry)
        return tuple(out)

    def webhook_observation_incidents(self) -> Tuple[Mapping[str, Any], ...]:
        """The contained post-finality webhook observation
        failures (health DATA only -- never business state, never
        an API response, never the mutation result).

        One incident per contained failure: the phase (queue or
        obligation write at emission time ``emission`` / the
        durable obligation recovery flush
        ``obligation-retry`` / the in-process residual retry
        ``emission-retry`` / the delivery pass ``delivery``), the
        error class and message, the boundary reason code when
        the failure is a boundary error, and the instant.
        Incidents are process-local health data: they are NOT
        journal records, they never survive a restart, and
        durable truth remains the journal alone.  The platform
        operator reads them to diagnose webhook-plane health;
        nothing in the commercial plane reads them."""
        return tuple(
            dict(incident) for incident in self._observation_incidents
        )

    def _observe_after_finality(self, emission: Callable[[], int]) -> None:
        """Run the webhook observation phase of one mutation,
        strictly after the mutation's finality point, fully
        contained.

        Containment semantics (the frozen W046 invariant): the
        emission first persists the DURABLE observation
        obligation and then queues the per-endpoint deliveries;
        a failure at either step retains the observation for
        recovery (the durable obligation when its write
        succeeded, the in-process residual otherwise) and
        records an incident; a delivery-pass failure records an
        incident.  NOTHING raised here ever reaches the caller:
        the mutation response was finalized before this method
        is entered, and this method must never raise.  The
        webhook system is an observer, never a transaction
        coordinator for the commercial plane."""
        try:
            emission()
        except Exception as error:
            # the obligation write or a queue write failed: the
            # observation is retained for recovery -- durably if
            # the obligation record landed (restart recovery
            # owns it), in-process as the honest residual
            # otherwise; the incident is webhook health data only
            self._record_observation_incident("emission", error)
            self._pending_emissions.append(emission)
            return
        try:
            self.process_due_deliveries()
        except Exception as error:
            # the delivery pass failed after the observation
            # queued: the queue record is durable and the pump
            # will retry the delivery; the incident is health
            # data only
            self._record_observation_incident("delivery", error)

    def _flush_outstanding_obligations(self) -> int:
        """Flush the durable outstanding observation obligations
        (contained: never raises).

        For every obligation whose queue phase did not complete
        (in-process failure or a crash before the queue writes),
        the still-missing endpoints are queued now (the delivery
        identity dedupe makes the flush exactly-once; a partial
        multi-endpoint queue phase resumes, never repeats).  A
        still-failing store keeps the obligation outstanding and
        records an incident.  Returns the number of deliveries
        queued."""
        if not self._index.obligations:
            return 0
        queued = 0
        for obligation_id in sorted(self._index.obligations):
            record = self._index.obligations[obligation_id]
            missing = [
                endpoint_id
                for endpoint_id in record.endpoints
                if webhook_platform.derive_delivery_id(
                    endpoint_id, record.event_id
                )
                not in self._index.deliveries
            ]
            if not missing:
                continue
            try:
                queued += self._queue_observation(
                    event_id=record.event_id,
                    event_type=record.event_type,
                    occurred_at=record.occurred_at,
                    developer_id=record.developer_id,
                    resource_kind=record.resource_kind,
                    resource_id=record.resource_id,
                    resource_version=record.resource_version,
                    correlation=record.correlation,
                    data=record.data_dict(),
                    endpoints=tuple(missing),
                )
            except Exception as error:
                # the obligation is durable: it stays outstanding
                # and the next pump pass retries; the incident is
                # webhook health data only
                self._record_observation_incident(
                    "obligation-retry", error
                )
        return queued

    def _retry_pending_emissions(self) -> int:
        """Retry the retained in-process residual observations
        (contained: never raises).

        These are observations whose DURABLE obligation write
        itself failed (the journal is the only durable medium):
        a still-failing store keeps the observation pending and
        records an incident; a healthy store flushes it (the
        queue dedupe by delivery identity makes this
        exactly-once even after a partial multi-endpoint
        emission).  Returns the number of observations flushed."""
        if not self._pending_emissions:
            return 0
        still_pending: List[Callable[[], int]] = []
        flushed = 0
        for emission in self._pending_emissions:
            try:
                emission()
                flushed += 1
            except Exception as error:
                self._record_observation_incident(
                    "emission-retry", error
                )
                still_pending.append(emission)
        self._pending_emissions = still_pending
        return flushed

    def _record_observation_incident(
        self, phase: str, error: BaseException
    ) -> None:
        """Record one contained webhook observation failure as
        health data (structured, deterministic, secret-free:
        store/journal errors carry paths and record kinds only)."""
        reason = ""
        if isinstance(error, DeveloperApiError):
            reason = error.reason
        self._observation_incidents.append(
            {
                "kind": "webhook_observation_incident",
                "phase": phase,
                "error_class": type(error).__name__,
                "error_message": str(error),
                "reason_code": reason,
                "instant": self._clock.now(),
                "observational_only": True,
            }
        )

    # -----------------------------------------------------------------
    # The request path
    # -----------------------------------------------------------------

    def handle(self, request: ApiRequest) -> ApiResponse:
        """The single request admission path.

        Canonical subsystem failures surfacing anywhere in the
        read or mutation paths are translated HERE with the
        exact canonical reason preserved (criterion 4)."""
        request_id = derive_request_id(
            self._environment,
            request.api_version or "",
            request.method,
            request.route,
            request.canonical_body(),
        )
        try:
            return self._handle(request, request_id)
        except DeveloperApiError as error:
            return self._error_response(request, request_id, error)
        except (CommercialError, UsageLedgerError, AllocationError) as error:
            return self._error_response(
                request,
                request_id,
                self._adapted_error(error, request_id=request_id),
            )

    def _handle(
        self, request: ApiRequest, request_id: str
    ) -> ApiResponse:
        # 1. the unambiguous API version (route + header must
        #    agree when both are present)
        version = self._resolve_request_version(request)
        # 2. authentication (constant-time, environment-bound)
        credential = self._authenticate(request)
        # 3. rate limiting (per application; non-mutating)
        rate = None
        if self._rate_limiter is not None:
            rate = self._rate_limiter.check(request.application_id)
        # 4. route + scoped capability
        spec, positional = match_route(request.method, request.route)
        if spec.capability:
            require_capability(credential, spec.capability)
        # 5. the mutation gate: durable idempotency
        if spec.mutation:
            return self._handle_mutation(
                request, request_id, version, spec, positional, credential, rate
            )
        return self._handle_read(
            request, request_id, version, spec, positional, credential, rate
        )

    # -- version --------------------------------------------------------

    def _resolve_request_version(self, request: ApiRequest) -> ApiVersionSpec:
        parts = [part for part in request.route.split("/") if part]
        route_version = ""
        if len(parts) >= 2 and parts[0] == "api":
            route_version = parts[1]
        header_version = request.api_version
        if header_version and route_version and header_version != route_version:
            raise DeveloperApiError(
                DeveloperApiReasonCode.VERSION_UNSUPPORTED,
                "route version %r and %s %r disagree (a request must be "
                "unambiguously attributable to one API version)"
                % (route_version, API_VERSION_HEADER, header_version),
            )
        return resolve_version(header_version or route_version)

    # -- authentication ---------------------------------------------------

    def _authenticate(self, request: ApiRequest) -> ApplicationCredential:
        entry = self._index.credentials.get(request.application_id)
        if entry is None:
            raise DeveloperApiError(
                DeveloperApiReasonCode.AUTHENTICATION_INVALID,
                "application %r is not issued in environment %r"
                % (request.application_id, self._environment),
                request_id="",
            )
        credential = ApplicationCredential(
            application_id=entry["application_id"],
            developer_id=entry["developer_id"],
            application_name=entry["application_name"],
            environment=entry["environment"],
            capabilities=tuple(entry["capabilities"]),
            status=entry["status"],
            valid_until=entry["valid_until"],
            issued_at=entry["issued_at"],
            secret_digest=entry["secret_digest"],
        )
        verify_credential(
            credential, self._environment, request.secret, self._clock
        )
        return credential

    # -- reads ------------------------------------------------------------

    def _handle_read(
        self,
        request: ApiRequest,
        request_id: str,
        version: ApiVersionSpec,
        spec: RouteSpec,
        positional: List[str],
        credential: ApplicationCredential,
        rate: Optional[RateDecision],
    ) -> ApiResponse:
        body = request.canonical_body()
        developer = credential.developer_id

        if spec.operation == "application_self":
            data = dict(credential.to_dict())
            data["kind"] = "application"
            data["evidence_class"] = evidence_class(self._environment)
            return self._envelope(
                request, request_id, version, data, rate=rate
            )

        if spec.operation == "offers_list":
            items = self._developer_offers(developer)
            filters = normalize_filters(
                body.get("filters"), ("pricing_currency", "pricing_unit")
            )
            page, cursor, more = self._page(
                items, "offer", developer, filters, body
            )
            data = {"items": page, "next_cursor": cursor, "has_more": more}
            return self._envelope(
                request, request_id, version, data, rate=rate
            )

        if spec.operation == "offer_get":
            offer = self._index.offers.get(positional[0])
            if offer is None or offer.get("developer_id") != developer:
                raise self._resource_unknown(
                    "offer", positional[0], request_id
                )
            return self._envelope(
                request, request_id, version, offer, rate=rate
            )

        if spec.operation == "intents_list":
            items = [
                self._intent_resource(tx_id)
                for tx_id in self._developer_transaction_ids(developer)
            ]
            filters = normalize_filters(body.get("filters"), ("state",))
            page, cursor, more = self._page(
                items, "intent", developer, filters, body
            )
            data = {"items": page, "next_cursor": cursor, "has_more": more}
            return self._envelope(
                request, request_id, version, data, rate=rate
            )

        if spec.operation == "intent_get":
            transaction = self._developer_transaction(
                positional[0], developer
            )
            return self._envelope(
                request,
                request_id,
                version,
                self._intent_resource_from(transaction),
                rate=rate,
            )

        if spec.operation == "intent_lifecycle":
            transaction = self._developer_transaction(
                positional[0], developer
            )
            data = self._lifecycle_resource(transaction)
            return self._envelope(
                request, request_id, version, data, rate=rate
            )

        if spec.operation == "reservations_list":
            items = [
                self._reservation_resource_from(
                    self._core.transaction(tx_id)
                )
                for tx_id in self._developer_transaction_ids(developer)
                if self._core.transaction(tx_id).to_dict().get("state")
                in _LEASE_STATES
            ]
            filters = normalize_filters(body.get("filters"), ("state",))
            page, cursor, more = self._page(
                items, "reservation", developer, filters, body
            )
            data = {"items": page, "next_cursor": cursor, "has_more": more}
            return self._envelope(
                request, request_id, version, data, rate=rate
            )

        if spec.operation == "reservation_get":
            transaction = self._developer_transaction(
                positional[0], developer
            )
            if (
                transaction.to_dict().get("state") not in _LEASE_STATES
            ):
                raise self._resource_unknown(
                    "reservation", positional[0], request_id
                )
            return self._envelope(
                request,
                request_id,
                version,
                self._reservation_resource_from(transaction),
                rate=rate,
            )

        if spec.operation == "usage_list":
            items = [
                self._usage_resource(account_id)
                for account_id in self._developer_usage_ids(developer)
            ]
            filters = normalize_filters(body.get("filters"), ("state",))
            page, cursor, more = self._page(
                items, "usage", developer, filters, body
            )
            data = {"items": page, "next_cursor": cursor, "has_more": more}
            return self._envelope(
                request, request_id, version, data, rate=rate
            )

        if spec.operation == "usage_get":
            if positional[0] not in self._developer_usage_ids(developer):
                raise self._resource_unknown(
                    "usage account", positional[0], request_id
                )
            return self._envelope(
                request,
                request_id,
                version,
                self._usage_resource(positional[0]),
                rate=rate,
            )

        if spec.operation == "billing_list":
            items = []
            for account_id in self._developer_usage_ids(developer):
                account = self._usage.account(account_id).to_dict()
                if not account.get("finality"):
                    continue
                billing = {
                    "id": account_id,
                    "kind": "billing_record",
                    "transaction_id": account.get("transaction_id", ""),
                    "environment": self._environment,
                    "usage": self._usage_resource(account_id),
                    "finality": dict(account.get("finality") or {}),
                    "allocation": self._allocation_snapshot(account_id),
                }
                items.append(billing)
            page, cursor, more = self._page(
                items, "billing_record", developer, {}, body
            )
            data = {"items": page, "next_cursor": cursor, "has_more": more}
            return self._envelope(
                request, request_id, version, data, rate=rate
            )

        if spec.operation == "policies_list":
            items = [
                self._policy_resource(policy)
                for policy in self._allocation.policies()
            ]
            page, cursor, more = self._page(
                items, "economic_policy", developer, {}, body
            )
            data = {"items": page, "next_cursor": cursor, "has_more": more}
            return self._envelope(
                request, request_id, version, data, rate=rate
            )

        if spec.operation == "policy_get":
            try:
                policy_version = int(positional[1])
            except (TypeError, ValueError):
                raise DeveloperApiError(
                    DeveloperApiReasonCode.INVALID_INPUT,
                    "the policy version path segment %r must be an integer"
                    % positional[1],
                ) from None
            policy = self._allocation.policy(
                positional[0], policy_version
            )
            return self._envelope(
                request,
                request_id,
                version,
                self._policy_resource(policy),
                rate=rate,
            )

        if spec.operation == "endpoints_list":
            items = self._developer_endpoints(developer)
            page, cursor, more = self._page(
                items, "webhook_endpoint", developer, {}, body
            )
            data = {"items": page, "next_cursor": cursor, "has_more": more}
            return self._envelope(
                request, request_id, version, data, rate=rate
            )

        if spec.operation == "endpoint_get":
            endpoint = self._index.endpoints.get(positional[0])
            if endpoint is None or endpoint.get("developer_id") != developer:
                raise self._resource_unknown(
                    "webhook endpoint", positional[0], request_id
                )
            data = dict(endpoint)
            data["health"] = self._endpoint_health(positional[0])
            return self._envelope(
                request, request_id, version, data, rate=rate
            )

        if spec.operation == "deliveries_list":
            endpoint = self._index.endpoints.get(positional[0])
            if endpoint is None or endpoint.get("developer_id") != developer:
                raise self._resource_unknown(
                    "webhook endpoint", positional[0], request_id
                )
            items = [
                self._delivery_resource(state)
                for delivery_id, state in sorted(
                    self._index.deliveries.items()
                )
                if state.endpoint_id == positional[0]
            ]
            page, cursor, more = self._page(
                items, "webhook_delivery", developer, {}, body
            )
            data = {"items": page, "next_cursor": cursor, "has_more": more}
            return self._envelope(
                request, request_id, version, data, rate=rate
            )

        raise DeveloperApiError(
            DeveloperApiReasonCode.ROUTE_UNKNOWN,
            "operation %r is declared but not dispatched"
            % spec.operation,
        )

    # -- mutations ---------------------------------------------------------

    def _handle_mutation(
        self,
        request: ApiRequest,
        request_id: str,
        version: ApiVersionSpec,
        spec: RouteSpec,
        positional: List[str],
        credential: ApplicationCredential,
        rate: Optional[RateDecision],
    ) -> ApiResponse:
        if not request.idempotency_key:
            raise DeveloperApiError(
                DeveloperApiReasonCode.IDEMPOTENCY_KEY_REQUIRED,
                "mutations require an idempotency key "
                "(X-ADCOS-Idempotency-Key)",
            )
        key = request.idempotency_key
        body = request.canonical_body()
        digest = derive_request_digest(
            request.method,
            request.route,
            body,
            self._environment,
            credential.developer_id,
            key,
        )
        prior = self._index.mutations.get(key)
        if prior is not None:
            if prior.request_digest != digest:
                raise DeveloperApiError(
                    DeveloperApiReasonCode.IDEMPOTENCY_CONFLICT,
                    "idempotency key %r was already admitted with a "
                    "materially different request" % key,
                )
            # byte-identical canonical prior response
            body_out = _json_loads(prior.response_body)
            return self._response(
                int(prior.response_status),
                body_out,
                {
                    "X-ADCOS-Request-Id": request_id,
                    "X-ADCOS-API-Version": version.version,
                    "X-ADCOS-Environment": self._environment,
                    "X-ADCOS-Idempotent-Replay": "true",
                },
            )

        schema_role = spec.schema_role
        deprecations: Tuple[str, ...] = ()
        if schema_role:
            schema = version.schemas.get(schema_role)
            if schema is not None:
                schema.validate(body, "request body")
                deprecations = schema.deprecations_in(body)

        data, resource_kind, resource_id, resource, emission = self._execute_mutation(
            request, version, spec, positional, credential, key
        )
        envelope = self._envelope(
            request,
            request_id,
            version,
            data,
            rate=rate,
            idempotency={"key": key, "replayed": False},
            deprecations=deprecations,
        )
        record = MutationRecord.build(
            sequence=self._journal.tail_sequence() + 1,
            prev_record_id=self._journal.tail_record_id(),
            idempotency_key=key,
            application_id=credential.application_id,
            developer_id=credential.developer_id,
            method=request.method,
            route=request.route,
            api_version=version.version,
            request_id=request_id,
            request_digest=digest,
            resource_kind=resource_kind,
            resource_id=resource_id,
            resource=resource,
            response_status=envelope.status,
            response_body=canonical_json_bytes(
                dict(envelope.body)
            ).decode("utf-8"),
        )
        self._journal.append(record)
        self._index.apply(record)

        # FINALITY POINT: the canonical mutation is admitted, its
        # idempotency record is durable, and the envelope above is
        # THE response.  The webhook observation phase runs
        # strictly after finality and is fully contained: a queue
        # or delivery failure may affect only webhook
        # observability/retry state.  It can NEVER turn an
        # admitted mutation into an API failure, alter the
        # canonical mutation result, cause a duplicate canonical
        # mutation, invalidate idempotency, or act as a hidden
        # transaction coordinator for the commercial plane (the
        # W046 frozen observational-only invariant; battery case
        # 42 failure-injects the exact sequence).  Inside that
        # contained phase the observation's DELIVERY OBLIGATION
        # is made DURABLE FIRST (a journal record carrying the
        # full event payload and the resolved audience): the
        # obligation survives a process crash and restart
        # recovery re-queues its still-missing endpoints exactly
        # once (battery case 43 failure-injects the crash).
        if emission is not None:
            self._observe_after_finality(emission)
        return envelope

    def _execute_mutation(
        self,
        request: ApiRequest,
        version: ApiVersionSpec,
        spec: RouteSpec,
        positional: List[str],
        credential: ApplicationCredential,
        key: str,
    ) -> Tuple[
        Any, str, str, Mapping[str, Any], Optional[Callable[[], int]]
    ]:
        """Execute one mutation: adapt to the canonical subsystem
        or the developerapi-owned projection.  Returns
        (response data, resource kind, resource id, resource
        mapping, webhook emission callable).

        Adapted mutations carry empty resource mappings (the
        truth stays in the canonical subsystem journal); the
        crash-window idempotency is the canonical subsystem's
        own (command id derived from the idempotency key)."""
        body = request.canonical_body()
        developer = credential.developer_id
        source = "developerapi:%s" % credential.application_id

        if spec.operation == "offer_publish":
            offer_id = derive_resource_id(
                self._environment, "offer", developer, key
            )
            resource = {
                "id": offer_id,
                "kind": "offer",
                "environment": self._environment,
                "developer_id": developer,
                "created_at": self._clock.now(),
                "api_version": version.version,
            }
            for member in (
                "name",
                "description",
                "capacity_bps",
                "pricing_currency",
                "pricing_amount",
                "pricing_unit",
                "effective_from",
                "effective_until",
                "region",
            ):
                if member in body:
                    resource[member] = body[member]

            def emit() -> int:
                return self._emit_event(
                    event_type="offer.published",
                    event_id=webhook_platform.derive_api_event_id(
                        self._environment,
                        "offer",
                        offer_id,
                        "offer.published",
                        1,
                    ),
                    occurred_at=resource["created_at"],
                    resource_kind="offer",
                    resource_id=offer_id,
                    resource_version=1,
                    correlation=derive_request_id(
                        self._environment,
                        version.version,
                        request.method,
                        request.route,
                        body,
                    ),
                    data=dict(resource),
                )

            return dict(resource), "offer", offer_id, resource, emit

        if spec.operation == "endpoint_register":
            url, event_types = webhook_platform.validate_endpoint_registration(
                body.get("url"), body.get("event_types")
            )
            endpoint_id = derive_resource_id(
                self._environment, "webhook_endpoint", developer, key
            )
            resource = {
                "id": endpoint_id,
                "kind": "webhook_endpoint",
                "environment": self._environment,
                "developer_id": developer,
                "created_at": self._clock.now(),
                "api_version": version.version,
                "url": url,
                "event_types": list(event_types),
                "key_id": webhook_platform.derive_webhook_key_id(
                    endpoint_id
                ),
            }

            def emit_endpoint() -> int:
                return self._emit_event(
                    event_type="webhook_endpoint.registered",
                    event_id=webhook_platform.derive_api_event_id(
                        self._environment,
                        "webhook_endpoint",
                        endpoint_id,
                        "webhook_endpoint.registered",
                        1,
                    ),
                    occurred_at=resource["created_at"],
                    resource_kind="webhook_endpoint",
                    resource_id=endpoint_id,
                    resource_version=1,
                    correlation="",
                    data=dict(resource),
                )

            return dict(resource), "webhook_endpoint", endpoint_id, resource, emit_endpoint

        if spec.operation == "intent_create":
            intent = body.get("intent")
            if not isinstance(intent, Mapping):
                raise DeveloperApiError(
                    DeveloperApiReasonCode.INVALID_INPUT,
                    "the intent member must be a mapping (the canonical "
                    "commercial intent payload)",
                )
            command_id = derive_api_command_id(
                self._environment, developer, key
            )
            try:
                outcome = self._core.submit_intent(
                    command_id=command_id,
                    actor=developer,
                    source=source,
                    intent=dict(intent),
                )
            except CommercialError as error:
                raise self._adapted_error(error, request_id="") from error
            if outcome.status == "duplicate":
                # the crash window: the canonical subsystem holds
                # the command; reconstruct the canonical prior
                # result from its PUBLIC journal reads
                record = self._find_core_record(command_id)
                if record is None:
                    raise DeveloperApiError(
                        DeveloperApiReasonCode.JOURNAL_CORRUPT,
                        "core reports duplicate for %r but the journal "
                        "record is unreadable" % command_id,
                    )
                data = self._intent_resource_at_creation(
                    record, developer
                )
                return (
                    data,
                    "",
                    "",
                    {},
                    None,
                )
            transaction = self._core.transaction(outcome.transaction_id)
            data = self._intent_resource_from(transaction)
            event_id = outcome.event_id

            def emit_intent() -> int:
                return self._emit_event(
                    event_type="connectivity_intent.created",
                    event_id=event_id,
                    occurred_at=outcome.instant,
                    resource_kind="intent",
                    resource_id=outcome.transaction_id,
                    resource_version=transaction.to_dict().get(
                        "event_count", 1
                    ),
                    correlation=derive_request_id(
                        self._environment,
                        version.version,
                        request.method,
                        request.route,
                        body,
                    ),
                    data=dict(data),
                )

            return data, "", "", {}, emit_intent

        if spec.operation == "reservation_create":
            transaction_id = positional[0]
            transaction = self._developer_transaction(
                transaction_id, developer
            )
            expires_at = body.get("expires_at")
            if not isinstance(expires_at, str) or not expires_at:
                raise DeveloperApiError(
                    DeveloperApiReasonCode.INVALID_INPUT,
                    "expires_at must be a non-empty RFC 3339 UTC instant",
                )
            payment_refs_raw = body.get("payment_refs") or ()
            if not isinstance(payment_refs_raw, (list, tuple)):
                raise DeveloperApiError(
                    DeveloperApiReasonCode.INVALID_INPUT,
                    "payment_refs must be a list of payment observation "
                    "references (DATA)",
                )
            command_id = derive_api_command_id(
                self._environment, developer, key
            )
            try:
                outcome = self._core.hold_reservation(
                    command_id=command_id,
                    transaction_id=transaction_id,
                    actor=developer,
                    source=source,
                    expires_at=expires_at,
                    payment_refs=tuple(payment_refs_raw),
                )
            except CommercialError as error:
                raise self._adapted_error(error, request_id="") from error
            if outcome.status == "duplicate":
                record = self._find_core_record(command_id)
                if record is None:
                    raise DeveloperApiError(
                        DeveloperApiReasonCode.JOURNAL_CORRUPT,
                        "core reports duplicate for %r but the journal "
                        "record is unreadable" % command_id,
                    )
                data = self._reservation_resource_at_creation(
                    record, developer
                )
                return data, "", "", {}, None
            held = self._core.transaction(transaction_id)
            data = self._reservation_resource_from(held)
            event_id = outcome.event_id

            def emit_reservation() -> int:
                return self._emit_event(
                    event_type="reservation.held",
                    event_id=event_id,
                    occurred_at=outcome.instant,
                    resource_kind="intent",
                    resource_id=transaction_id,
                    resource_version=held.to_dict().get("event_count", 1),
                    correlation=derive_request_id(
                        self._environment,
                        version.version,
                        request.method,
                        request.route,
                        body,
                    ),
                    data=dict(data),
                )

            return data, "", "", {}, emit_reservation

        if spec.operation == "policy_register":
            required = (
                "policy_id",
                "version",
                "currency",
                "exponent",
                "rounding",
                "effective_from",
                "effective_until",
                "adc_os_share_bps",
                "tax_bps",
                "developer_share_min_bps",
                "developer_share_max_bps",
            )
            payload = {}
            for member in required:
                if member not in body:
                    if member == "effective_until":
                        # the open-ended window (the W053 model:
                        # absent until = open-ended)
                        payload[member] = ""
                        continue
                    raise DeveloperApiError(
                        DeveloperApiReasonCode.INVALID_INPUT,
                        "economic policy registration is missing member %r"
                        % member,
                    )
                payload[member] = body[member]
            command_id = derive_api_command_id(
                self._environment, developer, key
            )
            try:
                outcome = self._allocation.register_policy(
                    command_id=command_id,
                    actor=developer,
                    source=source,
                    **payload,
                )
            except AllocationError as error:
                raise self._adapted_error(error, request_id="") from error
            policy = self._allocation.policy(
                payload["policy_id"], payload["version"]
            )
            data = self._policy_resource(policy)
            event_id = outcome.event_id

            def emit_policy() -> int:
                return self._emit_event(
                    event_type="economic_policy.registered",
                    event_id=event_id,
                    occurred_at=outcome.instant,
                    resource_kind="economic_policy",
                    resource_id="%s@%s"
                    % (payload["policy_id"], payload["version"]),
                    resource_version=1,
                    correlation=derive_request_id(
                        self._environment,
                        version.version,
                        request.method,
                        request.route,
                        body,
                    ),
                    data=dict(data),
                )

            return data, "", "", {}, emit_policy

        raise DeveloperApiError(
            DeveloperApiReasonCode.ROUTE_UNKNOWN,
            "mutation %r is declared but not dispatched" % spec.operation,
        )

    # -- webhook machinery ---------------------------------------------------

    def _emit_event(
        self,
        *,
        event_type: str,
        event_id: str,
        occurred_at: str,
        resource_kind: str,
        resource_id: str,
        resource_version: int,
        correlation: str,
        data: Mapping[str, Any],
    ) -> int:
        """Emit one observation: FIRST the durable delivery
        obligation (the audience resolved at emission time; the
        obligation survives a process crash), THEN the
        per-endpoint queue writes (dedupe by delivery identity:
        the same event never queues twice).

        Called post-finality-and-pre-response from the API
        mutation path (contained there) and directly from the
        platform-side observation surface (failures raise to
        the operator, never to a developer response)."""
        developer_id = self._resource_owner(resource_kind, resource_id)
        if developer_id is None:
            return 0
        endpoints = tuple(
            endpoint_id
            for endpoint_id in sorted(self._index.endpoints)
            if self._index.endpoints[endpoint_id].get("developer_id")
            == developer_id
            and event_type
            in self._index.endpoints[endpoint_id].get("event_types", ())
        )
        if not endpoints:
            # no audience: no delivery obligation exists
            return 0
        obligation_id = webhook_platform.derive_obligation_id(
            self._environment, event_id
        )
        if obligation_id not in self._index.obligations:
            record = WebhookObligationRecord.build(
                sequence=self._journal.tail_sequence() + 1,
                prev_record_id=self._journal.tail_record_id(),
                obligation_id=obligation_id,
                event_id=event_id,
                event_type=event_type,
                occurred_at=occurred_at,
                environment=self._environment,
                developer_id=developer_id,
                resource_kind=resource_kind,
                resource_id=resource_id,
                resource_version=resource_version,
                correlation=correlation,
                data=data,
                endpoints=endpoints,
            )
            self._journal.append(record)
            self._index.apply(record)
        return self._queue_observation(
            event_id=event_id,
            event_type=event_type,
            occurred_at=occurred_at,
            developer_id=developer_id,
            resource_kind=resource_kind,
            resource_id=resource_id,
            resource_version=resource_version,
            correlation=correlation,
            data=data,
            endpoints=endpoints,
        )

    def _queue_observation(
        self,
        *,
        event_id: str,
        event_type: str,
        occurred_at: str,
        developer_id: str,
        resource_kind: str,
        resource_id: str,
        resource_version: int,
        correlation: str,
        data: Mapping[str, Any],
        endpoints: Tuple[str, ...],
    ) -> int:
        """Queue one observation for exactly the given target
        endpoints (the obligation's resolved audience or its
        still-missing subset at recovery): per-endpoint delivery
        sequence, deterministic delivery identity, dedupe
        (never twice).  The single queue-write site for the
        emission path AND the crash-recovery flush.  The owner
        is the obligation-recorded audience owner (never
        re-resolved at recovery)."""
        queued = 0
        for endpoint_id in endpoints:
            delivery_id = webhook_platform.derive_delivery_id(
                endpoint_id, event_id
            )
            if delivery_id in self._index.deliveries:
                continue
            sequence = (
                self._index.delivery_sequences.get(endpoint_id, 0) + 1
            )
            event = webhook_platform.build_observation_event(
                event_id=event_id,
                event_type=event_type,
                occurred_at=occurred_at,
                api_version="1.0",
                environment=self._environment,
                resource_kind=resource_kind,
                resource_id=resource_id,
                resource_version=resource_version,
                sequence=sequence,
                delivery_id=delivery_id,
                correlation=correlation,
                data=data,
            )
            record = WebhookQueueRecord.build(
                sequence=self._journal.tail_sequence() + 1,
                prev_record_id=self._journal.tail_record_id(),
                delivery_id=delivery_id,
                endpoint_id=endpoint_id,
                developer_id=developer_id,
                environment=self._environment,
                delivery_sequence=sequence,
                event=event,
            )
            self._journal.append(record)
            self._index.apply(record)
            queued += 1
        return queued

    def _resource_owner(
        self, resource_kind: str, resource_id: str
    ) -> Optional[str]:
        """The developer owning one observed resource (from the
        boundary's public projections; adapted resources are
        resolved through the canonical public reads)."""
        if resource_kind == "offer":
            offer = self._index.offers.get(resource_id)
            return offer.get("developer_id") if offer else None
        if resource_kind == "webhook_endpoint":
            endpoint = self._index.endpoints.get(resource_id)
            return endpoint.get("developer_id") if endpoint else None
        if resource_kind in ("intent",):
            try:
                transaction = self._core.transaction(resource_id)
            except CommercialError:
                return None
            return transaction.to_dict().get("actor")
        if resource_kind == "economic_policy":
            policy_id, _, version = resource_id.rpartition("@")
            try:
                policy = self._allocation.policy(
                    policy_id, int(version)
                )
            except (AllocationError, ValueError):
                return None
            # policies are platform-level: notify every endpoint
            # subscribed to the event type
            return "*"
        return None

    def _attempt_delivery(self, delivery_id: str, now: str) -> None:
        state = self._index.deliveries[delivery_id]
        endpoint = self._index.endpoints.get(state.endpoint_id)
        if endpoint is None:
            # the endpoint was never registered in this index
            # (cannot happen via the fold; fail closed)
            raise DeveloperApiError(
                DeveloperApiReasonCode.JOURNAL_CORRUPT,
                "delivery %r references unknown endpoint %r"
                % (delivery_id, state.endpoint_id),
            )
        event = dict(state.event)
        attempt_number = state.attempts + 1
        headers = webhook_platform.delivery_headers(
            secret=self.endpoint_signing_secret(state.endpoint_id),
            key_id=webhook_platform.derive_webhook_key_id(
                state.endpoint_id
            ),
            timestamp=now,
            event_id=event["event_id"],
            delivery_id=delivery_id,
            sequence=event["sequence"],
            payload=event,
        )
        transport = self._transports.get(state.endpoint_id)
        if transport is None:
            delivered, response_code = False, 0
        else:
            try:
                delivered, response_code = transport(
                    state.endpoint_id,
                    endpoint.get("url", ""),
                    event,
                    headers,
                )
            except Exception:
                # a raising transport is recorded as a failed
                # attempt (code 0 = no transport response); the
                # canonical mutation outcome is unaffected --
                # delivery state is observational only
                delivered, response_code = False, 0
        status = "delivered" if delivered else "failed"
        next_at = ""
        if status == "failed":
            next_at = webhook_platform.next_attempt_at(
                now, attempt_number
            )
        record = WebhookAttemptRecord.build(
            sequence=self._journal.tail_sequence() + 1,
            prev_record_id=self._journal.tail_record_id(),
            delivery_id=delivery_id,
            endpoint_id=state.endpoint_id,
            event_id=event["event_id"],
            attempt=attempt_number,
            status=status,
            response_code=response_code,
            instant=now,
            next_attempt_at=next_at,
        )
        self._journal.append(record)
        self._index.apply(record)

    # -- resource serializers (the adapted projections) ------------------

    def _intent_resource(self, transaction_id: str) -> Dict[str, Any]:
        return self._intent_resource_from(
            self._core.transaction(transaction_id)
        )

    def _intent_resource_from(self, transaction: Any) -> Dict[str, Any]:
        projection = transaction.to_dict()
        resource = {
            "id": projection.get("transaction_id", ""),
            "kind": "intent",
            "environment": self._environment,
        }
        for member in (
            "state",
            "actor",
            "source",
            "created_at",
            "intent",
            "offer",
            "expires_at",
            "session_ref",
            "path_ref",
            "delivery_evidence_refs",
            "usage_refs",
            "settlement_refs",
            "payment_refs",
            "last_action",
            "last_instant",
            "event_count",
        ):
            if member in projection:
                resource[member] = projection[member]
        return resource

    def _reservation_resource_from(self, transaction: Any) -> Dict[str, Any]:
        projection = transaction.to_dict()
        return {
            "id": projection.get("transaction_id", ""),
            "kind": "reservation",
            "environment": self._environment,
            "transaction_id": projection.get("transaction_id", ""),
            "state": projection.get("state", ""),
            "expires_at": projection.get("expires_at", ""),
            "payment_refs": projection.get("payment_refs", ()),
            "last_action": projection.get("last_action", ""),
            "last_instant": projection.get("last_instant", ""),
            "event_count": projection.get("event_count", 0),
        }

    def _intent_resource_at_creation(
        self, record: Any, developer: str
    ) -> Dict[str, Any]:
        event = record.event.to_dict()
        command = record.command.to_dict()
        return {
            "id": event.get("transaction_id", ""),
            "kind": "intent",
            "environment": self._environment,
            "state": event.get("to_state", ""),
            "actor": command.get("actor", developer),
            "source": command.get("source", ""),
            "created_at": event.get("instant", ""),
            "intent": dict(
                (command.get("payload") or {}).get("intent") or {}
            ),
            "offer": {},
            "expires_at": "",
            "session_ref": "",
            "path_ref": "",
            "delivery_evidence_refs": (),
            "usage_refs": (),
            "settlement_refs": (),
            "payment_refs": (),
            "last_action": event.get("action", ""),
            "last_instant": event.get("instant", ""),
            "event_count": 1,
        }

    def _reservation_resource_at_creation(
        self, record: Any, developer: str
    ) -> Dict[str, Any]:
        event = record.event.to_dict()
        command = record.command.to_dict()
        payload = command.get("payload") or {}
        return {
            "id": event.get("transaction_id", ""),
            "kind": "reservation",
            "environment": self._environment,
            "transaction_id": event.get("transaction_id", ""),
            "state": event.get("to_state", ""),
            "expires_at": payload.get("expires_at", ""),
            "payment_refs": tuple(
                ref.get("reference_id", "")
                for ref in event.get("causal_references", ())
                if isinstance(ref, Mapping)
                and ref.get("family") == "payment"
            ),
            "last_action": event.get("action", ""),
            "last_instant": event.get("instant", ""),
            "event_count": 1,
        }

    def _lifecycle_resource(self, transaction: Any) -> Dict[str, Any]:
        projection = transaction.to_dict()
        state = projection.get("state", "")
        # The honest classification: the developer API reports
        # the canonical COMMERCIAL state; it NEVER claims
        # connectivity or physical evidence.  Physical
        # connectivity is a W040-owned evidence plane the
        # commercial state cannot promote.
        connectivity = "not-evidenced"
        if state in ("PATH_ACTIVE", "DELIVERY_STARTED", "USAGE_ACCRUING",
                     "DELIVERY_COMPLETED", "BILLABLE_FINAL"):
            connectivity = "commercial-path-active"
        return {
            "id": projection.get("transaction_id", ""),
            "kind": "intent_lifecycle",
            "environment": self._environment,
            "commercial_state": state,
            "entered_at": projection.get("last_instant", ""),
            "event_count": projection.get("event_count", 0),
            "connectivity": connectivity,
            "physical_connectivity_observed": False,
            "physical_evidence": "not-claimed",
            "statements": list(_LIFECYCLE_STATEMENTS),
            "note": (
                "API success never implies physical connectivity "
                "success: this observation reports canonical commercial "
                "state only; physical connectivity evidence is owned by "
                "the physical evidence plane (W040) and is never "
                "fabricated or promoted by the developer API."
            ),
            "evidence_class": evidence_class(self._environment),
        }

    def _usage_resource(self, account_id: str) -> Dict[str, Any]:
        account = self._usage.account(account_id).to_dict()
        resource = {
            "id": account_id,
            "kind": "usage_account",
            "environment": self._environment,
        }
        for member in (
            "transaction_id",
            "state",
            "actor",
            "source",
            "created_at",
            "session_ref",
            "path_ref",
            "unit",
            "total_quantity",
            "evidence_refs",
            "payment_refs",
            "reconciliation",
            "finality",
            "compensations",
            "compensated_amount",
            "last_action",
            "last_instant",
            "event_count",
        ):
            if member in account:
                resource[member] = account[member]
        return resource

    def _policy_resource(self, policy: Any) -> Dict[str, Any]:
        content = policy.to_dict()
        resource = {
            "id": "%s@%s"
            % (content.get("policy_id", ""), content.get("version", "")),
            "kind": "economic_policy",
            "environment": self._environment,
        }
        for member in (
            "policy_id",
            "version",
            "currency",
            "exponent",
            "rounding",
            "effective_from",
            "effective_until",
            "adc_os_share_bps",
            "tax_bps",
            "developer_share_min_bps",
            "developer_share_max_bps",
        ):
            if member in content:
                resource[member] = content[member]
        return resource

    def _delivery_resource(self, state: Any) -> Dict[str, Any]:
        event = dict(state.event)
        return {
            "id": state.delivery_id,
            "kind": "webhook_delivery",
            "environment": self._environment,
            "endpoint_id": state.endpoint_id,
            "delivery_sequence": state.delivery_sequence,
            "event_id": event.get("event_id", ""),
            "event_type": event.get("event_type", ""),
            "resource_id": event.get("resource_id", ""),
            "resource_version": event.get("resource_version", 0),
            "occurred_at": event.get("occurred_at", ""),
            "attempts": state.attempts,
            "last_status": state.last_status,
            "last_attempt_at": state.last_attempt_at,
            "next_attempt_at": state.next_attempt_at,
            "response_codes": list(state.response_codes),
        }

    def _endpoint_health(self, endpoint_id: str) -> Dict[str, Any]:
        states = [
            state
            for state in self._index.deliveries.values()
            if state.endpoint_id == endpoint_id
        ]
        states.sort(key=lambda state: state.delivery_id)
        delivered = sum(
            1 for state in states if state.last_status == "delivered"
        )
        pending = sum(
            1
            for state in states
            if state.last_status in ("pending", "failed")
        )
        last_status = states[-1].last_status if states else "idle"
        return {
            "deliveries": len(states),
            "delivered": delivered,
            "undelivered": pending,
            "last_status": last_status,
            "observational_only": True,
            "note": (
                "webhook delivery state is an observation channel: "
                "delivery success or failure never changes canonical "
                "commercial, usage, or allocation state"
            ),
        }

    def _allocation_snapshot(self, account_id: str) -> Any:
        account = self._usage.account(account_id).to_dict()
        finality = account.get("finality") or {}
        record_id = finality.get("record_id", "")
        if not record_id:
            return ""
        try:
            allocation_entry = self._allocation.allocation(record_id)
        except AllocationError:
            return ""
        return allocation_entry.to_dict()

    # -- pagination helper -------------------------------------------------

    def _page(
        self,
        items: List[Dict[str, Any]],
        kind: str,
        developer: str,
        filters: Mapping[str, str],
        body: Mapping[str, Any],
    ) -> Tuple[List[Dict[str, Any]], str, bool]:
        return paginate(
            items,
            environment=self._environment,
            kind=kind,
            developer_id=developer,
            filters=dict(filters),
            cursor=body.get("cursor"),
            limit=body.get("limit"),
        )

    # -- tenant scoping ----------------------------------------------------

    def _developer_offers(self, developer: str) -> List[Dict[str, Any]]:
        return [
            dict(offer)
            for offer_id, offer in sorted(self._index.offers.items())
            if offer.get("developer_id") == developer
        ]

    def _developer_endpoints(self, developer: str) -> List[Dict[str, Any]]:
        return [
            dict(endpoint)
            for endpoint_id, endpoint in sorted(
                self._index.endpoints.items()
            )
            if endpoint.get("developer_id") == developer
        ]

    def _developer_transaction_ids(self, developer: str) -> List[str]:
        out = []
        for transaction in self._core.transactions():
            if transaction.to_dict().get("actor") == developer:
                out.append(transaction.to_dict()["transaction_id"])
        return sorted(out)

    def _developer_transaction(
        self, transaction_id: str, developer: str
    ) -> Any:
        try:
            transaction = self._core.transaction(transaction_id)
        except CommercialError as error:
            raise self._adapted_error(
                error,
                request_id="",
                resource_id=transaction_id,
            ) from error
        if transaction.to_dict().get("actor") != developer:
            raise self._resource_unknown(
                "intent", transaction_id, ""
            )
        return transaction

    def _developer_usage_ids(self, developer: str) -> List[str]:
        owned = set(self._developer_transaction_ids(developer))
        out = []
        for account in self._usage.accounts():
            if account.to_dict().get("transaction_id") in owned:
                out.append(account.to_dict()["transaction_id"])
        return sorted(out)

    # -- envelope / error mapping -------------------------------------------

    def _envelope(
        self,
        request: ApiRequest,
        request_id: str,
        version: ApiVersionSpec,
        data: Any,
        *,
        rate: Optional[RateDecision] = None,
        idempotency: Optional[Mapping[str, Any]] = None,
        deprecations: Tuple[str, ...] = (),
    ) -> ApiResponse:
        body: Dict[str, Any] = {
            "api_version": version.version,
            "environment": self._environment,
            "request_id": request_id,
            "data": data,
        }
        headers: Dict[str, str] = {
            "X-ADCOS-Request-Id": request_id,
            "X-ADCOS-API-Version": version.version,
            "X-ADCOS-Environment": self._environment,
        }
        if idempotency is not None:
            body["idempotency"] = dict(idempotency)
        if rate is not None:
            body["rate_limit"] = rate.to_dict()
            headers["X-RateLimit-Limit"] = str(rate.limit)
            headers["X-RateLimit-Remaining"] = str(rate.remaining)
            headers["X-RateLimit-Reset"] = rate.reset_at
        if version.status == "deprecated":
            body["deprecation"] = {
                "version": version.version,
                "message": version.notice,
            }
            headers["X-ADCOS-Deprecation"] = version.notice
        if deprecations:
            body["deprecated_fields"] = list(deprecations)
        return self._response(200, body, headers)

    def _response(
        self, status: int, body: Mapping[str, Any], headers: Mapping[str, str]
    ) -> ApiResponse:
        return ApiResponse(status=status, body=body, headers=headers)

    def _error_response(
        self, request: ApiRequest, request_id: str, error: DeveloperApiError
    ) -> ApiResponse:
        error_body = error.to_dict()
        error_body["request_id"] = error_body.get("request_id") or request_id
        if not error_body.get("environment"):
            error_body["environment"] = self._environment
        body: Dict[str, Any] = {
            "api_version": request.api_version or "",
            "environment": self._environment,
            "request_id": request_id,
            "error": error_body,
        }
        headers: Dict[str, str] = {
            "X-ADCOS-Request-Id": request_id,
            "X-ADCOS-Environment": self._environment,
        }
        if error.retry_after:
            headers["Retry-After"] = error.retry_after
        return self._response(error.http_status, body, headers)

    def _adapted_error(
        self,
        error: Exception,
        *,
        request_id: str = "",
        resource_id: str = "",
    ) -> DeveloperApiError:
        """Map one canonical subsystem failure to the boundary,
        preserving the EXACT canonical reason code (criterion 4).

        The boundary reason classifies the failure family; the
        HTTP status derives from the canonical reason (the
        frozen mapping); the developer-facing error body always
        carries the canonical reason string unchanged."""
        canonical_reason = getattr(error, "reason", "")
        detail = getattr(error, "detail", "") or str(error)
        if canonical_reason == "command-conflict":
            # the crash-window conflicting redelivery surfaces as
            # the boundary idempotency conflict, with the
            # canonical reason attached unchanged
            boundary_reason = DeveloperApiReasonCode.IDEMPOTENCY_CONFLICT
        elif canonical_reason in (
            "transaction-unknown",
            "account-unknown",
            "policy-unknown",
            "reference-unknown",
            "allocation-unknown",
        ):
            boundary_reason = DeveloperApiReasonCode.RESOURCE_UNKNOWN
        else:
            boundary_reason = DeveloperApiReasonCode.INVALID_INPUT
        return DeveloperApiError(
            boundary_reason,
            detail,
            canonical_reason=canonical_reason,
            request_id=request_id,
            resource_id=resource_id,
            environment=self._environment,
        )

    def _resource_unknown(
        self, kind: str, resource_id: str, request_id: str
    ) -> DeveloperApiError:
        return DeveloperApiError(
            DeveloperApiReasonCode.RESOURCE_UNKNOWN,
            "%s %r is not visible in environment %r for this application"
            % (kind, resource_id, self._environment),
            request_id=request_id,
            resource_id=resource_id,
            environment=self._environment,
        )

    # -- canonical-subsystem public journal search ----------------------------

    def _find_core_record(self, command_id: str) -> Optional[Any]:
        for record in self._core.journal_records():
            if record.command.command_id == command_id:
                return record
        return None

    def _latest_core_event_id(self, transaction_id: str) -> str:
        latest = ""
        for record in self._core.journal_records():
            if record.event.transaction_id == transaction_id:
                latest = record.event.event_id
        return latest


def _json_loads(text: str) -> Any:
    import json

    return json.loads(text)


def _require_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise DeveloperApiError(
            DeveloperApiReasonCode.INVALID_INPUT,
            "%s must be an integer" % label,
        )
    return value


class _FreshStoreView(ApiStore):
    """A zero-record view over a real store (load-construction
    aid): the fresh constructor sees an empty store, then the
    real store is replayed through the real journal."""

    def __init__(self, store: ApiStore) -> None:
        self._store = store

    def append_line(self, line: str) -> None:  # pragma: no cover
        raise DeveloperApiError(
            DeveloperApiReasonCode.STORE_FAILED,
            "the fresh-construction view never persists",
        )

    def read_lines(self) -> List[str]:
        return []
