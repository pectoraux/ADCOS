"""ADCOS developer platform package (WORK-046): the
developer-facing Connectivity API, SDK & Webhook platform.

Implements the frozen WORK-046 contract under the active
authorization ``WORK-046-CORE-001`` (DEC-0065, baseline
reconciled to ``3db7500`` by DEC-0066): a versioned, scoped,
idempotent, deterministic developer API boundary over the
accepted canonical commercial plane, with signed webhook
observation delivery and an SDK that reproduces the canonical
server semantics exactly.

The commercial operations the boundary supports (issue #90,
native ADCOS semantics):

- publishing connectivity offers
- creating connectivity intents
- reserving/leasing capacity
- observing lifecycle (commercial state; NEVER physical
  connectivity claims)
- retrieving usage/billing records
- configuring economic policy
- receiving signed webhooks (observations only)

Frozen authority boundary (mirrors the W044/W045 discipline):

- The developer platform is an INTERFACE BOUNDARY, not a new
  system authority.  It composes the accepted commercial
  authorities through their PUBLIC surfaces only:
  WORK-051 CommercialCore (submit_intent / hold_reservation
  and the public reads), WORK-052 UsageLedger (public reads
  only), WORK-053 AllocationLedger (register_policy and the
  public reads).
- It is NOT an identity authority (WORK-004), NOT a session
  authority (WORK-012), NOT a NetworkPath authority (WORK-041),
  NOT a routing engine (WORK-011), NOT a transport manager
  (WORK-017), NOT an eligibility authority (WORK-045), and NOT
  a payment boundary (WORK-044 owns payment-provider adapter
  semantics and custody).  There is no authority object,
  client, or private accessor for any of those planes anywhere
  in this family: the commercial core is injected ALREADY
  COMPOSED by the platform.
- API success NEVER implies physical connectivity success.  The
  lifecycle observation keeps the distinct statements distinct
  and never fabricates or promotes physical evidence.
- Webhook delivery is an observation channel only: delivery
  state never becomes canonical business state.  The channel's
  DELIVERY OBLIGATION, however, is durable operational state of
  the channel itself (persisted before the API response,
  recovered across restart) -- durability of the obligation,
  observational purity of the delivery state.
- Sandbox and production are non-interchangeable, isolated
  namespaces; sandbox results are never production or physical
  evidence.
- Developer-facing errors preserve the canonical ADCOS reason
  codes unchanged (no second reason-code authority).
- The SDK contains no hidden business authority (import
  discipline is battery-audited).

Determinism discipline (the family precedent): every id,
digest, record, and response body is content-derived over
WORK-003 canonical JSON; the ONLY time source is the injected
WORK-033 clock seam; no randomness, no UUIDs, no wall clock,
no network, no live credentials; secrets (credential secrets,
webhook signing secrets) are derived from the injected platform
issuance key and NEVER journaled or logged.
"""

from __future__ import annotations

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
from .environments import (
    Environment,
    evidence_class,
    is_production_evidence,
    require_environment,
)
from .errors import (
    CANONICAL_REASON_HTTP_STATUS,
    REASON_HTTP_STATUS,
    RETRYABLE_REASONS,
    DeveloperApiError,
    DeveloperApiReasonCode,
)
from .gateway import (
    ApiRequest,
    ApiResponse,
    RouteSpec,
    DeveloperApiService,
    match_route,
)
from .identifiers import (
    derive_api_command_id,
    derive_request_id,
    derive_resource_id,
)
from .journal import (
    ApiStore,
    AppendOnlyApiJournal,
    CredentialRecord,
    FileApiStore,
    MemoryApiStore,
    MutationRecord,
    WebhookAttemptRecord,
    WebhookObligationRecord,
    WebhookQueueRecord,
    derive_record_id,
    derive_request_digest,
    fold_index,
)
from .pagination import (
    DEFAULT_PAGE_LIMIT,
    MAX_PAGE_LIMIT,
    decode_cursor,
    encode_cursor,
    normalize_filters,
    normalize_limit,
    paginate,
)
from .ratelimit import RateDecision, RateLimiter
from .schema import (
    API_VERSION_CURRENT,
    API_VERSION_HEADER,
    API_VERSIONS,
    ApiVersionSpec,
    FieldSpec,
    ResourceSchema,
    assert_backward_compatible,
    canonical_response_bytes,
    classify_change,
    resolve_version,
)
from . import webhooks as webhook_platform
from .webhooks import (
    DEFAULT_TIMESTAMP_TOLERANCE_SECONDS,
    EVENT_TYPES,
    MAX_DELIVERY_ATTEMPTS,
    RETRY_BACKOFF_SECONDS,
    SIGNATURE_ALGORITHM,
    backoff_for_attempt,
    build_observation_event,
    canonical_signing_input,
    check_timestamp_freshness,
    delivery_headers,
    derive_api_event_id,
    derive_delivery_id,
    derive_endpoint_signing_secret,
    derive_obligation_id,
    derive_webhook_key_id,
    next_attempt_at,
    sign_delivery,
    validate_endpoint_registration,
    verify_delivery_signature,
)
from .sdk import (
    DeveloperApiClient,
    DuplicateDetector,
    OrderTracker,
    SdkError,
    SdkList,
    SdkResource,
    SdkWebhookEvent,
    WebhookVerifier,
    deterministic_key,
)

__all__ = [
    # boundary model
    "ApiRequest",
    "ApiResponse",
    "RouteSpec",
    "DeveloperApiService",
    "match_route",
    # credentials / capabilities
    "ApplicationCredential",
    "Capability",
    "IssuedCredential",
    "derive_application_id",
    "derive_credential_secret",
    "require_capability",
    "secret_digest",
    "verify_credential",
    # environments
    "Environment",
    "evidence_class",
    "is_production_evidence",
    "require_environment",
    # errors (canonical reason preservation)
    "CANONICAL_REASON_HTTP_STATUS",
    "REASON_HTTP_STATUS",
    "RETRYABLE_REASONS",
    "DeveloperApiError",
    "DeveloperApiReasonCode",
    # identifiers / correlation
    "derive_api_command_id",
    "derive_request_id",
    "derive_resource_id",
    # journal (durable idempotency + observational deliveries)
    "ApiStore",
    "AppendOnlyApiJournal",
    "CredentialRecord",
    "FileApiStore",
    "MemoryApiStore",
    "MutationRecord",
    "WebhookAttemptRecord",
    "WebhookObligationRecord",
    "WebhookQueueRecord",
    "derive_record_id",
    "derive_request_digest",
    "fold_index",
    # pagination
    "DEFAULT_PAGE_LIMIT",
    "MAX_PAGE_LIMIT",
    "decode_cursor",
    "encode_cursor",
    "normalize_filters",
    "normalize_limit",
    "paginate",
    # rate limiting
    "RateDecision",
    "RateLimiter",
    # schema (the versioned API contract)
    "API_VERSION_CURRENT",
    "API_VERSION_HEADER",
    "API_VERSIONS",
    "ApiVersionSpec",
    "FieldSpec",
    "ResourceSchema",
    "assert_backward_compatible",
    "canonical_response_bytes",
    "classify_change",
    "resolve_version",
    # webhooks (observation channel)
    "webhook_platform",
    "DEFAULT_TIMESTAMP_TOLERANCE_SECONDS",
    "EVENT_TYPES",
    "MAX_DELIVERY_ATTEMPTS",
    "RETRY_BACKOFF_SECONDS",
    "SIGNATURE_ALGORITHM",
    "backoff_for_attempt",
    "build_observation_event",
    "canonical_signing_input",
    "check_timestamp_freshness",
    "delivery_headers",
    "derive_api_event_id",
    "derive_delivery_id",
    "derive_endpoint_signing_secret",
    "derive_obligation_id",
    "derive_webhook_key_id",
    "next_attempt_at",
    "sign_delivery",
    "validate_endpoint_registration",
    "verify_delivery_signature",
    # SDK
    "DeveloperApiClient",
    "DuplicateDetector",
    "OrderTracker",
    "SdkError",
    "SdkList",
    "SdkResource",
    "SdkWebhookEvent",
    "WebhookVerifier",
    "deterministic_key",
]
