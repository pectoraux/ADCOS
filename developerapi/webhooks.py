"""WORK-046 webhook platform (observation channel ONLY).

The frozen W046 webhook architecture (contract criterion 3 and
the authority boundary):

> Webhooks are an observation channel only.  They are NOT a
> second source of truth.  Canonical state is always resolved
> from ADCOS server state.

Consequently this module owns NO business state: it constructs
observation events FROM the canonical public projections the
gateway reads, signs them, schedules deterministic retries, and
reports delivery health.  The fold of delivery state lives in
:mod:`developerapi.journal` and is observational DATA; there is
no code path anywhere in the developerapi family that turns a
delivery outcome into commercial, usage, or allocation state
(the battery proves this structurally).

Members (the W046 contract's webhook requirements):

- **Event identity**: every webhook event carries the event id,
  the event type, the resource id/kind, the ``resource_version``
  ORDER METADATA (the canonical subsystem's own version counter
  -- the commercial transaction's ``event_count``, or version 1
  for one-shot developerapi resources), the creation timestamp
  (``occurred_at``), the API/schema version, the ENVIRONMENT,
  and the originating correlation id where one exists.  For
  commercial events the event id is the CANONICAL core event id
  CITED unchanged (never re-derived); for developerapi resource
  events it is content-derived over (environment, kind,
  resource, event type, version).

- **Signing** (criterion 3): every delivery is signed
  HMAC-SHA256 over the canonical envelope bytes
  (:func:`canonical_signing_input`: key id + timestamp +
  delivery id + the full payload, WORK-003 canonical JSON).
  The signature construction, the key identifier, the
  algorithm, and the timestamp/age window are the frozen single
  site below; consumers verify with the same construction
  (:func:`verify_delivery_signature`, constant-time) -- the SDK
  helper (:mod:`developerapi.sdk`) reproduces exactly this
  semantics (parity battery-pinned).

- **Replay protection**: the consumer-side verifier rejects a
  timestamp outside the age window (default 300s against the
  consumer's own clock) -- ``webhook-timestamp-stale`` -- so a
  replayed old delivery fails deterministically.

- **Duplicate protection**: the same event may be delivered
  more than once (at-least-once queueing); the consumer
  deduplicates by event id (the SDK's DuplicateDetector).  A
  re-observed UNCHANGED resource emits no new event (event
  identity is version-bound).

- **Out-of-order protection**: events may arrive out of order;
  consumers must not infer truth from arrival order.  The
  ``resource_version`` member (plus the per-endpoint delivery
  ``sequence``) is the deterministic staleness signal: the SDK
  OrderTracker detects stale events by version comparison.

- **Retry semantics**: deterministic backoff schedule
  (:data:`RETRY_BACKOFF_SECONDS`), a bounded attempt count, and
  scheduled next-attempt instants; a failed delivery retries
  without EVER mutating the canonical observed event (the
  event bytes are fixed at queueing; retries re-deliver the
  same signed payload).

- **Endpoint model**: one registered webhook endpoint per
  (developer, environment): the synthetic URL, the subscribed
  event-type set, the content-derived endpoint id, and the
  derived signing secret (the platform issuance key is the only
  secret-holder; the journal stores NO secret material).
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any, Dict, List, Mapping, Tuple

from agent.clock import add_seconds, parse_utc

from protocol.canonicalization import canonical_json_bytes

from .errors import DeveloperApiError, DeveloperApiReasonCode
from .identifiers import ID_NAMESPACE

#: The synthetic webhook signing-secret prefix.
WEBHOOK_SECRET_PREFIX = "dwh_"

#: The signature algorithm identifier.
SIGNATURE_ALGORITHM = "hmac-sha256"

#: The signing-key version.
KEY_VERSION = "whv1"

#: The signed delivery headers (single site).
SIGNATURE_HEADER = "X-ADCOS-Signature"
TIMESTAMP_HEADER = "X-ADCOS-Timestamp"
KEY_ID_HEADER = "X-ADCOS-Key-Id"
EVENT_ID_HEADER = "X-ADCOS-Event-Id"
DELIVERY_ID_HEADER = "X-ADCOS-Delivery-Id"
SEQUENCE_HEADER = "X-ADCOS-Sequence"
ALGORITHM_HEADER = "X-ADCOS-Algorithm"

#: The default consumer-side timestamp age window (seconds).
DEFAULT_TIMESTAMP_TOLERANCE_SECONDS = 300

#: The frozen deterministic retry backoff schedule: attempt N
#: (1-based) failing schedules the next attempt after
#: RETRY_BACKOFF_SECONDS[N-1] seconds.
RETRY_BACKOFF_SECONDS = (60, 300, 1800, 7200, 21600)

#: The maximum delivery attempts (the first attempt + the
#: scheduled retries).
MAX_DELIVERY_ATTEMPTS = 1 + len(RETRY_BACKOFF_SECONDS)

#: The frozen webhook event-type vocabulary.
EVENT_TYPES = (
    "offer.published",
    "connectivity_intent.created",
    "reservation.held",
    "economic_policy.registered",
    "webhook_endpoint.registered",
    "connectivity_transaction.state_changed",
)

#: The event member set every signed payload carries.
EVENT_MEMBERS = (
    "event_id",
    "event_type",
    "occurred_at",
    "api_version",
    "environment",
    "resource_kind",
    "resource_id",
    "resource_version",
    "sequence",
    "delivery_id",
    "correlation",
    "data",
)


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise DeveloperApiError(
            DeveloperApiReasonCode.INVALID_INPUT,
            "%s must be a non-empty string" % label,
        )
    return value


def _require_event_types(event_types: object) -> Tuple[str, ...]:
    if isinstance(event_types, str) or not isinstance(
        event_types, (list, tuple)
    ):
        raise DeveloperApiError(
            DeveloperApiReasonCode.INVALID_INPUT,
            "event_types must be a list of event-type strings",
        )
    out: List[str] = []
    for event_type in event_types:
        _require_text(event_type, "event type")
        if event_type not in EVENT_TYPES:
            raise DeveloperApiError(
                DeveloperApiReasonCode.INVALID_INPUT,
                "event type %r is not in the frozen vocabulary %s"
                % (event_type, list(EVENT_TYPES)),
            )
        if event_type not in out:
            out.append(event_type)
    if not out:
        raise DeveloperApiError(
            DeveloperApiReasonCode.INVALID_INPUT,
            "a webhook endpoint must subscribe to at least one event type",
        )
    return tuple(sorted(out))


def validate_endpoint_registration(
    url: object, event_types: object
) -> Tuple[str, Tuple[str, ...]]:
    """Validate one webhook-endpoint registration (the request
    surface; synthetic URLs in tests, no live endpoints)."""
    url = _require_text(url, "endpoint url")
    if not (url.startswith("https://") or url.startswith("http://")):
        raise DeveloperApiError(
            DeveloperApiReasonCode.INVALID_INPUT,
            "endpoint url must be an http(s) URL",
        )
    return url, _require_event_types(event_types)


def derive_endpoint_signing_secret(
    issuance_key: bytes, endpoint_id: str
) -> str:
    """The deterministic endpoint signing secret.

    Derived from the platform's injected issuance key -- never
    stored, never journaled; the consumer receives it at
    endpoint registration exactly once."""
    if not isinstance(issuance_key, (bytes, bytearray)) or not issuance_key:
        raise DeveloperApiError(
            DeveloperApiReasonCode.INVALID_INPUT,
            "issuance_key must be non-empty bytes",
        )
    _require_text(endpoint_id, "endpoint_id")
    digest = hmac.new(
        bytes(issuance_key),
        b"%s:webhook-secret:%s" % (endpoint_id.encode("utf-8"), KEY_VERSION.encode("utf-8")),
        hashlib.sha256,
    ).hexdigest()
    return WEBHOOK_SECRET_PREFIX + digest


def derive_webhook_key_id(endpoint_id: str) -> str:
    """The deterministic signing key identifier (endpoint-bound,
    versioned)."""
    _require_text(endpoint_id, "endpoint_id")
    return "whk-%s-%s" % (endpoint_id[len("sha256:"):][:16], KEY_VERSION)


def derive_api_event_id(
    environment: str,
    resource_kind: str,
    resource_id: str,
    event_type: str,
    resource_version: int,
) -> str:
    """The content-derived event id for a developerapi-owned
    resource observation (cited core event ids are used
    unchanged for commercial events)."""
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(
            {
                "namespace": ID_NAMESPACE,
                "event": True,
                "environment": environment,
                "resource_kind": resource_kind,
                "resource_id": resource_id,
                "event_type": event_type,
                "resource_version": resource_version,
            }
        )
    ).hexdigest()


def derive_delivery_id(endpoint_id: str, event_id: str) -> str:
    """The content-derived delivery id: one per (endpoint,
    event); every RETRY of the same delivery reuses it (the
    consumer's duplicate signal)."""
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(
            {
                "namespace": ID_NAMESPACE,
                "delivery": True,
                "endpoint": endpoint_id,
                "event": event_id,
            }
        )
    ).hexdigest()


def derive_obligation_id(environment: str, event_id: str) -> str:
    """The content-derived obligation id: one per (environment,
    event) -- the durable identity of the observation-channel's
    operational OBLIGATION to deliver one observed event to its
    resolved audience.  Distinct from the delivery id (which is
    per endpoint): the obligation is the event-level duty, the
    deliveries are its per-endpoint satisfactions."""
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(
            {
                "namespace": ID_NAMESPACE,
                "obligation": True,
                "environment": environment,
                "event": event_id,
            }
        )
    ).hexdigest()


def derive_admission_id(
    environment: str, event_id: str, event_type: str
) -> str:
    """The content-derived observation-ADMISSION id: one per
    (environment, event identity, event type) -- the durable
    identity of the observation-admission DECISION for exactly
    one emission (whether that emission required a webhook
    audience, and the audience frozen at admission time when it
    did).  The event TYPE is part of the identity because the
    same canonical event may legitimately back more than one
    observation type (an intent's ``created`` observation and a
    transaction's ``state_changed`` observation cite the same
    core event id): each is a distinct admission decision.  The
    admission is a strictly earlier truth than the obligation
    (``derive_obligation_id``): the admission answers "was
    observation required, and for WHOM"; the obligation answers
    "the required observation has not yet reached queue state
    for all frozen audience members"; the queue/attempt records
    answer "where did delivery get to"."""
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(
            {
                "namespace": ID_NAMESPACE,
                "admission": True,
                "environment": environment,
                "event": event_id,
                "event_type": event_type,
            }
        )
    ).hexdigest()


def build_observation_event(
    *,
    event_id: str,
    event_type: str,
    occurred_at: str,
    api_version: str,
    environment: str,
    resource_kind: str,
    resource_id: str,
    resource_version: int,
    sequence: int,
    delivery_id: str,
    correlation: str,
    data: Mapping[str, Any],
) -> Dict[str, Any]:
    """Construct one webhook observation payload (validated
    frozen member set; the observed snapshot is DATA copied
    from the canonical public read -- never re-derived
    truth)."""
    _require_text(event_id, "event_id")
    if event_type not in EVENT_TYPES:
        raise DeveloperApiError(
            DeveloperApiReasonCode.INVALID_INPUT,
            "event type %r is not in the frozen vocabulary" % event_type,
        )
    _require_text(occurred_at, "occurred_at")
    parse_utc(occurred_at)
    _require_text(api_version, "api_version")
    _require_text(environment, "environment")
    _require_text(resource_kind, "resource_kind")
    _require_text(resource_id, "resource_id")
    _require_text(delivery_id, "delivery_id")
    if not isinstance(resource_version, int) or isinstance(
        resource_version, bool
    ) or resource_version < 1:
        raise DeveloperApiError(
            DeveloperApiReasonCode.INVALID_INPUT,
            "resource_version must be a positive integer",
        )
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise DeveloperApiError(
            DeveloperApiReasonCode.INVALID_INPUT,
            "sequence must be a positive integer",
        )
    if correlation and not isinstance(correlation, str):
        raise DeveloperApiError(
            DeveloperApiReasonCode.INVALID_INPUT,
            "correlation must be a string (or empty)",
        )
    if not isinstance(data, Mapping):
        raise DeveloperApiError(
            DeveloperApiReasonCode.INVALID_INPUT,
            "event data must be a mapping (the observed snapshot)",
        )
    return {
        "event_id": event_id,
        "event_type": event_type,
        "occurred_at": occurred_at,
        "api_version": api_version,
        "environment": environment,
        "resource_kind": resource_kind,
        "resource_id": resource_id,
        "resource_version": resource_version,
        "sequence": sequence,
        "delivery_id": delivery_id,
        "correlation": correlation,
        "data": dict(data),
    }


# ---------------------------------------------------------------------------
# Signing (the canonical construction -- single site)
# ---------------------------------------------------------------------------

def canonical_signing_input(
    key_id: str,
    timestamp: str,
    delivery_id: str,
    payload: Mapping[str, Any],
) -> bytes:
    """The canonical signed envelope bytes: key id + timestamp +
    delivery id + the full payload, WORK-003 canonical JSON.

    This is THE signature construction: the server signs it and
    the SDK verifier verifies against exactly these bytes
    (byte-identical by construction; parity battery-pinned)."""
    _require_text(key_id, "key_id")
    _require_text(timestamp, "timestamp")
    parse_utc(timestamp)
    _require_text(delivery_id, "delivery_id")
    return canonical_json_bytes(
        {
            "key_id": key_id,
            "timestamp": timestamp,
            "delivery_id": delivery_id,
            "payload": dict(payload),
        }
    )


def sign_delivery(
    secret: str,
    *,
    key_id: str,
    timestamp: str,
    delivery_id: str,
    payload: Mapping[str, Any],
) -> str:
    """The HMAC-SHA256 signature over the canonical envelope
    (hex, algorithm-prefixed)."""
    _require_text(secret, "signing secret")
    envelope = canonical_signing_input(
        key_id=key_id,
        timestamp=timestamp,
        delivery_id=delivery_id,
        payload=payload,
    )
    digest = hmac.new(
        secret.encode("utf-8"), envelope, hashlib.sha256
    ).hexdigest()
    return "%s=%s" % (SIGNATURE_ALGORITHM, digest)


def verify_delivery_signature(
    secret: str,
    *,
    key_id: str,
    timestamp: str,
    delivery_id: str,
    payload: Mapping[str, Any],
    signature: object,
) -> bool:
    """Constant-time verification of a delivery signature
    against the canonical envelope (the consumer-side
    primitive; ``False`` on any malformed input -- never an
    exception oracle)."""
    if not isinstance(signature, str) or not signature:
        return False
    expected = sign_delivery(
        secret,
        key_id=key_id,
        timestamp=timestamp,
        delivery_id=delivery_id,
        payload=payload,
    )
    return hmac.compare_digest(
        expected.encode("utf-8"), signature.encode("utf-8")
    )


def delivery_headers(
    *,
    secret: str,
    key_id: str,
    timestamp: str,
    event_id: str,
    delivery_id: str,
    sequence: int,
    payload: Mapping[str, Any],
) -> Dict[str, str]:
    """The full signed delivery header set (deterministic)."""
    signature = sign_delivery(
        secret,
        key_id=key_id,
        timestamp=timestamp,
        delivery_id=delivery_id,
        payload=payload,
    )
    return {
        EVENT_ID_HEADER: event_id,
        DELIVERY_ID_HEADER: delivery_id,
        SEQUENCE_HEADER: str(sequence),
        TIMESTAMP_HEADER: timestamp,
        KEY_ID_HEADER: key_id,
        ALGORITHM_HEADER: SIGNATURE_ALGORITHM,
        SIGNATURE_HEADER: signature,
    }


def check_timestamp_freshness(
    timestamp: object, now: str, tolerance: int
) -> None:
    """Replay protection: reject a stale/future timestamp
    outside the tolerance window (fail closed
    ``webhook-timestamp-stale``)."""
    _require_text(now, "now")
    parse_utc(now)
    if not isinstance(timestamp, str) or not timestamp:
        raise DeveloperApiError(
            DeveloperApiReasonCode.WEBHOOK_TIMESTAMP_STALE,
            "the signed timestamp header is missing or malformed",
        )
    try:
        moment = parse_utc(timestamp)
    except Exception as error:  # noqa: BLE001 - re-wrapped typed
        raise DeveloperApiError(
            DeveloperApiReasonCode.WEBHOOK_TIMESTAMP_STALE,
            "timestamp %r is not RFC 3339 UTC: %s" % (timestamp, error),
        ) from error
    if not isinstance(tolerance, int) or isinstance(tolerance, bool) or tolerance <= 0:
        raise DeveloperApiError(
            DeveloperApiReasonCode.INVALID_INPUT,
            "timestamp tolerance must be a positive integer (seconds)",
        )
    current = parse_utc(now)
    delta = abs(int((current - moment).total_seconds()))
    if delta > tolerance:
        raise DeveloperApiError(
            DeveloperApiReasonCode.WEBHOOK_TIMESTAMP_STALE,
            "timestamp %r is %ds from %r (outside the %ds window)"
            % (timestamp, delta, now, tolerance),
        )


# ---------------------------------------------------------------------------
# The deterministic retry schedule
# ---------------------------------------------------------------------------

def backoff_for_attempt(failed_attempt: int) -> int:
    """The backoff seconds after the Nth failed attempt (1-based)."""
    if (
        not isinstance(failed_attempt, int)
        or isinstance(failed_attempt, bool)
        or failed_attempt < 1
    ):
        raise DeveloperApiError(
            DeveloperApiReasonCode.INVALID_INPUT,
            "failed attempt must be a positive integer",
        )
    if failed_attempt > MAX_DELIVERY_ATTEMPTS:
        raise DeveloperApiError(
            DeveloperApiReasonCode.INVALID_INPUT,
            "attempt %d exceeds the schedule (%d max)"
            % (failed_attempt, MAX_DELIVERY_ATTEMPTS),
        )
    if failed_attempt >= MAX_DELIVERY_ATTEMPTS:
        return 0  # schedule exhausted: no further attempt
    return RETRY_BACKOFF_SECONDS[failed_attempt - 1]


def next_attempt_at(instant: str, failed_attempt: int) -> str:
    """The scheduled next-attempt instant after a failed attempt
    (deterministic arithmetic via the accepted clock helpers;
    empty when the schedule is exhausted)."""
    _require_text(instant, "instant")
    parse_utc(instant)
    backoff = backoff_for_attempt(failed_attempt)
    if backoff == 0:
        return ""
    return add_seconds(instant, backoff)


def attempts_remaining(attempts: int) -> int:
    """How many attempts remain under the schedule."""
    if not isinstance(attempts, int) or isinstance(attempts, bool) or attempts < 0:
        raise DeveloperApiError(
            DeveloperApiReasonCode.INVALID_INPUT,
            "attempts must be a non-negative integer",
        )
    return max(0, MAX_DELIVERY_ATTEMPTS - attempts)
