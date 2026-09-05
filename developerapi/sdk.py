"""WORK-046 SDK: the canonical-semantics client surface.

The SDK contract (W046 criterion 5): the SDK reproduces the
canonical server semantics EXACTLY and contains NO hidden
commercial authority:

- **Request parity**: every SDK mutation/read builds the same
  :class:`developerapi.gateway.ApiRequest` representation the
  direct API caller builds (method, route, body, headers,
  idempotency key); the canonical request bytes are identical by
  construction (parity battery-pinned at the byte level).

- **Response parity**: the typed response models parse the
  canonical server response bodies unchanged (enums as the
  server's exact state strings, optional members absent --
  never re-shaped, never re-semantics); the error model carries
  the canonical reason code across the SDK boundary unchanged.

- **Pagination parity**: the SDK iterator follows the server's
  ``next_cursor`` discipline exactly (same pages, same order).

- **Idempotency helpers**: mutations REQUIRE the idempotency
  key (like the server); :func:`deterministic_key` derives a
  stable key from the caller's content so a retry chain reuses
  it deterministically.

- **Webhook verification helpers**: :class:`WebhookVerifier`
  verifies server-signed deliveries with the SAME canonical
  signing construction (single site in
  :mod:`developerapi.webhooks`), rejects stale timestamps
  (replay protection), and returns the parsed observation;
  :class:`DuplicateDetector` and :class:`OrderTracker` are the
  consumer-side duplicate and out-of-order protections.

- **NO business authority**: the SDK decides nothing -- no
  eligibility, no pricing, no allocation, no connectivity, no
  session, no route validity, no settlement, no physical
  connectivity.  It imports ONLY the boundary's DATA modules
  (errors, schema, identifiers, webhooks signing) plus the
  request/response types -- never the gateway's journal,
  credential store, or the canonical subsystems (the import
  audit is battery-pinned).

The transport is injected: a callable taking the canonical
:class:`ApiRequest` and returning :class:`ApiResponse` (the
in-process service boundary in this repository's offline
determinism model; an HTTP adapter in a deployment, speaking
the same representation).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Iterator, List, Mapping, Optional, Tuple

from agent.clock import AgentClock

from protocol.canonicalization import canonical_json_bytes

from .errors import (
    DeveloperApiError,
    DeveloperApiReasonCode,
)
from .identifiers import ID_NAMESPACE
from .schema import API_VERSION_HEADER, resolve_version
from . import webhooks as webhook_platform

import hashlib


#: The idempotency-key header (the server's header name).
IDEMPOTENCY_KEY_HEADER = "X-ADCOS-Idempotency-Key"

#: The application credential headers.
APPLICATION_HEADER = "X-ADCOS-Application"
CREDENTIAL_HEADER = "X-ADCOS-Credential"

#: The client transport seam.
Transport = Callable[[Any], Any]


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise DeveloperApiError(
            DeveloperApiReasonCode.INVALID_INPUT,
            "%s must be a non-empty string" % label,
        )
    return value


def deterministic_key(*parts: str) -> str:
    """A stable idempotency key derived from the caller's own
    content: retries with the same arguments reuse the same key
    (the SDK idempotency helper)."""
    for part in parts:
        _require_text(part, "key part")
    return (
        "sdk-"
        + hashlib.sha256(
            canonical_json_bytes({"parts": list(parts)})
        ).hexdigest()
    )


# ---------------------------------------------------------------------------
# Typed response models (the server's canonical shapes, parsed)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SdkError:
    """The developer-facing error, parsed from the canonical
    error body (the canonical reason survives unchanged)."""

    http_status: int
    reason: str
    canonical_reason: str
    message: str
    retryable: bool
    retry_after: str
    resource_id: str
    environment: str
    request_id: str

    @classmethod
    def from_response(cls, body: Mapping[str, Any]) -> "SdkError":
        error = body.get("error")
        if not isinstance(error, Mapping):
            raise DeveloperApiError(
                DeveloperApiReasonCode.INVALID_INPUT,
                "the error body carries no error member",
            )
        return cls(
            http_status=error.get("http_status", 0),
            reason=error.get("reason", ""),
            canonical_reason=error.get("canonical_reason", ""),
            message=error.get("message", ""),
            retryable=bool(error.get("retryable", False)),
            retry_after=error.get("retry_after", ""),
            resource_id=error.get("resource_id", ""),
            environment=error.get("environment", ""),
            request_id=error.get("request_id", ""),
        )


@dataclass(frozen=True)
class SdkResource:
    """One parsed canonical resource (kind + id + the server's
    members, unchanged)."""

    kind: str
    id: str
    members: Tuple[Tuple[str, Any], ...]

    @classmethod
    def from_data(cls, data: Mapping[str, Any]) -> "SdkResource":
        kind = data.get("kind", "")
        resource_id = data.get("id", "")
        _require_text(kind, "resource kind")
        _require_text(resource_id, "resource id")
        return cls(
            kind=kind,
            id=resource_id,
            members=tuple(
                (key, data[key]) for key in sorted(data) if key not in ("kind", "id")
            ),
        )

    def get(self, member: str) -> Any:
        for key, value in self.members:
            if key == member:
                return value
        return None

    def to_dict(self) -> Dict[str, Any]:
        out = {"kind": self.kind, "id": self.id}
        for key, value in self.members:
            out[key] = value
        return out

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SdkResource):
            return NotImplemented
        return self.to_dict() == other.to_dict()


@dataclass(frozen=True)
class SdkList:
    """One parsed canonical list page (items + cursor)."""

    items: Tuple[SdkResource, ...]
    next_cursor: str
    has_more: bool

    @classmethod
    def from_data(cls, data: Mapping[str, Any]) -> "SdkList":
        items_raw = data.get("items")
        if not isinstance(items_raw, (list, tuple)):
            raise DeveloperApiError(
                DeveloperApiReasonCode.INVALID_INPUT,
                "list data carries no items member",
            )
        return cls(
            items=tuple(SdkResource.from_data(item) for item in items_raw),
            next_cursor=data.get("next_cursor", ""),
            has_more=bool(data.get("has_more", False)),
        )


# ---------------------------------------------------------------------------
# The client (request parity by construction)
# ---------------------------------------------------------------------------

class DeveloperApiClient:
    """The ergonomic developer client over the injected
    transport.

    Every method builds the EXACT canonical request the direct
    API caller builds (byte-identical canonical request bytes:
    the parity battery's substrate)."""

    def __init__(
        self,
        *,
        transport: Transport,
        application_id: str,
        secret: str,
        api_version: str = "1.0",
        environment: str = "",
    ) -> None:
        self._transport = transport
        self._application_id = _require_text(
            application_id, "application id"
        )
        self._secret = _require_text(secret, "credential secret")
        resolve_version(api_version)
        self._api_version = api_version
        self._environment = environment

    # -- request construction (the parity substrate) --------------------

    def _request(
        self,
        method: str,
        resource_path: str,
        body: Optional[Mapping[str, Any]] = None,
        idempotency_key: str = "",
    ) -> Any:
        from .gateway import ApiRequest

        route = "/api/%s/%s" % (self._api_version, resource_path)
        request = ApiRequest(
            method=method,
            route=route,
            body=dict(body or {}),
            api_version=self._api_version,
            idempotency_key=idempotency_key,
            application_id=self._application_id,
            secret=self._secret,
        )
        response = self._transport(request)
        return response

    def _call(
        self,
        method: str,
        resource_path: str,
        body: Optional[Mapping[str, Any]] = None,
        idempotency_key: str = "",
    ) -> SdkResource:
        response = self._request(
            method, resource_path, body, idempotency_key
        )
        if response.status != 200:
            raise self._raise_error(response)
        return SdkResource.from_data(response.data())

    def _raise_error(self, response: Any) -> DeveloperApiError:
        error = SdkError.from_response(dict(response.body))
        return DeveloperApiError(
            error.reason,
            error.message,
            canonical_reason=error.canonical_reason,
            request_id=error.request_id,
            resource_id=error.resource_id,
            environment=error.environment,
            retry_after=error.retry_after,
        )

    def _call_list(
        self,
        resource_path: str,
        body: Optional[Mapping[str, Any]] = None,
    ) -> SdkList:
        response = self._request("GET", resource_path, body)
        if response.status != 200:
            raise self._raise_error(response)
        return SdkList.from_data(response.data())

    # -- the developer operations (native ADCOS semantics) ---------------

    def application(self) -> SdkResource:
        return self._call("GET", "application")

    def publish_offer(
        self, *, idempotency_key: str, offer: Mapping[str, Any]
    ) -> SdkResource:
        return self._call(
            "POST", "offers", dict(offer), idempotency_key
        )

    def list_offers(
        self,
        *,
        cursor: str = "",
        limit: Optional[int] = None,
        filters: Optional[Mapping[str, str]] = None,
    ) -> SdkList:
        return self._call_list(
            "offers", _list_body(cursor, limit, filters)
        )

    def get_offer(self, offer_id: str) -> SdkResource:
        return self._call("GET", "offers/%s" % offer_id)

    def create_intent(
        self, *, idempotency_key: str, intent: Mapping[str, Any]
    ) -> SdkResource:
        return self._call(
            "POST", "intents", {"intent": dict(intent)}, idempotency_key
        )

    def list_intents(
        self,
        *,
        cursor: str = "",
        limit: Optional[int] = None,
        filters: Optional[Mapping[str, str]] = None,
    ) -> SdkList:
        return self._call_list(
            "intents", _list_body(cursor, limit, filters)
        )

    def get_intent(self, intent_id: str) -> SdkResource:
        return self._call("GET", "intents/%s" % intent_id)

    def get_intent_lifecycle(self, intent_id: str) -> SdkResource:
        return self._call("GET", "intents/%s/lifecycle" % intent_id)

    def hold_reservation(
        self,
        *,
        idempotency_key: str,
        intent_id: str,
        expires_at: str,
        payment_refs: Iterable[str] = (),
    ) -> SdkResource:
        body: Dict[str, Any] = {"expires_at": expires_at}
        if payment_refs:
            body["payment_refs"] = list(payment_refs)
        return self._call(
            "POST",
            "intents/%s/reservations" % intent_id,
            body,
            idempotency_key,
        )

    def list_reservations(
        self,
        *,
        cursor: str = "",
        limit: Optional[int] = None,
        filters: Optional[Mapping[str, str]] = None,
    ) -> SdkList:
        return self._call_list(
            "reservations", _list_body(cursor, limit, filters)
        )

    def get_reservation(self, reservation_id: str) -> SdkResource:
        return self._call("GET", "reservations/%s" % reservation_id)

    def list_usage(
        self,
        *,
        cursor: str = "",
        limit: Optional[int] = None,
        filters: Optional[Mapping[str, str]] = None,
    ) -> SdkList:
        return self._call_list("usage", _list_body(cursor, limit, filters))

    def get_usage(self, transaction_id: str) -> SdkResource:
        return self._call("GET", "usage/%s" % transaction_id)

    def list_billing(
        self, *, cursor: str = "", limit: Optional[int] = None
    ) -> SdkList:
        return self._call_list("billing", _list_body(cursor, limit, None))

    def register_economic_policy(
        self, *, idempotency_key: str, policy: Mapping[str, Any]
    ) -> SdkResource:
        return self._call(
            "POST", "economic-policies", dict(policy), idempotency_key
        )

    def list_economic_policies(
        self, *, cursor: str = "", limit: Optional[int] = None
    ) -> SdkList:
        return self._call_list(
            "economic-policies", _list_body(cursor, limit, None)
        )

    def get_economic_policy(
        self, policy_id: str, version: int
    ) -> SdkResource:
        return self._call(
            "GET", "economic-policies/%s/%d" % (policy_id, version)
        )

    def register_webhook_endpoint(
        self,
        *,
        idempotency_key: str,
        url: str,
        event_types: Iterable[str],
    ) -> SdkResource:
        return self._call(
            "POST",
            "webhook-endpoints",
            {"url": url, "event_types": list(event_types)},
            idempotency_key,
        )

    def list_webhook_endpoints(
        self, *, cursor: str = "", limit: Optional[int] = None
    ) -> SdkList:
        return self._call_list(
            "webhook-endpoints", _list_body(cursor, limit, None)
        )

    def get_webhook_endpoint(self, endpoint_id: str) -> SdkResource:
        return self._call("GET", "webhook-endpoints/%s" % endpoint_id)

    def list_deliveries(
        self, endpoint_id: str, *, cursor: str = "", limit: Optional[int] = None
    ) -> SdkList:
        return self._call_list(
            "webhook-endpoints/%s/deliveries" % endpoint_id,
            _list_body(cursor, limit, None),
        )

    # -- the pagination helper ---------------------------------------------

    def iterate(
        self,
        list_call: Callable[..., SdkList],
        **list_kwargs: Any,
    ) -> Iterator[SdkResource]:
        """Iterate a whole list through the server's cursor
        discipline (identical pages and order to the direct
        API)."""
        cursor = ""
        while True:
            page = list_call(cursor=cursor, **list_kwargs)
            for item in page.items:
                yield item
            if not page.has_more or not page.next_cursor:
                return
            cursor = page.next_cursor


def _list_body(
    cursor: str, limit: Optional[int], filters: Optional[Mapping[str, str]]
) -> Dict[str, Any]:
    body: Dict[str, Any] = {}
    if cursor:
        body["cursor"] = cursor
    if limit is not None:
        body["limit"] = limit
    if filters:
        body["filters"] = dict(filters)
    return body


# ---------------------------------------------------------------------------
# Webhook verification helpers (consumer side)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SdkWebhookEvent:
    """One verified webhook observation (the parsed canonical
    payload)."""

    event_id: str
    event_type: str
    occurred_at: str
    environment: str
    resource_kind: str
    resource_id: str
    resource_version: int
    sequence: int
    delivery_id: str
    correlation: str
    data: Dict[str, Any]


class WebhookVerifier:
    """The consumer-side webhook verifier.

    Reproduces the canonical server verification semantics
    exactly: signature verification against the canonical
    signing construction (single site in
    :mod:`developerapi.webhooks`), then the timestamp replay
    window (fail closed ``webhook-timestamp-stale``)."""

    def __init__(
        self,
        *,
        secret: str,
        clock: AgentClock,
        tolerance: int = webhook_platform.DEFAULT_TIMESTAMP_TOLERANCE_SECONDS,
    ) -> None:
        _require_text(secret, "webhook signing secret")
        if not isinstance(clock, AgentClock):
            raise DeveloperApiError(
                DeveloperApiReasonCode.INVALID_INPUT,
                "the webhook verifier requires an AgentClock",
            )
        self._secret = secret
        self._clock = clock
        self._tolerance = tolerance

    def verify(
        self,
        headers: Mapping[str, str],
        raw_payload: Mapping[str, Any],
    ) -> SdkWebhookEvent:
        """Verify one delivery: signature first, then the
        timestamp window, then parse the observation."""
        key_id = _require_text(
            headers.get(webhook_platform.KEY_ID_HEADER, ""), "key id header"
        )
        timestamp = _require_text(
            headers.get(webhook_platform.TIMESTAMP_HEADER, ""),
            "timestamp header",
        )
        delivery_id = _require_text(
            headers.get(webhook_platform.DELIVERY_ID_HEADER, ""),
            "delivery id header",
        )
        signature = headers.get(webhook_platform.SIGNATURE_HEADER, "")
        if not webhook_platform.verify_delivery_signature(
            self._secret,
            key_id=key_id,
            timestamp=timestamp,
            delivery_id=delivery_id,
            payload=raw_payload,
            signature=signature,
        ):
            raise DeveloperApiError(
                DeveloperApiReasonCode.WEBHOOK_SIGNATURE_INVALID,
                "the delivery signature does not verify against the "
                "canonical signing envelope",
            )
        webhook_platform.check_timestamp_freshness(
            timestamp, self._clock.now(), self._tolerance
        )
        return self._parse(raw_payload, delivery_id)

    def _parse(
        self, raw_payload: Mapping[str, Any], delivery_id: str
    ) -> SdkWebhookEvent:
        for member in webhook_platform.EVENT_MEMBERS:
            if member not in raw_payload:
                raise DeveloperApiError(
                    DeveloperApiReasonCode.INVALID_INPUT,
                    "webhook payload missing member %r" % member,
                )
        if raw_payload.get("delivery_id") != delivery_id:
            raise DeveloperApiError(
                DeveloperApiReasonCode.WEBHOOK_SIGNATURE_INVALID,
                "the payload delivery id does not match the signed header",
            )
        return SdkWebhookEvent(
            event_id=raw_payload["event_id"],
            event_type=raw_payload["event_type"],
            occurred_at=raw_payload["occurred_at"],
            environment=raw_payload["environment"],
            resource_kind=raw_payload["resource_kind"],
            resource_id=raw_payload["resource_id"],
            resource_version=raw_payload["resource_version"],
            sequence=raw_payload["sequence"],
            delivery_id=raw_payload["delivery_id"],
            correlation=raw_payload["correlation"],
            data=dict(raw_payload["data"]),
        )


class DuplicateDetector:
    """The consumer-side duplicate protection.

    Tracks seen event ids with deterministic FIFO eviction (the
    fixed capacity keeps the detector's behavior independent of
    arrival count).  ``observe`` returns True when the event is
    NEW (process it) and False when it is a duplicate (skip
    it)."""

    def __init__(self, capacity: int = 1024) -> None:
        if not isinstance(capacity, int) or isinstance(capacity, bool) or capacity < 1:
            raise DeveloperApiError(
                DeveloperApiReasonCode.INVALID_INPUT,
                "duplicate detector capacity must be a positive integer",
            )
        self._capacity = capacity
        self._seen: Dict[str, None] = {}

    def observe(self, event_id: str) -> bool:
        _require_text(event_id, "event id")
        if event_id in self._seen:
            return False
        self._seen[event_id] = None
        if len(self._seen) > self._capacity:
            # FIFO eviction in insertion order (deterministic)
            for key in list(self._seen)[: len(self._seen) - self._capacity]:
                del self._seen[key]
        return True

    def known(self) -> Tuple[str, ...]:
        return tuple(self._seen)


class OrderTracker:
    """The consumer-side out-of-order protection.

    Tracks the highest resource version seen per resource id:
    ``observe`` classifies each event as ``advance`` (a newer
    version than any seen -- safe to apply), ``stale`` (an older
    version than the current knowledge -- must NOT overwrite
    truth), or ``duplicate`` (the same version).  Consumers
    never infer truth from arrival order: the version metadata
    decides."""

    def __init__(self) -> None:
        self._latest: Dict[str, int] = {}

    def observe(
        self, resource_id: str, resource_version: int
    ) -> str:
        _require_text(resource_id, "resource id")
        if (
            not isinstance(resource_version, int)
            or isinstance(resource_version, bool)
            or resource_version < 1
        ):
            raise DeveloperApiError(
                DeveloperApiReasonCode.INVALID_INPUT,
                "resource version must be a positive integer",
            )
        current = self._latest.get(resource_id)
        if current is None or resource_version > current:
            self._latest[resource_id] = resource_version
            return "advance"
        if resource_version == current:
            return "duplicate"
        return "stale"
