"""WORK-046 developer-platform append-only journal and durable
persistence seam.

The journal-first durable core of the developer API boundary
(the ACR-006 / W044-atomic journal discipline):

    immutable developerapi records
        + append-only file discipline
        + content-derived record ids
        + a hash chain over (sequence, content, previous link)
        = tamper-evident, deterministically replayable boundary
          history

Discipline (battery-pinned, mirroring the accepted W044/W051
journals):

- **atomic mutation records**: every admitted API mutation
  appends EXACTLY ONE journal record carrying the admitted
  request (idempotency key + application + route + canonical
  request digest -- the durable idempotency ledger) AND its
  canonical response (status + canonical body bytes).  One
  append = one atomic persist-then-ack; there is no intermediate
  state where a mutation is admitted without its response.

- **content-derived ids**: every ``record_id`` is the
  fingerprint of (sequence, ``chain_content()``, previous
  record id) -- the hash chain; every ``request_digest`` is the
  fingerprint of the canonical request.  All are mechanically
  verified at construction and on deserialization, so a tampered
  record can never carry an attacker-chosen id.

- **canonical serialization**: one canonical-JSON line per
  record (WORK-003 profile); identical logical histories produce
  byte-identical journals.

- **immutable records**: there is NO API that modifies,
  rewrites, or removes a journal record; the file discipline is
  append-only (``ab``), so the journal can only grow.

- **deterministic replay**: loading and folding the same journal
  bytes always reproduces the same boundary index (credentials,
  idempotency ledger, API-owned resources, webhook delivery
  state) -- the fold lives in :func:`fold_index` and is exactly
  what the service reloads after a restart.

- **duplicate detection**: the idempotency ledger is journaled
  with each mutation record, so API idempotency SURVIVES
  RESTART; a duplicate idempotency key in a stored journal
  fails closed at load (``journal-corrupt``).

- **corruption/tamper detection**: load verifies every record
  id, the chain links, the contiguous 1..N sequence, and
  duplicate keys -- any tampered byte, reordered line,
  truncated tail, or sequence gap fails closed.

- **persist-then-ack**: the journal is persisted BEFORE the
  in-memory index acknowledges the record; a store failure
  leaves no phantom in-memory state (``store-failed``).

- **secret hygiene**: records carry credential SECRET DIGESTS
  only, never secrets; the battery's secret-hygiene case audits
  the serialized journal bytes for secret material.

The persistence seam (:class:`ApiStore`) is injectable:
:class:`MemoryApiStore` keeps verification deterministic and
in-process; :class:`FileApiStore` is the real durable store
(the only filesystem-write site in the developerapi family,
battery-audited).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import DeveloperApiError, DeveloperApiReasonCode
from .webhooks import MAX_DELIVERY_ATTEMPTS

GENESIS_RECORD_ID = "sha256:" + "0" * 64

#: The record-kind vocabulary: one discriminated family.
RECORD_KINDS = (
    "mutation",
    "credential-issue",
    "credential-revoke",
    "webhook-obligation",
    "webhook-queue",
    "webhook-attempt",
)


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise DeveloperApiError(
            DeveloperApiReasonCode.INVALID_INPUT,
            "%s must be a non-empty string" % label,
        )
    return value


def derive_record_id(
    sequence: int, record_content: Dict[str, Any], prev_record_id: str
) -> str:
    """The content-derived journal record fingerprint (hash
    chain): binds the record to its position, its content, and
    the ENTIRE preceding journal."""
    content = {
        "sequence": sequence,
        "record": record_content,
        "prev": prev_record_id,
    }
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(content)
    ).hexdigest()


def derive_request_digest(
    method: str,
    route: str,
    body: Mapping[str, Any],
    environment: str,
    developer_id: str,
    idempotency_key: str,
) -> str:
    """The fingerprint of one API mutation's effective request
    (the idempotency equivalence class: same key + same
    effective request = same digest; a materially different
    request under the same key differs deterministically)."""
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(
            {
                "method": method,
                "route": route,
                "body": dict(body),
                "environment": environment,
                "developer": developer_id,
                "key": idempotency_key,
            }
        )
    ).hexdigest()


@dataclass(frozen=True)
class MutationRecord:
    """One admitted API mutation and its canonical response:
    THE atomic durable idempotency record (request AND response
    in one persist-then-ack append).

    ``resource`` carries the canonical resource mapping for
    developerapi-OWNED resources (offers, webhook endpoints) --
    the boundary's own projection truth, rebuilt by the fold.
    For ADAPTED resources (intents, reservations, policies) the
    truth stays in the canonical subsystem's journal and
    ``resource_kind`` is empty."""

    sequence: int
    record_id: str
    idempotency_key: str = ""
    application_id: str = ""
    developer_id: str = ""
    method: str = ""
    route: str = ""
    api_version: str = ""
    request_id: str = ""
    request_digest: str = ""
    resource_kind: str = ""
    resource_id: str = ""
    resource: Tuple[Tuple[str, Any], ...] = ()
    response_status: int = 0
    response_body: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.sequence, int) or isinstance(
            self.sequence, bool
        ) or self.sequence < 1:
            raise DeveloperApiError(
                DeveloperApiReasonCode.JOURNAL_CORRUPT,
                "sequence must be an integer >= 1",
            )
        for label, value in (
            ("idempotency_key", self.idempotency_key),
            ("application_id", self.application_id),
            ("developer_id", self.developer_id),
            ("method", self.method),
            ("route", self.route),
            ("api_version", self.api_version),
            ("request_id", self.request_id),
            ("request_digest", self.request_digest),
            ("record_id", self.record_id),
        ):
            _require_text(value, label)
        if not isinstance(self.response_status, int) or isinstance(
            self.response_status, bool
        ) or self.response_status < 100 or self.response_status > 599:
            raise DeveloperApiError(
                DeveloperApiReasonCode.JOURNAL_CORRUPT,
                "response status must be an HTTP status code",
            )
        _require_text(self.response_body, "response body")
        if self.resource_kind:
            _require_text(self.resource_id, "resource_id")

    # -- the hash-chain content (single site) --------------------------

    def chain_content(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "record_kind": "mutation",
            "idempotency_key": self.idempotency_key,
            "application_id": self.application_id,
            "developer_id": self.developer_id,
            "method": self.method,
            "route": self.route,
            "api_version": self.api_version,
            "request_id": self.request_id,
            "request_digest": self.request_digest,
            "resource_kind": self.resource_kind,
            "response_status": self.response_status,
            "response_body": self.response_body,
        }
        if self.resource_kind:
            out["resource_id"] = self.resource_id
            out["resource"] = self.resource_dict()
        return out

    def resource_dict(self) -> Dict[str, Any]:
        return dict(self.resource)

    def response_bytes(self) -> bytes:
        return self.response_body.encode("utf-8")

    def to_dict(self) -> Dict[str, Any]:
        out = self.chain_content()
        out["sequence"] = self.sequence
        out["record_id"] = self.record_id
        return out

    @classmethod
    def build(
        cls,
        *,
        sequence: int,
        prev_record_id: str,
        idempotency_key: str,
        application_id: str,
        developer_id: str,
        method: str,
        route: str,
        api_version: str,
        request_id: str,
        request_digest: str,
        resource_kind: str,
        resource_id: str,
        resource: Mapping[str, Any],
        response_status: int,
        response_body: str,
    ) -> "MutationRecord":
        proto = cls(
            sequence=sequence,
            record_id="pending",
            idempotency_key=idempotency_key,
            application_id=application_id,
            developer_id=developer_id,
            method=method,
            route=route,
            api_version=api_version,
            request_id=request_id,
            request_digest=request_digest,
            resource_kind=resource_kind,
            resource_id=resource_id,
            resource=tuple(sorted(dict(resource).items())),
            response_status=response_status,
            response_body=response_body,
        )
        record_id = derive_record_id(
            sequence, proto.chain_content(), prev_record_id
        )
        return cls(
            sequence=sequence,
            record_id=record_id,
            idempotency_key=idempotency_key,
            application_id=application_id,
            developer_id=developer_id,
            method=method,
            route=route,
            api_version=api_version,
            request_id=request_id,
            request_digest=request_digest,
            resource_kind=resource_kind,
            resource_id=resource_id,
            resource=proto.resource,
            response_status=response_status,
            response_body=response_body,
        )


@dataclass(frozen=True)
class CredentialRecord:
    """One application-credential lifecycle record (issuance or
    revocation).  The issuance record carries the credential's
    public fields plus the SECRET DIGEST -- never the secret."""

    sequence: int
    record_id: str
    action: str
    application_id: str
    developer_id: str
    application_name: str = ""
    environment: str = ""
    capabilities: Tuple[str, ...] = ()
    status: str = ""
    valid_until: str = ""
    issued_at: str = ""
    secret_digest: str = ""
    revoked_at: str = ""

    def __post_init__(self) -> None:
        if self.action not in ("credential-issue", "credential-revoke"):
            raise DeveloperApiError(
                DeveloperApiReasonCode.JOURNAL_CORRUPT,
                "credential record action must be credential-issue or "
                "credential-revoke",
            )
        if not isinstance(self.sequence, int) or isinstance(
            self.sequence, bool
        ) or self.sequence < 1:
            raise DeveloperApiError(
                DeveloperApiReasonCode.JOURNAL_CORRUPT,
                "sequence must be an integer >= 1",
            )
        for label, value in (
            ("record_id", self.record_id),
            ("application_id", self.application_id),
            ("developer_id", self.developer_id),
        ):
            _require_text(value, label)
        if self.action == "credential-issue":
            for label, value in (
                ("application_name", self.application_name),
                ("environment", self.environment),
                ("status", self.status),
                ("valid_until", self.valid_until),
                ("issued_at", self.issued_at),
                ("secret_digest", self.secret_digest),
            ):
                _require_text(value, label)
            if self.status not in ("active",):
                raise DeveloperApiError(
                    DeveloperApiReasonCode.JOURNAL_CORRUPT,
                    "issued credential status must be active",
                )
            if self.revoked_at:
                raise DeveloperApiError(
                    DeveloperApiReasonCode.JOURNAL_CORRUPT,
                    "issuance record cannot carry revoked_at",
                )
        else:
            if not self.revoked_at:
                raise DeveloperApiError(
                    DeveloperApiReasonCode.JOURNAL_CORRUPT,
                    "revoke record must carry revoked_at",
                )

    def chain_content(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "record_kind": self.action,
            "application_id": self.application_id,
            "developer_id": self.developer_id,
        }
        if self.action == "credential-issue":
            out.update(
                {
                    "application_name": self.application_name,
                    "environment": self.environment,
                    "capabilities": list(self.capabilities),
                    "status": self.status,
                    "valid_until": self.valid_until,
                    "issued_at": self.issued_at,
                    "secret_digest": self.secret_digest,
                }
            )
        else:
            out["revoked_at"] = self.revoked_at
        return out

    def to_dict(self) -> Dict[str, Any]:
        out = self.chain_content()
        out["sequence"] = self.sequence
        out["record_id"] = self.record_id
        return out

    @classmethod
    def build(
        cls,
        *,
        sequence: int,
        prev_record_id: str,
        action: str,
        application_id: str,
        developer_id: str,
        application_name: str = "",
        environment: str = "",
        capabilities: Tuple[str, ...] = (),
        status: str = "",
        valid_until: str = "",
        issued_at: str = "",
        secret_digest: str = "",
        revoked_at: str = "",
    ) -> "CredentialRecord":
        proto = cls(
            sequence=sequence,
            record_id="pending",
            action=action,
            application_id=application_id,
            developer_id=developer_id,
            application_name=application_name,
            environment=environment,
            capabilities=tuple(sorted(capabilities)),
            status=status,
            valid_until=valid_until,
            issued_at=issued_at,
            secret_digest=secret_digest,
            revoked_at=revoked_at,
        )
        record_id = derive_record_id(
            sequence, proto.chain_content(), prev_record_id
        )
        return cls(
            sequence=sequence,
            record_id=record_id,
            action=action,
            application_id=application_id,
            developer_id=developer_id,
            application_name=application_name,
            environment=environment,
            capabilities=proto.capabilities,
            status=status,
            valid_until=valid_until,
            issued_at=issued_at,
            secret_digest=secret_digest,
            revoked_at=revoked_at,
        )


@dataclass(frozen=True)
class WebhookQueueRecord:
    """One webhook delivery QUEUED for an endpoint: the full
    observation event, the per-endpoint delivery sequence, and
    the deterministic delivery id.

    Appended persist-then-ack BEFORE any transport attempt, so
    the delivery semantics are at-least-once (a crash between
    queue and attempt re-attempts deterministically)."""

    sequence: int
    record_id: str
    delivery_id: str = ""
    endpoint_id: str = ""
    developer_id: str = ""
    environment: str = ""
    delivery_sequence: int = 0
    event: Tuple[Tuple[str, Any], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.sequence, int) or isinstance(
            self.sequence, bool
        ) or self.sequence < 1:
            raise DeveloperApiError(
                DeveloperApiReasonCode.JOURNAL_CORRUPT,
                "sequence must be an integer >= 1",
            )
        for label, value in (
            ("record_id", self.record_id),
            ("delivery_id", self.delivery_id),
            ("endpoint_id", self.endpoint_id),
            ("developer_id", self.developer_id),
            ("environment", self.environment),
        ):
            _require_text(value, label)
        if (
            not isinstance(self.delivery_sequence, int)
            or isinstance(self.delivery_sequence, bool)
            or self.delivery_sequence < 1
        ):
            raise DeveloperApiError(
                DeveloperApiReasonCode.JOURNAL_CORRUPT,
                "delivery sequence must be an integer >= 1",
            )
        event = self.event_dict()
        for member in (
            "event_id",
            "event_type",
            "occurred_at",
            "api_version",
            "environment",
            "resource_kind",
            "resource_id",
            "resource_version",
        ):
            if member not in event:
                raise DeveloperApiError(
                    DeveloperApiReasonCode.JOURNAL_CORRUPT,
                    "queued event missing member %r" % member,
                )

    def event_dict(self) -> Dict[str, Any]:
        return dict(self.event)

    def chain_content(self) -> Dict[str, Any]:
        return {
            "record_kind": "webhook-queue",
            "delivery_id": self.delivery_id,
            "endpoint_id": self.endpoint_id,
            "developer_id": self.developer_id,
            "environment": self.environment,
            "delivery_sequence": self.delivery_sequence,
            "event": self.event_dict(),
        }

    def to_dict(self) -> Dict[str, Any]:
        out = self.chain_content()
        out["sequence"] = self.sequence
        out["record_id"] = self.record_id
        return out

    @classmethod
    def build(
        cls,
        *,
        sequence: int,
        prev_record_id: str,
        delivery_id: str,
        endpoint_id: str,
        developer_id: str,
        environment: str,
        delivery_sequence: int,
        event: Mapping[str, Any],
    ) -> "WebhookQueueRecord":
        proto = cls(
            sequence=sequence,
            record_id="pending",
            delivery_id=delivery_id,
            endpoint_id=endpoint_id,
            developer_id=developer_id,
            environment=environment,
            delivery_sequence=delivery_sequence,
            event=tuple(sorted(dict(event).items())),
        )
        record_id = derive_record_id(
            sequence, proto.chain_content(), prev_record_id
        )
        return cls(
            sequence=sequence,
            record_id=record_id,
            delivery_id=delivery_id,
            endpoint_id=endpoint_id,
            developer_id=developer_id,
            environment=environment,
            delivery_sequence=delivery_sequence,
            event=proto.event,
        )


@dataclass(frozen=True)
class WebhookAttemptRecord:
    """One webhook delivery ATTEMPT outcome (delivered or
    failed) with the deterministic retry schedule position.

    Delivery state is OBSERVATIONAL ONLY: the fold uses these
    records to report delivery health and schedule retries --
    no code path anywhere turns a delivery outcome into
    commercial, usage, or allocation state (battery-pinned
    structurally)."""

    sequence: int
    record_id: str
    delivery_id: str = ""
    endpoint_id: str = ""
    event_id: str = ""
    attempt: int = 0
    status: str = ""
    response_code: int = 0
    instant: str = ""
    next_attempt_at: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.sequence, int) or isinstance(
            self.sequence, bool
        ) or self.sequence < 1:
            raise DeveloperApiError(
                DeveloperApiReasonCode.JOURNAL_CORRUPT,
                "sequence must be an integer >= 1",
            )
        for label, value in (
            ("record_id", self.record_id),
            ("delivery_id", self.delivery_id),
            ("endpoint_id", self.endpoint_id),
            ("event_id", self.event_id),
            ("instant", self.instant),
        ):
            _require_text(value, label)
        if (
            not isinstance(self.attempt, int)
            or isinstance(self.attempt, bool)
            or self.attempt < 1
        ):
            raise DeveloperApiError(
                DeveloperApiReasonCode.JOURNAL_CORRUPT,
                "attempt must be an integer >= 1",
            )
        if self.attempt > MAX_DELIVERY_ATTEMPTS:
            raise DeveloperApiError(
                DeveloperApiReasonCode.JOURNAL_CORRUPT,
                "attempt %d exceeds the frozen schedule (%d max)"
                % (self.attempt, MAX_DELIVERY_ATTEMPTS),
            )
        if self.status not in ("delivered", "failed"):
            raise DeveloperApiError(
                DeveloperApiReasonCode.JOURNAL_CORRUPT,
                "attempt status %r must be delivered or failed"
                % self.status,
            )
        if (
            not isinstance(self.response_code, int)
            or isinstance(self.response_code, bool)
            or self.response_code < 0
            or self.response_code > 599
        ):
            raise DeveloperApiError(
                DeveloperApiReasonCode.JOURNAL_CORRUPT,
                "response code must be 0..599 (0 = no transport)",
            )
        if self.status == "failed":
            from .webhooks import backoff_for_attempt

            exhausted = backoff_for_attempt(self.attempt) == 0
            if bool(self.next_attempt_at) != (not exhausted):
                raise DeveloperApiError(
                    DeveloperApiReasonCode.JOURNAL_CORRUPT,
                    "failed attempt %d must carry next_attempt_at iff the "
                    "schedule is not exhausted" % self.attempt,
                )

    def chain_content(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "record_kind": "webhook-attempt",
            "delivery_id": self.delivery_id,
            "endpoint_id": self.endpoint_id,
            "event_id": self.event_id,
            "attempt": self.attempt,
            "status": self.status,
            "response_code": self.response_code,
            "instant": self.instant,
        }
        if self.next_attempt_at:
            out["next_attempt_at"] = self.next_attempt_at
        return out

    def to_dict(self) -> Dict[str, Any]:
        out = self.chain_content()
        out["sequence"] = self.sequence
        out["record_id"] = self.record_id
        return out

    @classmethod
    def build(
        cls,
        *,
        sequence: int,
        prev_record_id: str,
        delivery_id: str,
        endpoint_id: str,
        event_id: str,
        attempt: int,
        status: str,
        response_code: int,
        instant: str,
        next_attempt_at: str = "",
    ) -> "WebhookAttemptRecord":
        proto = cls(
            sequence=sequence,
            record_id="pending",
            delivery_id=delivery_id,
            endpoint_id=endpoint_id,
            event_id=event_id,
            attempt=attempt,
            status=status,
            response_code=response_code,
            instant=instant,
            next_attempt_at=next_attempt_at,
        )
        record_id = derive_record_id(
            sequence, proto.chain_content(), prev_record_id
        )
        return cls(
            sequence=sequence,
            record_id=record_id,
            delivery_id=delivery_id,
            endpoint_id=endpoint_id,
            event_id=event_id,
            attempt=attempt,
            status=status,
            response_code=response_code,
            instant=instant,
            next_attempt_at=next_attempt_at,
        )


@dataclass(frozen=True)
class WebhookObligationRecord:
    """One DURABLE webhook observation obligation: the complete
    observation payload and its resolved audience, persisted
    BEFORE the API response is returned for the admitting
    mutation (post-finality for the business mutation,
    pre-response for the caller) so the obligation to observe
    SURVIVES a process crash.

    The record is the observation channel's own operational
    state -- never business state: nothing in the commercial,
    usage, or allocation planes reads it, and it can never
    change a mutation result.  Satisfaction is DERIVED, never
    stored: the obligation is retired exactly when every target
    endpoint holds its queue record (the delivery-identity
    dedupe), so restart recovery, pump retries, and journal
    replay agree on the outstanding set by construction."""

    sequence: int
    record_id: str
    obligation_id: str = ""
    event_id: str = ""
    event_type: str = ""
    occurred_at: str = ""
    environment: str = ""
    developer_id: str = ""
    resource_kind: str = ""
    resource_id: str = ""
    resource_version: int = 0
    correlation: str = ""
    data: Tuple[Tuple[str, Any], ...] = ()
    endpoints: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.sequence, int) or isinstance(
            self.sequence, bool
        ) or self.sequence < 1:
            raise DeveloperApiError(
                DeveloperApiReasonCode.JOURNAL_CORRUPT,
                "sequence must be an integer >= 1",
            )
        for label, value in (
            ("record_id", self.record_id),
            ("obligation_id", self.obligation_id),
            ("event_id", self.event_id),
            ("event_type", self.event_type),
            ("occurred_at", self.occurred_at),
            ("environment", self.environment),
            ("developer_id", self.developer_id),
            ("resource_kind", self.resource_kind),
            ("resource_id", self.resource_id),
        ):
            _require_text(value, label)
        if not isinstance(self.resource_version, int) or isinstance(
            self.resource_version, bool
        ) or self.resource_version < 1:
            raise DeveloperApiError(
                DeveloperApiReasonCode.JOURNAL_CORRUPT,
                "resource version must be a positive integer",
            )
        if not isinstance(self.correlation, str):
            raise DeveloperApiError(
                DeveloperApiReasonCode.JOURNAL_CORRUPT,
                "correlation must be a string (or empty)",
            )
        if not isinstance(self.data, tuple) or not self.data:
            raise DeveloperApiError(
                DeveloperApiReasonCode.JOURNAL_CORRUPT,
                "an obligation must carry the observed data payload",
            )
        if not isinstance(self.endpoints, tuple) or not self.endpoints:
            raise DeveloperApiError(
                DeveloperApiReasonCode.JOURNAL_CORRUPT,
                "an obligation must carry its resolved audience",
            )
        for endpoint_id in self.endpoints:
            if not isinstance(endpoint_id, str) or not endpoint_id:
                raise DeveloperApiError(
                    DeveloperApiReasonCode.JOURNAL_CORRUPT,
                    "obligation endpoints must be non-empty strings",
                )

    # -- the hash-chain content (single site) --------------------------

    def chain_content(self) -> Dict[str, Any]:
        return {
            "record_kind": "webhook-obligation",
            "obligation_id": self.obligation_id,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "occurred_at": self.occurred_at,
            "environment": self.environment,
            "developer_id": self.developer_id,
            "resource_kind": self.resource_kind,
            "resource_id": self.resource_id,
            "resource_version": self.resource_version,
            "correlation": self.correlation,
            "data": self.data_dict(),
            "endpoints": list(self.endpoints),
        }

    def data_dict(self) -> Dict[str, Any]:
        return dict(self.data)

    def to_dict(self) -> Dict[str, Any]:
        out = self.chain_content()
        out["sequence"] = self.sequence
        out["record_id"] = self.record_id
        return out

    @classmethod
    def build(
        cls,
        *,
        sequence: int,
        prev_record_id: str,
        obligation_id: str,
        event_id: str,
        event_type: str,
        occurred_at: str,
        environment: str,
        developer_id: str,
        resource_kind: str,
        resource_id: str,
        resource_version: int,
        correlation: str,
        data: Mapping[str, Any],
        endpoints: Tuple[str, ...],
    ) -> "WebhookObligationRecord":
        proto = cls(
            sequence=sequence,
            record_id="pending",
            obligation_id=obligation_id,
            event_id=event_id,
            event_type=event_type,
            occurred_at=occurred_at,
            environment=environment,
            developer_id=developer_id,
            resource_kind=resource_kind,
            resource_id=resource_id,
            resource_version=resource_version,
            correlation=correlation,
            data=tuple(sorted(dict(data).items())),
            endpoints=tuple(endpoints),
        )
        record_id = derive_record_id(
            sequence, proto.chain_content(), prev_record_id
        )
        return cls(
            sequence=sequence,
            record_id=record_id,
            obligation_id=obligation_id,
            event_id=event_id,
            event_type=event_type,
            occurred_at=occurred_at,
            environment=environment,
            developer_id=developer_id,
            resource_kind=resource_kind,
            resource_id=resource_id,
            resource_version=resource_version,
            correlation=correlation,
            data=proto.data,
            endpoints=proto.endpoints,
        )


#: The record types the journal discriminates.
RECORD_TYPES = (
    MutationRecord,
    CredentialRecord,
    WebhookQueueRecord,
    WebhookAttemptRecord,
    WebhookObligationRecord,
)


class ApiStore:
    """The injectable persistence seam (append-only)."""

    def append_line(self, line: str) -> None:
        raise NotImplementedError

    def read_lines(self) -> List[str]:
        raise NotImplementedError


class MemoryApiStore(ApiStore):
    """The deterministic in-process store (verification)."""

    def __init__(self) -> None:
        self._lines: List[str] = []

    def append_line(self, line: str) -> None:
        if not line.endswith("\n"):
            raise DeveloperApiError(
                DeveloperApiReasonCode.STORE_FAILED,
                "journal lines must be newline-terminated",
            )
        self._lines.append(line)

    def read_lines(self) -> List[str]:
        return list(self._lines)


class FileApiStore(ApiStore):
    """The real durable store (append-only file discipline)."""

    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path):
            raise DeveloperApiError(
                DeveloperApiReasonCode.INVALID_INPUT,
                "FileApiStore requires a pathlib.Path",
            )
        self._path = path

    def append_line(self, line: str) -> None:
        if not line.endswith("\n"):
            raise DeveloperApiError(
                DeveloperApiReasonCode.STORE_FAILED,
                "journal lines must be newline-terminated",
            )
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("ab") as handle:
                handle.write(line.encode("utf-8"))
                handle.flush()
        except OSError as error:
            raise DeveloperApiError(
                DeveloperApiReasonCode.STORE_FAILED,
                "api journal append failed: %s" % error,
            ) from error

    def read_lines(self) -> List[str]:
        if not self._path.is_file():
            return []
        try:
            raw = self._path.read_bytes()
        except OSError as error:
            raise DeveloperApiError(
                DeveloperApiReasonCode.STORE_FAILED,
                "api journal read failed: %s" % error,
            ) from error
        if not raw:
            return []
        text = raw.decode("utf-8")
        if not text.endswith("\n"):
            raise DeveloperApiError(
                DeveloperApiReasonCode.JOURNAL_CORRUPT,
                "journal tail is truncated (partial line without newline)",
            )
        return text.splitlines()


def _record_from_dict(data: object) -> Any:
    if not isinstance(data, Mapping):
        raise DeveloperApiError(
            DeveloperApiReasonCode.JOURNAL_CORRUPT,
            "journal line is not a mapping",
        )
    kind = data.get("record_kind")
    sequence = data.get("sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool):
        raise DeveloperApiError(
            DeveloperApiReasonCode.JOURNAL_CORRUPT,
            "journal record sequence must be an integer",
        )
    if kind == "mutation":
        resource = data.get("resource") or {}
        return MutationRecord(
            sequence=sequence,
            record_id=data.get("record_id", ""),
            idempotency_key=data.get("idempotency_key", ""),
            application_id=data.get("application_id", ""),
            developer_id=data.get("developer_id", ""),
            method=data.get("method", ""),
            route=data.get("route", ""),
            api_version=data.get("api_version", ""),
            request_id=data.get("request_id", ""),
            request_digest=data.get("request_digest", ""),
            resource_kind=data.get("resource_kind", ""),
            resource_id=data.get("resource_id", ""),
            resource=tuple(sorted(dict(resource).items())),
            response_status=data.get("response_status", 0),
            response_body=data.get("response_body", ""),
        )
    if kind in ("credential-issue", "credential-revoke"):
        return CredentialRecord(
            sequence=sequence,
            record_id=data.get("record_id", ""),
            action=kind,
            application_id=data.get("application_id", ""),
            developer_id=data.get("developer_id", ""),
            application_name=data.get("application_name", ""),
            environment=data.get("environment", ""),
            capabilities=tuple(data.get("capabilities") or ()),
            status=data.get("status", ""),
            valid_until=data.get("valid_until", ""),
            issued_at=data.get("issued_at", ""),
            secret_digest=data.get("secret_digest", ""),
            revoked_at=data.get("revoked_at", ""),
        )
    if kind == "webhook-queue":
        return WebhookQueueRecord(
            sequence=sequence,
            record_id=data.get("record_id", ""),
            delivery_id=data.get("delivery_id", ""),
            endpoint_id=data.get("endpoint_id", ""),
            developer_id=data.get("developer_id", ""),
            environment=data.get("environment", ""),
            delivery_sequence=data.get("delivery_sequence", 0),
            event=tuple(sorted(dict(data.get("event") or {}).items())),
        )
    if kind == "webhook-attempt":
        return WebhookAttemptRecord(
            sequence=sequence,
            record_id=data.get("record_id", ""),
            delivery_id=data.get("delivery_id", ""),
            endpoint_id=data.get("endpoint_id", ""),
            event_id=data.get("event_id", ""),
            attempt=data.get("attempt", 0),
            status=data.get("status", ""),
            response_code=data.get("response_code", -1),
            instant=data.get("instant", ""),
            next_attempt_at=data.get("next_attempt_at", ""),
        )
    if kind == "webhook-obligation":
        return WebhookObligationRecord(
            sequence=sequence,
            record_id=data.get("record_id", ""),
            obligation_id=data.get("obligation_id", ""),
            event_id=data.get("event_id", ""),
            event_type=data.get("event_type", ""),
            occurred_at=data.get("occurred_at", ""),
            environment=data.get("environment", ""),
            developer_id=data.get("developer_id", ""),
            resource_kind=data.get("resource_kind", ""),
            resource_id=data.get("resource_id", ""),
            resource_version=data.get("resource_version", 0),
            correlation=data.get("correlation", ""),
            data=tuple(sorted(dict(data.get("data") or {}).items())),
            endpoints=tuple(data.get("endpoints") or ()),
        )
    raise DeveloperApiError(
        DeveloperApiReasonCode.JOURNAL_CORRUPT,
        "journal record kind %r is not in the family" % (kind,),
    )


class AppendOnlyApiJournal:
    """The append-only, hash-chained, atomically-verified
    developerapi journal.

    Every record is ONE canonical-JSON line; every append is
    persist-then-ack (the store write happens BEFORE the
    in-memory record list acknowledges the record)."""

    def __init__(self, *, store: ApiStore) -> None:
        if not isinstance(store, ApiStore):
            raise DeveloperApiError(
                DeveloperApiReasonCode.INVALID_INPUT,
                "the api journal requires an ApiStore",
            )
        self._store = store
        self._records: List[Any] = []
        self._load_and_verify()

    # -- load + tamper detection --------------------------------------

    def _load_and_verify(self) -> None:
        records: List[Any] = []
        prev = GENESIS_RECORD_ID
        seen_keys: Dict[str, str] = {}
        for line in self._store.read_lines():
            if not line.strip():
                raise DeveloperApiError(
                    DeveloperApiReasonCode.JOURNAL_CORRUPT,
                    "journal contains a blank line",
                )
            try:
                data = json.loads(line)
            except ValueError as error:
                raise DeveloperApiError(
                    DeveloperApiReasonCode.JOURNAL_CORRUPT,
                    "journal line is not valid JSON: %s" % error,
                ) from error
            record = _record_from_dict(data)
            expected_sequence = len(records) + 1
            if record.sequence != expected_sequence:
                raise DeveloperApiError(
                    DeveloperApiReasonCode.JOURNAL_CORRUPT,
                    "journal sequence gap: record %d where %d expected"
                    % (record.sequence, expected_sequence),
                )
            expected_id = derive_record_id(
                record.sequence, record.chain_content(), prev
            )
            if record.record_id != expected_id:
                raise DeveloperApiError(
                    DeveloperApiReasonCode.JOURNAL_CORRUPT,
                    "record id %s does not match the hash chain"
                    % record.record_id,
                )
            if isinstance(record, MutationRecord):
                known = seen_keys.get(record.idempotency_key)
                if known is not None:
                    raise DeveloperApiError(
                        DeveloperApiReasonCode.JOURNAL_CORRUPT,
                        "duplicate idempotency key %r in stored journal"
                        % record.idempotency_key,
                    )
                seen_keys[record.idempotency_key] = record.record_id
            prev = record.record_id
            records.append(record)
        self._records = records

    # -- append + read -------------------------------------------------

    def __len__(self) -> int:
        return len(self._records)

    def records(self) -> Tuple[Any, ...]:
        return tuple(self._records)

    def tail_sequence(self) -> int:
        return len(self._records)

    def tail_record_id(self) -> str:
        if not self._records:
            return GENESIS_RECORD_ID
        return self._records[-1].record_id

    def append(self, record: Any) -> None:
        """Persist-then-ack: the canonical line is written to
        the store FIRST; only then is the record acknowledged
        in memory.  A store failure leaves no phantom record."""
        if type(record) not in RECORD_TYPES:
            raise DeveloperApiError(
                DeveloperApiReasonCode.INVALID_INPUT,
                "the api journal appends only family record types",
            )
        expected_sequence = len(self._records) + 1
        if record.sequence != expected_sequence:
            raise DeveloperApiError(
                DeveloperApiReasonCode.INVALID_INPUT,
                "append sequence %d does not follow tail %d"
                % (record.sequence, len(self._records)),
            )
        expected_id = derive_record_id(
            record.sequence,
            record.chain_content(),
            self.tail_record_id(),
        )
        if record.record_id != expected_id:
            raise DeveloperApiError(
                DeveloperApiReasonCode.INVALID_INPUT,
                "record id %s does not match the hash chain"
                % record.record_id,
            )
        line = canonical_json_bytes(record.to_dict()).decode("utf-8") + "\n"
        # persist BEFORE ack
        self._store.append_line(line)
        self._records.append(record)

    def journal_digest(self) -> str:
        """The deterministic digest of the whole journal state
        (evidence stream member)."""
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(
                {
                    "kind": "developerapi-journal",
                    "tail_sequence": self.tail_sequence(),
                    "tail_record_id": self.tail_record_id(),
                }
            )
        ).hexdigest()


# ---------------------------------------------------------------------------
# The fold: the boundary index replayed from journal bytes
# ---------------------------------------------------------------------------

@dataclass
class WebhookDeliveryState:
    """The fold projection of one queued webhook delivery:
    observational delivery health DATA only."""

    delivery_id: str
    endpoint_id: str
    developer_id: str
    environment: str
    delivery_sequence: int
    event: Dict[str, Any]
    attempts: int
    last_status: str
    last_attempt_at: str
    next_attempt_at: str
    response_codes: Tuple[int, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "delivery_id": self.delivery_id,
            "endpoint_id": self.endpoint_id,
            "delivery_sequence": self.delivery_sequence,
            "event": dict(self.event),
            "attempts": self.attempts,
            "last_status": self.last_status,
            "last_attempt_at": self.last_attempt_at,
            "next_attempt_at": self.next_attempt_at,
            "response_codes": list(self.response_codes),
        }


class ApiIndex:
    """The deterministic fold of the developerapi journal:
    credentials, the durable idempotency ledger, API-owned
    resources, and the observational webhook delivery index.

    Exactly what a restarted service reloads (byte-identical
    replay; construction IS recovery)."""

    def __init__(self) -> None:
        self.credentials: Dict[str, Dict[str, Any]] = {}
        self.mutations: Dict[str, MutationRecord] = {}
        self.offers: Dict[str, Dict[str, Any]] = {}
        self.endpoints: Dict[str, Dict[str, Any]] = {}
        self.obligations: Dict[str, WebhookObligationRecord] = {}
        self.deliveries: Dict[str, WebhookDeliveryState] = {}
        self.delivery_sequences: Dict[str, int] = {}
        self.attempts_by_delivery: Dict[str, List[WebhookAttemptRecord]] = {}

    # -- the fold ------------------------------------------------------

    def apply(self, record: Any) -> None:
        if isinstance(record, MutationRecord):
            self.mutations[record.idempotency_key] = record
            if record.resource_kind == "offer":
                self.offers[record.resource_id] = record.resource_dict()
            elif record.resource_kind == "webhook_endpoint":
                self.endpoints[record.resource_id] = record.resource_dict()
        elif isinstance(record, CredentialRecord):
            if record.action == "credential-issue":
                if record.application_id in self.credentials:
                    raise DeveloperApiError(
                        DeveloperApiReasonCode.JOURNAL_CORRUPT,
                        "credential %r issued twice"
                        % record.application_id,
                    )
                self.credentials[record.application_id] = {
                    "application_id": record.application_id,
                    "developer_id": record.developer_id,
                    "application_name": record.application_name,
                    "environment": record.environment,
                    "capabilities": tuple(record.capabilities),
                    "status": record.status,
                    "valid_until": record.valid_until,
                    "issued_at": record.issued_at,
                    "secret_digest": record.secret_digest,
                }
            else:
                entry = self.credentials.get(record.application_id)
                if entry is None:
                    raise DeveloperApiError(
                        DeveloperApiReasonCode.JOURNAL_CORRUPT,
                        "revocation for unknown credential %r"
                        % record.application_id,
                    )
                entry["status"] = "revoked"
        elif isinstance(record, WebhookObligationRecord):
            if record.obligation_id in self.obligations:
                raise DeveloperApiError(
                    DeveloperApiReasonCode.JOURNAL_CORRUPT,
                    "webhook obligation %r recorded twice"
                    % record.obligation_id,
                )
            self.obligations[record.obligation_id] = record
        elif isinstance(record, WebhookQueueRecord):
            if record.delivery_id in self.deliveries:
                raise DeveloperApiError(
                    DeveloperApiReasonCode.JOURNAL_CORRUPT,
                    "delivery %r queued twice" % record.delivery_id,
                )
            self.deliveries[record.delivery_id] = WebhookDeliveryState(
                delivery_id=record.delivery_id,
                endpoint_id=record.endpoint_id,
                developer_id=record.developer_id,
                environment=record.environment,
                delivery_sequence=record.delivery_sequence,
                event=record.event_dict(),
                attempts=0,
                last_status="pending",
                last_attempt_at="",
                next_attempt_at="",
                response_codes=(),
            )
            self.attempts_by_delivery[record.delivery_id] = []
            endpoint_seq = self.delivery_sequences.get(record.endpoint_id, 0)
            if record.delivery_sequence != endpoint_seq + 1:
                raise DeveloperApiError(
                    DeveloperApiReasonCode.JOURNAL_CORRUPT,
                    "endpoint %s delivery sequence gap: %d after %d"
                    % (
                        record.endpoint_id,
                        record.delivery_sequence,
                        endpoint_seq,
                    ),
                )
            self.delivery_sequences[record.endpoint_id] = (
                record.delivery_sequence
            )
        elif isinstance(record, WebhookAttemptRecord):
            state = self.deliveries.get(record.delivery_id)
            if state is None:
                raise DeveloperApiError(
                    DeveloperApiReasonCode.JOURNAL_CORRUPT,
                    "attempt for unqueued delivery %r"
                    % record.delivery_id,
                )
            attempts = self.attempts_by_delivery[record.delivery_id]
            if record.attempt != len(attempts) + 1:
                raise DeveloperApiError(
                    DeveloperApiReasonCode.JOURNAL_CORRUPT,
                    "attempt numbering for %r is not contiguous"
                    % record.delivery_id,
                )
            attempts.append(record)
            state.attempts = len(attempts)
            state.last_status = record.status
            state.last_attempt_at = record.instant
            state.next_attempt_at = record.next_attempt_at
            state.response_codes = tuple(
                attempt.response_code for attempt in attempts
            )
        else:
            raise DeveloperApiError(
                DeveloperApiReasonCode.JOURNAL_CORRUPT,
                "unknown record family in fold",
            )


def fold_index(records: Tuple[Any, ...]) -> ApiIndex:
    """Fold a verified journal into the boundary index.

    Deterministic: records in journal order, one apply per
    record.  The live service index and this fold are
    byte-identical by construction (the same apply function)."""
    index = ApiIndex()
    for record in records:
        index.apply(record)
    return index
