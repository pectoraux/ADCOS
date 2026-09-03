"""WORK-049 client runtime core (the neutral orchestration spine).

One :class:`ClientRuntime` binds a :class:`ClientContext` (the
authenticated user/device/application references — identity
references HELD, never minted), one platform
:class:`~client.adapters.PlatformAdapter`, and one
:class:`~client.gateway.CanonicalGateway` (the canonical read
window), and owns the shared client-local machinery:

- the append-only event journal (taxonomy classified, privacy
  gated, never canonical);
- the idempotent mutating-request ledger (deterministic
  content-derived request ids; an exact replay returns the
  recorded outcome — no duplicate local action can create
  duplicate canonical state);
- the bounded, marked, non-authoritative projection cache
  (stale-marked when the canonical surface is unreachable);
- the context binding verification (authenticated canonical
  reads must name THIS context's principals; mismatches fail
  closed);
- snapshot/restore (the restart path: local state is restored
  STALE and must reconcile against canonical truth before any
  operating action — a prior local ACTIVE is never resume
  authority).

The runtime is the platform-neutral core: it imports no platform
mechanism, holds no canonical truth, and constructs no authority.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from protocol.canonicalization import canonical_json_bytes

from .adapters import PlatformAdapter, require_adapter
from .capability import AdapterCapabilitySnapshot
from .errors import ClientError, ClientReasonCode
from .events import ClientEvent, ClientEventJournal
from .gateway import CanonicalGateway, GatewayRead
from .model import ClientContext, ReasonRef, RequestRecord
from .privacy import privacy_scan
from .projection import Freshness, ProjectionCache, StatusSnapshot

import hashlib


def _derive_request_id(
    mode: str, action: str, subject: str, binding: str
) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes(
            {
                "mode": mode,
                "action": action,
                "subject": subject,
                "binding": binding,
            }
        )
    ).hexdigest()


class ClientRuntime:
    """The platform-neutral client core shared by both modes."""

    def __init__(
        self,
        *,
        context: ClientContext,
        adapter: PlatformAdapter,
        gateway: CanonicalGateway,
    ) -> None:
        if not isinstance(context, ClientContext):
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "the runtime requires a ClientContext (identity references "
                "held, never minted)",
            )
        self._context = context
        self._adapter = require_adapter(adapter)
        if not isinstance(gateway, CanonicalGateway):
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "the runtime requires a CanonicalGateway (the canonical "
                "read window)",
            )
        self._gateway = gateway
        self._journal = ClientEventJournal()
        self._cache = ProjectionCache()
        self._requests: Dict[str, RequestRecord] = {}
        self._offline_observed = False

    # -- the composed surfaces -------------------------------------------------

    @property
    def context(self) -> ClientContext:
        return self._context

    @property
    def adapter(self) -> PlatformAdapter:
        return self._adapter

    @property
    def gateway(self) -> CanonicalGateway:
        return self._gateway

    @property
    def journal(self) -> ClientEventJournal:
        return self._journal

    @property
    def cache(self) -> ProjectionCache:
        return self._cache

    # -- events ------------------------------------------------------------------

    def emit(self, event: ClientEvent) -> ClientEvent:
        """Journal one event (privacy-gated: sensitive detail keys
        are rejected fail-closed — never redacted-and-kept)."""
        detail_map = {pair[0].lower(): pair[1] for pair in event.detail}
        found = privacy_scan(detail_map)
        if found:
            raise ClientError(
                ClientReasonCode.PRIVACY_DENIED,
                "event %r carries the forbidden sensitive detail key %r"
                % (event.kind, found),
            )
        return self._journal.append(event)

    def events_digest(self) -> str:
        return self._journal.digest()

    # -- the idempotent request ledger ---------------------------------------------

    def request_id(self, mode: str, action: str, subject: str) -> str:
        return _derive_request_id(
            mode, action, subject, self._context.binding_digest()
        )

    def recorded_request(self, request_id: str) -> Optional[RequestRecord]:
        return self._requests.get(request_id)

    def record_request(self, record: RequestRecord) -> None:
        """Record one mutating-request outcome in the ledger.

        The claimed ``request_id`` is RE-DERIVED from the record's
        own (mode, action, subject) plus THIS context's binding
        digest and must match exactly: an unverifiable record —
        a forged id, a record minted under another context, or a
        restored entry whose fields no longer derive its id — is
        rejected fail-closed (INVALID_INPUT), never silently
        loaded.  (P1-3 correction: a request-ledger entry is
        proof of origin only when its id is the deterministic
        content-derived id; persisted local state may never
        manufacture performed requests.)"""
        if not isinstance(record, RequestRecord):
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "the request ledger records RequestRecord entries only",
            )
        derived = _derive_request_id(
            record.mode, record.action, record.subject,
            self._context.binding_digest(),
        )
        if record.request_id != derived:
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "request record %r is unverifiable: its id is not the "
                "deterministic id derived from (mode=%r, action=%r, "
                "subject=%r, this context's binding) — forged or "
                "cross-context records are rejected (fail closed)"
                % (record.request_id, record.mode, record.action,
                   record.subject),
            )
        if record.request_id in self._requests:
            return
        self._requests[record.request_id] = record

    def request_records(self) -> Tuple[RequestRecord, ...]:
        return tuple(
            self._requests[key] for key in sorted(self._requests)
        )

    def require_not_recorded_performed(
        self, request_id: str, action: str
    ) -> Optional[RequestRecord]:
        """The idempotency seam for mutating requests.

        Returns the recorded outcome when this exact request was
        already issued (the caller short-circuits — an exact
        replay is a no-op), else ``None`` (the caller proceeds
        and records the outcome)."""
        record = self._requests.get(request_id)
        if record is not None:
            if record.action != action:
                raise ClientError(
                    ClientReasonCode.INVALID_INPUT,
                    "request id collision across actions (%r vs %r)"
                    % (record.action, action),
                )
            return record
        return None

    # -- the connection model --------------------------------------------------------

    def observe_offline(self) -> None:
        """Observe loss of contact with the canonical surface.

        Demotes cached CURRENT projections to STALE_CACHE (marked,
        never authoritative); nothing is fabricated."""
        if self._offline_observed:
            return
        now = self._now()
        self._gateway.set_reachable(False)
        demoted = self._cache.mark_stale(observed_at=now)
        self._offline_observed = True
        if demoted:
            self._cache.apply(
                StatusSnapshot(
                    subject="client.connection",
                    state="OFFLINE",
                    freshness=Freshness.LOCAL_OBSERVATION,
                    observed_at=now,
                    canonical_source="client",
                )
            )

    def observe_reconnected(self) -> None:
        """Observe restored contact (the reconcile entry point).

        Restoring reachability NEVER auto-resumes anything: the
        mode runtimes must reconcile against canonical truth and
        resume only if the canonical authorities permit."""
        self._gateway.set_reachable(True)
        self._offline_observed = False
        self._cache.apply(
            StatusSnapshot(
                subject="client.connection",
                state="RECONNECTED",
                freshness=Freshness.LOCAL_OBSERVATION,
                observed_at=self._now(),
                canonical_source="client",
            )
        )

    @property
    def offline_observed(self) -> bool:
        return self._offline_observed

    def _now(self) -> str:
        # the clock is reached through the gateway's injected seam
        # (the gateway holds the composed clock; a wall clock is
        # never read here)
        return self._gateway.read_clock()

    # -- canonical reads + binding verification -----------------------------------------

    def canonical_read(self, read: GatewayRead, *, expect: Dict[str, str]) -> GatewayRead:
        """Verify one gateway read is bound to THIS context.

        ``expect`` maps binding names to the values this context
        REQUIRES (e.g. provider_ref == context.user_ref).  Every
        required binding must be PRESENT and EXACTLY EQUAL: a
        missing/empty binding on an authenticated canonical
        response is just as fatal as a mismatched one — an
        unbound response is never provably for this principal, so
        it fails closed (BINDING_MISMATCH; resolution DENY — the
        response is never acted on).  An empty expectation value
        is a malformed caller input (INVALID_INPUT, fail closed):
        it can never be satisfied by a present-and-equal binding.
        (P0-1 correction: the previous presence-tolerant form let
        missing principal bindings pass verification.)"""
        for name, required in sorted(expect.items()):
            if not required:
                raise ClientError(
                    ClientReasonCode.INVALID_INPUT,
                    "the %s binding expectation for the canonical %s read "
                    "is empty: a required binding must name the principal "
                    "this context requires (fail closed)"
                    % (name, read.authority),
                )
            actual = read.binding(name)
            if actual != required:
                raise ClientError(
                    ClientReasonCode.BINDING_MISMATCH,
                    "canonical %s read for %r is not bound to this context: "
                    "%s is %r, required %r (a missing, empty, or differing "
                    "required binding fails closed — the response is never "
                    "acted on)"
                    % (read.authority, read.subject, name, actual, required),
                )
        return read

    def project(self, snapshot: StatusSnapshot) -> bool:
        """Apply one status projection to the bounded cache."""
        return self._cache.apply(snapshot)

    # -- capability ---------------------------------------------------------------------

    def adapter_capabilities(self) -> AdapterCapabilitySnapshot:
        """The explicit adapter capability report (the ONLY
        capability source; no platform assumption exists)."""
        return self._adapter.capabilities()

    # -- snapshot / restore (the restart path) ----------------------------------------------

    def snapshot(self) -> Dict[str, Any]:
        """The deterministic local-state snapshot (restart input).

        Contains ONLY client-local state (events, cache, request
        ledger, offline flag) — never canonical authority state.
        Restored state is STALE by construction until reconciled."""
        return {
            "context": {
                "user_ref": self._context.user_ref,
                "device_ref": self._context.device_ref,
                "application_ref": self._context.application_ref,
                "platform_id": self._context.platform_id,
            },
            "events": [event.to_dict() for event in self._journal.events()],
            "cache": self._cache.snapshot(),
            "requests": [
                {
                    "request_id": record.request_id,
                    "mode": record.mode,
                    "action": record.action,
                    "subject": record.subject,
                    "outcome": record.outcome,
                    "resolution": record.resolution,
                    "reason": record.reason,
                    "issued_at": record.issued_at,
                    "outcome_at": record.outcome_at,
                }
                for record in self.request_records()
            ],
            "offline_observed": self._offline_observed,
        }

    def restore(self, data: object) -> None:
        """Restore local state from a snapshot (the restart path).

        The restore is ATOMIC against forgery: every request-ledger
        entry is RE-DERIVED and validated against this context, and
        every restored event's id is verified against its own
        content digest (PR #142 round-2 P1) — BOTH BEFORE any local
        state is loaded (a forged snapshot can neither manufacture
        performed requests nor alter the evidentiary event record,
        and a single unverifiable entry of either kind aborts the
        whole restore — no partial load; the P1-3 correction
        extended by the round-2 event-integrity correction).  The
        restored cache keeps its recorded freshness classes
        (anything recorded as current is
        DEMOTED to STALE_CACHE: restart alone never preserves
        current-truth status).  Canonical truth is only
        re-established by reconciliation."""
        if not isinstance(data, dict):
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "runtime snapshot must be a map",
            )
        # P1-3: the request ledger is validated FIRST (nothing is
        # loaded from a snapshot whose ledger does not fully
        # re-derive)
        requests = data.get("requests", [])
        if not isinstance(requests, list):
            raise ClientError(
                ClientReasonCode.INVALID_INPUT, "snapshot requests must be a list"
            )
        restored_records: list = []
        for entry in requests:
            if not isinstance(entry, dict):
                raise ClientError(
                    ClientReasonCode.INVALID_INPUT,
                    "snapshot request entry must be a map",
                )
            record = RequestRecord(
                request_id=str(entry.get("request_id", "")),
                mode=str(entry.get("mode", "")),
                action=str(entry.get("action", "")),
                subject=str(entry.get("subject", "")),
                outcome=str(entry.get("outcome", "")),
                resolution=str(entry.get("resolution", "")),
                reason=str(entry.get("reason", "")),
                issued_at=str(entry.get("issued_at", "")),
                outcome_at=str(entry.get("outcome_at", "")),
            )
            derived = _derive_request_id(
                record.mode, record.action, record.subject,
                self._context.binding_digest(),
            )
            if record.request_id != derived:
                raise ClientError(
                    ClientReasonCode.INVALID_INPUT,
                    "restored request record %r is unverifiable: its id is "
                    "not the deterministic id derived from (mode=%r, "
                    "action=%r, subject=%r, this context's binding) — the "
                    "forged request-ledger entry is rejected and the "
                    "restore aborts (fail closed)"
                    % (record.request_id, record.mode, record.action,
                       record.subject),
                )
            restored_records.append(record)
        events = data.get("events", [])
        if not isinstance(events, list):
            raise ClientError(
                ClientReasonCode.INVALID_INPUT, "snapshot events must be a list"
            )
        # round-2 P1: every restored event's id is re-derived from
        # its own content and verified HERE (inside _event_from_dict
        # -> ClientEvent.__post_init__) — a tampered id, or tampered
        # content wearing a preserved id, raises before ANY local
        # state loads; the journal never accepts a record whose id
        # does not digest its content
        restored_events = [_event_from_dict(entry) for entry in events]
        cache_data = data.get("cache", {})
        restored = ProjectionCache.restore(cache_data)
        # -- only after full validation does any state load --
        for event in restored_events:
            self._journal.append(event)
        for subject in restored.subjects():
            snapshot = restored.get(subject)
            freshness = snapshot.freshness
            if freshness == Freshness.CANONICAL_STATE:
                freshness = Freshness.STALE_CACHE
            self._cache.apply(
                StatusSnapshot(
                    subject=snapshot.subject,
                    state=snapshot.state,
                    freshness=freshness,
                    observed_at=snapshot.observed_at,
                    canonical_source=snapshot.canonical_source,
                )
            )
        for record in restored_records:
            if record.request_id not in self._requests:
                self._requests[record.request_id] = record
        self._offline_observed = bool(data.get("offline_observed", False))


def _event_from_dict(entry: object) -> ClientEvent:
    if not isinstance(entry, dict):
        raise ClientError(
            ClientReasonCode.INVALID_INPUT, "snapshot event must be a map"
        )
    reason_data = entry.get("canonical_reason")
    reason = (
        ReasonRef(
            code=str(reason_data.get("code", "")),
            source=str(reason_data.get("source", "")),
            severity=str(reason_data.get("severity", "")),
        )
        if isinstance(reason_data, dict)
        else None
    )
    detail_raw = entry.get("detail", [])
    detail = tuple(
        (str(pair[0]), str(pair[1])) for pair in detail_raw
    )
    return ClientEvent(
        kind=str(entry.get("kind", "")),
        taxonomy=str(entry.get("taxonomy", "")),
        subject=str(entry.get("subject", "")),
        observed_at=str(entry.get("observed_at", "")),
        detail=detail,
        canonical_source=str(entry.get("canonical_source", "")),
        canonical_reason=reason,
        event_id=str(entry.get("event_id", "")),
    )
