"""WORK-049 privacy-bounded presentation (the frozen privacy model).

The client must not retain or expose more information than
necessary (docs/WORK-049-handoff.md):

- no unnecessary exact provider/buyer location (the bounded
  coverage CELL from the canonical marketplace proximity contract
  is the ONLY location representation the client ever carries;
  exact coordinates cannot even be represented);
- no raw payment credentials (payment appears, at most, as
  capability DATA and canonical price terms);
- no unnecessary KYC data (KYC references belong to W045 and are
  never projected into client presentation);
- no sensitive provider metadata simply because it is available
  upstream.

The presentation gate is fail-closed: a payload carrying a
forbidden sensitive field is REJECTED (typed PRIVACY_DENIED),
never silently redacted-and-kept.  No secrets transit events,
logs, or presentations (LOCK-022/LOCK-023 discipline: exception
class names only, never values).
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, Mapping, Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import ClientError, ClientReasonCode
from .model import ConsentFacts, OfferView, ReasonRef

import hashlib

#: Sensitive FIELD-name fragments forbidden anywhere in client
#: presentation payloads, event details, or logged maps (fail
#: closed on match — the fragment list is DATA, not authority).
SENSITIVE_FIELD_FRAGMENTS: Tuple[str, ...] = (
    "payment_credential",
    "card_number",
    "card_cvv",
    "card_expiry",
    "payment_secret",
    "payment_token",
    "secret",
    "password",
    "credential",
    "private_key",
    "access_token",
    "refresh_token",
    "kyc_document",
    "kyc_reference",
    "exact_location",
    "latitude",
    "longitude",
    "lat_lng",
    "gps",
    "identity_document",
)


def privacy_scan(payload: Mapping[str, Any]) -> str:
    """Scan one flat string-keyed payload for sensitive fields.

    Returns the FIRST forbidden key found (deterministic: sorted
    key order), or ``""`` when the payload is clean.  Nested
    maps are scanned recursively (sorted order at every level).
    """
    for key in sorted(payload):
        value = payload[key]
        lowered = key.lower()
        for fragment in SENSITIVE_FIELD_FRAGMENTS:
            if fragment in lowered:
                return key
        if isinstance(value, Mapping):
            found = privacy_scan(value)
            if found:
                return "%s.%s" % (key, found)
    return ""


def privacy_gate(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    """The fail-closed presentation gate.

    Raises :class:`ClientError` (PRIVACY_DENIED) when the payload
    carries a forbidden sensitive field; otherwise returns the
    payload unchanged (bounded fields are the CALLER's
    responsibility — the gate is the sensitive-field floor, the
    bounded record constructors are the ceiling).
    """
    found = privacy_scan(payload)
    if found:
        raise ClientError(
            ClientReasonCode.PRIVACY_DENIED,
            "presentation payload carries the forbidden sensitive field "
            "%r (fail closed; never redacted-and-kept)" % found,
        )
    return payload


def present_reason(reason: ReasonRef) -> Dict[str, str]:
    """Present one canonical reason (preserving it verbatim).

    The presentation may add human wording, but the canonical
    code, the canonical severity/meaning, and the machine-readable
    source are preserved EXACTLY (UI wording is not authority)."""
    if not isinstance(reason, ReasonRef):
        raise ClientError(
            ClientReasonCode.INVALID_INPUT,
            "present_reason requires a canonical ReasonRef",
        )
    return {
        "canonical_code": reason.code,
        "canonical_source": reason.source,
        "canonical_severity": reason.severity,
        "presentation": "canonical reason %s from %s" % (reason.code, reason.source),
    }


def present_offer(
    *,
    offer_id: str,
    provider_id: str,
    currency: str,
    price_minor: int,
    billing_mode: str,
    metered: bool,
    access_type: str,
    latency_ms: int,
    throughput_kbps: int,
    coverage_cell: str,
) -> OfferView:
    """Build the privacy-bounded presentation of one discovered offer.

    ``coverage_cell`` is the canonical bounded proximity
    representation (the marketplace LocationBound's cell token) —
    the ONLY location dimension the client ever presents; exact
    coordinates are not representable in this surface.
    """
    view = OfferView(
        offer_id=offer_id,
        provider_id=provider_id,
        currency=currency,
        price_minor=price_minor,
        billing_mode=billing_mode,
        metered=metered,
        access_type=access_type,
        latency_ms=latency_ms,
        throughput_kbps=throughput_kbps,
        coverage_cell=coverage_cell,
        facts_digest="sha256:" + hashlib.sha256(
            canonical_json_bytes(
                {
                    "offer_id": offer_id,
                    "provider_id": provider_id,
                    "currency": currency,
                    "price_minor": price_minor,
                    "billing_mode": billing_mode,
                    "metered": metered,
                    "access_type": access_type,
                    "latency_ms": latency_ms,
                    "throughput_kbps": throughput_kbps,
                    "coverage_cell": coverage_cell,
                }
            )
        ).hexdigest(),
    )
    return view


def present_consent_facts(
    *,
    exposed_egress: Iterable[str],
    time_quota_expiry: str,
    buyer_ref: str,
    quota_bytes: int,
    max_concurrent_buyers: int,
    commercial_terms: str,
    canonical_state: str,
    canonical_source_refs: Iterable[str] = (),
) -> ConsentFacts:
    """Build the frozen provider-consent presentation record.

    Every dimension of the frozen consent presentation is filled
    from canonical citations (W048 scope, W051 commercial terms)
    or the fixed privacy implications text; the immediate stop
    control is ALWAYS exposed; ``current_actual_state`` is the
    canonical state string (never the local projection)."""
    return ConsentFacts(
        what_is_shared=tuple(sorted(set(exposed_egress))),
        duration_until=time_quota_expiry,
        buyer_scope=(buyer_ref,),
        quota_bytes=quota_bytes,
        max_concurrent_buyers=max_concurrent_buyers,
        expected_economic_result=commercial_terms,
        privacy_implications=(
            "sharing is presented with bounded coverage cells only; no "
            "exact location, no payment credentials, and no KYC material "
            "is stored or displayed by the client"
        ),
        immediate_stop_control=True,
        current_actual_state=canonical_state,
        canonical_source_refs=tuple(canonical_source_refs),
    )
