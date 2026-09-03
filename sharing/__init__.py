"""WORK-048 provider sharing runtime package.

The provider-side connectivity sharing runtime (issue #92),
implemented under the WORK-048-CORE-001 authorization (DEC-0073,
baseline reconciled by DEC-0074) with the containment authority
frozen by DEC-0072 / ACR-012.

W048 is a LOCAL ENFORCEMENT MECHANISM.  It composes the canonical
authorities and owns none of them:

- /identity     — NodeID and credential references (never minted)
- /session      — logical session identity (referenced, never created)
- /routing      — path computation/selection (referenced, never duplicated)
- /transport    — secure transport mappings (tunnel configured to the
                  leased egress, never reimplemented)
- W041          — NetworkPath lifecycle authority (driven through its
                  public machinery; never bypassed, never duplicated)
- W051          — CommercialCore Lease authority (read-only truth)
- W052/W042     — UsageLedger canonical usage journal (idempotent
                  evidence emission INTO it; never a second ledger)
- ACR-012       — the containment authority (``containment/``):
                  one ContainmentBoundary per sharing session

The central frozen invariant (ACR-012):

    NO PROVEN CONTAINMENT  =>  NO BUYER TRAFFIC

and the fail-closed admission chain:

    lease inactive OR consent absent/revoked OR NetworkPath not
    valid/active OR quota exhausted OR isolation unavailable OR
    containment proof invalid
        =>
    NO NEW BUYER TRAFFIC

The sharing-session lifecycle and the containment boundary
lifecycle are DISTINCT state machines that coordinate without
merging.  All evidence produced by this family is SOFTWARE-class;
physical containment claims remain OPEN until physically
demonstrated (W040's obligations stay W040-owned).

Public surface (the frozen API of this family):
"""

from __future__ import annotations

from .consent import ConsentRegistry
from .errors import SharingError, SharingReasonCode
from .lifecycle import (
    LEASE_DELIVERY_ACTIVE_STATES,
    SHARING_RUNTIME_SOURCE,
    SharingRuntime,
)
from .model import (
    ConsentTransition,
    ProviderConsent,
    SharingEvent,
    SharingScope,
    SharingSession,
    UsageEmission,
    derive_consent_id,
    derive_sharing_session_id,
    derive_usage_correlation_id,
    sharing_event_list_digest,
)
from .quota import ProviderEnvelope, QuotaLedger
from .state import (
    CONSENT_TRANSITIONS,
    SHARING_TRANSITIONS,
    ConsentState,
    SharingAction,
    SharingSessionState,
    transition_is_legal,
)
from .timeutil import (
    epoch_seconds,
    instant_from_epoch,
    instant_is_after,
    instant_plus_seconds,
)
from .usage import (
    BYTE_UNIT,
    SHARING_USAGE_ACTOR,
    SHARING_USAGE_SOURCE,
    build_usage_evidence_index,
    emit_usage_evidence,
)

__all__ = [
    "BYTE_UNIT",
    "CONSENT_TRANSITIONS",
    "ConsentRegistry",
    "ConsentState",
    "ConsentTransition",
    "LEASE_DELIVERY_ACTIVE_STATES",
    "ProviderConsent",
    "ProviderEnvelope",
    "SHARING_RUNTIME_SOURCE",
    "SHARING_TRANSITIONS",
    "SHARING_USAGE_ACTOR",
    "SHARING_USAGE_SOURCE",
    "SharingAction",
    "SharingError",
    "SharingEvent",
    "SharingReasonCode",
    "SharingRuntime",
    "SharingScope",
    "SharingSession",
    "SharingSessionState",
    "UsageEmission",
    "build_usage_evidence_index",
    "derive_consent_id",
    "derive_sharing_session_id",
    "derive_usage_correlation_id",
    "emit_usage_evidence",
    "epoch_seconds",
    "instant_from_epoch",
    "instant_is_after",
    "instant_plus_seconds",
    "sharing_event_list_digest",
    "transition_is_legal",
]
