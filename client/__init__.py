"""WORK-049 Provider & Buyer Connectivity Client Runtime package.

The end-user PARTICIPATION boundary (issue #98), implemented under
the WORK-049-CORE-001 authorization (DEC-0076, baseline reconciled
by DEC-0077).  W049 is a CLIENT/CONSUMER/ORCHESTRATOR/PROJECTION
BOUNDARY — NOT a new authority:

    CLIENT INTENT / CONSENT / PROJECTION
                    ↓
    CANONICAL ADCOS AUTHORITIES
                    ↓
    LOCAL CLIENT ENFORCEMENT / PRESENTATION

Every canonical truth and enforcement stays with its existing
owner:

- /identity     — NodeID and credential references (held/
                  referenced/displayed; NEVER minted; no
                  credential-validity/revocation authority)
- /sessions     — logical session identity (referenced; never a
                  parallel session authority)
- W041 (networkpath/) — path validation/activation/handover/
                  retirement authority (requested/handed off,
                  never reimplemented; NO ClientLocalPath/
                  ClientRoute/ClientPreferredRoute/
                  ClientActivatedPath networking authority)
- /routing      — path computation/selection (never duplicated;
                  no client routing algorithm, no authoritative
                  route cache, no forwarding)
- /transport    — secure transport mappings (invoked through
                  public contracts; no bespoke tunnel protocol)
- W051 (commercial/) — price/lease/quota/duration/authorization/
                  expiry/revocation truth (read-only projection;
                  no local billing ledger, no shadow lease, no
                  payment-succeeded-therefore-connected shortcut)
- W042 (usage/) — the canonical usage journal (surfaced; client
                  observations only where the public contract
                  requires; never an alternate ledger)
- W047 (marketplace/) — discovery/proximity/candidate selection
                  (the ONLY source of presentable offers; never
                  a client marketplace; stale telemetry never
                  becomes current reachability)
- W048 (sharing/ + containment/) — provider-side sharing
                  enforcement and the ACR-012 containment
                  authority; provider-mode W049 is a client/
                  controller for consent, configuration, status,
                  stop/revoke controls, presentation, and handoff
                  and NEVER recreates containment, isolation,
                  quota, or provider-traffic enforcement:

      NO PROVEN CONTAINMENT  =>  NO BUYER TRAFFIC

- W046 (developerapi/) — the developer/application boundary the
                  client may sit behind or delegate into (never a
                  duplication of its business authority)
- /adapters     — platform mechanisms (isolated behind the W049
                  platform-adapter boundary; the platform-neutral
                  client core imports no OS/SDK-specific
                  implementation)
- /policy, /telemetry — composed; evaluation and observations
                  remain theirs
- W045 / W050   — eligibility where applicable; W050's capability
                  matrix is ADVISORY capability input, NOT a gate

Frozen client rules implemented by this package: the provider and
buyer client lifecycles (client-local projections only — a local
ACTIVE is never proof that connectivity exists; a local
LEASE_CONFIRMED requires canonical commercial confirmation);
explicit/attributable/revocable/fail-closed provider consent with
the frozen presentation dimensions; the ACR-012 capability
vocabulary (reused from the containment authority) with
fail-closed semantics; the platform-adapter boundary; the
offline/reconnect semantics (CANONICAL STATE / LOCAL
OBSERVATION / LOCAL INTENT / STALE CACHE / UNKNOWN; never
fabricated truth; resume only if canonical authority permits);
the emergency-stop control (REQUEST STOP / ENFORCE LOCAL SAFETY
-> canonical termination -> W048 enforcement -> traffic
termination); the privacy model (bounded coverage cells, no raw
payment credentials, no unnecessary KYC); the event taxonomy
(OBSERVED_CANONICAL_EVENT / LOCAL_UI_EVENT / LOCAL_REQUEST_EVENT
/ LOCAL_FAILURE — never promoted to canonical domain events);
canonical reason-code preservation (UI wording is not authority);
the security invariants (idempotent mutating requests, no stale
overwrite, no revoked/expired resurrection, context-bound
authenticated reads, bounded marked cache, secrets through the
platform secure-storage boundary, no credential logging); and
the fail-closed rule (unresolved ambiguity that could produce
unauthorized connectivity resolves to DENY/STOP/UNKNOWN).

All sandbox/client simulations are SOFTWARE-class evidence only;
real platform behavior on physical Android/desktop/router-class
devices is PHYSICAL-class, separately governed, and W040's
physical obligations remain W040-owned and untouched.

Public surface (the frozen API of this family):
"""

from __future__ import annotations

from .adapters import (
    AdapterResult,
    LIFECYCLE_PHASES,
    LOCAL_PERMISSIONS,
    PlatformAdapter,
    require_adapter,
)
from .capability import (
    CAPABILITY_FAIL_CLOSED,
    CAPABILITY_VALUES,
    AdapterCapabilitySnapshot,
    CapabilityDecision,
    CapabilityGateResult,
    evaluate_capability,
)
from .errors import (
    ClientError,
    ClientReasonCode,
    FailClosedResolution,
)
from .events import (
    EVENT_KINDS,
    ClientEvent,
    ClientEventJournal,
    EventTaxonomy,
)
from .gateway import (
    GATEWAY_AUTHORITIES,
    CanonicalGateway,
    ComposedGateway,
    GatewayRead,
)
from .model import (
    ClientContext,
    ConsentFacts,
    OfferView,
    ReasonRef,
    RequestRecord,
    StatusSnapshot,
)
from .privacy import (
    SENSITIVE_FIELD_FRAGMENTS,
    present_consent_facts,
    present_offer,
    present_reason,
    privacy_gate,
    privacy_scan,
)
from .projection import (
    Freshness,
    ProjectionCache,
    ReconciliationReport,
)
from .provider import ProviderClient
from .buyer import BuyerClient
from .runtime import ClientRuntime
from .sandbox import SandboxPlatformAdapter
from .state import (
    BUYER_CLIENT_TRANSITIONS,
    PROVIDER_CLIENT_TRANSITIONS,
    BuyerClientState,
    ProviderClientState,
    transition_is_legal,
)

__all__ = [
    # adapter boundary
    "AdapterResult",
    "LIFECYCLE_PHASES",
    "LOCAL_PERMISSIONS",
    "PlatformAdapter",
    "require_adapter",
    # capability model (ACR-012 vocabulary reused)
    "CAPABILITY_FAIL_CLOSED",
    "CAPABILITY_VALUES",
    "AdapterCapabilitySnapshot",
    "CapabilityDecision",
    "CapabilityGateResult",
    "evaluate_capability",
    # typed errors + the frozen fail-closed resolution
    "ClientError",
    "ClientReasonCode",
    "FailClosedResolution",
    # event taxonomy + journal
    "EVENT_KINDS",
    "ClientEvent",
    "ClientEventJournal",
    "EventTaxonomy",
    # the canonical read window
    "GATEWAY_AUTHORITIES",
    "CanonicalGateway",
    "ComposedGateway",
    "GatewayRead",
    # shared records
    "ClientContext",
    "ConsentFacts",
    "OfferView",
    "ReasonRef",
    "RequestRecord",
    "StatusSnapshot",
    # privacy-bounded presentation
    "SENSITIVE_FIELD_FRAGMENTS",
    "present_consent_facts",
    "present_offer",
    "present_reason",
    "privacy_gate",
    "privacy_scan",
    # projection + freshness + reconcile
    "Freshness",
    "ProjectionCache",
    "ReconciliationReport",
    # the two client modes + the neutral runtime core
    "ProviderClient",
    "BuyerClient",
    "ClientRuntime",
    # the deterministic sandbox adapter (SOFTWARE evidence only)
    "SandboxPlatformAdapter",
    # the frozen client lifecycles
    "BUYER_CLIENT_TRANSITIONS",
    "PROVIDER_CLIENT_TRANSITIONS",
    "BuyerClientState",
    "ProviderClientState",
    "transition_is_legal",
]
