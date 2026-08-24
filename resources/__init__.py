"""ADCOS resources package -- WORK-008: resource model and measurements.

Implements a technology-neutral resource model with the central boundary:

    RESOURCE OFFER        !=  MEASURED OBSERVATION
                          !=  ACCOUNTING STATE
                          !=  ADMISSION DECISION   (out of scope -- WORK-010)
                          !=  ROUTING/PREFERENCE   (out of scope -- WORK-011)
                          !=  PRICE/SETTLEMENT     (out of scope -- forbidden)

A provider may OFFER 100 Mbps while a measurement currently OBSERVES 63 Mbps.
Those are different objects with different provenance, validity, and authority.
A measurement MUST NOT mutate an offer. An offer MUST NOT imply the resource
is currently available. Accounting MUST NOT become settlement. Resource state
MUST NOT become route preference (WORK-008 acceptance criterion: resource
offers are separable from measured observations).

The most important adversarial invariant (mirrors WORK-007 LOCK-008):

    Node A relays a measurement about resource R owned by O  -->  stored as
    source_node_id=A, source_class=REMOTE_RELAY  -->  NEVER becomes O's
    self-observation of R. ``get_authoritative_measurements`` returns ONLY
    self-observations (source == owner AND SELF_OBSERVATION), so a remote
    relay can never enter the authoritative set. Likewise, an offer's
    ``provider_node_id`` MUST equal the resource's owner (a provider only
    offers its own resource); a relayed offer is rejected at ``create_offer``.

Resource-core logic never branches on 5G, Wi-Fi, LTE, 6G, satellite, or
vendor names (LOCK-001/002/003). Resource identifiers are stable and
independent of volatile measurement samples (rule 3). Resource kinds are the
frozen section 17 closed core set with open-world additive evolution (rule 4).
Quantities carry explicit units; the unit registry rejects unknown/
incompatible units (rule 5); authoritative accounting uses integer base-unit
math -- no floating point (rule 5). Validity/expiry and freshness are
first-class and evaluated against an injected timezone-aware instant (rule 6).
Provenance is first-class for measurements (rule 7). Resource availability !=
topology reachability -- a resource observation never mutates WORK-007
ReachabilityState or LinkState (rule 8). Accounting is deterministic, local,
and fail-closed (rule 9). Reservation != policy/admission (rule 10). Energy
is a resource state, not a policy (rule 11). Measurement uncertainty is
preserved, never hidden (rule 12). A signed offer is still a claim; a
measured observation is still evidence (rule 13). Future access/profile
identifiers remain data (rule 14). Standards are leveraged as design
references, not imported wholesale (rule 15, RFC 9232/8194/8428/9439,
LOCK-018).

No settlement, pricing, intent normalization, policy/authorization/admission,
path computation/route selection, logical sessions, concrete access adapters,
telemetry transport, persistent production database, UI, trust scoring,
resource "winner" election, or capacity inference from a remote topology
claim is implemented here. No second NodeID, capability, evidence, envelope,
or unit vocabulary is introduced -- resource-core reuses WORK-004
``parse_node_id``, WORK-003 ``parse_instant`` / ``canonical_json_bytes``, and
the frozen WORK-002 resource kind / availability enum.
"""

from __future__ import annotations

from .ingest import (
    ingest_provider_offer,
    measurement_from_observation,
    offer_from_provider_claim,
    record_observation,
)
from .model import (
    AccountingOutcome,
    AvailabilityMode,
    EnergyState,
    MeasurementSource,
    MergeOutcome,
    ParsedResourceId,
    Quantity,
    Resource,
    ResourceAccount,
    ResourceError,
    ResourceKind,
    ResourceMeasurement,
    ResourceOffer,
    ResourceStore,
    make_resource_id,
    measurement_from_mapping,
    offer_from_mapping,
    parse_resource_id,
    power_unit_base,
    power_unit_multiplier,
    unit_base_for,
    unit_multiplier_for,
)

__all__ = [
    "AccountingOutcome",
    "AvailabilityMode",
    "EnergyState",
    "MeasurementSource",
    "MergeOutcome",
    "ParsedResourceId",
    "Quantity",
    "Resource",
    "ResourceAccount",
    "ResourceError",
    "ResourceKind",
    "ResourceMeasurement",
    "ResourceOffer",
    "ResourceStore",
    "ingest_provider_offer",
    "make_resource_id",
    "measurement_from_mapping",
    "measurement_from_observation",
    "offer_from_mapping",
    "offer_from_provider_claim",
    "parse_resource_id",
    "power_unit_base",
    "power_unit_multiplier",
    "record_observation",
    "unit_base_for",
    "unit_multiplier_for",
]
