"""ADCOS mesh/relay adapter family (WORK-023): multi-hop
connectivity behind the frozen ``/adapters`` boundary.

Implements the frozen WORK-023 backlog entry (spec/work-items.md)
behind the frozen ``/adapters`` module boundary
(spec/architecture.md §29): multi-hop connectivity mechanisms --
integration points for 3GPP IAB/sidelink relay and generic
mesh/store-and-forward paths.  Peers: ``adapters.ip`` (WORK-018),
``adapters.fivegc`` (WORK-019), ``adapters.wifi`` (WORK-021),
``adapters.backhaul`` (WORK-022) -- all accepted on this branch.

The boundary (WORK-023 -- the architect-anchored handoff):

    +----------------------------------------------+
    |  ADCOS core (routing/sessions/topology/...)  |
    |        | ordinary Path objects + path refs   |
    |        | sacred session_id (WORK-012)        |
    |        v                                     |
    |  MeshManager  --mediated-->  SandboxedMesh   |
    |        |                          |          |
    |        |                  MeshContract (ABC) |
    |        |                     /        \\     |
    |        |        ReferenceMeshEngine  Sidelink|
    |        |        (ordinary multi-hop) Relay-  |
    |        |                          Engine    |
    |        v                                     |
    |  MeshTechnologyAdapter (WORK-016 bridge)    |
    +----------------------------------------------+

Discipline carried by the whole family:

* **Ordinary Paths.**  Multi-hop routes are ordinary WORK-011
  ``routing.model.Path`` objects; the route identity IS the ordinary
  path fingerprint; the family mints NO parallel mesh-only route
  identity and runs NO second routing authority (it never
  enumerates, scores, or selects paths).
* **Evidence preservation.**  Every hop/reporter contribution
  carries reporter identity and provenance class
  (``HopEvidence``); relay-reported (``remote-claim``) evidence is
  preserved verbatim and NEVER upgraded to self-observed or
  authoritative (the LOCK-008 discipline applied to the forwarding
  path).
* **Configured store-and-forward.**  Bundles queue under explicit
  configured limits (bytes, count, TTL, hop budget); expiry is
  deterministic (injected instants); duplicates/replays are detected
  by content-derived bundle-ref equality and rejected fail closed;
  an expired bundle is NEVER a ghost delivery.
* **Explicit loop prevention.**  The forwarding guard rejects a
  cycle BEFORE any enqueue/forward commit; the rejection is a TOTAL
  no-op (bundle queue, path state, observation counters, manager
  events -- all byte-identical).
* **Session identity independence.**  ``session_id`` is sacred and
  hop/relay/bundle-independent; relay/route/bundle changes mint new
  opaque refs for the SAME session (never a new session identity).
* **IAB/sidelink behind adapters.**  External 3GPP identifiers ride
  the seam as opaque DATA (never parsed, never identity, never
  canonical state); the technology classification is registry DATA;
  no vendor or PHY semantics enter core state.
* **Replaceability.**  ``ReferenceMeshEngine`` and
  ``SidelinkRelayEngine`` are independent implementations behind the
  SAME contract; swapping the default implementation preserves live
  bindings (B2 per-record ownership) and canonical state.

Module catalog (the family surface; later WORK-023 tasks extend
these exports -- never narrow them):

- contract.py      MeshContract ABC (16 operations) + MeshContext
                   least-authority facade + SessionReader/SessionView
- model.py         frozen vocabularies + RelayLinkDescriptor/View,
                   MeshRouteView (ordinary-Path-bound), MeshBinding,
                   HopEvidence, BundleView, ForwardOutcome,
                   MeshAllocation, MeshObservation, MeshEvent +
                   the deterministic derive_* family
- validation.py    opaque-ref grammar, ref/session separation,
                   credential-like rejection, NodeID/path/hop shapes,
                   external-relay-id DATA validation
- errors.py        MeshError/MeshReasonCode/MeshFailure (typed,
                   isolated, secret-free)
- sandbox.py       SandboxedMesh (exception isolation, contract
                   enforcement, deterministic budget) + STEP_CHARGES
- engine.py        ReferenceMeshEngine -- the ordinary multi-hop
                   reference implementation (store-and-forward,
                   loop guard, expiry, duplicates, partition model)
- sidelink.py      SidelinkRelayEngine -- the INDEPENDENT 3GPP
                   IAB/sidelink-seam relay implementation
- session.py       MeshAppSession -- the standard application facade
                   (connect/send/recv/close; NO ADCOS/mesh API)
- manager.py       MeshManager -- the mediated integration service
                   (B2 ownership, canonical state, honest delivery
                   accounting)
- bridge.py        MeshTechnologyAdapter -- the WORK-016 nine-op SDK
                   bridge over the manager
- serialization.py canonical-JSON reduction helpers

Verification: ``python3 tools/mesh_selftest.py`` (the WORK-023
selftest battery: multi-hop construction, evidence preservation,
partition/recovery, queue exhaustion/expiry, duplicate replay,
loop prevention with no-state-change proofs, implementation swap,
IAB/sidelink DATA seam, determinism, frozen-spec identity, and
validate/commit sequence discipline -- failed operations consume
no identity-derivation state).
"""

from __future__ import annotations

from .contract import (
    CONTEXT_SURFACE,
    CONTRACT_OPERATIONS,
    MeshContext,
    MeshContract,
    SessionReader,
    SessionView,
)
from .errors import (
    MESH_PREFIX,
    MeshError,
    MeshFailure,
    MeshReasonCode,
)
from .model import (
    AllocationState,
    BundleState,
    CredentialSlot,
    DEFAULT_STORE_AND_FORWARD_CONFIG,
    EvidenceSourceClass,
    ForwardOutcome,
    ForwardVerdict,
    HopEvidence,
    LinkMetricName,
    MeshAllocation,
    MeshBinding,
    MeshEvent,
    MeshObservation,
    MeshRouteState,
    MeshRouteView,
    RelayLinkDescriptor,
    RelayLinkState,
    RelayTechnology,
    RelayLinkView,
    StoreAndForwardConfig,
    BundleView,
    compute_expiry_instant,
    derive_allocation_ref,
    derive_bearer_ref,
    derive_binding_id,
    derive_bundle_ref,
    derive_integration_id,
    derive_link_ref,
)
from .sandbox import (
    DEFAULT_STEP_BUDGET,
    FAILURE_THRESHOLD_DEGRADED,
    FAILURE_THRESHOLD_FAILED,
    MeshOpResult,
    SandboxedMesh,
    STEP_CHARGES,
)
from .engine import (
    MAX_BUNDLE_BYTES,
    ReferenceMeshEngine,
    STORAGE_KIND_BYTES,
)
from .sidelink import SidelinkRelayEngine
from .session import MeshAppSession
from .manager import DEFAULT_INTEGRATION_ID, MeshManager
from .bridge import MeshTechnologyAdapter
from .serialization import (
    canonical_json_bytes,
    to_canonical_bytes,
    to_canonical_dict,
)
from .validation import (
    assert_ref_session_separation,
    reject_credential_like_text,
    validate_bundle_count,
    validate_credential_slot_name,
    validate_external_relay_id,
    validate_hop_budget,
    validate_hop_id,
    validate_instant,
    validate_link_name,
    validate_node_id,
    validate_opaque_ref,
    validate_path_ref,
    validate_queue_bytes,
    validate_technology,
    validate_ttl_seconds,
)

__all__ = [
    # Contract surface
    "CONTEXT_SURFACE",
    "CONTRACT_OPERATIONS",
    "MeshContext",
    "MeshContract",
    "SessionReader",
    "SessionView",
    # Errors
    "MESH_PREFIX",
    "MeshError",
    "MeshFailure",
    "MeshReasonCode",
    # Model
    "AllocationState",
    "BundleState",
    "CredentialSlot",
    "DEFAULT_STORE_AND_FORWARD_CONFIG",
    "EvidenceSourceClass",
    "ForwardOutcome",
    "ForwardVerdict",
    "HopEvidence",
    "LinkMetricName",
    "MeshAllocation",
    "MeshBinding",
    "MeshEvent",
    "MeshObservation",
    "MeshRouteState",
    "MeshRouteView",
    "RelayLinkDescriptor",
    "RelayLinkState",
    "RelayTechnology",
    "RelayLinkView",
    "StoreAndForwardConfig",
    "BundleView",
    "compute_expiry_instant",
    "derive_allocation_ref",
    "derive_bearer_ref",
    "derive_binding_id",
    "derive_bundle_ref",
    "derive_integration_id",
    "derive_link_ref",
    # Sandbox
    "DEFAULT_STEP_BUDGET",
    "FAILURE_THRESHOLD_DEGRADED",
    "FAILURE_THRESHOLD_FAILED",
    "MeshOpResult",
    "SandboxedMesh",
    "STEP_CHARGES",
    # Implementations
    "MAX_BUNDLE_BYTES",
    "ReferenceMeshEngine",
    "STORAGE_KIND_BYTES",
    "SidelinkRelayEngine",
    # Application facade
    "MeshAppSession",
    # Manager + bridge
    "DEFAULT_INTEGRATION_ID",
    "MeshManager",
    "MeshTechnologyAdapter",
    # Serialization
    "canonical_json_bytes",
    "to_canonical_bytes",
    "to_canonical_dict",
    # Validators
    "assert_ref_session_separation",
    "reject_credential_like_text",
    "validate_bundle_count",
    "validate_credential_slot_name",
    "validate_external_relay_id",
    "validate_hop_budget",
    "validate_hop_id",
    "validate_instant",
    "validate_link_name",
    "validate_node_id",
    "validate_opaque_ref",
    "validate_path_ref",
    "validate_queue_bytes",
    "validate_technology",
    "validate_ttl_seconds",
]
