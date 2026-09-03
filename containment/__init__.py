"""WORK-048 containment authority package (ACR-012 — binding).

The first-class Buyer-Traffic Containment Boundary authority
frozen by ACR-012 (accepted as DEC-0072), implemented under the
WORK-048-CORE-001 authorization (DEC-0073, baseline reconciled by
DEC-0074).  The frozen invariant this package enforces:

    NO PROVEN CONTAINMENT  =>  NO BUYER TRAFFIC

Authority ownership (ACR-012 §1/§2 — frozen): this package owns
buyer-traffic admission into the isolated provider boundary, the
containment capability dimension, the boundary lifecycle, control-
plane/buyer-plane separation, deny-by-default reachability,
fail-closed transitions, isolation establishment/verification,
teardown/revocation, and containment proof records.  It owns
NOTHING else: identity, logical session identity, routing,
NetworkPath lifecycle, transport semantics, lease truth, usage
truth, payment custody, marketplace ranking, and plaintext
payload semantics all remain with their frozen owners (referenced,
never duplicated).

Platform primitives (netns/nftables, VRF, VpnService, Network
Extension) implement the neutral :class:`IsolationPrimitive`
contract behind the ``/adapters`` boundary; this package imports
no platform SDK and no vendor type.  The deterministic software
sandbox (:class:`SandboxedIsolationPrimitive`) is SOFTWARE-class
evidence only — physical containment claims remain OPEN until
physically demonstrated (the evidence-class honesty disclosure).

Public surface (the frozen API of this family):
"""

from __future__ import annotations

from .capability import CapabilityMatrix, PlatformCapability
from .errors import ContainmentError, ContainmentReasonCode
from .isolation import (
    DenyProbe,
    IsolationPrimitive,
    PrimitiveFailure,
    ReachabilityDecision,
    ScopeEstablishment,
    ScopeSpec,
    TeardownResult,
    VerificationProof,
)
from .lifecycle import (
    AdmissionDecision,
    AdmissionFacts,
    ContainmentAuthority,
)
from .model import (
    BoundaryEvent,
    ContainmentBoundary,
    ContainmentProof,
    SecurityEvidence,
    boundary_event_list_digest,
    derive_boundary_event_id,
)
from .sandbox import SandboxedIsolationPrimitive
from .state import (
    ACTION_REQUIRED_STATE,
    BOUNDARY_TRANSITIONS,
    BoundaryAction,
    BoundaryState,
    CapabilityState,
    ISOLATION_MECHANISMS,
    transition_is_legal,
)

__all__ = [
    "AdmissionDecision",
    "AdmissionFacts",
    "BOUNDARY_TRANSITIONS",
    "BoundaryAction",
    "BoundaryEvent",
    "BoundaryState",
    "CapabilityMatrix",
    "CapabilityState",
    "ContainmentAuthority",
    "ContainmentBoundary",
    "ContainmentError",
    "ContainmentProof",
    "ContainmentReasonCode",
    "DenyProbe",
    "ISOLATION_MECHANISMS",
    "IsolationPrimitive",
    "PlatformCapability",
    "PrimitiveFailure",
    "ReachabilityDecision",
    "SandboxedIsolationPrimitive",
    "ScopeEstablishment",
    "ScopeSpec",
    "SecurityEvidence",
    "TeardownResult",
    "VerificationProof",
    "ACTION_REQUIRED_STATE",
    "boundary_event_list_digest",
    "derive_boundary_event_id",
    "transition_is_legal",
]
