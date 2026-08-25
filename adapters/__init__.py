"""ADCOS adapters package (WORK-016): the generic Adapter SDK/runtime.

Implements the frozen adapter contract (spec/architecture.md sections
6.3 and 10.1) behind the frozen ``/adapters`` module boundary
(spec/architecture.md section 29):

- :class:`AdapterContract` -- the stable section 10.1 interface every
  adapter implementation satisfies (open / capabilities / observe /
  allocate / release / bind_session / unbind_session / health / close);
- :class:`AdapterContext` -- the least-authority facade handed to
  implementations (ids, injected instant, deterministic step budget;
  nothing else);
- :class:`GenericAdapter` -- the built-in generic adapter for
  experimental technologies (section 10.5);
- :class:`SandboxedAdapter` -- the failure-isolation mediator
  (exception isolation, contract enforcement, deterministic budget);
- :class:`AdapterRuntime` -- the Agent's Adapter Runtime service
  (registration, lifecycle supervision, capability exposure, the
  adapter-scoped resource ledger, read-only WORK-012 session binding,
  deterministic event history);
- :class:`AdapterDescriptor` and friends -- the typed section 6.3
  MUST-expose surface;
- serialization helpers producing the frozen Adapter wire object of
  ``spec/schemas/adapter.schema.json`` and WORK-003 envelope wrapping.

Module authority: ``/adapters`` owns the generic contract and runtime
for the technology boundary.  It does NOT own node identity (WORK-004),
capability statements/negotiation (WORK-005), fabric resource
accounting (WORK-008), session lifecycle (WORK-012), topology truth
(WORK-007), policy (WORK-010), transport (WORK-017), or any concrete
access technology (WORK-019..WORK-022, WORK-038).  Adapter identity is
distinct from NodeID by grammar.  Adapter failures are isolated values,
never exceptions crossing into core callers.  The core never imports
adapter implementations and never branches on technology names
(LOCK-001..003, LOCK-016, LOCK-017).

Dependencies (declared, Architect-accepted): WORK-003 (envelope/
canonical JSON/instants), WORK-005 (capability-id classification,
read-only), WORK-012 (SessionStore, read-only binding verification).
The resource mapping additionally uses the WORK-008 unit tables
read-only (a transitive ancestor of WORK-012) so mapped quantities are
expressed in the canonical resource model rather than a duplicate
vocabulary.
"""

from __future__ import annotations

from .contract import (
    CONTEXT_SURFACE,
    CONTRACT_OPERATIONS,
    AdapterContext,
    AdapterContract,
    GenericAdapter,
)
from .errors import ADAPTER_PREFIX, AdapterError, AdapterReasonCode
from .model import (
    AdapterDescriptor,
    AdapterEventType,
    AdapterLifecycle,
    AdapterSecurityState,
    Allocation,
    AllocationState,
    BindingState,
    HealthReport,
    HealthState,
    LinkMetricName,
    LinkMetricsSample,
    LIFECYCLE_TRANSITIONS,
    ParsedAdapterId,
    ResourceMappingEntry,
    SessionBearerBinding,
    derive_adapter_id,
    derive_allocation_id,
    derive_binding_id,
    derive_event_id,
    lifecycle_transition_is_legal,
    parse_adapter_id,
)
from .runtime import BINDABLE_SESSION_STATES, AdapterOpResult, AdapterRuntime
from .sandbox import (
    DEFAULT_STEP_BUDGET,
    FAILURE_THRESHOLD_DEGRADED,
    FAILURE_THRESHOLD_FAILED,
    AdapterFailure,
    OperationOutcome,
    SandboxedAdapter,
)
from .serialization import (
    ADAPTER_STATE_EXTENSION_KEY,
    REQUIRED_ADAPTER_MEMBERS,
    adapter_state_from_envelope,
    adapter_state_to_envelope,
    adapter_view,
    adapter_view_canonical_bytes,
    adapter_view_from_mapping,
    descriptor_from_mapping,
)
from .validation import (
    AccessTechnologyClass,
    classify_access_technology_id,
    known_access_technology_ids,
    validate_access_technology_id,
    validate_adapter_id,
    validate_capability_references,
    validate_profile_versions,
    validate_resource_mapping_entries,
)

__all__ = [
    # Contract (frozen section 10.1 surface)
    "AdapterContract",
    "AdapterContext",
    "GenericAdapter",
    "CONTRACT_OPERATIONS",
    "CONTEXT_SURFACE",
    # Sandbox / failure isolation
    "SandboxedAdapter",
    "AdapterFailure",
    "OperationOutcome",
    "DEFAULT_STEP_BUDGET",
    "FAILURE_THRESHOLD_DEGRADED",
    "FAILURE_THRESHOLD_FAILED",
    # Runtime
    "AdapterRuntime",
    "AdapterOpResult",
    "BINDABLE_SESSION_STATES",
    # Domain objects
    "AdapterDescriptor",
    "AdapterSecurityState",
    "AdapterEventType",
    "AdapterLifecycle",
    "Allocation",
    "SessionBearerBinding",
    "ResourceMappingEntry",
    "LinkMetricsSample",
    "LinkMetricName",
    "HealthReport",
    "HealthState",
    "LIFECYCLE_TRANSITIONS",
    "lifecycle_transition_is_legal",
    "ParsedAdapterId",
    "AllocationState",
    "BindingState",
    # Identity
    "ADAPTER_PREFIX",
    "derive_adapter_id",
    "parse_adapter_id",
    "derive_allocation_id",
    "derive_binding_id",
    "derive_event_id",
    # Errors
    "AdapterError",
    "AdapterReasonCode",
    # Serialization
    "descriptor_from_mapping",
    "adapter_view",
    "adapter_view_from_mapping",
    "adapter_view_canonical_bytes",
    "adapter_state_to_envelope",
    "adapter_state_from_envelope",
    "ADAPTER_STATE_EXTENSION_KEY",
    "REQUIRED_ADAPTER_MEMBERS",
    # Validation / classification
    "AccessTechnologyClass",
    "classify_access_technology_id",
    "known_access_technology_ids",
    "validate_access_technology_id",
    "validate_adapter_id",
    "validate_capability_references",
    "validate_profile_versions",
    "validate_resource_mapping_entries",
]
