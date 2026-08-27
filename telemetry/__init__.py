"""ADCOS telemetry / observability package (WORK-026).

Public API:

- frozen vocabularies: :class:`TelemetrySubjectKind` (the six
  measurement subjects), :class:`TelemetrySourceClass` (the frozen
  spec/architecture 6.11 evidence types), :class:`PrivacyClass`,
  :class:`SourceDisclosure` (the promotion-authorization
  source-identity disclosure modes), :class:`ValidityState`,
  :class:`TelemetryEventType`, the standardized per-subject metric
  registry :data:`TELEMETRY_METRIC_REGISTRY`
- canonical records: :class:`TelemetryObservation` (source, time,
  confidence, validity), :class:`TopologyPromotion` (the
  policy-authorized export artifact), :class:`TelemetryEvent` (the
  audit trail), :class:`TelemetryQueryResult`
- deterministic derivations: :func:`derive_observation_id`,
  :func:`derive_promotion_id`, :func:`derive_pseudonym`
- the store: :class:`TelemetryStore` (privacy-fenced queries,
  monotonic ingest, policy-gated topology promotion, explainability)
- the authorization consumption seam:
  :func:`extract_promotion_binding` (verification + extraction ONLY --
  no binding construction exists in this package)

Module authority: ``/telemetry`` owns observations and operational
measurements (LOCK section 3) -- nothing else.  Topology authority
remains WORK-007, resource authority WORK-008, session authority
WORK-012, adapter authority WORK-016, policy authority WORK-010.
Telemetry never mutates another subsystem's state; the only path
toward topology authority is an explicit, policy-authorized promotion
export under a genuine born-bound WORK-010
``telemetry.topology-promote`` ALLOW (deny-by-default: without
policy, telemetry can never become topology authority).
"""

from __future__ import annotations

from .errors import (
    TELEMETRY_PREFIX,
    TelemetryError,
    TelemetryReasonCode,
)
from .model import (
    HEALTH_STATE_ORDINALS,
    MAX_BASIS_POINTS,
    MAX_METRIC_VALUE,
    OBSERVATION_ID_PREFIX,
    PRIVACY_VISIBILITY,
    PROMOTION_ID_PREFIX,
    PSEUDONYM_PREFIX,
    TELEMETRY_METRIC_REGISTRY,
    PrivacyClass,
    SourceDisclosure,
    TelemetryEvent,
    TelemetryEventType,
    TelemetryMetric,
    TelemetryObservation,
    TelemetryQueryResult,
    TelemetrySourceClass,
    TelemetrySubjectKind,
    TopologyPromotion,
    ValidityState,
    derive_observation_id,
    derive_promotion_id,
    derive_pseudonym,
    metric_is_basis_point,
    metric_max_value,
)
from .authorization import (
    PROMOTION_BINDING_CONSUMER_KIND,
    TELEMETRY_PROMOTION_OPERATION,
    PromotionBinding,
    decision_is_tamper_evident,
    extract_promotion_binding,
)
from .store import TelemetryStore
from .validation import (
    reject_credential_like_text,
    validate_confidence_basis_points,
    validate_metric_for_subject,
    validate_metric_value,
    validate_privacy_scope,
    validate_purpose,
    validate_source_class,
    validate_source_disclosure,
    validate_subject_kind,
    validate_subject_ref,
)

__all__ = [
    # Prefixes / scales
    "TELEMETRY_PREFIX",
    "OBSERVATION_ID_PREFIX",
    "PROMOTION_ID_PREFIX",
    "PSEUDONYM_PREFIX",
    "MAX_BASIS_POINTS",
    "MAX_METRIC_VALUE",
    # Frozen vocabularies
    "TelemetrySubjectKind",
    "TelemetrySourceClass",
    "PrivacyClass",
    "SourceDisclosure",
    "PRIVACY_VISIBILITY",
    "ValidityState",
    "TelemetryEventType",
    "TelemetryMetric",
    "TELEMETRY_METRIC_REGISTRY",
    "HEALTH_STATE_ORDINALS",
    # Canonical records
    "TelemetryObservation",
    "TelemetryEvent",
    "TopologyPromotion",
    "TelemetryQueryResult",
    # Deterministic derivations
    "derive_observation_id",
    "derive_promotion_id",
    "derive_pseudonym",
    "metric_is_basis_point",
    "metric_max_value",
    # Authorization consumption seam (verification + extraction ONLY)
    "TELEMETRY_PROMOTION_OPERATION",
    "PROMOTION_BINDING_CONSUMER_KIND",
    "PromotionBinding",
    "decision_is_tamper_evident",
    "extract_promotion_binding",
    # The store
    "TelemetryStore",
    # Validators
    "reject_credential_like_text",
    "validate_subject_kind",
    "validate_source_class",
    "validate_metric_for_subject",
    "validate_metric_value",
    "validate_confidence_basis_points",
    "validate_subject_ref",
    "validate_privacy_scope",
    "validate_source_disclosure",
    "validate_purpose",
    # Errors
    "TelemetryError",
    "TelemetryReasonCode",
]
