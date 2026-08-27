"""ADCOS telemetry / observability fail-closed validation (WORK-026).

Structural validators for the frozen vocabularies and record shapes:
subject kinds, source classes (the frozen §6.11 evidence types),
standardized metrics (per-subject closed registry with fixed units),
integer basis-point confidence, opaque reference text, and the
privacy-gated context channel.  Every validator fails closed with a
code from the frozen :class:`~telemetry.errors.TelemetryReasonCode`
vocabulary.

Credential-like content is rejected in EVERY free-text field
(LOCK-023: secrets never become telemetry DATA), mirroring the
WORK-016..025 family discipline.
"""

from __future__ import annotations

import re
from typing import Tuple

from .errors import TelemetryError, TelemetryReasonCode
from .model import (
    MAX_BASIS_POINTS,
    MAX_METRIC_VALUE,
    PRIVACY_VISIBILITY,
    PrivacyClass,
    SourceDisclosure,
    TelemetrySubjectKind,
    TelemetrySourceClass,
    TELEMETRY_METRIC_REGISTRY,
    metric_is_basis_point,
    metric_max_value,
)

#: Forbidden credential-like tokens (LOCK-023) -- the house vocabulary
#: mirrored from the sibling families (services/backhaul/mesh/...).
_CREDENTIAL_LIKE_FORBIDDEN = (
    "private_key", "secret_key", "password", "passphrase", "token",
    "api_key", "shared_secret", "community_string", "psk",
    "pre_shared_key", "preshared", "sim_pin", "session_key",
    "credential_value", "client_secret", "access_key", "signing_key",
    "hmac_key", "master_key", "root_password", "mgmt_secret",
    "telemetry_secret", "observation_secret",
)

_SEPARATOR_RUN = re.compile(r"[\s_.\-]+")

#: Context keys that carry location-bearing content (spec/architecture
#: §20: location disclosure is capability/policy controlled and never
#: required merely because a node participates) -- such context may
#: ride ONLY restricted observations.
_LOCATION_CONTEXT_KEYS = ("location", "geo", "position")


def _normalized(text: str) -> str:
    return _SEPARATOR_RUN.sub("-", text.strip().lower())


def reject_credential_like_text(value: object, *, label: str = "text") -> str:
    """Validate free text and reject credential-like content.

    Both the lowered text and its separator-normalized form are
    matched against the frozen forbidden-token vocabulary, so
    ``shared_secret``, ``shared-secret``, ``shared.secret`` and
    ``shared secret`` all fail closed.
    """
    if not isinstance(value, str):
        raise TelemetryError(
            TelemetryReasonCode.CREDENTIAL_LIKE_INPUT,
            "%s must be a str (got %s)" % (label, type(value).__name__),
        )
    lowered = value.strip().lower()
    normalized = _normalized(value)
    for token in _CREDENTIAL_LIKE_FORBIDDEN:
        if token in lowered or _normalized(token) in normalized:
            raise TelemetryError(
                TelemetryReasonCode.CREDENTIAL_LIKE_INPUT,
                "%s must not carry credential-like content (LOCK-023: "
                "secrets never become telemetry DATA)" % (label,),
            )
    return value


def validate_subject_kind(value: object) -> str:
    """Validate a measurement subject kind against the frozen
    six-subject vocabulary."""
    if not isinstance(value, str) or value not in TelemetrySubjectKind.values():
        raise TelemetryError(
            TelemetryReasonCode.UNKNOWN_SUBJECT_KIND,
            "subject kind must be one of the frozen WORK-026 subject "
            "kinds %s (got %r)"
            % (list(TelemetrySubjectKind.values()), value),
        )
    return value


def validate_source_class(value: object) -> str:
    """Validate a measurement source class against the frozen §6.11
    evidence-type vocabulary."""
    if not isinstance(value, str) or value not in TelemetrySourceClass.values():
        raise TelemetryError(
            TelemetryReasonCode.UNKNOWN_SOURCE_CLASS,
            "source class must be one of the frozen spec/architecture "
            "6.11 evidence types %s (got %r)"
            % (list(TelemetrySourceClass.values()), value),
        )
    return value


def validate_metric_for_subject(subject_kind: str, metric: object) -> str:
    """Validate a (subject, metric) pair against the frozen
    standardized-metric registry: unknown metrics fail closed, and a
    metric registered for ANOTHER subject kind is an explicit
    mismatch (never a silent cross-subject reinterpretation)."""
    registered = TELEMETRY_METRIC_REGISTRY[subject_kind]
    names = tuple(m.name for m in registered)
    if not isinstance(metric, str):
        raise TelemetryError(
            TelemetryReasonCode.UNKNOWN_METRIC,
            "metric must be a str (got %s)" % (type(metric).__name__,),
        )
    if metric in names:
        return metric
    for other_kind, other_metrics in sorted(TELEMETRY_METRIC_REGISTRY.items()):
        if other_kind != subject_kind and metric in tuple(
            m.name for m in other_metrics
        ):
            raise TelemetryError(
                TelemetryReasonCode.METRIC_SUBJECT_MISMATCH,
                "metric %r is a %s-subject metric, not a %s-subject "
                "metric (the standardized registry is per-subject)"
                % (metric, other_kind, subject_kind),
            )
    raise TelemetryError(
        TelemetryReasonCode.UNKNOWN_METRIC,
        "metric %r is not in the frozen standardized registry for "
        "subject kind %r (allowed: %s; technology-specific counters "
        "ride the extensions channel)"
        % (metric, subject_kind, list(names)),
    )


def validate_metric_value(subject_kind: str, metric: str, value: object) -> int:
    """Validate a measurement value: integers only (bool rejected),
    non-negative, bounded by the metric's scale (basis-point metrics
    are bounded by 10000; the adapter health ordinal by the frozen
    ladder)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TelemetryError(
            TelemetryReasonCode.INVALID_INPUT,
            "metric %r value must be an integer (got %s) -- the house "
            "numeric discipline forbids binary floating point"
            % (metric, type(value).__name__),
        )
    maximum = metric_max_value(subject_kind, metric)
    if value < 0:
        raise TelemetryError(
            TelemetryReasonCode.INVALID_INPUT,
            "metric %r value must be >= 0 (got %d)" % (metric, value),
        )
    if value > maximum:
        raise TelemetryError(
            TelemetryReasonCode.INVALID_INPUT,
            "metric %r value %d exceeds the metric scale maximum %d"
            % (metric, value, maximum),
        )
    return value


def validate_confidence_basis_points(value: object) -> int:
    """Validate confidence on the repository-wide WORK-011 basis-point
    scale (integer 0..10000; deterministic, explainable,
    input-derived -- NOT a trust score)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TelemetryError(
            TelemetryReasonCode.INVALID_CONFIDENCE,
            "confidence_basis_points must be an integer (got %s)"
            % (type(value).__name__,),
        )
    if not (0 <= value <= MAX_BASIS_POINTS):
        raise TelemetryError(
            TelemetryReasonCode.INVALID_CONFIDENCE,
            "confidence_basis_points must be within 0..%d (got %d)"
            % (MAX_BASIS_POINTS, value),
        )
    return value


def validate_subject_ref(value: object) -> str:
    """Validate an opaque subject reference (the subject is owned by
    its respective authority -- link/path refs by topology/routing,
    session refs by the session subsystem, resource ids by WORK-008,
    adapter refs by WORK-016; telemetry NEVER interprets their
    internal formats, only carries them opaquely)."""
    if not isinstance(value, str):
        raise TelemetryError(
            TelemetryReasonCode.INVALID_INPUT,
            "subject_ref must be a str (got %s)" % (type(value).__name__,),
        )
    stripped = value.strip()
    if not stripped or stripped != value:
        raise TelemetryError(
            TelemetryReasonCode.INVALID_INPUT,
            "subject_ref must be a non-empty, trimmed opaque reference",
        )
    if len(value) > 256:
        raise TelemetryError(
            TelemetryReasonCode.INVALID_INPUT,
            "subject_ref must be at most 256 characters",
        )
    reject_credential_like_text(value, label="subject_ref")
    return value


def validate_observation_ref_text(value: object, label: str) -> str:
    """Validate opaque reference/free text carried on records
    (evidence refs, provenance, decision ids, ids)."""
    if not isinstance(value, str):
        raise TelemetryError(
            TelemetryReasonCode.INVALID_INPUT,
            "%s must be a str (got %s)" % (label, type(value).__name__),
        )
    if len(value) > 512:
        raise TelemetryError(
            TelemetryReasonCode.INVALID_INPUT,
            "%s must be at most 512 characters" % (label,),
        )
    reject_credential_like_text(value, label=label)
    return value


def validate_context_pairs(
    value: object, label: str, privacy_class: str
) -> Tuple[Tuple[str, str], ...]:
    """Validate the technology-neutral key/value context (or
    extensions) channel: sorted, deduplicated (canonical
    determinism), non-empty string keys/values, no credential-like
    content, and the §20 privacy gate -- location-bearing keys may
    ride ONLY restricted-class observations."""
    if not isinstance(value, tuple):
        raise TelemetryError(
            TelemetryReasonCode.INVALID_INPUT,
            "%s must be a tuple of (str, str) pairs" % (label,),
        )
    seen = []
    for pair in value:
        if not isinstance(pair, tuple) or len(pair) != 2:
            raise TelemetryError(
                TelemetryReasonCode.INVALID_INPUT,
                "%s entries must be (str, str) pairs" % (label,),
            )
        key, item = pair
        if not isinstance(key, str) or not key or not isinstance(item, str):
            raise TelemetryError(
                TelemetryReasonCode.INVALID_INPUT,
                "%s keys must be non-empty strings and values must be "
                "strings" % (label,),
            )
        if not item:
            raise TelemetryError(
                TelemetryReasonCode.INVALID_INPUT,
                "%s values must be non-empty strings" % (label,),
            )
        reject_credential_like_text(key, label="%s key" % (label,))
        reject_credential_like_text(item, label="%s value" % (label,))
        normalized_key = _normalized(key)
        if any(
            normalized_key == _normalized(forbidden)
            or normalized_key.startswith(_normalized(forbidden) + "-")
            or normalized_key.startswith(_normalized(forbidden) + "/")
            for forbidden in _LOCATION_CONTEXT_KEYS
        ) and privacy_class != PrivacyClass.RESTRICTED:
            raise TelemetryError(
                TelemetryReasonCode.PRIVACY_VIOLATION,
                "%s key %r carries location-bearing content -- "
                "location disclosure is policy controlled (spec/"
                "architecture 20) and may ride ONLY restricted-class "
                "observations" % (label, key),
            )
        if (key, item) in seen:
            raise TelemetryError(
                TelemetryReasonCode.INVALID_INPUT,
                "%s carries duplicate pair %r (canonical determinism "
                "requires sorted, deduplicated pairs)" % (label, (key, item)),
            )
        seen.append((key, item))
    if seen != sorted(seen):
        raise TelemetryError(
            TelemetryReasonCode.INVALID_INPUT,
            "%s pairs must be sorted by key (canonical determinism)" % (label,),
        )
    return value


def validate_privacy_scope(value: object) -> str:
    """Validate an explicit privacy scope (the fail-closed §20
    fence): the maximum privacy class a query may observe or a
    topology-promotion authorization may disclose.  Observations
    above the scope are simply invisible on the query path, and a
    promotion above the scope fails closed."""
    if not isinstance(value, str) or value not in PrivacyClass.values():
        raise TelemetryError(
            TelemetryReasonCode.PRIVACY_VIOLATION,
            "privacy_scope must be one of the frozen privacy classes %s "
            "(got %r) -- every telemetry query and every promotion "
            "authorization states the maximum privacy class it may "
            "observe or disclose" % (list(PrivacyClass.values()), value),
        )
    return value


def validate_source_disclosure(value: object) -> str:
    """Validate a promotion authorization's source-identity disclosure
    mode against the frozen vocabulary (PR #27 Architect review
    blocker 2): the mode is part of the born-bound promotion
    authorization, and the privacy boundary fails closed on anything
    the authorization does not explicitly permit."""
    if not isinstance(value, str) or value not in SourceDisclosure.values():
        raise TelemetryError(
            TelemetryReasonCode.PRIVACY_VIOLATION,
            "source_disclosure must be one of the frozen disclosure "
            "modes %s (got %r) -- a promotion authorization must "
            "explicitly state what source-identity disclosure it "
            "permits (identity or pseudonymous; never a caller flag)"
            % (list(SourceDisclosure.values()), value),
        )
    return value


def validate_purpose(value: object) -> str:
    """Validate a stated query purpose (required for restricted
    scopes; audited operator intent)."""
    if not isinstance(value, str):
        raise TelemetryError(
            TelemetryReasonCode.PRIVACY_VIOLATION,
            "purpose must be a str (got %s)" % (type(value).__name__),
        )
    stripped = value.strip()
    if not stripped:
        raise TelemetryError(
            TelemetryReasonCode.PRIVACY_VIOLATION,
            "a restricted-scope query requires an explicit non-empty "
            "purpose (spec/architecture 20: privacy-sensitive "
            "measurements are never read without stated intent)",
        )
    reject_credential_like_text(value, label="purpose")
    return value


def privacy_visible(privacy_scope: str, observation_class: str) -> bool:
    """True iff an observation of ``observation_class`` is visible to
    a query holding ``privacy_scope`` (the fail-closed visibility
    lattice)."""
    return observation_class in PRIVACY_VISIBILITY[privacy_scope]


__all__ = [
    "reject_credential_like_text",
    "validate_subject_kind",
    "validate_source_class",
    "validate_metric_for_subject",
    "validate_metric_value",
    "validate_confidence_basis_points",
    "validate_subject_ref",
    "validate_observation_ref_text",
    "validate_context_pairs",
    "validate_privacy_scope",
    "validate_source_disclosure",
    "validate_purpose",
    "privacy_visible",
    "MAX_METRIC_VALUE",
]
