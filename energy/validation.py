"""ADCOS energy / resilience fail-closed validation (WORK-027).

Structural validators for the frozen vocabularies and record shapes:
power sources, thermal states, energy stages, service priorities,
connectivity states, adaptation outcomes, upstream subjects, opaque
reference text, and the free-text channels.  Every validator fails
closed with a code from the frozen
:class:`~energy.errors.EnergyReasonCode` vocabulary.

Credential-like content is rejected in EVERY free-text field
(LOCK-023: secrets never become energy/resilience DATA), mirroring
the WORK-016..026 family discipline.
"""

from __future__ import annotations

import re
from typing import Any, List, Tuple

from .errors import EnergyError, EnergyReasonCode
from .model import (
    AdaptationOutcome,
    ConnectivityState,
    EnergyStage,
    PowerSource,
    ServicePriority,
    ThermalState,
    UpstreamEventKind,
)

#: Forbidden credential-like tokens (LOCK-023) -- the house vocabulary
#: mirrored from the sibling families (telemetry/services/backhaul/...).
_CREDENTIAL_LIKE_FORBIDDEN = (
    "private_key", "secret_key", "password", "passphrase", "token",
    "api_key", "shared_secret", "community_string", "psk",
    "pre_shared_key", "preshared", "sim_pin", "session_key",
    "credential_value", "client_secret", "access_key", "signing_key",
    "hmac_key", "master_key", "root_password", "mgmt_secret",
    "telemetry_secret", "observation_secret", "energy_secret",
)

_SEPARATOR_RUN = re.compile(r"[\s_.\-]+")

#: Upstream subject pattern: opaque non-empty reference text (a link
#: subject / backhaul label / gateway subject -- technology-neutral).
_UPSTREAM_SUBJECT_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")


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
        raise EnergyError(
            EnergyReasonCode.CREDENTIAL_LIKE_INPUT,
            "%s must be a str (got %s)" % (label, type(value).__name__),
        )
    lowered = value.strip().lower()
    normalized = _normalized(value)
    for token in _CREDENTIAL_LIKE_FORBIDDEN:
        if token in lowered or _normalized(token) in normalized:
            raise EnergyError(
                EnergyReasonCode.CREDENTIAL_LIKE_INPUT,
                "%s must not carry credential-like content (LOCK-023: "
                "secrets never become energy/resilience DATA)" % (label,),
            )
    return value


def validate_power_source(value: object) -> str:
    if not isinstance(value, str) or value not in PowerSource.values():
        raise EnergyError(
            EnergyReasonCode.UNKNOWN_POWER_SOURCE,
            "power_source %r must be one of %s"
            % (value, list(PowerSource.values())),
        )
    return value


def validate_thermal_state(value: object) -> str:
    if not isinstance(value, str) or value not in ThermalState.values():
        raise EnergyError(
            EnergyReasonCode.UNKNOWN_THERMAL_STATE,
            "thermal_state %r must be one of %s" % (value, list(ThermalState.values())),
        )
    return value


def validate_energy_stage(value: object) -> str:
    if not isinstance(value, str) or value not in EnergyStage.values():
        raise EnergyError(
            EnergyReasonCode.UNKNOWN_ENERGY_STAGE,
            "stage %r must be one of %s" % (value, list(EnergyStage.values())),
        )
    return value


def validate_service_priority(value: object) -> str:
    if not isinstance(value, str) or value not in ServicePriority.values():
        raise EnergyError(
            EnergyReasonCode.UNKNOWN_SERVICE_PRIORITY,
            "service priority %r must be one of %s"
            % (value, list(ServicePriority.values())),
        )
    return value


def validate_connectivity_state(value: object) -> str:
    if not isinstance(value, str) or value not in ConnectivityState.values():
        raise EnergyError(
            EnergyReasonCode.UNKNOWN_CONNECTIVITY_STATE,
            "connectivity state %r must be one of %s"
            % (value, list(ConnectivityState.values())),
        )
    return value


def validate_adaptation_outcome(value: object) -> str:
    if not isinstance(value, str) or value not in AdaptationOutcome.values():
        raise EnergyError(
            EnergyReasonCode.INVALID_INPUT,
            "adaptation outcome %r must be one of %s"
            % (value, list(AdaptationOutcome.values())),
        )
    return value


def validate_upstream_event_kind(value: object) -> str:
    if not isinstance(value, str) or value not in UpstreamEventKind.values():
        raise EnergyError(
            EnergyReasonCode.INVALID_INPUT,
            "upstream event kind %r must be one of %s"
            % (value, list(UpstreamEventKind.values())),
        )
    return value


def validate_upstream_subject(value: object) -> str:
    """Upstream subjects are opaque technology-neutral reference text
    (link subjects, backhaul/gateway labels).  Credential-like
    content fails closed (LOCK-023)."""
    reject_credential_like_text(value, label="upstream subject")
    assert isinstance(value, str)
    if not _UPSTREAM_SUBJECT_RE.match(value):
        raise EnergyError(
            EnergyReasonCode.INVALID_INPUT,
            "upstream subject %r must match %s"
            % (value, _UPSTREAM_SUBJECT_RE.pattern),
        )
    return value


def validate_service_ref(value: object) -> str:
    """A WORK-025 service reference carried by survival profiles and
    demands.  Free-form non-empty reference text; credential-like
    content fails closed (LOCK-023)."""
    reject_credential_like_text(value, label="service_ref")
    if not isinstance(value, str) or not value.strip():
        raise EnergyError(
            EnergyReasonCode.INVALID_INPUT,
            "service_ref must be a non-empty reference string",
        )
    return value


def validate_instant(value: object, *, label: str) -> str:
    """A required RFC 3339 UTC instant (no wall-clock fallback)."""
    from protocol.temporal import TemporalError, parse_instant

    if not isinstance(value, str) or not value:
        raise EnergyError(
            EnergyReasonCode.INVALID_INPUT,
            "%s must be a non-empty RFC 3339 UTC instant" % label,
        )
    try:
        parse_instant(value)
    except TemporalError as error:
        raise EnergyError(
            EnergyReasonCode.INVALID_INPUT,
            "%s %r is not RFC 3339 UTC: %s" % (label, value, error),
        ) from error
    return value


def validate_extensions(value: object) -> Tuple[Tuple[str, str], ...]:
    """WORK-003-style opaque string-pair extensions; credential-like
    values fail closed (LOCK-023)."""
    if not isinstance(value, (tuple, list)):
        raise EnergyError(
            EnergyReasonCode.INVALID_INPUT,
            "extensions must be a tuple of (string, string) pairs",
        )
    out: List[Tuple[str, str]] = []
    for pair in value:
        if (
            not isinstance(pair, (tuple, list))
            or len(pair) != 2
            or not isinstance(pair[0], str)
            or not isinstance(pair[1], str)
        ):
            raise EnergyError(
                EnergyReasonCode.INVALID_INPUT,
                "extensions entries must be (string, string) pairs",
            )
        reject_credential_like_text(pair[1], label="extensions value")
        out.append((pair[0], pair[1]))
    return tuple(out)


def validate_non_negative_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise EnergyError(
            EnergyReasonCode.INVALID_INPUT,
            "%s must be a non-negative int (got %r)" % (label, value),
        )
    return value


__all__ = [
    "reject_credential_like_text",
    "validate_power_source",
    "validate_thermal_state",
    "validate_energy_stage",
    "validate_service_priority",
    "validate_connectivity_state",
    "validate_adaptation_outcome",
    "validate_upstream_event_kind",
    "validate_upstream_subject",
    "validate_service_ref",
    "validate_instant",
    "validate_extensions",
    "validate_non_negative_int",
]
