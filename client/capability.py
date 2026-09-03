"""WORK-049 client capability model (fail closed).

Device/platform capability is represented EXPLICITLY using the
ACR-012 frozen capability vocabulary — reused, not redeclared:

    UNSUPPORTED | UNKNOWN | SUPPORTED | RESTRICTED

(the constants are imported from the accepted containment
authority's frozen vocabulary so the client dimension can never
drift from ACR-012; no second capability vocabulary exists in
this family).

Semantics (frozen, docs/WORK-049-handoff.md):

    UNKNOWN      => fail closed
    UNSUPPORTED  => fail closed
    RESTRICTED   => constrained operation ONLY within the declared
                    restriction set
    SUPPORTED    => eligible for operation SUBJECT to canonical
                    authority checks (never a connectivity claim)

No implicit platform assumption exists anywhere in this family:
no platform LABEL (however familiar its shape) ever implies
sharing support, and no transport technology's availability ever
implies provider-mode safety — the ONLY
capability source is an explicit adapter report, and an
unregistered platform id reads UNKNOWN (fail closed).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import ClientError, ClientReasonCode

import hashlib

#: The ACR-012 frozen capability vocabulary — IMPORTED from the
#: accepted containment authority (reuse, never redeclaration).
from containment.state import CapabilityState as _Acr012CapabilityState

CAPABILITY_VALUES: Tuple[str, ...] = _Acr012CapabilityState.values()
CAPABILITY_FAIL_CLOSED: Tuple[str, ...] = (
    _Acr012CapabilityState.fail_closed_values()
)


@dataclass(frozen=True)
class AdapterCapabilitySnapshot:
    """One explicit platform-adapter capability report (DATA).

    ``provider_support`` / ``buyer_support`` are ACR-012
    vocabulary values for the two participation modes.
    ``restrictions`` is the declared constrained-operation set
    (required non-empty exactly when a mode is RESTRICTED; always
    empty for the other states).  ``mechanism`` labels the
    platform mechanism behind the report.  ``evidence_class`` is
    always ``SOFTWARE`` for software-declared adapters: no
    capability report here is a PHYSICAL platform claim.
    """

    platform_id: str
    provider_support: str
    buyer_support: str
    restrictions: Tuple[str, ...] = ()
    mechanism: str = ""
    evidence_class: str = "SOFTWARE"

    def __post_init__(self) -> None:
        if not isinstance(self.platform_id, str) or not self.platform_id:
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "capability snapshot platform_id must be non-empty",
            )
        for label, value in (
            ("provider_support", self.provider_support),
            ("buyer_support", self.buyer_support),
        ):
            if value not in CAPABILITY_VALUES:
                raise ClientError(
                    ClientReasonCode.INVALID_INPUT,
                    "capability %s %r is outside the frozen ACR-012 "
                    "vocabulary %s (never coerced)" % (label, value, list(CAPABILITY_VALUES)),
                )
        if not isinstance(self.restrictions, tuple) or any(
            not isinstance(item, str) or not item for item in self.restrictions
        ):
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "restrictions must be a tuple of non-empty tokens",
            )
        if len(set(self.restrictions)) != len(self.restrictions):
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "restrictions must be deduplicated",
            )
        provider_restricted = (
            self.provider_support == _Acr012CapabilityState.RESTRICTED
        )
        buyer_restricted = (
            self.buyer_support == _Acr012CapabilityState.RESTRICTED
        )
        any_restricted = provider_restricted or buyer_restricted
        if any_restricted and not self.restrictions:
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "a RESTRICTED mode requires a non-empty declared "
                "restriction set (provider=%s, buyer=%s)"
                % (self.provider_support, self.buyer_support),
            )
        if not any_restricted and self.restrictions:
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "restrictions declared while no mode is RESTRICTED "
                "(provider=%s, buyer=%s)"
                % (self.provider_support, self.buyer_support),
            )
        if self.evidence_class != "SOFTWARE":
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "a software-declared adapter capability snapshot is "
                "SOFTWARE-class only (physical platform capability is "
                "separately governed)",
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "platform_id": self.platform_id,
            "provider_support": self.provider_support,
            "buyer_support": self.buyer_support,
            "restrictions": list(self.restrictions),
            "mechanism": self.mechanism,
            "evidence_class": self.evidence_class,
        }

    def content_digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.to_dict())
        ).hexdigest()


class CapabilityDecision:
    """The frozen capability-gate decision vocabulary."""

    #: proceed, SUBJECT to canonical authority checks
    ALLOWED = "ALLOWED"
    #: constrained operation only (within the declared set)
    CONSTRAINED = "CONSTRAINED"
    #: fail closed (UNKNOWN / UNSUPPORTED / out-of-set request)
    DENIED = "DENIED"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.ALLOWED, cls.CONSTRAINED, cls.DENIED)


@dataclass(frozen=True)
class CapabilityGateResult:
    """The deterministic result of one capability gate evaluation."""

    mode: str
    decision: str
    support_state: str
    restrictions: Tuple[str, ...]
    detail: str

    def __post_init__(self) -> None:
        if self.mode not in ("provider", "buyer"):
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "capability gate mode must be provider/buyer",
            )
        if self.decision not in CapabilityDecision.values():
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "capability decision %r is outside the frozen vocabulary"
                % (self.decision,),
            )
        if self.support_state not in CAPABILITY_VALUES:
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "capability support_state %r is outside the frozen "
                "vocabulary" % (self.support_state,),
            )


def evaluate_capability(
    snapshot: AdapterCapabilitySnapshot,
    mode: str,
    *,
    requested_constraints: FrozenSet[str] = frozenset(),
) -> CapabilityGateResult:
    """Evaluate one mode's capability gate (deterministic, fail closed).

    - UNKNOWN / UNSUPPORTED  => DENIED (fail closed; NO silent
      downgrade, NO fallback, NO implicit platform assumption);
    - RESTRICTED             => CONSTRAINED only when the requested
      operation constraints are a subset of the declared
      restriction set (otherwise DENIED);
    - SUPPORTED              => ALLOWED — an eligibility to proceed
      SUBJECT to canonical authority checks; never itself a
      connectivity or safety claim.
    """
    if not isinstance(snapshot, AdapterCapabilitySnapshot):
        raise ClientError(
            ClientReasonCode.INVALID_INPUT,
            "the capability gate requires an explicit adapter "
            "capability snapshot (never an assumed platform label)",
        )
    if mode not in ("provider", "buyer"):
        raise ClientError(
            ClientReasonCode.INVALID_INPUT,
            "capability gate mode must be provider/buyer",
        )
    support = (
        snapshot.provider_support if mode == "provider"
        else snapshot.buyer_support
    )
    if support in CAPABILITY_FAIL_CLOSED:
        return CapabilityGateResult(
            mode=mode,
            decision=CapabilityDecision.DENIED,
            support_state=support,
            restrictions=(),
            detail="platform %s reports %s for %s mode: exposure refused "
            "(fail closed; no fallback)"
            % (snapshot.platform_id, support, mode),
        )
    if support == _Acr012CapabilityState.RESTRICTED:
        declared = frozenset(snapshot.restrictions)
        if not requested_constraints.issubset(declared):
            outside = sorted(requested_constraints - declared)
            return CapabilityGateResult(
                mode=mode,
                decision=CapabilityDecision.DENIED,
                support_state=support,
                restrictions=snapshot.restrictions,
                detail="restricted platform %s permits %s mode only within "
                "%s; requested %s is outside the declared set"
                % (
                    snapshot.platform_id,
                    mode,
                    sorted(declared),
                    outside[:3],
                ),
            )
        return CapabilityGateResult(
            mode=mode,
            decision=CapabilityDecision.CONSTRAINED,
            support_state=support,
            restrictions=snapshot.restrictions,
            detail="platform %s permits %s mode as CONSTRAINED within the "
            "declared set %s" % (snapshot.platform_id, mode, sorted(declared)),
        )
    return CapabilityGateResult(
        mode=mode,
        decision=CapabilityDecision.ALLOWED,
        support_state=support,
        restrictions=(),
        detail="platform %s reports %s for %s mode: eligible to proceed "
        "subject to canonical authority checks"
        % (snapshot.platform_id, support, mode),
    )
