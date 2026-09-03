"""WORK-048 containment platform capability dimension (ACR-012 §4).

The capability dimension of the containment authority: an explicit,
deterministic, W048-LOCAL mapping from a platform identifier to
the frozen :class:`CapabilityState` (``unsupported | unknown |
supported | restricted``) plus the isolation mechanism that state
claims.  It is DATA, never architecture authority: adding a
platform row changes no frozen contract (LOCK-025: Linux-first is
not Linux-dependent).

Provenance discipline (the ACR-011 advisory-edge ruling, preserved
by ACR-012): a capability matrix may be built from WORK-050's
advisory capability/isolation matrix INPUT, but W050 is NOT a hard
gate and the containment authority NEVER depends on it — the
caller composes advisory rows; the matrix itself decides with its
own frozen rules.

Fail-closed rules (frozen, battery-pinned):

1. ``unknown`` and ``unsupported`` MUST refuse exposure; they never
   silently degrade to a weaker isolation mechanism (there is no
   "fallback mechanism" anywhere in this family).
2. A capability claim outside the frozen vocabulary is rejected
   (``CAPABILITY_INVALID``) — never coerced to a valid state.
3. The DEFAULT for an unregistered platform is ``unknown`` (fail
   closed), never ``supported``.
4. ``restricted`` is usable only within its explicit, documented
   restriction set (sorted, deduplicated, frozen at declaration);
   exposure outside that set refuses.
5. A ``supported`` claim is a SOFTWARE-conformance claim only: it
   never becomes a physical containment claim (PHYSICAL evidence
   stays OPEN until physically demonstrated; the evidence-class
   honesty disclosure in docs/WORK-048-evidence.md).
"""

from __future__ import annotations

from typing import Any, Dict, FrozenSet, Mapping, Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import ContainmentError, ContainmentReasonCode
from .state import (
    ISOLATION_MECHANISMS,
    BoundaryState,
    CapabilityState,
)


class PlatformCapability:
    """One platform's frozen capability claim (DATA only).

    ``platform_id`` is an opaque platform label (e.g. a W050
    profile id).  ``state`` is the frozen capability vocabulary
    value.  ``mechanism`` is the isolation mechanism the claim
    selects.  ``restrictions`` is the documented restriction set
    (required non-empty for ``restricted``; always empty for the
    other states).  ``evidence_class`` is always ``SOFTWARE`` for
    software-declared matrices: no row of this local matrix ever
    asserts a PHYSICAL containment claim.
    """

    __slots__ = (
        "platform_id", "state", "mechanism", "restrictions", "evidence_class",
    )

    def __init__(
        self,
        platform_id: str,
        state: str,
        mechanism: str,
        restrictions: Tuple[str, ...] = (),
    ) -> None:
        if not isinstance(platform_id, str) or not platform_id:
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "platform_id must be a non-empty string",
            )
        if state not in CapabilityState.values():
            raise ContainmentError(
                ContainmentReasonCode.CAPABILITY_INVALID,
                "capability state %r must be one of %s (the frozen "
                "ACR-012 vocabulary; never coerced)" % (state, list(CapabilityState.values())),
            )
        if state == CapabilityState.RESTRICTED:
            if not isinstance(mechanism, str) or not mechanism:
                raise ContainmentError(
                    ContainmentReasonCode.MECHANISM_INVALID,
                    "a restricted capability requires its mechanism",
                )
        if mechanism != "":
            if mechanism not in ISOLATION_MECHANISMS:
                raise ContainmentError(
                    ContainmentReasonCode.MECHANISM_INVALID,
                    "mechanism %r must be one of %s (frozen vocabulary)"
                    % (mechanism, list(ISOLATION_MECHANISMS)),
                )
        if not isinstance(restrictions, tuple) or any(
            not isinstance(item, str) or not item for item in restrictions
        ):
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "restrictions must be a tuple of non-empty strings",
            )
        deduped = tuple(sorted(set(restrictions)))
        if state != CapabilityState.RESTRICTED and deduped:
            raise ContainmentError(
                ContainmentReasonCode.CAPABILITY_INVALID,
                "only restricted capabilities carry a restriction set",
            )
        if state == CapabilityState.RESTRICTED and not deduped:
            raise ContainmentError(
                ContainmentReasonCode.CAPABILITY_INVALID,
                "a restricted capability requires a non-empty documented "
                "restriction set (the restriction set is the exposure "
                "envelope -- an empty set would silently mean unrestricted)",
            )
        if state in (CapabilityState.UNSUPPORTED, CapabilityState.UNKNOWN) and mechanism != "":
            raise ContainmentError(
                ContainmentReasonCode.CAPABILITY_INVALID,
                "unsupported/unknown platforms declare no mechanism (no "
                "fallback mechanism exists anywhere in this family)",
            )
        if state == CapabilityState.SUPPORTED and mechanism == "":
            raise ContainmentError(
                ContainmentReasonCode.MECHANISM_INVALID,
                "a supported capability requires its mechanism",
            )
        self.platform_id = platform_id
        self.state = state
        self.mechanism = mechanism
        self.restrictions = deduped
        self.evidence_class = "SOFTWARE"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "platform_id": self.platform_id,
            "state": self.state,
            "mechanism": self.mechanism,
            "restrictions": list(self.restrictions),
            "evidence_class": self.evidence_class,
        }

    @classmethod
    def from_dict(cls, data: object) -> "PlatformCapability":
        if not isinstance(data, Mapping):
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "platform capability must be a mapping",
            )
        restrictions = data.get("restrictions", ())
        if not isinstance(restrictions, (list, tuple)):
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "platform capability restrictions must be a sequence",
            )
        return cls(
            platform_id=str(data.get("platform_id", "")),
            state=str(data.get("state", "")),
            mechanism=str(data.get("mechanism", "")),
            restrictions=tuple(str(item) for item in restrictions),
        )

    def content_digest(self) -> str:
        import hashlib

        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.to_dict())
        ).hexdigest()

    def admits_within(self, requested_restrictions: FrozenSet[str]) -> bool:
        """A ``restricted`` capability admits exposure only within
        its documented restriction set; ``supported`` admits any
        requested envelope; ``unknown``/``unsupported`` never admit."""
        if self.state == CapabilityState.SUPPORTED:
            return True
        if self.state == CapabilityState.RESTRICTED:
            return set(requested_restrictions).issubset(set(self.restrictions))
        return False


class CapabilityMatrix:
    """The deterministic platform capability matrix (W048-local).

    Built by the CALLER from its own declarations and (optionally)
    WORK-050 advisory rows — the matrix never queries W050 and
    never depends on it.  Duplicate platform ids with conflicting
    content fail closed; identical duplicates are idempotent.
    """

    def __init__(self, rows: Tuple[PlatformCapability, ...] = ()) -> None:
        self._rows: Dict[str, PlatformCapability] = {}
        for row in rows:
            known = self._rows.get(row.platform_id)
            if known is not None:
                if known.to_dict() != row.to_dict():
                    raise ContainmentError(
                        ContainmentReasonCode.CAPABILITY_INVALID,
                        "conflicting capability rows for platform %r "
                        "(fail closed; never first-wins)" % row.platform_id,
                    )
                continue
            self._rows[row.platform_id] = row

    def capability(self, platform_id: str) -> PlatformCapability:
        """The capability of one platform; unregistered platforms
        fail closed as ``unknown`` (the DEFAULT, never supported)."""
        if not isinstance(platform_id, str) or not platform_id:
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "platform_id must be a non-empty string",
            )
        row = self._rows.get(platform_id)
        if row is None:
            return PlatformCapability(
                platform_id=platform_id,
                state=CapabilityState.UNKNOWN,
                mechanism="",
            )
        return row

    def platforms(self) -> Tuple[str, ...]:
        return tuple(sorted(self._rows))

    def rows(self) -> Tuple[PlatformCapability, ...]:
        return tuple(self._rows[key] for key in sorted(self._rows))

    def to_dict(self) -> Dict[str, Any]:
        return {"rows": [row.to_dict() for row in self.rows()]}

    @classmethod
    def from_dict(cls, data: object) -> "CapabilityMatrix":
        if not isinstance(data, Mapping):
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "capability matrix must be a mapping",
            )
        rows = data.get("rows", ())
        if not isinstance(rows, (list, tuple)):
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "capability matrix rows must be a sequence",
            )
        return cls(tuple(PlatformCapability.from_dict(row) for row in rows))

    def content_digest(self) -> str:
        import hashlib

        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.to_dict())
        ).hexdigest()

    def admission_state(
        self, platform_id: str
    ) -> Tuple[str, str]:
        """The capability-derived admission decision for a platform:
        (state, typed denial reason).  ``supported``/``restricted``
        within their documented sets pass; ``unknown``/``unsupported``
        fail closed with their typed reason.  There is no downgrade
        path — the mechanism vocabulary admits no fallback."""
        row = self.capability(platform_id)
        if row.state == CapabilityState.UNKNOWN:
            return row.state, ContainmentReasonCode.CAPABILITY_UNKNOWN
        if row.state == CapabilityState.UNSUPPORTED:
            return row.state, ContainmentReasonCode.CAPABILITY_UNSUPPORTED
        return row.state, ""


__all__ = [
    "PlatformCapability",
    "CapabilityMatrix",
    "CapabilityState",
    "BoundaryState",
]
