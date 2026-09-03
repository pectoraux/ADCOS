"""WORK-048 containment isolation primitive contract (ACR-012).

The technology-neutral contract an OS/network isolation primitive
implements for the containment authority.  This is the
``/adapters``-facing boundary of ACR-012: platform-specific
enforcement (Linux netns/nftables, VRF, Android VpnService, Apple
Network Extension) belongs BEHIND this contract, in adapter
implementations; the core ``containment/`` contract stays
technology-neutral and imports no platform SDK, no vendor type,
and no 3GPP RAN/Core type (LOCK-016/LOCK-017; the import audit in
``tools/sharing_selftest.py`` pins this).

The critical discipline (ACR-012 frozen invariant): verification
comes from the ACTUAL platform/network boundary, not a software
declaration.  Concretely:

- ``establish`` MUST be performed by the primitive (the platform
  mechanism), returning an opaque scope reference plus the
  platform-observed establishment facts;
- ``verify`` MUST return a proof result derived from the primitive's
  OWN observation of the scope (scope observed to exist, the
  egress allow-list active, deny-by-default reachability of denied
  destinations demonstrated BY THE MECHANISM), never from caller
  input;
- ``decide`` is the primitive's own enforcement decision for one
  destination — the containment core NEVER substitutes an
  application-level destination check for it;
- ``teardown`` destroys the scope AT THE PRIMITIVE LEVEL (the
  namespace/tunnel/scope is destroyed, not just forgotten).

This module defines ONLY the neutral contract + value records.
The deterministic reference implementation (the software sandbox
model of the platform mechanism) is :mod:`containment.sandbox`;
real platform implementations live in ``/adapters`` under their
own authority (out of WORK-048's literal scope).

Determinism: every record is content-addressable over canonical
bytes; no wall clock (instants are injected); no randomness; no
environment-dependent identity.  Exception discipline: primitives
MUST convert their own exceptions into typed
:class:`PrimitiveFailure` values (class name only — LOCK-023);
the containment authority additionally fail-closes on any
exception that escapes anyway.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import ContainmentError, ContainmentReasonCode
from .state import ISOLATION_MECHANISMS


#: The frozen deny-by-default floor: destination classes that a
#: buyer-traffic boundary may NEVER expose (control-plane/admin/
#: private surfaces — the control-plane/buyer-plane separation
#: ACR-012 owns).  Every verification proof MUST demonstrate them
#: DENIED by the mechanism, and no scope declaration may place
#: them in the allow-list or the exposed local services.  These
#: are technology-neutral destination CLASS tokens (opaque data
#: to the core), not addresses and not platform types.
MANDATORY_DENIED_PROBE_DESTINATIONS: Tuple[str, ...] = (
    "provider-control-plane",
    "provider-admin-services",
    "provider-private-lan",
    "unrelated-local-service",
)


def _envelope_floor_violations(
    allowed_egress: Tuple[str, ...],
    exposed_local_services: Tuple[str, ...],
) -> Tuple[str, ...]:
    """The declared-envelope destinations that fall on the frozen
    deny floor (sorted, deterministic).  A boundary may never
    expose the control plane, admin services, the private LAN, or
    unrelated local services to buyer traffic."""
    floor = set(MANDATORY_DENIED_PROBE_DESTINATIONS)
    violations = (
        set(allowed_egress) | set(exposed_local_services)
    ) & floor
    return tuple(sorted(violations))


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContainmentError(
            ContainmentReasonCode.INVALID_INPUT,
            "%s must be a non-empty string" % label,
        )
    return value


def _require_destination(value: object) -> str:
    """A reachability destination is an OPAQUE destination token
    (egress endpoint or local-service reference).  It is DATA for
    the allow-list; the containment core never parses addresses,
    never inspects payloads, and never learns packet content
    (NO PLAINTEXT INSPECTION — byte accounting only)."""
    if not isinstance(value, str) or not value:
        raise ContainmentError(
            ContainmentReasonCode.INVALID_INPUT,
            "destination must be a non-empty opaque destination token",
        )
    return value


@dataclass(frozen=True)
class ScopeSpec:
    """The neutral specification of one isolation scope to
    establish.

    ``boundary_id`` ties the scope to exactly one ContainmentBoundary
    instance.  ``mechanism`` is the frozen isolation mechanism label
    the platform adapter implements.  ``allowed_egress`` is the
    declared egress allow-list (sorted, deduplicated at the
    constructor); ``exposed_local_services`` is the deny-by-default
    local-service exposure set (empty = none).  Everything else is
    denied by the platform mechanism.
    """

    boundary_id: str
    mechanism: str
    allowed_egress: Tuple[str, ...]
    exposed_local_services: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text(self.boundary_id, "boundary_id")
        if self.mechanism not in ISOLATION_MECHANISMS:
            raise ContainmentError(
                ContainmentReasonCode.MECHANISM_INVALID,
                "mechanism %r must be one of %s (frozen vocabulary)"
                % (self.mechanism, list(ISOLATION_MECHANISMS)),
            )
        for label, value in (
            ("allowed_egress", self.allowed_egress),
            ("exposed_local_services", self.exposed_local_services),
        ):
            if not isinstance(value, tuple) or any(
                not isinstance(item, str) or not item for item in value
            ):
                raise ContainmentError(
                    ContainmentReasonCode.INVALID_INPUT,
                    "%s must be a tuple of non-empty opaque tokens" % label,
                )
        overlap = set(self.allowed_egress) & set(self.exposed_local_services)
        if overlap:
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "allowed egress and exposed local services must be "
                "disjoint (a token is either egress or a local service: %s)"
                % sorted(overlap)[:3],
            )
        floor = _envelope_floor_violations(
            self.allowed_egress, self.exposed_local_services,
        )
        if floor:
            # deny-by-default floor: a buyer boundary may NEVER
            # expose the control plane / admin / private surfaces
            # (fail closed at declaration, before any scope exists)
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "the declared envelope exposes deny-by-default floor "
                "destinations a buyer boundary may never reach (%s); the "
                "scope specification is rejected fail closed"
                % list(floor),
            )
        object.__setattr__(
            self, "allowed_egress", tuple(sorted(set(self.allowed_egress)))
        )
        object.__setattr__(
            self,
            "exposed_local_services",
            tuple(sorted(set(self.exposed_local_services))),
        )

    def content(self) -> Dict[str, Any]:
        return {
            "boundary_id": self.boundary_id,
            "mechanism": self.mechanism,
            "allowed_egress": list(self.allowed_egress),
            "exposed_local_services": list(self.exposed_local_services),
        }

    def spec_digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.content())
        ).hexdigest()


@dataclass(frozen=True)
class ScopeEstablishment:
    """The primitive's answer to ``establish``: the opaque scope
    reference plus the platform-observed establishment facts.

    ``established_at`` is the injected instant the primitive records
    (the caller passes the current clock reading; the primitive
    never reads a wall clock).  ``enforcement_digest`` is the
    primitive's own digest over the enforced allow-list state —
    the core recomputes nothing and trusts only the primitive's
    observation (then verifies it via ``verify``).
    """

    scope_ref: str
    boundary_id: str
    mechanism: str
    enforcement_digest: str
    established_at: str
    enforced_allowlist: Tuple[str, ...]
    enforced_local_services: Tuple[str, ...]

    def __post_init__(self) -> None:
        _require_text(self.scope_ref, "scope_ref")
        _require_text(self.boundary_id, "boundary_id")
        if self.mechanism not in ISOLATION_MECHANISMS:
            raise ContainmentError(
                ContainmentReasonCode.MECHANISM_INVALID,
                "mechanism %r outside the frozen vocabulary" % self.mechanism,
            )
        _require_text(self.enforcement_digest, "enforcement_digest")
        _require_text(self.established_at, "established_at")

    def content(self) -> Dict[str, Any]:
        return {
            "scope_ref": self.scope_ref,
            "boundary_id": self.boundary_id,
            "mechanism": self.mechanism,
            "enforcement_digest": self.enforcement_digest,
            "established_at": self.established_at,
            "enforced_allowlist": list(self.enforced_allowlist),
            "enforced_local_services": list(self.enforced_local_services),
        }


@dataclass(frozen=True)
class DenyProbe:
    """One deny-by-default probe the primitive executes during
    verification: the destination, the primitive's own decision,
    and the proof that the decision came from the MECHANISM (never
    an application-level declaration)."""

    destination: str
    decision: str  # "denied" | "allowed"
    decided_by: str  # always "platform-scope"

    def __post_init__(self) -> None:
        _require_destination(self.destination)
        if self.decision not in ("denied", "allowed"):
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "deny-probe decision %r must be denied|allowed" % self.decision,
            )
        if self.decided_by != "platform-scope":
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "deny-probe decisions come from the platform scope only",
            )


@dataclass(frozen=True)
class VerificationProof:
    """The primitive's verification result for one scope.

    ``scope_exists``: the primitive OBSERVED the scope to exist.
    ``allowlist_active``: the primitive OBSERVED its egress
    allow-list enforcing.  ``deny_probes``: the mechanism's own
    decisions for a fixed probe set (allowed destinations allowed,
    denied destinations denied).  ``observed_at``: the injected
    instant.  A proof is SOFTWARE-class evidence produced by the
    actual primitive; it never becomes a PHYSICAL containment
    claim.
    """

    scope_ref: str
    scope_exists: bool
    allowlist_active: bool
    deny_probes: Tuple[DenyProbe, ...]
    observed_at: str
    mechanism: str

    def __post_init__(self) -> None:
        _require_text(self.scope_ref, "scope_ref")
        if not isinstance(self.scope_exists, bool):
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "scope_exists must be a boolean",
            )
        if not isinstance(self.allowlist_active, bool):
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "allowlist_active must be a boolean",
            )
        if not isinstance(self.deny_probes, tuple):
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "deny_probes must be a tuple",
            )
        _require_text(self.observed_at, "observed_at")

    def content(self) -> Dict[str, Any]:
        return {
            "scope_ref": self.scope_ref,
            "scope_exists": self.scope_exists,
            "allowlist_active": self.allowlist_active,
            "deny_probes": [probe.__dict__ for probe in self.deny_probes],
            "observed_at": self.observed_at,
            "mechanism": self.mechanism,
        }

    def proof_digest(self) -> str:
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.content())
        ).hexdigest()

    def proves_boundary(self, spec: "ScopeSpec") -> bool:
        """A proof proves the boundary ONLY when it semantically
        matches the EXACT declared scope specification (the
        boundary envelope binding — a structurally shaped proof of
        some other envelope, or a lying probe matrix, proves
        nothing):

        - the primitive OBSERVED the scope to exist AND its
          egress allow-list enforcing;
        - the proof's mechanism IS the specification's mechanism;
        - every probe is decided by the platform scope, no
          destination is probed twice, and every decision MATCHES
          the declared semantics: a destination in the declared
          envelope MUST be probed ``allowed``; a destination
          outside it MUST be probed ``denied``;
        - the probe matrix COVERS the declared envelope: every
          allowed-egress and exposed-local-service destination is
          probed (an unprobed allowed destination proves nothing);
        - deny-by-default is DEMONSTRATED: every frozen
          mandatory-denied floor destination (never inside a legal
          envelope) is probed ``denied``.

        Anything else is a structurally valid but semantically
        false or incomplete observation: it does NOT prove the
        boundary (fail closed)."""
        if not isinstance(spec, ScopeSpec):
            return False
        if not (self.scope_exists and self.allowlist_active):
            return False
        if self.mechanism != spec.mechanism:
            return False
        envelope = set(spec.allowed_egress) | set(
            spec.exposed_local_services
        )
        seen: set = set()
        for probe in self.deny_probes:
            if probe.decided_by != "platform-scope":
                return False
            if probe.destination in seen:
                return False  # a duplicated probe is malformed evidence
            seen.add(probe.destination)
            if probe.destination in envelope:
                if probe.decision != "allowed":
                    return False
            else:
                if probe.decision != "denied":
                    return False
        # coverage: every declared-allowed destination is proved allowed
        if not envelope <= seen:
            return False
        # the deny floor: every mandatory denied destination is
        # proved denied (deny-by-default demonstrated, not declared)
        for destination in MANDATORY_DENIED_PROBE_DESTINATIONS:
            if destination in envelope:
                return False  # illegal envelope (defensive; spec rejects)
            if destination not in seen:
                return False
        return True


@dataclass(frozen=True)
class ReachabilityDecision:
    """The primitive's own enforcement decision for one
    destination: allowed iff the destination is in the enforced
    allow-list (egress or exposed local service) — decided by the
    platform scope, never by an application-level check."""

    destination: str
    allowed: bool
    decided_by: str = "platform-scope"

    def __post_init__(self) -> None:
        _require_destination(self.destination)
        if not isinstance(self.allowed, bool):
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "allowed must be a boolean",
            )
        if self.decided_by != "platform-scope":
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "reachability is decided by the platform scope only",
            )


@dataclass(frozen=True)
class TeardownResult:
    """The primitive's teardown answer: the scope was destroyed AT
    THE PRIMITIVE LEVEL (namespace/tunnel/scope destroyed, not only
    forgotten), with the teardown instant recorded."""

    scope_ref: str
    destroyed: bool
    torn_down_at: str

    def __post_init__(self) -> None:
        _require_text(self.scope_ref, "scope_ref")
        if not isinstance(self.destroyed, bool):
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "destroyed must be a boolean",
            )
        _require_text(self.torn_down_at, "torn_down_at")


@dataclass(frozen=True)
class PrimitiveFailure:
    """A typed primitive failure VALUE (never a propagated
    exception): the operation, the reason code, and the exception
    CLASS NAME only (LOCK-023 — no message text, no secret
    material in diagnostics)."""

    operation: str
    reason: str
    exception_class: str = ""

    def __post_init__(self) -> None:
        _require_text(self.operation, "operation")
        _require_text(self.reason, "reason")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "operation": self.operation,
            "reason": self.reason,
            "exception_class": self.exception_class,
        }


class IsolationPrimitive:
    """The neutral OS/network isolation primitive contract.

    Implementations (platform adapters, or the deterministic
    sandbox model in tests) own the ACTUAL mechanism.  Contract
    rules:

    - every method returns contract-shaped VALUES; an internal
      exception is converted to :class:`PrimitiveFailure` (class
      name only) and re-raised by the authority as a typed
      :class:`ContainmentError` — an escaping exception is
      fail-closed by the authority as ``UNEXPECTED_EXCEPTION``;
    - ``establish`` is the only scope-creation path;
    - ``verify`` produces the verification proof FROM the
      mechanism's own observation (never from caller claims);
    - ``decide`` answers reachability from the enforced scope;
    - ``scope_exists``/``bytes_observed`` are read-only public
      observations (byte COUNTS only — never payload content);
    - ``teardown`` destroys the scope at the primitive level;
    - ``simulate_scope_loss`` exists ONLY on failure-injection
      implementations (the sandbox); the abstract contract does
      not carry it — real platform scopes are lost by the OS, not
      by callers.
    """

    def establish(self, spec: ScopeSpec, *, at: str) -> ScopeEstablishment:
        raise NotImplementedError

    def verify(self, scope_ref: str, *, at: str) -> VerificationProof:
        raise NotImplementedError

    def decide(self, scope_ref: str, destination: str) -> ReachabilityDecision:
        raise NotImplementedError

    def scope_exists(self, scope_ref: str) -> bool:
        raise NotImplementedError

    def bytes_observed(self, scope_ref: str) -> int:
        """Bytes counted AT the scope boundary (integer frame/byte
        accounting only; payload content is never read)."""
        raise NotImplementedError

    def teardown(self, scope_ref: str, *, at: str) -> TeardownResult:
        raise NotImplementedError


__all__ = [
    "ScopeSpec",
    "ScopeEstablishment",
    "DenyProbe",
    "VerificationProof",
    "ReachabilityDecision",
    "TeardownResult",
    "PrimitiveFailure",
    "IsolationPrimitive",
    "MANDATORY_DENIED_PROBE_DESTINATIONS",
]
