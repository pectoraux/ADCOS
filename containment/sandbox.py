"""WORK-048 deterministic sandbox isolation primitive (SOFTWARE).

The deterministic reference implementation of the neutral
:class:`~containment.isolation.IsolationPrimitive` contract.  It
models, in software, what a real OS/network isolation scope
(netns + nftables egress allow-list, VRF, VpnService, Network
Extension) REPORTS to the containment authority:

- ``establish`` creates a scope record with an enforced egress
  allow-list and local-service exposure set, and answers with the
  platform-observed establishment facts;
- ``verify`` re-OBSERVES the scope (exists, allow-list active) and
  executes the deny-probe matrix THROUGH the scope's own decision
  path, proving deny-by-default from the mechanism side;
- ``decide`` answers reachability from the enforced scope state;
- ``bytes_observed`` counts integer bytes at the boundary (payload
  content is never read — there is no payload representation
  anywhere in this model);
- ``teardown`` destroys the scope at the primitive level;
- failure injection (deterministic): ``fail_next_establish``,
  ``fail_next_verify``, ``simulate_scope_loss``,
  ``set_step_budget`` — the battery's failure-injection surface.

EVIDENCE-CLASS HONESTY (frozen): this sandbox is SOFTWARE-class
evidence only.  It proves the mechanism contract and the
deterministic enforcement semantics; it does NOT prove physical
containment on any real device/network (ACR-012 §5; the
evidence-class disclosure in docs/WORK-048-evidence.md).  A
physical claim requires adapter implementations on real platforms
and remains OPEN until physically demonstrated.

Determinism: scope refs are content-derived; the step budget is
the deterministic hang model (no wall clock — the transport
sandbox discipline); iteration is sorted; identical inputs
produce byte-identical establishment/proof records.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Tuple

from protocol.canonicalization import canonical_json_bytes

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

#: The default deterministic step budget (the hang model).
DEFAULT_STEP_BUDGET = 1024


class _SandboxScope:
    """The internal scope record (established, enforcing, counting)."""

    __slots__ = (
        "scope_ref", "boundary_id", "mechanism", "allowlist",
        "local_services", "established_at", "bytes", "destroyed",
    )

    def __init__(
        self,
        scope_ref: str,
        boundary_id: str,
        mechanism: str,
        allowlist: Tuple[str, ...],
        local_services: Tuple[str, ...],
        established_at: str,
    ) -> None:
        self.scope_ref = scope_ref
        self.boundary_id = boundary_id
        self.mechanism = mechanism
        self.allowlist = allowlist
        self.local_services = local_services
        self.established_at = established_at
        self.bytes = 0
        self.destroyed = False


class SandboxedIsolationPrimitive(IsolationPrimitive):
    """The deterministic software model of the platform mechanism."""

    def __init__(self) -> None:
        self._scopes: Dict[str, _SandboxScope] = {}
        self._step_budget = DEFAULT_STEP_BUDGET
        self._steps_used = 0
        self._fail_next_establish = False
        self._fail_next_verify = False
        self._raise_next_establish: str = ""
        self._raise_next_verify: str = ""

    # ------------------------------------------------------------------
    # Failure injection (deterministic, battery-only)
    # ------------------------------------------------------------------

    def fail_next_establish(self) -> None:
        """The next ``establish`` fails closed (typed primitive
        failure — the primitive cannot be established)."""
        self._fail_next_establish = True

    def fail_next_verify(self) -> None:
        """The next ``verify`` returns an unproving observation
        (scope exists but the allow-list observation failed)."""
        self._fail_next_verify = True

    def raise_next_establish(self, exception_class: str) -> None:
        """The next ``establish`` RAISES (the unmodeled-exception
        fail-closed battery vector)."""
        self._raise_next_establish = exception_class

    def raise_next_verify(self, exception_class: str) -> None:
        """The next ``verify`` RAISES."""
        self._raise_next_verify = exception_class

    def simulate_scope_loss(self, scope_ref: str) -> None:
        """The OS destroys the scope mid-session (isolation lost):
        deterministic isolation-loss injection."""
        scope = self._scopes.get(scope_ref)
        if scope is not None:
            scope.destroyed = True

    def set_step_budget(self, budget: int) -> None:
        if not isinstance(budget, int) or isinstance(budget, bool) or budget < 0:
            raise ContainmentError(
                ContainmentReasonCode.SANDBOX_INVALID,
                "step budget must be a non-negative integer",
            )
        self._step_budget = budget

    def steps_used(self) -> int:
        return self._steps_used

    def _charge(self, operation: str) -> None:
        self._steps_used += 1
        if self._steps_used > self._step_budget:
            raise ContainmentError(
                ContainmentReasonCode.SANDBOX_INVALID,
                "sandbox step budget exhausted during %r (the "
                "deterministic hang model; no wall clock exists here)"
                % operation,
            )

    # ------------------------------------------------------------------
    # The primitive contract
    # ------------------------------------------------------------------

    def _derive_scope_ref(self, spec: ScopeSpec) -> str:
        content = {
            "boundary_id": spec.boundary_id,
            "mechanism": spec.mechanism,
            "spec_digest": spec.spec_digest(),
        }
        return "scope-" + hashlib.sha256(
            canonical_json_bytes(content)
        ).hexdigest()[:32]

    def establish(self, spec: ScopeSpec, *, at: str) -> ScopeEstablishment:
        if not isinstance(spec, ScopeSpec):
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "establish requires a ScopeSpec",
            )
        self._charge("establish")
        if self._fail_next_establish:
            self._fail_next_establish = False
            raise ContainmentError(
                ContainmentReasonCode.ISOLATION_UNAVAILABLE,
                "the platform primitive could not establish the isolation "
                "scope (deterministic injection; the boundary cannot leave "
                "prepared and NO buyer traffic is admitted)",
            )
        if self._raise_next_establish:
            raise self._injected(self._raise_next_establish)
        scope_ref = self._derive_scope_ref(spec)
        existing = self._scopes.get(scope_ref)
        if existing is not None and not existing.destroyed:
            # idempotent re-establishment of the identical scope
            return ScopeEstablishment(
                scope_ref=scope_ref,
                boundary_id=existing.boundary_id,
                mechanism=existing.mechanism,
                enforcement_digest=self._enforcement_digest(existing),
                established_at=existing.established_at,
                enforced_allowlist=existing.allowlist,
                enforced_local_services=existing.local_services,
            )
        scope = _SandboxScope(
            scope_ref=scope_ref,
            boundary_id=spec.boundary_id,
            mechanism=spec.mechanism,
            allowlist=spec.allowed_egress,
            local_services=spec.exposed_local_services,
            established_at=at,
        )
        self._scopes[scope_ref] = scope
        return ScopeEstablishment(
            scope_ref=scope_ref,
            boundary_id=scope.boundary_id,
            mechanism=scope.mechanism,
            enforcement_digest=self._enforcement_digest(scope),
            established_at=scope.established_at,
            enforced_allowlist=scope.allowlist,
            enforced_local_services=scope.local_services,
        )

    def verify(self, scope_ref: str, *, at: str) -> VerificationProof:
        self._charge("verify")
        if self._raise_next_verify:
            raise self._injected(self._raise_next_verify)
        scope = self._scopes.get(scope_ref)
        exists = scope is not None and not scope.destroyed
        probes = self._deny_probes(scope) if scope is not None else ()
        allowlist_active = (
            exists and not self._fail_next_verify
        )
        if self._fail_next_verify:
            self._fail_next_verify = False
        return VerificationProof(
            scope_ref=scope_ref,
            scope_exists=exists,
            allowlist_active=allowlist_active,
            deny_probes=probes,
            observed_at=at,
            mechanism=scope.mechanism if scope is not None else "",
        )

    def decide(self, scope_ref: str, destination: str) -> ReachabilityDecision:
        self._charge("decide")
        scope = self._scopes.get(scope_ref)
        if scope is None or scope.destroyed:
            # a nonexistent scope is TOTAL denial (fail closed):
            # nothing is reachable through a destroyed boundary
            return ReachabilityDecision(
                destination=destination, allowed=False,
            )
        allowed = (
            destination in scope.allowlist
            or destination in scope.local_services
        )
        return ReachabilityDecision(destination=destination, allowed=allowed)

    def scope_exists(self, scope_ref: str) -> bool:
        scope = self._scopes.get(scope_ref)
        return scope is not None and not scope.destroyed

    def bytes_observed(self, scope_ref: str) -> int:
        """Integer byte counts observed AT the boundary.  Payload
        content does not exist in this model — there is nothing to
        inspect and no inspection API (NO PLAINTEXT INSPECTION)."""
        scope = self._scopes.get(scope_ref)
        if scope is None:
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "scope %r does not exist (bytes are unobservable: "
                "quota accounting fails closed)" % scope_ref[:23],
            )
        return scope.bytes

    def account(self, scope_ref: str, byte_count: int) -> int:
        """Count ``byte_count`` integer bytes crossing the scope
        boundary (the metering seam used by the sharing runtime
        while the scope enforces reachability).  Byte COUNTS only:
        no payload is represented, read, or interpreted."""
        scope = self._scopes.get(scope_ref)
        if scope is None:
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "scope %r does not exist (accounting fails closed)"
                % scope_ref[:23],
            )
        if not isinstance(byte_count, int) or isinstance(byte_count, bool) or byte_count < 0:
            raise ContainmentError(
                ContainmentReasonCode.INVALID_INPUT,
                "byte_count must be a non-negative integer (byte "
                "accounting operates on counts, never payload content)",
            )
        if scope.destroyed:
            raise ContainmentError(
                ContainmentReasonCode.ISOLATION_LOST,
                "scope %r was destroyed: no bytes may be admitted "
                "(fail closed)" % scope_ref[:23],
            )
        scope.bytes += byte_count
        return scope.bytes

    def teardown(self, scope_ref: str, *, at: str) -> TeardownResult:
        self._charge("teardown")
        scope = self._scopes.get(scope_ref)
        if scope is None:
            return TeardownResult(
                scope_ref=scope_ref, destroyed=True, torn_down_at=at,
            )
        scope.destroyed = True
        return TeardownResult(
            scope_ref=scope_ref, destroyed=True, torn_down_at=at,
        )

    # ------------------------------------------------------------------
    # Internals (deterministic)
    # ------------------------------------------------------------------

    def _enforcement_digest(self, scope: _SandboxScope) -> str:
        content = {
            "scope_ref": scope.scope_ref,
            "mechanism": scope.mechanism,
            "allowlist": list(scope.allowlist),
            "local_services": list(scope.local_services),
        }
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(content)
        ).hexdigest()

    def _deny_probes(self, scope: _SandboxScope) -> Tuple[DenyProbe, ...]:
        """The mechanism's own probe matrix over the enforced scope:
        every allowed destination proves ALLOWED, and a fixed
        denied-destination set proves DENIED — decisions produced
        by the scope's decision path (decided_by=platform-scope),
        never by a caller declaration."""
        probes = []
        for destination in scope.allowlist + scope.local_services:
            decision = self.decide(scope.scope_ref, destination)
            if not decision.allowed:
                # the enforced scope must allow its own allow-list
                raise ContainmentError(
                    ContainmentReasonCode.SANDBOX_INVALID,
                    "the sandbox scope denied its own allow-list entry "
                    "%r (internal inconsistency)" % destination[:23],
                )
            probes.append(
                DenyProbe(
                    destination=destination,
                    decision="allowed",
                    decided_by="platform-scope",
                )
            )
        for destination in (
            "provider-control-plane",
            "provider-admin-services",
            "provider-private-lan",
            "unrelated-local-service",
        ):
            if destination in scope.allowlist or destination in scope.local_services:
                continue
            decision = self.decide(scope.scope_ref, destination)
            if decision.allowed:
                raise ContainmentError(
                    ContainmentReasonCode.SANDBOX_INVALID,
                    "the sandbox scope allowed a denied destination %r "
                    "(deny-by-default violated by the mechanism model)"
                    % destination,
                )
            probes.append(
                DenyProbe(
                    destination=destination,
                    decision="denied",
                    decided_by="platform-scope",
                )
            )
        return tuple(probes)

    def _injected(self, exception_class: str) -> Exception:
        """An injected unmodeled exception of the named class.  The
        authority converts it to a typed fail-closed denial carrying
        the CLASS NAME only (LOCK-023)."""

        class _Injected(Exception):
            pass

        _Injected.__name__ = exception_class
        return _Injected("injected %s" % exception_class)


__all__ = ["SandboxedIsolationPrimitive", "DEFAULT_STEP_BUDGET"]
