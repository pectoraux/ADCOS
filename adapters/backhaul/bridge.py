"""ADCOS backhaul technology adapter bridge (WORK-022): the adapter
translation layer onto the accepted WORK-016 Adapter SDK.

:class:`BackhaulTechnologyAdapter` IMPLEMENTS the WORK-016 SDK's
frozen nine-operation :class:`adapters.contract.AdapterContract` over
the backhaul family's RUNTIME -- the
:class:`adapters.backhaul.manager.BackhaulManager` -- NEVER over a
raw :class:`BackhaulContract` implementation.  This is how the
backhaul family USES the accepted WORK-016 Adapter SDK rather than
inventing a second adapter framework: the generic core-side surface
stays the SDK's; the backhaul-specific vocabulary (link provisioning,
capacity allocation, session bearers, endpoint binding) stays inside
the backhaul family's own seam -- exactly as the accepted WORK-019
5G-Core and WORK-021 Wi-Fi families keep their vocabularies behind
their contracts.

The Architect-anchored layering (the WORK-022 brief)::

    W016 Adapter Runtime
            |
    BackhaulTechnologyAdapter (this module: thin translation ONLY)
            |
    BackhaulManager          (the family runtime)
            |
    SandboxedBackhaul        (the family failure-isolation mediator)
            |
    BackhaulContract implementation

The bridge holds a reference to the MANAGER and NOTHING else.  It
never holds, invokes, inspects, or duck-types the concrete
implementation: every one of the nine SDK operations translates onto
the manager's public API, which mediates each call through the owning
:class:`~adapters.backhaul.sandbox.SandboxedBackhaul`
(BaseException isolation, contract-shape validation, backhaul
identity validation, deterministic per-operation step charging).
There is NO path from the SDK surface around the family mediator --
structurally, because the bridge cannot call a concrete
implementation (it holds no reference to one), and the sandbox
exposes no capability-escape surface onto the implementation.

Budget note: the SDK runtime wraps this bridge in the SDK's own
sandbox (WORK-016) and charges the SDK layer's generic budget; the
family mediator charges the family's own frozen
:data:`~adapters.backhaul.sandbox.STEP_CHARGES` per translated
operation.  The two budgets are independent authorities at their own
layers, exactly as in the WORK-021 bridge.

Session verification note (honest): the SDK's least-authority
:class:`AdapterContext` deliberately carries NO session-store
reference, and the WORK-016 runtime performs the read-only WORK-012
bindability verification BEFORE an adapter is invoked
(``AdapterRuntime.bind_session``).  The family-side session
verification is the MANAGER's -- the composition root injects the
read-only :class:`~adapters.backhaul.contract.SessionReader` facade
into the manager, and the manager's sandbox hands it to the
implementation inside the mediated
:class:`~adapters.backhaul.contract.BackhaulContext`.  The bridge
therefore asserts NO session facts of its own: it fabricates no
reader, echoes no secureability, and invents no endpoint node ids.

IP delegation note (the W022 brief): the bridge carries NO IPv6/IP/NAT
translation -- ordinary IP semantics are the accepted WORK-018 IP
integration layer's authority.  The backhaul bearer carries
frames/bytes between endpoints; IP addressing, prefix delegation, and
NAT/IPv4 compatibility never appear at this seam (LOCK-002/016: no
second IP authority).

Routing note (the W022 brief): the bridge accepts an optional
``path_ref`` (a WORK-011 content-derived path fingerprint) as caller
DATA through the requirements map and forwards it verbatim to the
family runtime, which records it on the binding -- it never
re-derives, scores, or branches on paths (no second routing/scoring
engine; WORK-011 stays the single routing authority).
"""

from __future__ import annotations

from typing import Any, Mapping, Optional, Sequence

from ..contract import AdapterContext, AdapterContract

from .errors import BackhaulError, BackhaulReasonCode
from .manager import BackhaulManager
from .model import LinkDescriptor, LinkMetricName
from .engine import RATE_KINDS_BPS

__all__ = ["BackhaulTechnologyAdapter"]


#: The bridge-fixed backhaul technology PROFILE for bridge-provisioned
#: links (Ethernet -- IEEE 802.3-2018; the family's frozen profile
#: vocabulary).  The SDK allocate surface carries a WORK-008 resource
#: KIND (not a technology classification), so the profile choice is
#: bridge-fixed, never caller-influenced, and honest -- a concrete
#: adapter with real element knowledge maps its own technology
#: profiles behind the seam; family-native callers (through the
#: manager) provision any of the four profiles explicitly.
_BRIDGE_PROFILE = "ethernet"

#: The fixed credential slot NAME the bridge provisions link profiles
#: under (LOCK-023: a slot NAME only -- the credential MATERIAL stays
#: in the adapter's private store; the SDK allocate surface carries no
#: credential-slot naming, so the bridge uses this documented constant
#: and never sees material).
_BRIDGE_CREDENTIAL_SLOT = "backhaul-technology-credentials"

#: The fixed endpoint LABEL the bridge provisions on its links and
#: associates its bearers on (adapter-side opaque DATA; deliberately
#: NOT derived from the session_id -- the identity axes never
#: collapse -- and validated by the family's endpoint-label grammar
#: at the implementation seam).  The SDK allocate surface carries no
#: port parameters; the choice is bridge-fixed, never
#: caller-influenced, and honest -- a concrete adapter with real
#: port knowledge maps its own endpoints behind the seam.
_BRIDGE_ENDPOINT_LABEL = "backhaul-sdk-endpoint"

#: The bridge-fixed concurrent-bearer bound for bridge-provisioned
#: links (documented default; the SDK allocate surface carries no
#: bearer-count parameter; a production element's own table sizes
#: live behind the seam).
_BRIDGE_MAX_BEARERS = 64

#: Requirement keys the bridge reads as the caller-supplied backhaul
#: binding coordinates in ``bind_session`` (the generic SDK surface
#: has no link-selection parameter, so the caller passes the
#: provisioned ``link_ref`` -- and optionally the ``endpoint_label``
#: and the WORK-011 ``path_ref`` -- through the requirements map;
#: DATA only, never identity).  The bridge CONSUMES these keys as its
#: documented translation (they become the manager's explicit
#: ``link_ref`` / ``endpoint_label`` / ``path_ref`` parameters) and
#: forwards only the LEFTOVER requirements map -- so the manager's
#: identity-smuggling gate sees a clean QoS-data map, and a
#: duplicate/override attempt still fails closed there.
_REQUIREMENT_LINK_REF = "link_ref"
_REQUIREMENT_ENDPOINT_LABEL = "endpoint_label"
_REQUIREMENT_PATH_REF = "path_ref"
_BRIDGE_REQUIREMENT_KEYS = (
    _REQUIREMENT_LINK_REF,
    _REQUIREMENT_ENDPOINT_LABEL,
    _REQUIREMENT_PATH_REF,
)


class BackhaulTechnologyAdapter(AdapterContract):
    """The WORK-016 SDK adapter over the backhaul family RUNTIME (the
    :class:`~adapters.backhaul.manager.BackhaulManager`).

    Constructed with the manager (which must already -- or before
    first use -- have a default implementation registered: the
    composition root wires ``register_implementation`` BEFORE the SDK
    runtime opens this bridge) and an informational label.  Subclasses
    the accepted SDK's :class:`adapters.contract.AdapterContract`
    (isinstance-enforced) and satisfies its frozen
    ``CONTRACT_OPERATIONS`` surface; each SDK operation translates
    onto the MANAGER's public API as documented in the module
    docstring, so every call traverses the family's sandboxed
    mediator.  The bridge owns NO state beyond the manager reference
    and the label, holds NO implementation reference, and constructs
    NO contexts (the manager builds the least-authority
    :class:`~adapters.backhaul.contract.BackhaulContext` per mediated
    call).

    The nine-op translation (SDK -> family runtime):

    * ``open``            -> a mediated manager health probe (the
                             family backhaul path came up at manager
                             registration; SDK open VERIFIES it is
                             observable through the mediated path --
                             fail-closed when the manager has no
                             default implementation yet)
    * ``capabilities``    -> the manager's informational capability
                             ladder (derived from mediated manager
                             state: the boundary caps once an
                             implementation is registered; the
                             data-path cap once a link is provisioned
                             through the manager)
    * ``observe``         -> the mediated manager health aggregate
                             projected onto the generic link-metric
                             vocabulary (link-up mirrors whether the
                             backhaul path can carry; counters are
                             honestly zero -- the frozen family
                             contract's per-link observation is a
                             family-native op the SDK surface has no
                             link parameter for, so nothing is
                             fabricated)
    * ``allocate``        -> manager ``provision_link`` (the
                             technology resource allocation; the
                             opaque ``backhaul:link:<hex>`` ref is
                             the technology_ref; ``kind`` is the
                             WORK-008 rate kind whose integer base
                             unit is bps (``bandwidth``/``backhaul``
                             -- the family validates it against the
                             same WORK-008 vocabulary by reference),
                             ``quantity_base`` is the link capacity
                             in those bps base units, and ``purpose``
                             names the link; the technology profile
                             is the documented bridge-fixed default)
    * ``release``         -> the family runtime release op for the
                             ref's kind (``release`` for allocation
                             refs; ``close_link`` for link refs --
                             which fails closed while the link has
                             outstanding bearers/allocations;
                             ``unbind_session`` for bearer refs -- the
                             same mediated teardown unbind carries)
    * ``bind_session``    -> manager ``bind_session`` (mediated); the
                             opaque ``backhaul:bearer:<hex>`` bearer
                             ref is the SDK bearer_ref
    * ``unbind_session``  -> manager ``unbind_session`` (mediated;
                             the manager's bearer index routes the
                             teardown to the OWNING binding's sandbox
                             -- B2)
    * ``health``          -> the manager's instant-free
                             ``computed_health`` (mediated outcomes),
                             translated onto the SDK's frozen
                             three-state vocabulary
    * ``close``           -> honest no-op at this seam (the frozen
                             family contract expresses close PER
                             LINK; the manager's lifecycle belongs to
                             the composition root, not to the SDK
                             bridge)
    """

    def __init__(
        self,
        manager: BackhaulManager,
        *,
        label: str = "backhaul-technology",
    ) -> None:
        if not isinstance(manager, BackhaulManager):
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "manager must be a BackhaulManager (the bridge adapts "
                "the family RUNTIME -- it never holds a BackhaulContract "
                "implementation reference; register the implementation "
                "with the manager, then construct the bridge over the "
                "manager)",
            )
        if not isinstance(label, str) or not label:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "label must be a non-empty string",
            )
        self._manager = manager
        # Informational only (the SDK contract's label discipline):
        # never parsed, never branched on, never canonical state.
        self.label = label

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _raise_failure(operation: str, detail: str) -> None:
        """Re-raise an isolated family-mediated failure as the
        family's typed error so the SDK sandbox isolates it (the SDK
        captures the exception CLASS NAME, never message text --
        LOCK-023; the family mediator already recorded the full typed
        failure).  Never returns."""
        raise BackhaulError(
            BackhaulReasonCode.BACKHAUL_FAILURE,
            "mediated backhaul family %s failed (%s); the family "
            "sandbox recorded the typed failure" % (operation, detail),
        ) from None

    def _require_ok(self, operation: str, result: Any) -> Any:
        """Require a mediated manager result to be ok; return its
        validated value (the family sandbox already validated the
        contract shape and the W022 identity invariants)."""
        if not getattr(result, "ok", False):
            self._raise_failure(
                operation, getattr(result, "detail", "") or "isolated failure"
            )
        return result.value

    @staticmethod
    def _ref_kind(technology_ref: str) -> str:
        """Parse the KIND segment of the family's opaque ref grammar
        (``backhaul:(link|bearer|alloc):<hex>``).

        A non-ref-shaped input is a caller input error (the full
        grammar, including the 32-lowercase-hex tail, is validated at
        the implementation seam by the family's own validators).
        """
        if not isinstance(technology_ref, str) or not technology_ref:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "technology_ref must be a non-empty string",
            )
        segments = technology_ref.split(":")
        if len(segments) != 3 or segments[0] != "backhaul":
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "technology_ref must match "
                "backhaul:(link|bearer|alloc):<hex>",
            )
        return segments[1]

    # ------------------------------------------------------------------
    # The nine frozen WORK-016 SDK operations
    # ------------------------------------------------------------------

    def open(self, context: AdapterContext) -> None:
        """SDK ``open`` -> a MEDIATED verification that the family
        backhaul path is up.

        The backhaul implementation was brought up at manager
        registration (``register_implementation`` opens it and probes
        health through the sandbox).  SDK open therefore VERIFIES,
        through the same mediated path, that the backhaul path is
        observable: one mediated manager health probe.  A manager with
        no default implementation yet fails closed (the caller-side
        ``BACKHAUL_UNAVAILABLE`` state error propagates and the SDK
        sandbox isolates it); a probe that reports a down aggregate
        (e.g. the honest FAILED-for-empty-link-store ladder) is a
        SUCCESSFUL probe of real state -- only a mediated probe FAULT
        fails the open.
        """
        self._require_ok("open", self._manager.health(now=context.now()))

    def capabilities(self) -> Sequence[str]:
        """SDK ``capabilities`` -> the manager's informational
        capability ladder (derived from MEDIATED manager state).

        The ladder reports exactly what the family runtime can see:
        ``()`` with no default implementation registered; the three
        boundary capabilities once one is; the data-path capability
        once the manager's mediated history shows a provisioned link.
        The bridge mints no capability references of its own (exposure
        by reference into WORK-005 registry semantics is never
        rewritten; the SDK runtime filters to the descriptor's
        declared set).
        """
        return self._manager.capabilities()

    def observe(self, context: AdapterContext) -> Mapping[str, int]:
        """SDK ``observe`` -> the mediated family health aggregate
        projected onto the GENERIC link metrics.

        Honest translation (the SDK observe surface has no link
        parameter, so the per-link metric observation is a
        family-native manager op -- ``observe_link`` -- the SDK caller
        cannot name a link for; the bridge translates the one family
        surface that IS parameterless and mediated, the health
        aggregate): ``HEALTHY`` (at least one ACTIVE link can carry --
        the backhaul path exists and can bear a bearer) maps to
        ``link-up: 1``; every other state (``NOT_RUNNING`` before
        registration, ``FAILED`` with an empty link store,
        ``DEGRADED`` with every link deactivated) maps to the honest
        link-DOWN sample -- ``link-up: 0`` with all-zero counters --
        exactly what the SDK's :class:`adapters.contract.
        GenericAdapter` reports for a down/unpopulated technology, so
        an adapter registered before any link is provisioned still
        satisfies the nine-op surface without fabricating access
        state.  Per-link byte/error/retransmit counters stay inside
        the implementation (there is no per-link source at this
        seam): they are reported as honest zeros through the generic
        metric vocabulary (metric name -> non-negative int; nothing
        fabricated, nothing dropped).
        """
        health = self._require_ok(
            "observe", self._manager.health(now=context.now())
        )
        if not isinstance(health, str) or health not in (
            "HEALTHY", "DEGRADED", "FAILED", "NOT_RUNNING",
        ):
            raise BackhaulError(
                BackhaulReasonCode.CONTRACT_VIOLATION,
                "health must report the frozen vocabulary (the bridge "
                "translates; it does not fabricate metrics)",
            )
        link_up = 1 if health == "HEALTHY" else 0
        return {
            LinkMetricName.LINK_UP: link_up,
            LinkMetricName.RX_BYTES_TOTAL: 0,
            LinkMetricName.TX_BYTES_TOTAL: 0,
            LinkMetricName.RX_ERROR_COUNT: 0,
            LinkMetricName.TX_ERROR_COUNT: 0,
            LinkMetricName.RETRANSMIT_COUNT: 0,
        }

    def allocate(
        self,
        context: AdapterContext,
        *,
        kind: str,
        quantity_base: int,
        purpose: str,
    ) -> str:
        """SDK ``allocate`` -> manager ``provision_link`` (the
        technology resource allocation, MEDIATED).

        The backhaul family's technology resource allocation IS the
        provisioned link: the bridge deterministically maps the
        generic allocation request onto a
        :class:`~adapters.backhaul.model.LinkDescriptor` -- the
        caller's ``purpose`` names the link profile, the resource
        ``kind`` is the WORK-008 rate kind whose integer base unit is
        bps (``bandwidth``/``backhaul`` -- the family validates it
        against the SAME WORK-008 vocabulary by reference, never a
        second registry), ``quantity_base`` is the link capacity in
        those bps base units, and the technology PROFILE is the
        documented bridge-fixed default (``_BRIDGE_PROFILE``; the SDK
        surface carries a resource kind, not a technology
        classification -- family-native callers provision any of the
        four profiles explicitly through the manager).  The endpoint
        label and the bearer bound are the documented bridge-fixed
        defaults (see the module constants; the SDK surface carries no
        port parameters and the bridge claims no element-management
        authority).  Returns the implementation's OPAQUE
        ``backhaul:link:<hex>`` ref -- never core state.
        """
        if not isinstance(kind, str) or not kind:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "kind must be a non-empty string (the WORK-008 rate kind "
                "whose base unit is bps: bandwidth/backhaul)",
            )
        # Fail closed EARLY on a resource kind the family grammar
        # rejects (an honest caller error surfaces before any mediated
        # call; the family re-asserts it at the implementation seam
        # against the SAME WORK-008 vocabulary).
        if kind not in RATE_KINDS_BPS:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "kind must be one of the WORK-008 bps-based rate kinds "
                "%s (canonical resource units reused by reference; the "
                "link capacity maps into exactly these kinds)"
                % (list(RATE_KINDS_BPS),),
            )
        if not isinstance(purpose, str) or not purpose:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "purpose must be a non-empty string (it names the link "
                "profile)",
            )
        if isinstance(quantity_base, bool) or not isinstance(
            quantity_base, int
        ):
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "quantity_base must be an integer (the link capacity in "
                "WORK-008 bps base units)",
            )
        descriptor = LinkDescriptor(
            name=purpose,
            profile=_BRIDGE_PROFILE,
            capacity_bps=quantity_base,
            max_bearers=_BRIDGE_MAX_BEARERS,
            endpoint_labels=(_BRIDGE_ENDPOINT_LABEL,),
        )
        link_view = self._require_ok(
            "allocate",
            self._manager.provision_link(
                now=context.now(),
                descriptor=descriptor,
                credential_slot_name=_BRIDGE_CREDENTIAL_SLOT,
            ),
        )
        # The family sandbox validated the LinkView contract shape.
        return link_view.link_ref

    def release(self, context: AdapterContext, technology_ref: str) -> None:
        """SDK ``release`` -> the family runtime release op for the
        ref's kind.

        The bridge parses the KIND segment of its own family's opaque
        ref grammar (``backhaul:(link|bearer|alloc):<hex>``) and
        dispatches: an ALLOCATION ref releases the capacity
        reservation through the manager (``release`` -- the manager's
        allocation index routes it to the OWNING sandbox, B2); a LINK
        ref decommissions the link through the manager
        (``close_link`` -- which fails closed while the link has
        outstanding bearers or allocations); a BEARER ref tears the
        session bearer down through the manager (``unbind_session``
        -- the same mediated teardown the SDK unbind carries; the
        bridge refuses to silently drop what it cannot translate).
        """
        kind = self._ref_kind(technology_ref)
        if kind == "alloc":
            self._require_ok(
                "release",
                self._manager.release(
                    now=context.now(), allocation_ref=technology_ref
                ),
            )
            return
        if kind == "link":
            self._require_ok(
                "release",
                self._manager.close_link(
                    now=context.now(), link_ref=technology_ref
                ),
            )
            return
        # kind == "bearer": the mediated bearer teardown (the same
        # one unbind_session carries).
        self._require_ok(
            "release",
            self._manager.unbind_session(
                now=context.now(), bearer_ref=technology_ref
            ),
        )

    def bind_session(
        self,
        context: AdapterContext,
        *,
        session_id: str,
        requirements: Optional[Mapping[str, Any]],
    ) -> str:
        """SDK ``bind_session`` -> manager ``bind_session`` (MEDIATED
        through the link's owning sandbox).

        The sacred ``session_id`` crosses EXACTLY as given (read-only
        passthrough identity -- never mutated, never re-derived,
        LOCK-006; the family mediator mechanically checks every
        returned ref against it, and the manager re-asserts the
        requirements-map and cross-binding identity guards).  The
        caller-supplied ``requirements`` DATA must carry the backhaul
        binding coordinates -- ``link_ref`` (the opaque
        ``backhaul:link:<hex>`` technology ref returned by
        ``allocate``); ``endpoint_label`` and ``path_ref`` (a WORK-011
        path fingerprint, consumed as opaque DATA) are optional (the
        documented bridge-fixed defaults otherwise -- an omitted
        endpoint label falls back to the one the bridge provisioned
        on its links) -- because the generic SDK surface has no
        link-selection parameter.  The bridge CONSUMES those keys
        (they become the manager's explicit binding parameters) and
        forwards only the leftover requirements map, which the
        manager's identity-smuggling gate screens like any caller's.
        The return is the OPAQUE ``backhaul:bearer:<hex>`` bearer ref
        (the SDK bearer for this family) -- backhaul-side identity,
        never ADCOS authority and never the ``session_id`` itself.
        """
        if not isinstance(session_id, str) or not session_id:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "session_id must be a non-empty string",
            )
        link_ref, endpoint_label, path_ref, forwarded = (
            self._binding_coordinates(requirements)
        )
        binding = self._require_ok(
            "bind_session",
            self._manager.bind_session(
                now=context.now(),
                session_id=session_id,
                link_ref=link_ref,
                endpoint_label=endpoint_label,
                path_ref=path_ref,
                requirements=forwarded,
            ),
        )
        # The family sandbox validated the BackhaulBinding shape and
        # re-asserted the W022 ref/session separation.  The family
        # model enforced the separation at BackhaulBinding
        # construction (session_id is hash INPUT only, never ref
        # text) and the sandbox seam re-asserted it against THIS
        # call's session_id -- the bridge returns the handle verbatim
        # and echoes nothing of the session.
        return binding.bearer_ref

    def unbind_session(self, context: AdapterContext, bearer_ref: str) -> None:
        """SDK ``unbind_session`` -> manager ``unbind_session``
        (MEDIATED; the manager's bearer index routes the teardown to
        the OWNING binding's sandbox -- B2).

        The SDK bearer for this family is the backhaul bearer
        (``backhaul:bearer:<hex>``), so the unbind tears down exactly
        that bearer.  A re-bind of the same session through this
        surface requires the release first -- a backhaul change is a
        REPLACEMENT after release, never a duplication.
        """
        kind = self._ref_kind(bearer_ref)
        if kind != "bearer":
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "bearer_ref must be a backhaul:bearer:<hex> opaque ref "
                "(the SDK bearer for this family is the backhaul "
                "session bearer)",
            )
        self._require_ok(
            "unbind_session",
            self._manager.unbind_session(
                now=context.now(), bearer_ref=bearer_ref
            ),
        )

    def health(self) -> str:
        """SDK ``health`` -> the manager's instant-free
        ``computed_health`` (mediated outcomes), translated onto the
        SDK's frozen three-state vocabulary.

        The SDK contract's health vocabulary is HEALTHY / DEGRADED /
        FAILED -- it has no NOT_RUNNING state.  The family's honest
        not-running aggregate (no default implementation registered,
        or the sandbox not open yet) maps to FAILED -- exactly the
        convention the SDK's own :class:`adapters.contract.
        GenericAdapter` uses for a not-open technology (a technology
        that is not up honestly cannot carry).  Reported, never
        authoritative by itself (LOCK-017: the SDK runtime computes
        the effective health from mediated outcomes -- and so does the
        family manager this reads from).
        """
        health = self._manager.computed_health()
        if health == "NOT_RUNNING":
            return "FAILED"
        return health

    def close(self, context: AdapterContext) -> None:
        """SDK ``close`` -> honest no-op at this seam.

        The frozen 11-op backhaul contract expresses close PER LINK
        (``close(context, link_ref)``); it carries NO
        technology-level shutdown operation (the reference engine's
        open flag retires with the instance).  The bridge therefore
        tears down NOTHING here: every bearer this bridge created is
        released per-bearer through ``unbind_session`` (and every
        capacity reservation through ``release``; every link through
        the ``close_link`` translation).  The MANAGER's lifecycle
        belongs to the composition root that constructed it -- the
        bridge adapts the manager, it does not own it, and it never
        yanks a shared family runtime out from under family-native
        callers as a side effect of an SDK adapter close.  Returning
        ``None`` keeps the nine-op surface satisfied without
        fabricating a teardown the family does not have.
        """

    # ------------------------------------------------------------------
    # Internal helpers (family-grammar parsing; no SDK imports)
    # ------------------------------------------------------------------

    @staticmethod
    def _binding_coordinates(
        requirements: Optional[Mapping[str, Any]],
    ) -> Any:
        """Read the caller-supplied backhaul binding coordinates from
        the SDK requirements map (DATA only -- never identity).

        ``link_ref`` is REQUIRED (the generic SDK surface has no
        link-selection parameter, so the caller names the provisioned
        link through the requirements map); ``endpoint_label`` falls
        back to the documented bridge-fixed default (the one the
        bridge provisions on its links); ``path_ref`` (a WORK-011 path
        fingerprint, consumed as opaque DATA) defaults to none.  The
        keys are CONSUMED by this translation (they become the
        manager's explicit binding parameters); the LEFTOVER
        requirements map is forwarded to the manager, whose
        identity-smuggling gate screens it fail-closed (a key that
        would re-identify the session or override the binding handles
        never reaches the implementation).  The coordinates themselves
        are validated by the family's own grammar validators at the
        implementation seam.
        """
        if not isinstance(requirements, Mapping):
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "bind_session requirements must be a mapping carrying "
                "the backhaul binding coordinates (link_ref from "
                "allocate) -- the generic SDK surface has no "
                "link-selection parameter",
            )
        link_ref = requirements.get(_REQUIREMENT_LINK_REF)
        endpoint_label = requirements.get(
            _REQUIREMENT_ENDPOINT_LABEL, _BRIDGE_ENDPOINT_LABEL
        )
        path_ref = requirements.get(_REQUIREMENT_PATH_REF, "")
        if not isinstance(link_ref, str) or not link_ref:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "requirements must carry a non-empty %r (the opaque "
                "backhaul:link:<hex> technology ref returned by "
                "allocate)" % _REQUIREMENT_LINK_REF,
            )
        if not isinstance(endpoint_label, str) or not endpoint_label:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "requirements %r must be a non-empty string when supplied"
                % _REQUIREMENT_ENDPOINT_LABEL,
            )
        if not isinstance(path_ref, str):
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "requirements %r must be a string when supplied (a "
                "WORK-011 path fingerprint or empty)" % _REQUIREMENT_PATH_REF,
            )
        forwarded = {
            key: value
            for key, value in requirements.items()
            if key not in _BRIDGE_REQUIREMENT_KEYS
        }
        # The coordinates are binding DATA forwarded as the manager's
        # explicit parameters; the session_id (the ONLY identity)
        # crossed above, read-only.
        return link_ref, endpoint_label, path_ref, forwarded
