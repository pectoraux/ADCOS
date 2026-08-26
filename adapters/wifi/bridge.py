"""ADCOS Wi-Fi/non-3GPP technology adapter bridge (WORK-021): the
adapter translation layer onto the accepted WORK-016 Adapter SDK.

:class:`WifiTechnologyAdapter` IMPLEMENTS the WORK-016 SDK's frozen
nine-operation :class:`adapters.contract.AdapterContract` over the
Wi-Fi family's RUNTIME -- the :class:`adapters.wifi.manager.WifiManager`
-- NEVER over a raw :class:`WifiContract` implementation.  This is how
the Wi-Fi/non-3GPP family USES the accepted WORK-016 Adapter SDK rather
than inventing a second adapter framework: the generic core-side
surface stays the SDK's; the Wi-Fi/non-3GPP-specific vocabulary (AP
provisioning, station association, 802.1X/SAE authentication, the
N3IWF tunnel, tunnel egress) stays inside the Wi-Fi family's own seam
-- exactly as the accepted WORK-019 5G-Core family keeps its
PDU-session/SUPI vocabulary behind ``FiveGCoreContract``.

The Architect's layering (verbatim)::

    W016 Adapter Runtime
            |
    WifiTechnologyAdapter      (this module: thin translation ONLY)
            |
    WifiManager               (the family runtime)
            |
    SandboxedWifi             (the family failure-isolation mediator)
            |
    WifiContract implementation

The bridge holds a reference to the MANAGER and NOTHING else.  It
never holds, invokes, inspects, or duck-types the concrete
implementation: every one of the nine SDK operations translates onto
the manager's public API, which mediates each call through the owning
:class:`~adapters.wifi.sandbox.SandboxedWifi` (BaseException
isolation, contract-shape validation, Wi-Fi identity validation,
deterministic per-operation step charging).  There is NO path from
the SDK surface around the family mediator -- structurally, because
the bridge has no implementation reference to take such a path with.

Composition (the application's wiring, not the bridge's)::

    manager = WifiManager(session_reader=..., ap_profile_reader=...)
    manager.register_implementation(
        implementation, label=..., make_default=True, now=...,
    )                      # opens + health-probes the implementation
    bridge = WifiTechnologyAdapter(manager, label=...)
    runtime.register(descriptor, bridge, now=...)

The implementation is registered with the manager FIRST (the family's
access path comes up at manager registration); the bridge is then
constructed over the manager and registered on the SDK runtime.
``bridge.open`` verifies through the mediated path that the family
access path is up (a mediated health probe) -- it does not (and
cannot) open the implementation itself.

Authority notes (every operation):

* The bridge (and the family runtime it adapts) is authoritative
  ONLY for the Wi-Fi/non-3GPP access state it controls -- its own
  AP/SSID/association/tunnel bookkeeping.  ADCOS remains
  authoritative for identity (WORK-004), topology (WORK-007),
  routing, policy, and session semantics (WORK-012): the bridge
  never mints, mutates, or re-derives any of them.
* The sacred, access-independent ``session_id`` (LOCK-006) crosses
  the bridge EXACTLY as given in ``bind_session`` -- a read-only
  passthrough, never mutated, never re-derived (LOCK-006; the W021
  identity invariant), and never echoed as a Wi-Fi handle.  The
  manager re-asserts the identity guards on every mediated bind.
* Every reference the bridge returns is an OPAQUE Wi-Fi-side handle
  minted by the implementation under the family's
  ``wifi:(ap|assoc|tunnel):<hex>`` grammar -- never the ``session_id``
  itself, never core state, never a re-derivation of either (the
  sandbox seam re-asserts the ref/session separation mechanically).
* The bridge owns NO state beyond the manager reference and the
  label.  It is a thin translation: it constructs no contexts,
  charges no steps, keeps no caches, and holds no implementation
  reference.

Mediation note (honest, and the reason this bridge adapts the
MANAGER): the bridge itself does no mediation of its own.  Failure
isolation and contract-shape enforcement happen INSIDE the Wi-Fi
family, because every bridge call routes manager -> SandboxedWifi ->
implementation (BaseException isolation, contract-shape validation,
the W021 identity re-assertion, deterministic per-operation step
charging against the frozen STEP_CHARGES table) -- and AGAIN at the
SDK layer, where the SDK's own
:class:`adapters.sandbox.SandboxedAdapter` mediates every bridge call
(the generic AdapterContract isolation).  The W016 sandbox
understands the generic contract; the family sandbox understands the
Wi-Fi domain's return shapes and identity invariants; the Wi-Fi
family used through this bridge loses NEITHER.  Wi-Fi-side
``WifiError`` reason codes cross the SDK seam only as far as the
SDK's isolation allows (the SDK captures the exception CLASS NAME,
never message text -- LOCK-023); full reason-code fidelity is
preserved at the Wi-Fi family's own mediator, which every bridge
call now traverses.

Budget note (honest): the bridge charges NOTHING and mints no
budget.  Deterministic step charging is the FAMILY mediator's job --
every manager call the bridge makes is mediated by the owning
``SandboxedWifi`` with the manager's step budget and the frozen
per-operation ``STEP_CHARGES``.  The SDK runtime's own budget still
bounds the bridge call at the SDK layer (the SDK sandbox's generic
accounting); the two budgets are independent authorities at their
own layers, exactly as in the WORK-016 model.

Session verification note (honest): the SDK's least-authority
:class:`AdapterContext` deliberately carries NO session-store
reference, and the WORK-016 runtime performs the read-only WORK-012
bindability verification BEFORE an adapter is invoked
(``AdapterRuntime.bind_session``).  The family-side session
verification is the MANAGER's -- the composition root injects the
read-only :class:`~adapters.wifi.contract.SessionReader` facade into
the manager, and the manager's sandbox hands it to the implementation
inside the mediated :class:`~adapters.wifi.contract.WifiContext`.  The
bridge therefore asserts NO session facts of its own: it fabricates
no reader, echoes no secureability, and invents no endpoint node ids
(the pre-redesign bridge's passthrough reader -- which echoed
``secureable=True`` for ANY session id -- is gone; a real session is
now really looked up by the family runtime, behind the seam).
"""

from __future__ import annotations

from typing import Any, Mapping, Optional, Sequence

from ..contract import AdapterContext, AdapterContract

from .errors import WifiError, WifiReasonCode
from .manager import WifiManager
from .model import (
    ApDescriptor,
    LinkMetricName,
    Non3GppAccessObservation,
    SecurityPolicy,
    SsidProfile,
)

__all__ = ["WifiTechnologyAdapter"]


#: The fixed credential slot NAME the bridge provisions AP profiles
#: under (LOCK-023: a slot NAME only -- the credential MATERIAL stays
#: in the adapter's private store; the SDK allocate surface carries no
#: credential-slot naming, so the bridge uses this documented constant
#: and never sees material).
_BRIDGE_CREDENTIAL_SLOT = "wifi-technology-credentials"

#: The fixed PHY band the bridge provisions on (IEEE 802.11-2020 5
#: GHz).  The SDK allocate surface carries no radio parameters; the
#: choice is bridge-fixed, never caller-influenced, and honest -- a
#: concrete adapter with real radio knowledge maps its own bands
#: behind the seam; this translation reserves capacity, it does not
#: configure a radio.
_BRIDGE_BAND = "5ghz"

#: The default station LABEL for bridge-driven associations
#: (adapter-side opaque DATA; deliberately NOT derived from the
#: session_id -- the identity axes never collapse -- and validated by
#: the family's station-label grammar at the implementation seam).
_BRIDGE_STATION_LABEL = "wifi-sdk-station"

#: Requirement keys the bridge reads as the caller-supplied Wi-Fi
#: binding coordinates in ``bind_session`` (the generic SDK surface
#: has no AP-selection parameter, so the caller passes the provisioned
#: ``ap_ref`` -- and the SSID to associate on -- through the
#: requirements map; DATA only, never identity).  The bridge CONSUMES
#: these three keys as its documented translation (they become the
#: manager's explicit ``ap_ref`` / ``ssid_name`` / ``station_label``
#: parameters) and forwards only the LEFTOVER requirements map -- so
#: the manager's identity-smuggling gate sees a clean QoS-data map,
#: and a duplicate/override attempt still fails closed there.
_REQUIREMENT_AP_REF = "ap_ref"
_REQUIREMENT_SSID_NAME = "ssid_name"
_REQUIREMENT_STATION_LABEL = "station_label"
_BRIDGE_REQUIREMENT_KEYS = (
    _REQUIREMENT_AP_REF, _REQUIREMENT_SSID_NAME, _REQUIREMENT_STATION_LABEL,
)


class WifiTechnologyAdapter(AdapterContract):
    """The WORK-016 SDK adapter over the Wi-Fi family RUNTIME (the
    :class:`~adapters.wifi.manager.WifiManager`).

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
    :class:`~adapters.wifi.contract.WifiContext` per mediated call).

    The nine-op translation (SDK -> family runtime):

    * ``open``            -> a mediated manager health probe (the
                             family access path came up at manager
                             registration; SDK open VERIFIES it is
                             observable through the mediated path --
                             fail-closed when the manager has no
                             default implementation yet)
    * ``capabilities``    -> the manager's informational capability
                             ladder (derived from mediated manager
                             state: the boundary caps once an
                             implementation is registered; the
                             data-path cap once an AP is provisioned
                             through the manager)
    * ``observe``         -> the mediated manager health aggregate
                             projected onto the generic link-metric
                             vocabulary (link-up mirrors whether the
                             access path can carry; counters are
                             honestly zero -- the frozen contract
                             carries no metric observation op, so
                             nothing is fabricated)
    * ``allocate``        -> manager ``provision_ap`` (the technology
                             resource allocation; the opaque
                             ``wifi:ap:<hex>`` ref is the
                             technology_ref)
    * ``release``         -> the family runtime release op for the
                             ref's kind (``release_tunnel`` for tunnel
                             refs, which unbind would also carry; an
                             AP ref fails closed -- the frozen
                             contract has no AP decommission
                             operation)
    * ``bind_session``    -> manager ``bind_session`` +
                             ``authenticate`` + ``establish_tunnel``
                             (each mediated); the opaque
                             ``wifi:tunnel:<hex>`` tunnel ref is the
                             bearer_ref
    * ``unbind_session``  -> manager ``release_tunnel`` (the SDK
                             bearer IS the N3IWF tunnel)
    * ``health``          -> the manager's instant-free
                             ``computed_health`` (mediated outcomes),
                             translated onto the SDK's frozen
                             three-state vocabulary
    * ``close``           -> honest no-op at this seam (the frozen
                             contract expresses close per association;
                             the manager's lifecycle belongs to the
                             composition root, not to the SDK bridge)
    """

    def __init__(
        self,
        manager: WifiManager,
        *,
        label: str = "wifi-technology",
    ) -> None:
        if not isinstance(manager, WifiManager):
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "manager must be a WifiManager (the bridge adapts the "
                "family RUNTIME -- it never holds a WifiContract "
                "implementation reference; register the implementation "
                "with the manager, then construct the bridge over the "
                "manager)",
            )
        if not isinstance(label, str) or not label:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
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
        raise WifiError(
            WifiReasonCode.WIFI_FAILURE,
            "mediated Wi-Fi family %s failed (%s); the family sandbox "
            "recorded the typed failure" % (operation, detail),
        ) from None

    def _require_ok(self, operation: str, result: Any) -> Any:
        """Require a mediated manager result to be ok; return its
        validated value (the family sandbox already validated the
        contract shape and the W021 identity invariants)."""
        if not getattr(result, "ok", False):
            self._raise_failure(
                operation, getattr(result, "detail", "") or "isolated failure"
            )
        return result.value

    @staticmethod
    def _ref_kind(technology_ref: str) -> str:
        """Parse the KIND segment of the family's opaque ref grammar
        (``wifi:(assoc|tunnel|ap):<hex>``).

        A non-ref-shaped input is a caller input error (the full
        grammar, including the 32-lowercase-hex tail, is validated at
        the implementation seam by the family's own validators).
        """
        if not isinstance(technology_ref, str) or not technology_ref:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "technology_ref must be a non-empty string",
            )
        segments = technology_ref.split(":")
        if len(segments) != 3 or segments[0] != "wifi":
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "technology_ref must match wifi:(assoc|tunnel|ap):<hex>",
            )
        return segments[1]

    # ------------------------------------------------------------------
    # The nine frozen WORK-016 SDK operations
    # ------------------------------------------------------------------

    def open(self, context: AdapterContext) -> None:
        """SDK ``open`` -> a MEDIATED verification that the family
        access path is up.

        The Wi-Fi implementation was brought up at manager
        registration (``register_implementation`` opens it and probes
        health through the sandbox).  SDK open therefore VERIFIES,
        through the same mediated path, that the access path is
        observable: one mediated manager health probe.  A manager with
        no default implementation yet fails closed (the caller-side
        ``WIFI_UNAVAILABLE`` state error propagates and the SDK
        sandbox isolates it); a probe that reports a down aggregate
        (e.g. the honest FAILED-for-empty-AP-store ladder) is a
        SUCCESSFUL probe of real state -- only a mediated probe FAULT
        fails the open.
        """
        self._require_ok("open", self._manager.health(now=context.now()))

    def capabilities(self) -> Sequence[str]:
        """SDK ``capabilities`` -> the manager's informational
        capability ladder (derived from MEDIATED manager state).

        The ladder reports exactly what the family runtime can see:
        ``()`` with no default implementation registered; the four
        boundary capabilities once one is; the data-path capability
        once the manager's mediated history shows a provisioned AP.
        The bridge mints no capability references of its own (exposure
        by reference into WORK-005 registry semantics is never
        rewritten; the SDK runtime filters to the descriptor's
        declared set).
        """
        return self._manager.capabilities()

    def observe(self, context: AdapterContext) -> Mapping[str, int]:
        """SDK ``observe`` -> the mediated family health aggregate
        projected onto the GENERIC link metrics.

        Honest translation (the frozen 12-op Wi-Fi contract carries no
        metric-observation operation -- unlike the ran family's
        ``observe`` -- so the bridge translates the one family surface
        that IS a mediated manager op, the health aggregate):
        ``HEALTHY`` (at least one ACTIVE SSID can carry -- the access
        path exists and can bear an association/tunnel) maps to
        ``link-up: 1``; every other state (``NOT_RUNNING`` before
        registration, ``FAILED`` with an empty AP store, ``DEGRADED``
        with every SSID deactivated) maps to the honest link-DOWN
        sample -- ``link-up: 0`` with all-zero counters -- exactly
        what the SDK's :class:`adapters.contract.GenericAdapter`
        reports for a down/unpopulated technology, so an adapter
        registered before any AP is provisioned still satisfies the
        nine-op surface without fabricating access state.  Per-path
        byte/error/retransmit counters stay inside the implementation
        (there is no source for them at this seam): they are reported
        as honest zeros through the family's
        :class:`~adapters.wifi.model.Non3GppAccessObservation` shape
        (metric name -> non-negative int; nothing fabricated, nothing
        dropped).
        """
        health = self._require_ok(
            "observe", self._manager.health(now=context.now())
        )
        if not isinstance(health, str) or health not in (
            "HEALTHY", "DEGRADED", "FAILED", "NOT_RUNNING",
        ):
            raise WifiError(
                WifiReasonCode.CONTRACT_VIOLATION,
                "health must report the frozen vocabulary (the bridge "
                "translates; it does not fabricate metrics)",
            )
        link_up = 1 if health == "HEALTHY" else 0
        observation = Non3GppAccessObservation(
            samples=(
                (LinkMetricName.LINK_UP, link_up),
                (LinkMetricName.RX_BYTES_TOTAL, 0),
                (LinkMetricName.TX_BYTES_TOTAL, 0),
                (LinkMetricName.RX_ERROR_COUNT, 0),
                (LinkMetricName.TX_ERROR_COUNT, 0),
                (LinkMetricName.RETRANSMIT_COUNT, 0),
            )
        )
        return {metric: value for metric, value in observation.samples}

    def allocate(
        self,
        context: AdapterContext,
        *,
        kind: str,
        quantity_base: int,
        purpose: str,
    ) -> str:
        """SDK ``allocate`` -> manager ``provision_ap`` (the technology
        resource allocation, MEDIATED).

        The Wi-Fi family's resource allocation IS the AP profile: the
        bridge deterministically maps the generic allocation request
        onto an :class:`~adapters.wifi.model.ApDescriptor` -- the
        caller's ``purpose`` names the AP profile, the resource
        ``kind`` names the single provisioned SSID, and
        ``quantity_base`` is the reserved station/association capacity
        (integer base units, WORK-016 semantics; the family bounds it
        by the IEEE 802.11-2020 association-identifier space).  The
        PHY band and the open security policy are the documented
        bridge-fixed defaults (see the module constants; the SDK
        surface carries no radio parameters and the bridge claims no
        data protection).  Returns the implementation's OPAQUE
        ``wifi:ap:<hex>`` ref -- never core state.
        """
        if not isinstance(kind, str) or not kind:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "kind must be a non-empty string (it names the "
                "provisioned SSID)",
            )
        if not isinstance(purpose, str) or not purpose:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "purpose must be a non-empty string (it names the AP "
                "profile)",
            )
        if isinstance(quantity_base, bool) or not isinstance(quantity_base, int):
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "quantity_base must be an integer",
            )
        descriptor = ApDescriptor(
            name=purpose,
            ssids=(
                SsidProfile(
                    ssid=kind,
                    band=_BRIDGE_BAND,
                    security_policy=SecurityPolicy.OPEN,
                    max_stations=quantity_base,
                ),
            ),
            bands=(_BRIDGE_BAND,),
            max_associations=quantity_base,
        )
        ap_view = self._require_ok(
            "allocate",
            self._manager.provision_ap(
                now=context.now(),
                descriptor=descriptor,
                credential_slot_name=_BRIDGE_CREDENTIAL_SLOT,
            ),
        )
        # The family sandbox validated the ApView contract shape.
        return ap_view.ap_ref

    def release(self, context: AdapterContext, technology_ref: str) -> None:
        """SDK ``release`` -> the family runtime release op for the
        ref's kind.

        The bridge parses the KIND segment of its own family's opaque
        ref grammar (``wifi:(ap|tunnel|assoc):<hex>``) and dispatches:
        a tunnel ref releases the N3IWF tunnel through the manager
        (``release_tunnel`` -- the manager's tunnel index routes it to
        the OWNING binding's sandbox, B2).  An ASSOCIATION ref fails
        closed: the SDK surface never carries assoc refs (allocate
        returns AP refs, bind_session returns tunnel refs), and the
        association's release is a FAMILY-NATIVE operation
        (``manager.close_binding`` by binding id) -- the bridge refuses
        to silently drop what it cannot translate.  An AP ref fails
        closed: the frozen 12-op Wi-Fi contract has NO AP decommission
        operation (a provisioned profile retires with the
        implementation instance), and the bridge refuses to silently
        drop the release.
        """
        kind = self._ref_kind(technology_ref)
        if kind == "tunnel":
            self._require_ok(
                "release",
                self._manager.release_tunnel(
                    now=context.now(), tunnel_ref=technology_ref
                ),
            )
            return
        if kind == "assoc":
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "the SDK surface carries no association refs (allocate "
                "returns wifi:ap:<hex>; bind_session returns "
                "wifi:tunnel:<hex>); the association release is the "
                "family-native manager.close_binding(binding_id) after "
                "the tunnel is released -- releasing assoc ref %s fails "
                "closed rather than silently dropping"
                % technology_ref[:80],
            )
        raise WifiError(
            WifiReasonCode.ILLEGAL_STATE,
            "the frozen 12-op Wi-Fi contract carries no AP decommission "
            "operation (a provisioned AP profile retires with the "
            "implementation instance); releasing AP ref %s fails closed "
            "rather than silently dropping" % technology_ref[:80],
        )

    def bind_session(
        self,
        context: AdapterContext,
        *,
        session_id: str,
        requirements: Optional[Mapping[str, Any]],
    ) -> str:
        """SDK ``bind_session`` -> manager ``bind_session`` +
        ``authenticate`` + ``establish_tunnel`` (each MEDIATED through
        the binding's owning sandbox).

        The sacred ``session_id`` crosses EXACTLY as given (read-only
        passthrough identity -- never mutated, never re-derived,
        LOCK-006; the family mediator mechanically checks every
        returned ref against it, and the manager re-asserts the
        requirements-map and cross-binding identity guards).  The
        caller-supplied ``requirements`` DATA must carry the Wi-Fi
        binding coordinates -- ``ap_ref`` (the opaque
        ``wifi:ap:<hex>`` technology ref returned by ``allocate``)
        and ``ssid_name`` (the SSID to associate on, named by the
        allocation ``kind``); ``station_label`` is optional (the
        documented bridge-fixed default otherwise) -- because the
        generic SDK surface has no AP-selection parameter.  The
        bridge CONSUMES those three keys (they become the manager's
        explicit binding parameters) and forwards only the leftover
        requirements map, which the manager's identity-smuggling gate
        screens like any caller's.  The return is the OPAQUE
        ``wifi:tunnel:<hex>`` N3IWF tunnel ref (the SDK bearer for
        this family) -- Wi-Fi/N3IWF-side identity, never ADCOS
        authority and never the ``session_id`` itself.
        """
        if not isinstance(session_id, str) or not session_id:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "session_id must be a non-empty string",
            )
        ap_ref, ssid_name, station_label, forwarded = (
            self._binding_coordinates(requirements)
        )
        now = context.now()
        binding = self._require_ok(
            "bind_session",
            self._manager.bind_session(
                now=now,
                session_id=session_id,
                ap_ref=ap_ref,
                ssid_name=ssid_name,
                station_label=station_label,
                requirements=forwarded,
            ),
        )
        # The family sandbox validated the AssociationBinding shape
        # and re-asserted the W021 ref/session separation.
        auth = self._require_ok(
            "authenticate",
            self._manager.authenticate(
                now=now, binding_id=binding.binding_id
            ),
        )
        if not auth.success:
            raise WifiError(
                WifiReasonCode.AUTHENTICATION_REJECTED,
                "the association's authentication phase rejected the "
                "bind (802.1X/SAE per the SSID's security policy)",
            )
        tunnel = self._require_ok(
            "establish_tunnel",
            self._manager.establish_tunnel(
                now=now, binding_id=binding.binding_id
            ),
        )
        # The bearer is the OPAQUE tunnel ref.  The family model
        # enforced the W021 separation at TunnelBinding construction
        # (session_id is hash INPUT only, never ref text) and the
        # sandbox seam re-asserted it against THIS call's session_id
        # -- the bridge returns the handle verbatim and echoes nothing
        # of the session.
        return tunnel.tunnel_ref

    def unbind_session(self, context: AdapterContext, bearer_ref: str) -> None:
        """SDK ``unbind_session`` -> manager ``release_tunnel``
        (MEDIATED; the manager's tunnel index routes the release to
        the OWNING binding's sandbox -- B2).

        The SDK bearer for this family is the N3IWF tunnel
        (``wifi:tunnel:<hex>``), so the unbind releases exactly that
        tunnel.  The family's per-association close is a SEPARATE
        release the SDK surface never carries (the association ref
        never crosses the SDK seam); a re-bind of the same session
        through this surface therefore reports the family's honest
        fail-closed ``binding-exists`` until the association is
        released through a family-native path (the manager's
        ``close_binding``) -- access change is a REPLACEMENT after
        release, never a duplication.
        """
        kind = self._ref_kind(bearer_ref)
        if kind != "tunnel":
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "bearer_ref must be a wifi:tunnel:<hex> opaque ref (the "
                "SDK bearer for this family is the N3IWF tunnel)",
            )
        self._require_ok(
            "unbind_session",
            self._manager.release_tunnel(
                now=context.now(), tunnel_ref=bearer_ref
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
        convention the SDK's own
        :class:`adapters.contract.GenericAdapter` uses for a not-open
        technology (a technology that is not up honestly cannot
        carry).  Reported, never authoritative by itself (LOCK-017:
        the SDK runtime computes the effective health from mediated
        outcomes -- and so does the family manager this reads from).
        """
        health = self._manager.computed_health()
        if health == "NOT_RUNNING":
            return "FAILED"
        return health

    def close(self, context: AdapterContext) -> None:
        """SDK ``close`` -> honest no-op at this seam.

        The frozen 12-op Wi-Fi contract expresses close PER
        ASSOCIATION (``close(context, assoc_ref)``); it carries NO
        technology-level shutdown operation (the reference engine's
        open flag retires with the instance).  The bridge therefore
        tears down NOTHING here: every bearer this bridge created is
        released per-bearer through ``unbind_session`` (and the
        association through a family-native ``close_binding``).  The
        MANAGER's lifecycle belongs to the composition root that
        constructed it -- the bridge adapts the manager, it does not
        own it, and it never yanks a shared family runtime out from
        under family-native callers as a side effect of an SDK
        adapter close.  Returning ``None`` keeps the nine-op surface
        satisfied without fabricating a teardown the family does not
        have.
        """

    # ------------------------------------------------------------------
    # Internal helpers (family-grammar parsing; no SDK imports)
    # ------------------------------------------------------------------

    @staticmethod
    def _binding_coordinates(
        requirements: Optional[Mapping[str, Any]],
    ) -> Any:
        """Read the caller-supplied Wi-Fi binding coordinates from the
        SDK requirements map (DATA only -- never identity).

        ``ap_ref`` and ``ssid_name`` are REQUIRED (the generic SDK
        surface has no AP-selection parameter, so the caller names the
        provisioned AP and the SSID to associate on through the
        requirements map); ``station_label`` falls back to the
        documented bridge-fixed default.  The three keys are CONSUMED
        by this translation (they become the manager's explicit
        binding parameters); the LEFTOVER requirements map is
        forwarded to the manager, whose identity-smuggling gate
        screens it fail-closed (a key that would re-identify the
        session or override the binding handles never reaches the
        implementation).  The coordinates themselves are validated by
        the family's own grammar validators at the implementation
        seam.
        """
        if not isinstance(requirements, Mapping):
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "bind_session requirements must be a mapping carrying "
                "the Wi-Fi binding coordinates (ap_ref from allocate, "
                "ssid_name) -- the generic SDK surface has no "
                "AP-selection parameter",
            )
        ap_ref = requirements.get(_REQUIREMENT_AP_REF)
        ssid_name = requirements.get(_REQUIREMENT_SSID_NAME)
        station_label = requirements.get(
            _REQUIREMENT_STATION_LABEL, _BRIDGE_STATION_LABEL
        )
        if not isinstance(ap_ref, str) or not ap_ref:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "requirements must carry a non-empty %r (the opaque "
                "wifi:ap:<hex> technology ref returned by allocate)"
                % _REQUIREMENT_AP_REF,
            )
        if not isinstance(ssid_name, str) or not ssid_name:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "requirements must carry a non-empty %r (the SSID to "
                "associate on; the allocation kind named it)"
                % _REQUIREMENT_SSID_NAME,
            )
        if not isinstance(station_label, str) or not station_label:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "requirements %r must be a non-empty string when supplied"
                % _REQUIREMENT_STATION_LABEL,
            )
        forwarded = {
            key: value
            for key, value in requirements.items()
            if key not in _BRIDGE_REQUIREMENT_KEYS
        }
        # The coordinates are binding DATA forwarded as the manager's
        # explicit parameters; the session_id (the ONLY identity)
        # crossed above, read-only.
        return ap_ref, ssid_name, station_label, forwarded
