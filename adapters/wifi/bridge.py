"""ADCOS Wi-Fi/non-3GPP technology adapter bridge (WORK-021): the
adapter translation layer onto the accepted WORK-016 Adapter SDK.

:class:`WifiTechnologyAdapter` IMPLEMENTS the WORK-016 SDK's frozen
nine-operation :class:`adapters.contract.AdapterContract` over a
Wi-Fi-family :class:`WifiContract` implementation.  This is how the
Wi-Fi/non-3GPP family USES the accepted WORK-016 Adapter SDK rather
than inventing a second adapter framework: the generic core-side
surface stays the SDK's; the Wi-Fi/non-3GPP-specific vocabulary (AP
provisioning, station association, 802.1X/SAE authentication, the
N3IWF tunnel, tunnel egress) stays inside the Wi-Fi family's own seam
-- exactly as the accepted WORK-019 5G-Core family keeps its
PDU-session/SUPI vocabulary behind ``FiveGCoreContract``.

The Architect's layering (verbatim)::

    Wi-Fi/non-3GPP implementation
        -> adapter translation
        -> generic AdapterContract
        -> ADCOS capabilities / resources / session mapping

This module is the middle box.  Authority notes (every operation):

* The bridge (and the implementation it adapts) is authoritative
  ONLY for the Wi-Fi/non-3GPP access state it controls -- its own
  AP/SSID/association/tunnel bookkeeping.  ADCOS remains
  authoritative for identity (WORK-004), topology (WORK-007),
  routing, policy, and session semantics (WORK-012): the bridge
  never mints, mutates, or re-derives any of them.
* The sacred, access-independent ``session_id`` (LOCK-006) crosses
  the bridge EXACTLY as given in ``bind_session`` -- a read-only
  passthrough, never mutated, never re-derived (LOCK-006; the W021
  identity invariant), and never echoed as a Wi-Fi handle.
* Every reference the bridge returns is an OPAQUE Wi-Fi-side handle
  (``wifi:ap:<digest>`` for allocations, ``wifi:tunnel:<digest>`` for
  bearers) -- never core state and never the ``session_id``.  The
  Wi-Fi association identity (BSSID/association id) and the IPsec/
  NAS identity stay adapter-side behind those handles by
  construction (the family's model enforces the separation at
  binding construction).

Sanctioned dependency direction (the SDK README, verbatim in
substance): "Implementations depend on ``AdapterContract`` + the
least-authority ``AdapterContext`` facade ... and on nothing else."
Accordingly this module imports ONLY
``from ..contract import AdapterContext, AdapterContract`` from the
SDK -- the stable interface, nothing else (no SDK errors module, no
SDK runtime, no SDK sandbox internals, no SDK model import).  Everything
else it uses is the Wi-Fi family's own vocabulary.

Mediation note (honest): the bridge itself does NO mediation -- it
is a thin translation with NO state of its own beyond the label (the
fixed passthrough session reader below is a stateless translation
constant, not mutable state).  Failure isolation and contract-shape
enforcement happen (a) inside the Wi-Fi family, when the
implementation is driven through
:class:`adapters.wifi.sandbox.SandboxedWifi`, and (b) when the bridge
is registered in the WORK-016 Adapter Runtime, via the SDK's own
:class:`adapters.sandbox.SandboxedAdapter` mediating every bridge
call.  Wi-Fi-side ``WifiError`` reason codes therefore cross the SDK
seam only as far as the SDK's isolation allows (the SDK captures the
exception CLASS NAME, never message text -- LOCK-023); full
reason-code fidelity is preserved at the Wi-Fi family's own mediator.

Budget conversion (honest): the bridge forwards the SDK's budget
semantics by constructing a fresh :class:`WifiContext` per call whose
instant is ``context.now()`` and whose step budget is the
AdapterContext's REMAINING budget (``context.steps_left()``) -- the
SDK budget is the single authority and the bridge never mints budget
of its own.  The bridge charges nothing itself: per-operation step
charging is the MEDIATORS' job (the Wi-Fi sandbox's fixed
``STEP_CHARGES`` table, or the SDK sandbox's own charges when the
bridge runs under the WORK-016 runtime).

Session verification note (honest): the SDK's least-authority
:class:`AdapterContext` deliberately carries NO session-store
reference, and the WORK-016 runtime performs the read-only WORK-012
bindability verification BEFORE an adapter is invoked
(``AdapterRuntime.bind_session``).  The bridge therefore supplies the
family's :class:`WifiContext` with a PASSTHROUGH session reader that
echoes the SDK caller-supplied ``session_id`` verbatim (LOCK-006:
read-only) with ``secureable`` reflecting exactly what the SDK
surface has already established -- the bridge adds NO session facts
of its own (it does not know, and does not fabricate, endpoint node
ids).  This mirrors the SDK's own :class:`AdapterContract` semantics,
under which the adapter takes the runtime-verified ``session_id`` as
given (the WORK-016 ``GenericAdapter`` does the same).
"""

from __future__ import annotations

from typing import Any, Mapping, Optional, Sequence

from ..contract import AdapterContext, AdapterContract

from .contract import (
    SessionReader,
    SessionView,
    WifiContext,
    WifiContract,
    _BudgetExhausted,
)
from .errors import WifiError, WifiReasonCode
from .manager import DEFAULT_INTEGRATION_ID
from .model import (
    ApDescriptor,
    ApView,
    AssociationBinding,
    AuthResult,
    LinkMetricName,
    Non3GppAccessObservation,
    SecurityPolicy,
    SsidProfile,
    TunnelBinding,
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
#: requirements map; DATA only, never identity).
_REQUIREMENT_AP_REF = "ap_ref"
_REQUIREMENT_SSID_NAME = "ssid_name"
_REQUIREMENT_STATION_LABEL = "station_label"


class _BridgeSessionReader(SessionReader):
    """The bridge's passthrough session reader (see the module
    docstring's session verification note).

    ``lookup`` returns the secret-free :class:`SessionView` projection
    for the ALREADY-VERIFIED SDK caller-supplied ``session_id``,
    echoed verbatim (LOCK-006: read-only passthrough).  The endpoint
    node ids are empty honest placeholders: the SDK surface does not
    carry them and the bridge fabricates none.  The reader asserts no
    session facts beyond what the SDK surface has already established
    (the WORK-016 runtime verifies bindability before the adapter is
    invoked; the WORK-016 ``GenericAdapter`` takes the caller's
    session_id as given the same way).
    """

    __slots__ = ()

    def lookup(self, session_id: str) -> Optional[SessionView]:
        return SessionView(
            session_id=session_id,
            secureable=True,
            initiator_node_id="",
            responder_node_id="",
        )


#: The bridge's single passthrough session reader (a stateless
#: translation constant; not per-instance mutable state).
_BRIDGE_SESSION_READER = _BridgeSessionReader()


class WifiTechnologyAdapter(AdapterContract):
    """The WORK-016 SDK adapter over a :class:`WifiContract`
    implementation.

    Constructed with the Wi-Fi/non-3GPP implementation and an
    informational label.  Subclasses the accepted SDK's
    :class:`adapters.contract.AdapterContract` (isinstance-enforced)
    and satisfies its frozen ``CONTRACT_OPERATIONS`` surface; each SDK
    operation translates onto the Wi-Fi seam as documented in the
    module docstring.  The bridge owns NO state beyond the
    implementation reference and the label: a fresh
    :class:`WifiContext` is built per call from the
    :class:`AdapterContext`'s injected instant and remaining step
    budget, so the SDK's budget semantics remain the single
    authority.

    The nine-op translation (SDK -> family):

    * ``open``            -> ``open`` (bring the access path up)
    * ``capabilities``    -> the implementation's informational
                             capability ladder (the frozen 12-op
                             contract carries no capabilities
                             operation; the ladder is surfaced when
                             the concrete implementation provides one,
                             ``()`` honestly otherwise)
    * ``observe``         -> the family health aggregate projected
                             onto the generic link-metric vocabulary
                             (link-up mirrors whether the access path
                             can carry; counters are honestly zero --
                             the frozen contract carries no metric
                             observation op, so nothing is fabricated)
    * ``allocate``        -> ``provision_ap`` (the technology resource
                             allocation; the opaque ``wifi:ap:<hex>``
                             ref is the technology_ref)
    * ``release``         -> the family release op for the ref's kind
                             (``release_tunnel`` for tunnel refs,
                             ``close`` for association refs; an AP ref
                             fails closed -- the frozen contract has
                             no AP decommission operation)
    * ``bind_session``    -> ``bind_session`` + ``authenticate`` +
                             ``establish_tunnel``; the opaque
                             ``wifi:tunnel:<hex>`` tunnel ref is the
                             bearer_ref
    * ``unbind_session``  -> ``release_tunnel`` (the SDK bearer IS the
                             N3IWF tunnel)
    * ``health``          -> ``health`` (verbatim; reported, never
                             authoritative -- LOCK-017)
    * ``close``           -> honest no-op at this seam (the frozen
                             contract expresses close per
                             association; there is no technology-level
                             shutdown operation)
    """

    def __init__(
        self,
        implementation: WifiContract,
        *,
        label: str = "wifi-technology",
    ) -> None:
        if not isinstance(implementation, WifiContract):
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "implementation must satisfy the WifiContract ABC "
                "(isinstance enforced; no hasattr duck-typing)",
            )
        if not isinstance(label, str) or not label:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "label must be a non-empty string",
            )
        self._implementation = implementation
        # Informational only (the SDK contract's label discipline):
        # never parsed, never branched on, never canonical state.
        self.label = label

    # ------------------------------------------------------------------
    # WifiContext construction (per call, from the AdapterContext)
    # ------------------------------------------------------------------

    def _wifi_context(self, context: AdapterContext) -> WifiContext:
        """Build the Wi-Fi seam's least-authority context from the
        SDK's.

        The AdapterContext's injected instant and REMAINING step
        budget become the WifiContext's instant/budget: the SDK budget
        is the single authority (the bridge never mints budget of its
        own).  The ``integration_id`` is the Wi-Fi family's default
        integration instance id (the bridge is implementation-neutral
        translation, not an integration instance of its own).  The
        session reader is the documented passthrough (see the module
        docstring); no AP-profile reader is supplied (the SDK surface
        carries no AP-profile authority -- the implementation's own
        provisioned store is authoritative behind the seam).
        """
        return WifiContext(
            integration_id=DEFAULT_INTEGRATION_ID,
            instant=context.now(),
            step_budget=context.steps_left(),
            session_reader=_BRIDGE_SESSION_READER,
            ap_profile_reader=None,
        )

    def _call(self, context: AdapterContext, fn: Any) -> Any:
        """Delegate to the implementation with a fresh WifiContext.

        The Wi-Fi seam's private ``_BudgetExhausted`` sentinel (the
        deterministic hang model raised by ``WifiContext.charge``
        when the remaining budget is spent) is kept INSIDE the
        family: it is re-raised as the family's own
        ``WifiError(BUDGET_EXHAUSTED)`` so the private sentinel class
        never crosses the SDK seam.  Whichever mediator is in charge
        (the Wi-Fi sandbox, or the SDK sandbox around this bridge)
        isolates the error as a typed failure value -- the bridge
        never lets an exception escape unmediated into core callers.
        """
        wifi_context = self._wifi_context(context)
        try:
            return fn(wifi_context)
        except _BudgetExhausted:
            raise WifiError(
                WifiReasonCode.BUDGET_EXHAUSTED,
                "Wi-Fi/non-3GPP implementation exhausted the adapter "
                "step budget (deterministic hang model; no wall clock "
                "is consulted)",
            ) from None

    # ------------------------------------------------------------------
    # The nine frozen WORK-016 SDK operations
    # ------------------------------------------------------------------

    def open(self, context: AdapterContext) -> None:
        """SDK ``open`` -> ``impl.open`` (bring the Wi-Fi/non-3GPP
        access path up)."""
        return self._call(
            context, lambda wifi: self._implementation.open(wifi)
        )

    def capabilities(self) -> Sequence[str]:
        """SDK ``capabilities`` -> the family/engine capability ladder.

        The frozen 12-op Wi-Fi contract carries no capabilities
        operation (unlike the ran family), so the bridge surfaces the
        implementation's INFORMATIONAL capability ladder when the
        concrete implementation provides one
        (:meth:`adapters.wifi.engine.ReferenceWifiEngine.capabilities`
        -- the honest ladder that grows with SSID activation) and
        honestly reports ``()`` when it does not.  The bridge mints no
        capability references of its own (exposure by reference into
        WORK-005 registry semantics is never rewritten).
        """
        ladder = getattr(self._implementation, "capabilities", None)
        if callable(ladder):
            return tuple(ladder())
        return ()

    def observe(self, context: AdapterContext) -> Mapping[str, int]:
        """SDK ``observe`` -> the family health aggregate projected
        onto the GENERIC link metrics.

        Honest translation (the frozen 12-op Wi-Fi contract carries no
        metric-observation operation -- unlike the ran family's
        ``observe`` -- so the bridge translates the one family surface
        that IS a contract op, the health aggregate): ``HEALTHY`` (at
        least one ACTIVE SSID can carry -- the access path exists and
        can bear an association/tunnel) maps to ``link-up: 1``; every
        other state (``NOT_RUNNING`` before open, ``FAILED`` with an
        empty AP store, ``DEGRADED`` with every SSID deactivated)
        maps to the honest link-DOWN sample -- ``link-up: 0`` with
        all-zero counters -- exactly what the SDK's
        :class:`adapters.contract.GenericAdapter` reports for a
        down/unpopulated technology, so an adapter registered before
        any AP is provisioned still satisfies the nine-op surface
        without fabricating access state.  Per-path byte/error/
        retransmit counters stay inside the implementation (there is
        no source for them at this seam): they are reported as honest
        zeros through the family's
        :class:`~adapters.wifi.model.Non3GppAccessObservation` shape
        (metric name -> non-negative int; nothing fabricated, nothing
        dropped).
        """
        health = self._implementation.health()
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
        """SDK ``allocate`` -> ``impl.provision_ap`` (the technology
        resource allocation).

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
        ap_view = self._call(
            context,
            lambda wifi: self._implementation.provision_ap(
                wifi,
                descriptor=descriptor,
                credential_slot_name=_BRIDGE_CREDENTIAL_SLOT,
            ),
        )
        if not isinstance(ap_view, ApView):
            raise WifiError(
                WifiReasonCode.CONTRACT_VIOLATION,
                "provision_ap must return an ApView (the bridge "
                "translates; it does not fabricate refs)",
            )
        return ap_view.ap_ref

    def release(self, context: AdapterContext, technology_ref: str) -> None:
        """SDK ``release`` -> the family release op for the ref's kind.

        The bridge parses the KIND segment of its own family's opaque
        ref grammar (``wifi:(assoc|tunnel|ap):<hex>``) and dispatches:
        a tunnel ref releases the N3IWF tunnel
        (``release_tunnel``); an association ref closes the
        association (``close`` -- the family's per-binding release).
        An AP ref fails closed: the frozen 12-op Wi-Fi contract has NO
        AP decommission operation (a provisioned profile retires with
        the implementation instance), and the bridge refuses to
        silently drop the release.
        """
        kind = self._ref_kind(technology_ref)
        if kind == "tunnel":
            return self._call(
                context,
                lambda wifi: self._implementation.release_tunnel(
                    wifi, tunnel_ref=technology_ref
                ),
            )
        if kind == "assoc":
            return self._call(
                context,
                lambda wifi: self._implementation.close(
                    wifi, assoc_ref=technology_ref
                ),
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
        """SDK ``bind_session`` -> family ``bind_session`` +
        ``authenticate`` + ``establish_tunnel``.

        The sacred ``session_id`` crosses EXACTLY as given (read-only
        passthrough identity -- never mutated, never re-derived,
        LOCK-006; the returned bearer reference is mechanically
        checked against it at the family seam, and the family model
        enforces the separation at binding construction).  The
        caller-supplied ``requirements`` DATA must carry the Wi-Fi
        binding coordinates -- ``ap_ref`` (the opaque
        ``wifi:ap:<hex>`` technology ref returned by ``allocate``)
        and ``ssid_name`` (the SSID to associate on, named by the
        allocation ``kind``); ``station_label`` is optional (the
        documented bridge-fixed default otherwise) -- because the
        generic SDK surface has no AP-selection parameter.  The return
        is the OPAQUE ``wifi:tunnel:<hex>`` N3IWF tunnel ref (the SDK
        bearer for this family) -- Wi-Fi/N3IWF-side identity, never
        ADCOS authority and never the ``session_id`` itself.
        """
        if not isinstance(session_id, str) or not session_id:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "session_id must be a non-empty string",
            )
        ap_ref, ssid_name, station_label = self._binding_coordinates(
            session_id, requirements
        )
        binding = self._call(
            context,
            lambda wifi: self._implementation.bind_session(
                wifi,
                session_id=session_id,
                ap_ref=ap_ref,
                ssid_name=ssid_name,
                station_label=station_label,
                requirements=requirements,
            ),
        )
        if not isinstance(binding, AssociationBinding):
            raise WifiError(
                WifiReasonCode.CONTRACT_VIOLATION,
                "bind_session must return an AssociationBinding (the "
                "bridge translates; it does not fabricate handles)",
            )
        auth = self._call(
            context,
            lambda wifi: self._implementation.authenticate(
                wifi, assoc_ref=binding.assoc_ref
            ),
        )
        if not isinstance(auth, AuthResult):
            raise WifiError(
                WifiReasonCode.CONTRACT_VIOLATION,
                "authenticate must return an AuthResult (the bridge "
                "translates; it does not fabricate auth state)",
            )
        if not auth.success:
            raise WifiError(
                WifiReasonCode.AUTHENTICATION_REJECTED,
                "the association's authentication phase rejected the "
                "bind (802.1X/SAE per the SSID's security policy)",
            )
        tunnel = self._call(
            context,
            lambda wifi: self._implementation.establish_tunnel(
                wifi, assoc_ref=binding.assoc_ref
            ),
        )
        if not isinstance(tunnel, TunnelBinding):
            raise WifiError(
                WifiReasonCode.CONTRACT_VIOLATION,
                "establish_tunnel must return a TunnelBinding (the "
                "bridge translates; it does not fabricate handles)",
            )
        # The bearer is the OPAQUE tunnel ref.  The family model
        # enforced the W021 separation at TunnelBinding construction
        # (session_id is hash INPUT only, never ref text) and the
        # sandbox seam re-asserts it when the implementation is driven
        # through SandboxedWifi -- the bridge returns the handle
        # verbatim and echoes nothing of the session.
        return tunnel.tunnel_ref

    def unbind_session(self, context: AdapterContext, bearer_ref: str) -> None:
        """SDK ``unbind_session`` -> ``impl.release_tunnel``.

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
        return self._call(
            context,
            lambda wifi: self._implementation.release_tunnel(
                wifi, tunnel_ref=bearer_ref
            ),
        )

    def health(self) -> str:
        """SDK ``health`` -> ``impl.health``.

        The Wi-Fi family's health vocabulary (HEALTHY / DEGRADED /
        FAILED / NOT_RUNNING) already matches the SDK's reporting
        vocabulary; the report passes through verbatim (reported,
        never authoritative by itself -- LOCK-017: the runtime
        computes the effective health from mediated outcomes).
        """
        return self._implementation.health()

    def close(self, context: AdapterContext) -> None:
        """SDK ``close`` -> honest no-op at this seam.

        The frozen 12-op Wi-Fi contract expresses close PER
        ASSOCIATION (``close(context, assoc_ref)``); it carries NO
        technology-level shutdown operation (the reference engine's
        open flag retires with the instance).  The bridge therefore
        tears down NOTHING here: every bearer this bridge created is
        released per-bearer through ``unbind_session`` (and the
        association through a family-native close), and the
        implementation instance's own lifecycle ends with the
        instance.  Returning ``None`` keeps the nine-op surface
        satisfied without fabricating a teardown the family does not
        have.
        """

    # ------------------------------------------------------------------
    # Internal helpers (family-grammar parsing; no SDK imports)
    # ------------------------------------------------------------------

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

    def _binding_coordinates(
        self,
        session_id: str,
        requirements: Optional[Mapping[str, Any]],
    ) -> Any:
        """Read the caller-supplied Wi-Fi binding coordinates from the
        SDK requirements map (DATA only -- never identity).

        ``ap_ref`` and ``ssid_name`` are REQUIRED (the generic SDK
        surface has no AP-selection parameter, so the caller names the
        provisioned AP and the SSID to associate on through the
        requirements map); ``station_label`` falls back to the
        documented bridge-fixed default.  The coordinates are passed
        to the family op verbatim and validated by the family's own
        grammar validators at the implementation seam.
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
        # The coordinates are binding DATA; the session_id is the ONLY
        # identity and crossed above, read-only.
        _ = session_id
        return ap_ref, ssid_name, station_label
