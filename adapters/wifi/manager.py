"""ADCOS Wi-Fi/non-3GPP access integration manager (WORK-021): the
runtime.

:class:`WifiManager` owns the integration instance state (the binding
table, the live-tunnel index, the observed external-association
evidence, the event log) and mediates every call through
:class:`adapters.wifi.sandbox.SandboxedWifi`.  It is the single
authoritative invocation path for the Wi-Fi/non-3GPP access boundary
(mirrors the WORK-019 :class:`FiveGCoreManager` and the WORK-018
``IPIntegrationManager``):

* ``register_implementation`` wraps EACH implementation in its OWN
  :class:`SandboxedWifi` and -- only when ``make_default=True`` --
  reassigns the DEFAULT sandbox for NEW work only (new AP profiles,
  new bindings); live bindings keep their OWNING sandbox, captured at
  ``bind_session`` time (B2 per-binding ownership; mirrors
  WORK-018/019).  A re-route into a new implementation fails closed
  for live bindings (R5 invariant).
* ``snapshot()`` carries only integration-instance state (bindings,
  events) -- NEVER Wi-Fi/N3IWF access state (LOCK-016/017: the
  station/association/tunnel/IPsec state lives in the adapter) and
  NEVER the ``implementation_label`` (B2; mirrors WORK-018/019).
* ``to_canonical_bytes()`` / ``content_digest()`` are byte-identical
  across runs and across equivalent implementations (determinism; R6):
  the canonical form contains no implementation identity, only the
  mediated operation history.
* ``diagnostic_state()`` exposes the ``implementation_label`` and
  health accounting SEPARATELY (NOT canonical public state; B2).

W021 identity discipline is enforced at the manager IN ADDITION to the
model's construction-time enforcement and the sandbox seam checks:
the sacred ``session_id`` is stored EXACTLY as provided (LOCK-006:
read-only passthrough, never mutated, never re-derived); a
``bind_session`` for a session_id that is ALREADY live-bound through
another binding of this manager fails closed with
``ACCESS_SESSION_COLLAPSE`` (one live association per session -- an
access change is a REPLACEMENT after release, never a duplication);
a requirements map that tries to smuggle a session/binding identity
override key fails closed the same way BEFORE the implementation is
ever invoked; and an implementation-returned ``assoc_ref`` already
registered under a DIFFERENT session_id is rejected as a collapse
(defense in depth -- the sandbox seam already checked the returned ref
against THIS call's session_id).

The manager knows nothing about IEEE 802.11 state machines, EAP/SAE
exchanges, N3IWF/IPsec mechanics, or Wi-Fi chipsets: it is pure
integration-instance bookkeeping.  Concrete Wi-Fi/non-3GPP access
paths (the reference engine, the conformance peer, a real N3IWF
integration) plug in behind the same ABC without modifying the manager
or any core semantics.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

from protocol.canonicalization import canonical_json_bytes

from .contract import ApProfileReader, SessionReader, WifiContract
from .errors import WifiError, WifiReasonCode
from .model import AssociationBinding, ExternalAssociationEvidence, WifiEvent
from .sandbox import DEFAULT_STEP_BUDGET, SandboxedWifi, WifiOpResult
from .serialization import to_canonical_dict
from .session import WifiAppSession
from .validation import assert_ref_session_separation, validate_opaque_ref

__all__ = ["WifiManager", "DEFAULT_INTEGRATION_ID"]


#: The default Wi-Fi/non-3GPP access integration instance id (a
#: deterministic constant; the manager's own id, never core state and
#: never a Wi-Fi-side reference).  The WORK-016 bridge imports it as
#: the family integration id for its per-call :class:`WifiContext`
#: construction (mirrors the WORK-020 ran family's
#: ``DEFAULT_INTEGRATION_ID`` naming convention).  Callers wanting a
#: content-derived instance id pass
#: :func:`adapters.wifi.model.derive_integration_id` output explicitly.
DEFAULT_INTEGRATION_ID = "wifi-integration"


#: Requirement keys that would smuggle a session/binding IDENTITY
#: override into the caller-supplied requirements map.  The
#: requirements map is DATA for the access path's own QoS enforcement;
#: it must never re-identify the sacred ``session_id`` or override the
#: binding handles / binding coordinates (the W021 identity invariant;
#: LOCK-006).  The binding coordinates (``ap_ref`` / ``ssid_name`` /
#: ``station_label``) are EXPLICIT manager parameters here -- a
#: requirements key duplicating them is an override attempt.  (The
#: WORK-016 bridge CONSUMES the SDK caller's binding-coordinate keys
#: from the requirements map as its documented translation -- the
#: generic SDK surface has no AP-selection parameter -- and passes the
#: coordinates as these explicit parameters, forwarding only the
#: leftover QoS data; the leftover map crosses THIS gate like any
#: other caller's.)
_FORBIDDEN_REQUIREMENT_KEYS: Tuple[str, ...] = (
    "session_id",
    "session",
    "assoc_ref",
    "tunnel_ref",
    "binding_id",
    "ap_ref",
    "ssid_name",
    "station_label",
)

#: Live external-association evidence states the adoption path accepts
#: (mirrors the reference engine's adoption gate; the conformance peer
#: reports these).
_LIVE_EXTERNAL_STATES: Tuple[str, ...] = ("associated", "authenticated")


@dataclass
class _BindingRecord:
    """A live binding's owning sandbox + binding (B2 per-binding
    ownership).  Captured at ``bind_session`` /
    ``attach_external_association`` time; subsequent binding-scoped
    ops dispatch to ``record.sandbox`` (never the default sandbox)."""

    binding: AssociationBinding
    sandbox: SandboxedWifi


class WifiManager:
    """The Wi-Fi/non-3GPP access integration runtime.

    Constructed with the integration instance id, the deterministic
    step budget, and the least-authority readers the manager injects
    into every sandbox.  NO implementation is registered initially.
    ``register_implementation`` validates
    ``isinstance(implementation, WifiContract)`` (NOT ``hasattr``),
    wraps the implementation in its OWN :class:`SandboxedWifi`, opens
    it, probes health, and -- only when ``make_default=True`` --
    reassigns ``self._default_sandbox``.  Live bindings keep their
    owning sandbox (B2).  Labels are unique per manager instance
    (re-registering a label fails closed with ``BINDING_EXISTS``, the
    caller-side state-error discipline the family uses for duplicate
    registrations).
    """

    def __init__(
        self,
        *,
        integration_id: Optional[str] = None,
        step_budget: int = DEFAULT_STEP_BUDGET,
        session_reader: Optional[SessionReader] = None,
        ap_profile_reader: Optional[ApProfileReader] = None,
    ) -> None:
        if integration_id is None:
            integration_id = DEFAULT_INTEGRATION_ID
        if not isinstance(integration_id, str) or not integration_id:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "integration_id must be a non-empty string",
            )
        if isinstance(step_budget, bool) or not isinstance(step_budget, int):
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "step_budget must be an integer",
            )
        if step_budget < 0:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "step_budget must be >= 0",
            )
        self._integration_id = integration_id
        self._step_budget = step_budget
        self._session_reader = session_reader
        self._ap_profile_reader = ap_profile_reader
        self._default_sandbox: Optional[SandboxedWifi] = None
        self._default_label = ""
        self._registrations: List[Tuple[str, SandboxedWifi]] = []
        self._bindings: Dict[str, _BindingRecord] = {}
        # Live-tunnel index: tunnel_ref -> binding_id (the manager's
        # projection of the tunnels IT mediated; tunnel-scoped ops
        # dispatch through it to the binding's OWNING sandbox -- B2).
        self._tunnels: Dict[str, str] = {}
        self._events: List[WifiEvent] = []
        self._observations: Dict[str, ExternalAssociationEvidence] = {}
        self._closed = False

    # ------------------------------------------------------------------
    # Implementation registration
    # ------------------------------------------------------------------

    def register_implementation(
        self,
        implementation: WifiContract,
        *,
        label: str,
        make_default: bool = False,
        now: str,
    ) -> WifiOpResult:
        """Register a Wi-Fi/non-3GPP access implementation.

        Validates ``isinstance(implementation, WifiContract)``, wraps
        it in its OWN :class:`SandboxedWifi` (with the manager's
        least-authority readers), opens it, probes health, and
        reassigns ONLY ``self._default_sandbox`` when
        ``make_default=True``.  Live bindings keep their owning
        sandbox (B2); registering with ``make_default=False`` is a
        verification pass that does not cut over the default.  Returns
        the health probe result.  ``label`` is informational only
        (diagnostic state, never canonical state -- B2) and unique per
        manager instance.
        """
        if self._closed:
            raise WifiError(WifiReasonCode.NOT_OPEN, "manager is closed")
        self._require_now(now)
        if not isinstance(label, str) or not label:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "label must be a non-empty string",
            )
        if not isinstance(make_default, bool):
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "make_default must be a boolean",
            )
        if not isinstance(implementation, WifiContract):
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "implementation must satisfy the WifiContract ABC "
                "(isinstance enforced; no hasattr duck-typing)",
            )
        for registered_label, _sandbox in self._registrations:
            if registered_label == label:
                raise WifiError(
                    WifiReasonCode.BINDING_EXISTS,
                    "implementation label %r is already registered "
                    "(labels are unique per manager instance)" % label,
                )
        sandbox = SandboxedWifi(
            implementation,
            integration_id=self._integration_id,
            step_budget=self._step_budget,
            session_reader=self._session_reader,
            ap_profile_reader=self._ap_profile_reader,
        )
        open_result = sandbox.open(now)
        if not open_result.ok:
            self._append_event(
                "REGISTER_FAILED", now=now, detail=open_result.detail
            )
            return open_result
        health_result = sandbox.health(now)
        self._registrations.append((label, sandbox))
        if make_default:
            self._default_sandbox = sandbox
            self._default_label = label
        # The REGISTERED event carries NO implementation label (B2:
        # the label is diagnostic-only and must never enter the
        # byte-identical canonical state; mirrors the WORK-018/019
        # register event discipline).
        self._append_event("REGISTERED", now=now)
        return health_result

    # ------------------------------------------------------------------
    # Public mediated operations
    # ------------------------------------------------------------------

    def _require_not_closed(self) -> None:
        if self._closed:
            raise WifiError(WifiReasonCode.NOT_OPEN, "manager is closed")

    def _require_now(self, now: str) -> None:
        if not isinstance(now, str) or not now:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "now must be an RFC 3339 instant string",
            )

    def _require_default(self) -> SandboxedWifi:
        self._require_not_closed()
        if self._default_sandbox is None:
            raise WifiError(
                WifiReasonCode.WIFI_UNAVAILABLE,
                "no Wi-Fi/non-3GPP access implementation registered "
                "(register_implementation with make_default=True first)",
            )
        return self._default_sandbox

    def _require_binding(self, binding_id: str) -> _BindingRecord:
        self._require_not_closed()
        if not isinstance(binding_id, str) or not binding_id:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "binding_id must be a non-empty string",
            )
        record = self._bindings.get(binding_id)
        if record is None:
            raise WifiError(
                WifiReasonCode.BINDING_UNKNOWN,
                "binding %s not found" % binding_id,
            )
        return record

    def _require_tunnel_binding(self, tunnel_ref: str) -> _BindingRecord:
        """Resolve a live tunnel to its binding's OWNING sandbox (B2).

        The tunnel index holds only tunnels THIS manager mediated
        (establish_tunnel through a binding); tunnel-scoped ops always
        dispatch to the owning binding's sandbox, never the default.
        """
        self._require_not_closed()
        if not isinstance(tunnel_ref, str) or not tunnel_ref:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "tunnel_ref must be a non-empty string",
            )
        binding_id = self._tunnels.get(tunnel_ref)
        if binding_id is None:
            raise WifiError(
                WifiReasonCode.BINDING_UNKNOWN,
                "tunnel %s was not established through this manager "
                "(tunnel-scoped ops dispatch to the owning binding's "
                "sandbox only)" % tunnel_ref,
            )
        return self._bindings[binding_id]

    def provision_ap(
        self, *, now: str, descriptor: Any, credential_slot_name: str,
    ) -> WifiOpResult:
        """Provision an AP profile through the DEFAULT sandbox (new AP
        profiles are created on the current default implementation;
        the returned :class:`~adapters.wifi.model.ApView` carries the
        opaque ``wifi:ap:<hex>`` ref -- Wi-Fi-side identity, never core
        state)."""
        sandbox = self._require_default()
        self._require_now(now)
        result = sandbox.provision_ap(
            now, descriptor=descriptor, credential_slot_name=credential_slot_name,
        )
        if result.ok:
            ap_view = result.value
            self._append_event(
                "AP_PROVISIONED", now=now,
                detail="ap_ref=%s" % ap_view.ap_ref,
            )
        return result

    def _reject_identity_smuggling(
        self, requirements: Optional[Mapping[str, Any]]
    ) -> None:
        """W021: a requirements map must never re-identify the binding.

        The requirements map is caller-supplied DATA for the access
        path's own QoS enforcement; a key that would override the
        sacred ``session_id`` or the binding handles / binding
        coordinates is a session/access identity-collapse attempt and
        fails closed BEFORE the implementation is invoked (extends the
        WORK-018/019/020 collapse rejection to the requirements-map
        vector).  Deep text scanning (credential-like material,
        session-digest fragments) stays with the implementation seam,
        which owns the bounded scan.
        """
        if requirements is None:
            return
        if not isinstance(requirements, Mapping):
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "requirements must be a mapping or None",
            )
        for key in requirements:
            if isinstance(key, str) and key in _FORBIDDEN_REQUIREMENT_KEYS:
                raise WifiError(
                    WifiReasonCode.ACCESS_SESSION_COLLAPSE,
                    "requirements key %r would override the session/binding "
                    "identity (W021: access-path QoS requirements are DATA "
                    "and never re-identify the sacred session_id; LOCK-006)"
                    % key,
                )

    def bind_session(
        self,
        *,
        now: str,
        session_id: str,
        ap_ref: str,
        ssid_name: str,
        station_label: str,
        requirements: Optional[Mapping[str, Any]] = None,
    ) -> WifiOpResult:
        """Bind a WORK-012 session to a Wi-Fi station association.

        The ``session_id`` is sacred and stored EXACTLY as given
        (LOCK-006); the sandbox checks the returned association ref
        against it mechanically (the W021 identity invariant), and the
        manager ADDITIONALLY rejects, caller-side and fail-closed:
        a session_id already live-bound through another binding of
        this manager (``ACCESS_SESSION_COLLAPSE`` -- one live
        association per session; an access change is a REPLACEMENT
        after release, never a duplication), a requirements map that
        smuggles a session/binding identity override key
        (``ACCESS_SESSION_COLLAPSE``), and -- post-bind, defense in
        depth -- an ``assoc_ref`` already registered under a DIFFERENT
        session_id (``ACCESS_SESSION_COLLAPSE``) or the SAME one
        (``BINDING_EXISTS``).  The returned value is the
        :class:`~adapters.wifi.model.AssociationBinding` whose
        ``binding_id`` keys this manager's binding table (the binding's
        opaque ref -- callers use it for every binding-scoped op).
        """
        sandbox = self._require_default()
        self._require_now(now)
        if not isinstance(session_id, str) or not session_id:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "session_id must be a non-empty string",
            )
        self._reject_identity_smuggling(requirements)
        validate_opaque_ref(ap_ref, "ap")
        existing = self._find_binding_by_session(session_id)
        if existing is not None:
            raise WifiError(
                WifiReasonCode.ACCESS_SESSION_COLLAPSE,
                "session %s is already live-bound through another binding "
                "of this manager (binding %s); the session/access identity "
                "axes never collapse -- release the existing binding first "
                "(an access change re-binds the SAME session_id to a NEW "
                "assoc_ref AFTER release, never alongside)"
                % (session_id, existing.binding.binding_id),
            )
        result = sandbox.bind_session(
            now, session_id=session_id, ap_ref=ap_ref, ssid_name=ssid_name,
            station_label=station_label, requirements=requirements,
        )
        if result.ok:
            binding = result.value
            # W021 (defense in depth; the model enforced separation at
            # construction and the sandbox seam re-asserted it against
            # THIS call's session_id).
            assert_ref_session_separation(binding.assoc_ref, session_id)
            for record in self._bindings.values():
                if record.binding.assoc_ref != binding.assoc_ref:
                    continue
                if record.binding.session_id != session_id:
                    raise WifiError(
                        WifiReasonCode.ACCESS_SESSION_COLLAPSE,
                        "implementation returned an association ref "
                        "already bound to a DIFFERENT session_id (W021: "
                        "Wi-Fi association identity never collapses onto "
                        "session identity; LOCK-006) -- registration "
                        "rejected; any engine-side state the implementation "
                        "created is its own",
                    )
                raise WifiError(
                    WifiReasonCode.BINDING_EXISTS,
                    "implementation returned an association ref already "
                    "bound to this session (binding already exists)",
                )
            # B2: capture the OWNING sandbox at bind time.  Subsequent
            # binding-scoped ops dispatch to record.sandbox (never the
            # default sandbox) -- so a register_implementation swap
            # leaves live bindings on their original sandbox.
            self._bindings[binding.binding_id] = _BindingRecord(
                binding=binding, sandbox=sandbox,
            )
            self._append_event(
                "BIND_SESSION", now=now, assoc_ref=binding.assoc_ref
            )
        return result

    def attach_external_association(
        self,
        *,
        now: str,
        session_id: str,
        ap_ref: str,
        station_label: str,
        evidence: ExternalAssociationEvidence,
    ) -> WifiOpResult:
        """Adopt adapter-observed state from an externally established
        Wi-Fi association (a real AP path).

        Mirrors the WORK-019 attach discipline: the evidence must have
        been OBSERVED through this manager first
        (:meth:`observe_external_association`) and be in a live state;
        the same-session collapse guard applies; the adopted binding
        registers under the DEFAULT sandbox with B2 ownership captured
        here.
        """
        if not isinstance(evidence, ExternalAssociationEvidence):
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "adapter observation is required",
            )
        self._require_now(now)
        if not isinstance(session_id, str) or not session_id:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "session_id must be a non-empty string",
            )
        observed = self._observations.get(evidence.external_association_id)
        if observed is not evidence:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "external association evidence was not observed by this "
                "manager",
            )
        if observed.state.lower() not in _LIVE_EXTERNAL_STATES:
            raise WifiError(
                WifiReasonCode.STATION_UNKNOWN,
                "external association is not in a live state",
            )
        sandbox = self._require_default()
        validate_opaque_ref(ap_ref, "ap")
        existing = self._find_binding_by_session(session_id)
        if existing is not None:
            raise WifiError(
                WifiReasonCode.ACCESS_SESSION_COLLAPSE,
                "session %s is already live-bound through another binding "
                "of this manager (binding %s); release it before adopting "
                "an external association for the same session"
                % (session_id, existing.binding.binding_id),
            )
        result = sandbox.attach_external_association(
            now, session_id=session_id, ap_ref=ap_ref,
            station_label=station_label, evidence=evidence,
        )
        if result.ok:
            binding = result.value
            assert_ref_session_separation(binding.assoc_ref, session_id)
            self._bindings[binding.binding_id] = _BindingRecord(
                binding=binding, sandbox=sandbox,
            )
            self._append_event(
                "ATTACH_EXTERNAL_ASSOCIATION", now=now,
                assoc_ref=binding.assoc_ref,
            )
        return result

    def observe_external_association(
        self, *, now: str, external_association_id: str
    ) -> WifiOpResult:
        """Query the external Wi-Fi path through the DEFAULT sandbox
        (the conformance peer / a real adapter observes; the reference
        engine honestly reports ``WIFI_UNAVAILABLE``).  A successful
        observation is remembered so :meth:`attach_external_association`
        can verify the evidence came through this manager."""
        self._require_now(now)
        result = self._require_default().observe_external_association(
            now, external_association_id=external_association_id,
        )
        if result.ok:
            self._observations[external_association_id] = result.value
        return result

    def authenticate(self, *, now: str, binding_id: str) -> WifiOpResult:
        """Run the 802.1X/SAE authentication phase on the binding's
        association (dispatched to the binding's OWNING sandbox)."""
        record = self._require_binding(binding_id)
        self._require_now(now)
        result = record.sandbox.authenticate(
            now, assoc_ref=record.binding.assoc_ref
        )
        if result.ok:
            self._append_event(
                "AUTHENTICATE", now=now, assoc_ref=record.binding.assoc_ref
            )
        return result

    def establish_tunnel(self, *, now: str, binding_id: str) -> WifiOpResult:
        """Establish the N3IWF tunnel on the binding's authenticated
        association (dispatched to the binding's OWNING sandbox; the
        returned :class:`~adapters.wifi.model.TunnelBinding` carries the
        opaque ``wifi:tunnel:<hex>`` ref -- N3IWF tunnel identity,
        never core state).  The manager indexes the live tunnel so
        tunnel-scoped ops (egress/release) dispatch to the OWNING
        binding's sandbox (B2)."""
        record = self._require_binding(binding_id)
        self._require_now(now)
        result = record.sandbox.establish_tunnel(
            now, assoc_ref=record.binding.assoc_ref
        )
        if result.ok:
            tunnel = result.value
            self._tunnels[tunnel.tunnel_ref] = binding_id
            self._append_event(
                "ESTABLISH_TUNNEL", now=now,
                assoc_ref=record.binding.assoc_ref,
                tunnel_ref=tunnel.tunnel_ref,
            )
        return result

    def egress_frame(
        self, *, now: str, tunnel_ref: str, payload: bytes
    ) -> WifiOpResult:
        """Carry a payload through the established N3IWF tunnel
        (dispatched to the tunnel's OWNING binding's sandbox -- a
        default swap never re-routes a live binding's bytes).  The ok
        value is the bytes that traversed the contract path."""
        record = self._require_tunnel_binding(tunnel_ref)
        self._require_now(now)
        result = record.sandbox.egress_frame(
            now, tunnel_ref=tunnel_ref, payload=payload
        )
        if result.ok:
            self._append_event(
                "EGRESS_FRAME", now=now,
                assoc_ref=record.binding.assoc_ref,
                tunnel_ref=tunnel_ref,
                detail="payload_len=%d" % len(payload),
            )
        return result

    def release_tunnel(self, *, now: str, tunnel_ref: str) -> WifiOpResult:
        """Release the N3IWF tunnel (dispatched to the tunnel's OWNING
        binding's sandbox; the manager drops its tunnel index entry
        only after the mediated release succeeds -- fail closed)."""
        record = self._require_tunnel_binding(tunnel_ref)
        self._require_now(now)
        result = record.sandbox.release_tunnel(now, tunnel_ref=tunnel_ref)
        if result.ok:
            self._tunnels.pop(tunnel_ref, None)
            self._append_event(
                "RELEASE_TUNNEL", now=now, tunnel_ref=tunnel_ref
            )
        return result

    def app_session(self, *, now: str, session_id: str) -> WifiOpResult:
        """Return the ordinary application session facade for a live
        binding.

        Mirrors the accepted WORK-019 ``app_session`` mechanics EXACTLY:
        the binding is located by the sacred ``session_id``, the
        family's own ``app_session`` operation is mediated through the
        binding's OWNING sandbox (charging its budget and validating
        the facade surface), and the application receives THE
        IMPLEMENTATION'S OWN validated :class:`WifiAppSession` --
        returned VERBATIM, never discarded and never re-constructed --
        with the manager's egress routing bound onto it (the
        documented ``_bind_manager`` / ``_set_now`` internal protocol)
        so the standard ``send()`` traverses
        ``manager.egress_frame`` on the binding's OWNING sandbox (B2).

        The facade OWNS whatever private data path the implementation
        gave it (a real tunnel socket stays ENCAPSULATED INSIDE the
        returned facade -- the adapter attaches it before the facade
        crosses the sandbox seam; the manager extracts NOTHING from
        the implementation and holds no second data-path authority).
        A live tunnel is required (the routed facade's data path is
        the binding's tunnel).
        """
        self._require_now(now)
        if not isinstance(session_id, str) or not session_id:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "session_id must be a non-empty string",
            )
        record = self._find_binding_by_session(session_id)
        if record is None:
            raise WifiError(
                WifiReasonCode.BINDING_UNKNOWN,
                "no active binding for session %s" % session_id,
            )
        tunnel_ref = self._live_tunnel_for_binding(record.binding.binding_id)
        if tunnel_ref is None:
            raise WifiError(
                WifiReasonCode.WIFI_UNAVAILABLE,
                "no live tunnel for the binding (establish_tunnel first; "
                "the routed application session carries bytes over the "
                "binding's tunnel)",
            )
        result = record.sandbox.app_session(now, session_id=session_id)
        if result.ok:
            session = result.value
            # The manager binds itself + the injected instant so the
            # facade's standard send() routes through the binding's
            # OWNING sandbox (B2).  The facade itself is the
            # implementation's AUTHORITATIVE object, returned verbatim.
            session._bind_manager(self)
            session._set_now(now)
            self._append_event(
                "APP_SESSION", now=now, assoc_ref=record.binding.assoc_ref
            )
        return result

    def health(self, *, now: str) -> WifiOpResult:
        """The DEFAULT implementation's health (the availability
        aggregate over the access path; reported, never authoritative
        by itself -- LOCK-017)."""
        self._require_now(now)
        sandbox = self._require_default()
        return sandbox.health(now)

    def computed_health(self) -> str:
        """The deterministic effective health of the DEFAULT
        implementation, from MEDIATED OUTCOMES ONLY (instant-free;
        LOCK-017: reported, never authoritative).

        ``NOT_RUNNING`` before any default implementation is
        registered (or before its sandbox opened); otherwise the
        owning sandbox's consecutive-failure aggregate (HEALTHY /
        DEGRADED / FAILED).  This is the instant-free informational
        surface the WORK-016 bridge translates onto the SDK's
        three-state health vocabulary -- it derives from what the
        manager can actually see (mediated outcomes), never from a
        reach-around into implementation state.
        """
        sandbox = self._default_sandbox
        if sandbox is None:
            return "NOT_RUNNING"
        return sandbox.computed_health()

    def capabilities(self) -> Tuple[str, ...]:
        """The informational capability ladder, derived from MEDIATED
        MANAGER STATE ONLY (LOCK-017: reported, never authoritative).

        ``()`` while no default implementation is registered; the four
        boundary capabilities once one is (the access boundary exists:
        non-3GPP access, association, authentication, N3IWF tunnel);
        the data-path capability additionally once the manager's
        mediated history shows at least one provisioned AP (the
        boundary has the capacity it provisioned).  The ladder is
        derived from the manager's OWN canonical event history -- the
        implementation's internal SSID activation state never crosses
        the seam (LOCK-016/017); the WORK-016 bridge surfaces this
        ladder on the SDK's ``capabilities`` surface and the SDK
        runtime filters it to the descriptor's declared set.
        """
        if self._default_sandbox is None:
            return ()
        caps: Tuple[str, ...] = (
            "capability.profile.wifi.non-3gpp-access",
            "capability.profile.wifi.association",
            "capability.profile.wifi.authentication",
            "capability.profile.wifi.n3iwf-tunnel",
        )
        if any(
            event.event_type == "AP_PROVISIONED" for event in self._events
        ):
            caps = caps + ("capability.profile.wifi.data-path",)
        return caps

    def close_binding(self, *, now: str, binding_id: str) -> WifiOpResult:
        """Close ONE binding: release the association AND its
        adapter-side resources on the binding's OWNING sandbox (fails
        closed while tunnels are outstanding -- release them first);
        the manager drops the binding record and its tunnel index
        entries only after the mediated close succeeds."""
        record = self._require_binding(binding_id)
        self._require_now(now)
        result = record.sandbox.close(
            now, assoc_ref=record.binding.assoc_ref
        )
        if result.ok:
            del self._bindings[binding_id]
            for tunnel_ref in [
                ref for ref, bid in self._tunnels.items()
                if bid == binding_id
            ]:
                del self._tunnels[tunnel_ref]
            self._append_event(
                "CLOSE_BINDING", now=now,
                assoc_ref=record.binding.assoc_ref,
            )
        return result

    def close(self) -> None:
        """Close the manager (fail-closed bookkeeping; mirrors the
        WORK-019 manager close: the binding registry is dropped and
        every subsequent op raises ``NOT_OPEN``).

        This is MANAGER-level bookkeeping only.  The implementation's
        own teardown remains a mediated operation the caller performs
        first (``release_tunnel`` / ``close_binding`` per live binding)
        -- the manager never tears a live session-to-association
        mapping out from under an application as a side effect of its
        own shutdown.
        """
        self._closed = True
        self._bindings.clear()
        self._tunnels.clear()

    # ------------------------------------------------------------------
    # Canonical public state (B2: implementation_label EXCLUDED)
    # ------------------------------------------------------------------

    def snapshot(self) -> Dict[str, Any]:
        """The canonical public state (byte-identical across impls).

        Carries ONLY integration-instance state (bindings, events).
        NEVER Wi-Fi/N3IWF access state (LOCK-016/017) and NEVER the
        ``implementation_label`` (B2; mirrors WORK-018/019).  Bindings
        are sorted by binding id; events are in append order --
        byte-stable across runs and across equivalent implementations
        for a given operation history.
        """
        bindings = [
            self._bindings[binding_id].binding.to_dict()
            for binding_id in sorted(self._bindings)
        ]
        events = [event.to_dict() for event in self._events]
        return {
            "integration_id": self._integration_id,
            "closed": self._closed,
            "binding_count": len(self._bindings),
            "bindings": bindings,
            "events": events,
        }

    def to_canonical_bytes(self) -> bytes:
        """Canonical-JSON bytes of the public state (byte-identical
        across runs and across equivalent implementations)."""
        return canonical_json_bytes(to_canonical_dict(self.snapshot()))

    def content_digest(self) -> str:
        """SHA-256 of the canonical public state."""
        return hashlib.sha256(self.to_canonical_bytes()).hexdigest()

    def diagnostic_state(self) -> Dict[str, Any]:
        """Diagnostic state (NOT canonical public state; B2).  Exposes
        the registered ``implementation_label`` and health accounting
        so operators can inspect the live implementation without it
        entering the byte-identical canonical state."""
        sandbox = self._default_sandbox
        if sandbox is None:
            return {
                "integration_id": self._integration_id,
                "implementation_label": "",
                "sandbox_health": "NOT_RUNNING",
                "registered_implementations": len(self._registrations),
                "binding_count": len(self._bindings),
                "closed": self._closed,
            }
        diag = sandbox.diagnostic_state()
        diag["integration_id"] = self._integration_id
        diag["registered_implementations"] = len(self._registrations)
        diag["binding_count"] = len(self._bindings)
        diag["closed"] = self._closed
        return diag

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _find_binding_by_session(
        self, session_id: str
    ) -> Optional[_BindingRecord]:
        for record in self._bindings.values():
            if record.binding.session_id == session_id:
                return record
        return None

    def _live_tunnel_for_binding(self, binding_id: str) -> Optional[str]:
        for tunnel_ref, bid in self._tunnels.items():
            if bid == binding_id:
                return tunnel_ref
        return None

    def _append_event(
        self,
        event_type: str,
        *,
        now: str,
        assoc_ref: str = "",
        tunnel_ref: str = "",
        detail: str = "",
    ) -> None:
        self._events.append(
            WifiEvent(
                event_type=event_type,
                integration_id=self._integration_id,
                instant=now,
                assoc_ref=assoc_ref,
                tunnel_ref=tunnel_ref,
                detail=detail,
            )
        )

    @property
    def integration_id(self) -> str:
        return self._integration_id

    @property
    def binding_count(self) -> int:
        return len(self._bindings)

    @property
    def closed(self) -> bool:
        return self._closed
