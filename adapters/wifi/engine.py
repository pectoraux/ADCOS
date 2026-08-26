"""ADCOS Wi-Fi/non-3GPP access reference engine (WORK-021).

:class:`ReferenceWifiEngine` is the deterministic, in-memory Wi-Fi/
non-3GPP access domain reference model.  It is the model CI runs
offline (deterministic byte-identical snapshots, no wall clock, no
randomness).  It is HONESTLY NON-CONFIDENTIAL: no real Wi-Fi stack, no
real N3IWF, no IPsec/IKEv2, no 802.11 radio, no vendor SDK, no
chipset API is present or imported.  It models the IEEE 802.11-2020
(association/SSID shapes), IEEE 802.1X-2020 + RFC 3748 (EAP
port-based access-control shapes), 3GPP TS 23.316 / TS 24.302
(non-3GPP access + N3IWF attach shapes), and RFC 7296 / RFC 4301
(IPsec/IKEv2 tunnel SHAPES only -- never the protocols) in-memory; a
production Wi-Fi/N3IWF path plugs in behind the same
:class:`WifiContract` without modifying the manager or any core
semantics (LOCK-002/016/017/018).  It can NEVER satisfy the
real-mixed-access interoperability acceptance evidence on its own --
that is the environment-gated real-interop gate's job (a later
WORK-021 task), never a fabricated PASS.

The reference engine is ACCESS-STATE-OUT (LOCK-016/017): its
in-memory access state (AP profile store, SSID activation states,
station association table, N3IWF tunnel table, adapter-private auth
state) lives in the ADAPTER package, NEVER in the ADCOS core.  The
manager's ``snapshot()`` (a later task) carries only
integration-instance state (bindings, events) -- NEVER access-path
state.  BSSID/association-id material (IEEE 802.11-2020) and
IPsec/NAS identity (RFC 7296/4301, TS 24.302) are NEVER modeled --
they stay adapter-side opaque behind the content-derived refs.

The reference engine is CREDENTIAL-OUT (LOCK-023): Wi-Fi/802.1X and
N3IWF IPsec credentials never cross the boundary.  The engine stores
credential slot NAMES only (the material is the adapter's private
concern; the reference models the slot-name lookup, never the
material).  The 802.1X/SAE authentication phase (IEEE 802.1X-2020,
IEEE 802.11-2020 Clause 12) is modeled as a deterministic
slot-name-lookup success for a provisioned AP profile -- the real
EAP/SAE exchange is the conformance peer's job, on a real path.

Identity discipline (the W021 invariant, structural throughout):
``session_id`` is SACRED and access-independent; ``assoc_ref`` (the
Wi-Fi association identity handle) and ``tunnel_ref`` (the N3IWF
tunnel identity handle) are content-derived OPAQUE refs minted over
canonical content that includes the session_id as hash INPUT only --
never as observable ref text.  A re-association or tunnel
re-establishment (an access change) mints a NEW ref for the SAME
session_id via the deterministic sequence bump; the boundary NEVER
collapses the identity axes and never mints a new session_id merely
because the access changed.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Dict, List, Mapping, Optional, Tuple

from .contract import WifiContext, WifiContract
from .errors import WifiError, WifiReasonCode
from .model import (
    ApDescriptor,
    ApState,
    ApView,
    AssociationBinding,
    AssociationState,
    AuthResult,
    ExternalAssociationEvidence,
    SsidProfile,
    TunnelBinding,
    derive_ap_ref,
    derive_assoc_ref,
    derive_binding_id,
    derive_tunnel_ref,
)
from .sandbox import STEP_CHARGES
from .session import WifiAppSession
from .validation import (
    reject_credential_like_text,
    validate_credential_slot_name,
    validate_opaque_ref,
    validate_ssid_name,
    validate_station_label,
)

__all__ = ["ReferenceWifiEngine", "CAPABILITIES"]

#: Honest capability ladder (informational; LOCK-017: reported, never
#: authoritative).  Identifiers are well-formed under the WORK-002
#: capability-registry grammar (open-world: preserved verbatim, safely
#: ignorable until registered).  They state exactly what the reference
#: model can do -- the modeled association/authentication/tunnel
#: lifecycles and the deterministic data path -- and nothing more.
CAPABILITIES: Tuple[str, ...] = (
    "capability.profile.wifi.non-3gpp-access",
    "capability.profile.wifi.association",
    "capability.profile.wifi.authentication",
    "capability.profile.wifi.n3iwf-tunnel",
    "capability.profile.wifi.data-path",
)

#: Per-association N3IWF tunnel capacity in the reference model.  3GPP
#: TS 23.316 carries the non-3GPP data path over a single IPsec
#: tunnel between the station and the N3IWF per association (RFC 7296
#: shapes, adapter-private): a second concurrent establish_tunnel on
#: one association is deterministic capacity exhaustion, reported
#: fail-closed (WIFI_UNAVAILABLE), never a silent drop.
MAX_TUNNELS_PER_ASSOCIATION = 1

#: Live external-association evidence states the adoption path
#: accepts (the conformance peer reports these; anything else is not
#: adoptable -- mirrors the fivegc "active"/"established" gate).
_LIVE_EXTERNAL_STATES: Tuple[str, ...] = ("associated", "authenticated")

#: Deterministic bound on the requirements smuggling scan (fail
#: closed on absurdly deep/arge caller payloads instead of scanning
#: unboundedly; a real policy engine lives behind the seam).
_REQUIREMENTS_SCAN_BOUND = 256

#: Hex alphabet for the digest-fragment smuggling guard (the a1
#: ``[0-9a-f]`` vocabulary; lowercase, matching the ref grammar).
_HEX_ALPHABET = frozenset("0123456789abcdef")


def _is_hex_fragment(text: str) -> bool:
    """True when ``text`` is a non-empty lowercase-hex fragment."""
    return bool(text) and all(char in _HEX_ALPHABET for char in text)


class _ApEntry:
    """Adapter-private AP profile state (never crosses the boundary)."""

    __slots__ = ("ap_view", "credential_slot_name", "ssid_states")

    def __init__(self, ap_view: ApView, credential_slot_name: str) -> None:
        self.ap_view = ap_view
        self.credential_slot_name = credential_slot_name
        # SSID activation states (the reference model provisions SSIDs
        # ACTIVE -- provision_ap is the deterministic stand-in for the
        # operator bringing the profile up; the reference-model
        # availability controls below move them between active and
        # inactive to exercise the degraded/down ladders).
        self.ssid_states: Dict[str, str] = {
            profile.ssid: ApState.ACTIVE for profile in ap_view.ssids
        }


class _AssociationEntry:
    """Adapter-private station association state (never crosses)."""

    __slots__ = ("binding", "state", "auth_ref")

    def __init__(self, binding: AssociationBinding) -> None:
        self.binding = binding
        self.state: str = AssociationState.ASSOCIATED
        # OPAQUE auth state (the reference models the credential-slot
        # lookup; NEVER the credential material).  The real
        # 802.1X/EAP or SAE exchange is the conformance peer's job.
        self.auth_ref: Optional[str] = None


class _TunnelEntry:
    """Adapter-private N3IWF tunnel state (never crosses)."""

    __slots__ = ("binding", "released")

    def __init__(self, binding: TunnelBinding) -> None:
        self.binding = binding
        self.released = False


class ReferenceWifiEngine(WifiContract):
    """The deterministic in-memory Wi-Fi/non-3GPP access reference
    (WORK-021).

    Implements the 12 :class:`WifiContract` operations in-memory.  No
    real Wi-Fi stack, no real N3IWF, no IPsec, no radio, no vendor
    SDK.  The IEEE 802.11-2020 / IEEE 802.1X-2020 / 3GPP TS 23.316 /
    TS 24.302 / RFC 7296 / RFC 4301 reference SHAPES are modeled
    in-memory (the conformance peer carries the real bytes on a real
    path; this engine is the deterministic model CI runs offline).

    Determinism: no wall clock (instants are context-injected), no
    randomness, no environment reads, no network I/O -- identical op
    history produces byte-identical canonical state.
    """

    label = "reference-wifi-engine"

    #: Deterministic step charges per operation (the family's frozen
    #: pinnable table, defined at module level in
    #: :mod:`adapters.wifi.sandbox`; the engine charges these against
    #: the :class:`WifiContext` budget at op entry -- mirroring the
    #: fivegc engine-side charging behavior).
    STEP_CHARGES: Mapping[str, int] = STEP_CHARGES

    def __init__(self) -> None:
        self._open = False
        self._aps: Dict[str, _ApEntry] = {}
        self._associations: Dict[str, _AssociationEntry] = {}
        self._tunnels: Dict[str, _TunnelEntry] = {}
        # Deterministic sequence counter for content-derived ids (no
        # randomness; reset on construction; increments predictably at
        # every identity mint -- bind, attach, tunnel establish -- so
        # byte-identical snapshots across runs hold and a re-bind after
        # release mints a NEW ref for the SAME sacred session_id).
        self._sequence = 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _require_open(self) -> None:
        if not self._open:
            raise WifiError(WifiReasonCode.NOT_OPEN, "engine not open")

    def _require_ap_entry(self, ap_ref: str) -> _ApEntry:
        entry = self._aps.get(ap_ref)
        if entry is None:
            raise WifiError(
                WifiReasonCode.AP_UNKNOWN,
                "ap %s not provisioned" % ap_ref,
            )
        return entry

    def _ssid_profile(self, ap_entry: _ApEntry, ssid_name: str) -> SsidProfile:
        for profile in ap_entry.ap_view.ssids:
            if profile.ssid == ssid_name:
                return profile
        raise WifiError(
            WifiReasonCode.SSID_UNKNOWN,
            "ssid %r is not on ap %r" % (ssid_name, ap_entry.ap_view.name),
        )

    def _require_availability(
        self, ap_entry: _ApEntry, ssid_name: str, *, operation: str
    ) -> None:
        """Availability gate: fail closed, degrade loudly -- a
        deactivated SSID or an inactive AP never carries silently."""
        if ap_entry.ap_view.state != ApState.ACTIVE:
            raise WifiError(
                WifiReasonCode.WIFI_UNAVAILABLE,
                "%s fails closed: ap %r is inactive (the access path "
                "degrades loudly, never kills silently)" % (operation, ap_entry.ap_view.name),
            )
        if ap_entry.ssid_states.get(ssid_name) != ApState.ACTIVE:
            raise WifiError(
                WifiReasonCode.WIFI_UNAVAILABLE,
                "%s fails closed: ssid %r is deactivated (the access "
                "path degrades loudly, never kills silently)" % (operation, ssid_name),
            )

    def _live_association(self, assoc_ref: str) -> _AssociationEntry:
        entry = self._associations.get(assoc_ref)
        if entry is None or entry.state == AssociationState.RELEASED:
            raise WifiError(
                WifiReasonCode.BINDING_UNKNOWN,
                "association %s not found" % assoc_ref,
            )
        return entry

    def _live_association_for_session(
        self, session_id: str
    ) -> Optional[_AssociationEntry]:
        for entry in self._associations.values():
            if entry.binding.session_id == session_id and entry.state != AssociationState.RELEASED:
                return entry
        return None

    def _live_association_count_for_ssid(self, ap_ref: str, ssid_name: str) -> int:
        return sum(
            1
            for entry in self._associations.values()
            if entry.state != AssociationState.RELEASED
            and entry.binding.ap_ref == ap_ref
            and entry.binding.ssid == ssid_name
        )

    def _live_association_count_for_ap(self, ap_ref: str) -> int:
        return sum(
            1
            for entry in self._associations.values()
            if entry.state != AssociationState.RELEASED
            and entry.binding.ap_ref == ap_ref
        )

    def _live_tunnel_count(self, assoc_ref: str) -> int:
        return sum(
            1
            for tunnel in self._tunnels.values()
            if not tunnel.released and tunnel.binding.assoc_ref == assoc_ref
        )

    def _live_tunnel_for_association(
        self, assoc_ref: str
    ) -> Optional[_TunnelEntry]:
        for tunnel in self._tunnels.values():
            if not tunnel.released and tunnel.binding.assoc_ref == assoc_ref:
                return tunnel
        return None

    def _active_ssid_count(self) -> int:
        return sum(
            1
            for ap_entry in self._aps.values()
            if ap_entry.ap_view.state == ApState.ACTIVE
            for state in ap_entry.ssid_states.values()
            if state == ApState.ACTIVE
        )

    @staticmethod
    def _reject_smuggled_text(text: str, session_id: str, *, label: str) -> None:
        """Reject one caller-supplied string that carries session
        authority or credential-like material (W021 identity
        invariant + LOCK-023), fail-closed as INVALID_INPUT.

        WORK-AROUND (foundation issue, documented in the W021-a2
        worklog): the foundation enforcer
        :func:`~adapters.wifi.validation.assert_ref_session_separation`
        assumes its first argument carries the ``wifi:<kind>:<hex>``
        ref shape (it splits on ``:`` unguarded and raises IndexError
        on colon-free text), so it cannot be reused for ARBITRARY
        caller text (labels, requirement keys/values).  The engine
        therefore enforces the same session-authority embedding rule
        locally for text: the text must not equal or embed the
        session_id, nor its digest fragment.  The a1-frozen
        ACCESS_SESSION_COLLAPSE code stays reserved for the
        ref/session seam, where the enforcer is shape-safe.
        """
        reject_credential_like_text(text, label=label)
        if text == session_id or session_id in text:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "%s must not embed WORK-012 session authority "
                "(the identity axes never collapse -- W021)" % label,
            )
        session_digest = session_id.split(":", 1)[1] if ":" in session_id else ""
        if len(session_digest) >= 16 and session_digest in text:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "%s must not embed WORK-012 session-id digest material "
                "(the identity axes never collapse -- W021)" % label,
            )
        # Truncated-digest smuggling (the a1 fragment guard, mirrored
        # for arbitrary text): any >=16-hex-char fragment of the text
        # that appears inside the session digest is session-authority
        # material.  Shorter fragments are not flagged (a 64-bit
        # collision cannot occur by accident between honest
        # content-derived values -- the a1 rule).
        if len(session_digest) >= 16:
            for start in range(0, max(0, len(text) - 15)):
                fragment = text[start:start + 16]
                if _is_hex_fragment(fragment) and fragment in session_digest:
                    raise WifiError(
                        WifiReasonCode.INVALID_INPUT,
                        "%s must not embed WORK-012 session-id digest "
                        "fragments (the identity axes never collapse -- "
                        "W021)" % label,
                    )

    @staticmethod
    def _reject_identity_smuggling(
        session_id: str,
        *,
        station_label: str,
        requirements: Optional[Mapping[str, Any]],
    ) -> None:
        """Reject identity/credential smuggling at the engine seam.

        Adapter-side labels and caller-supplied requirements carry NO
        session-authority material (embedding the sacred session_id or
        its digest collapses the identity axes) and NO credential-like
        material (LOCK-023); violations are caller-input errors
        (INVALID_INPUT), raised via the validation helpers.
        """
        ReferenceWifiEngine._reject_smuggled_text(
            station_label, session_id, label="station_label"
        )
        if requirements is None:
            return
        if not isinstance(requirements, Mapping):
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "requirements must be a mapping or None",
            )
        scanned = 0
        stack: List[Any] = [requirements]
        while stack:
            node = stack.pop()
            scanned += 1
            if scanned > _REQUIREMENTS_SCAN_BOUND:
                raise WifiError(
                    WifiReasonCode.INVALID_INPUT,
                    "requirements exceed the deterministic smuggling-scan "
                    "bound (%d nodes)" % _REQUIREMENTS_SCAN_BOUND,
                )
            if isinstance(node, Mapping):
                for key, value in node.items():
                    if not isinstance(key, str) or not key:
                        raise WifiError(
                            WifiReasonCode.INVALID_INPUT,
                            "requirement keys must be non-empty strings",
                        )
                    ReferenceWifiEngine._reject_smuggled_text(
                        key, session_id, label="requirements key"
                    )
                    stack.append(value)
            elif isinstance(node, (list, tuple)):
                stack.extend(node)
            elif isinstance(node, str):
                ReferenceWifiEngine._reject_smuggled_text(
                    node, session_id, label="requirements value"
                )
            elif isinstance(node, bool) or isinstance(node, int) or node is None:
                continue
            else:
                raise WifiError(
                    WifiReasonCode.INVALID_INPUT,
                    "requirements values must be strings, integers, "
                    "booleans, None, or nested mappings/lists",
                )

    # ------------------------------------------------------------------
    # Contract operations
    # ------------------------------------------------------------------

    def open(self, context: WifiContext) -> None:
        context.charge(STEP_CHARGES["open"])
        if self._open:
            raise WifiError(
                WifiReasonCode.ALREADY_OPEN, "engine already open"
            )
        self._open = True

    def provision_ap(
        self,
        context: WifiContext,
        *,
        descriptor: ApDescriptor,
        credential_slot_name: str,
    ) -> ApView:
        context.charge(STEP_CHARGES["provision_ap"])
        self._require_open()
        if not isinstance(descriptor, ApDescriptor):
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "descriptor must be an ApDescriptor (IEEE 802.11-2020 "
                "profile shape)",
            )
        # LOCK-023: the slot NAME only (credential material stays in
        # the adapter's private store); credential-LIKE names are
        # rejected so a key cannot be smuggled through the slot name.
        validate_credential_slot_name(credential_slot_name)
        reject_credential_like_text(descriptor.name, label="ap name")
        for profile in descriptor.ssids:
            reject_credential_like_text(profile.ssid, label="ssid name")
        ap_ref = derive_ap_ref(descriptor)
        if ap_ref in self._aps:
            raise WifiError(
                WifiReasonCode.BINDING_EXISTS,
                "ap profile already provisioned (identical canonical "
                "content)",
            )
        ap_view = ApView(
            ap_ref=ap_ref,
            name=descriptor.name,
            ssids=descriptor.ssids,
            bands=descriptor.bands,
            max_associations=descriptor.max_associations,
            state=ApState.ACTIVE,
        )
        self._aps[ap_ref] = _ApEntry(ap_view, credential_slot_name)
        return ap_view

    def bind_session(
        self,
        context: WifiContext,
        *,
        session_id: str,
        ap_ref: str,
        ssid_name: str,
        station_label: str,
        requirements: Optional[Mapping[str, Any]] = None,
    ) -> AssociationBinding:
        context.charge(STEP_CHARGES["bind_session"])
        self._require_open()
        if not isinstance(session_id, str) or not session_id:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "session_id must be a non-empty string",
            )
        # Verify the WORK-012 session exists AND is secureable (the
        # boundary NEVER binds a nonexistent or non-secureable
        # session; mirrors the WORK-018/019 discipline).  The reader
        # is the secret-free SessionReader facade.
        session_view = context.session_reader().lookup(session_id)
        if session_view is None:
            raise WifiError(
                WifiReasonCode.SESSION_NOT_SECUREABLE,
                "session %s does not exist (read-only WORK-012 lookup)"
                % session_id,
            )
        if not session_view.secureable:
            raise WifiError(
                WifiReasonCode.SESSION_NOT_SECUREABLE,
                "session %s is not secureable" % session_id,
            )
        validate_opaque_ref(ap_ref, "ap")
        validate_ssid_name(ssid_name)
        validate_station_label(station_label)
        self._reject_identity_smuggling(
            session_id, station_label=station_label, requirements=requirements
        )
        ap_entry = self._require_ap_entry(ap_ref)
        profile = self._ssid_profile(ap_entry, ssid_name)
        self._require_availability(
            ap_entry, ssid_name, operation="bind_session"
        )
        # Strict same-state transition: a session holds at most ONE
        # live association in the reference model; an access change
        # releases/rebinds (the SAME session_id gets a NEW assoc_ref).
        if self._live_association_for_session(session_id) is not None:
            raise WifiError(
                WifiReasonCode.BINDING_EXISTS,
                "session already has a live association (release or "
                "close it before rebinding; an access change re-binds "
                "the SAME session_id to a NEW assoc_ref)",
            )
        # Resource accounting (fail closed, never silently drop).
        ssid_count = self._live_association_count_for_ssid(ap_ref, ssid_name)
        if ssid_count >= profile.max_stations:
            raise WifiError(
                WifiReasonCode.WIFI_UNAVAILABLE,
                "ssid %r station capacity exhausted (%d/%d; the "
                "IEEE 802.11-2020 association identifier space is "
                "admission DATA -- a production AP enforces it behind "
                "the seam)" % (ssid_name, ssid_count, profile.max_stations),
            )
        ap_count = self._live_association_count_for_ap(ap_ref)
        if ap_count >= ap_entry.ap_view.max_associations:
            raise WifiError(
                WifiReasonCode.WIFI_UNAVAILABLE,
                "ap %r association capacity exhausted (%d/%d)"
                % (ap_entry.ap_view.name, ap_count,
                   ap_entry.ap_view.max_associations),
            )
        # Content-derive the Wi-Fi ACCESS identity (the W021 identity
        # invariant: distinct from the sacred session_id by
        # construction -- the session_id is hash INPUT, never ref text).
        self._sequence += 1
        assoc_ref = derive_assoc_ref(session_id, ap_ref, station_label, self._sequence)
        binding_id = derive_binding_id(session_id, assoc_ref)
        binding = AssociationBinding(
            session_id=session_id,
            assoc_ref=assoc_ref,
            binding_id=binding_id,
            ap_ref=ap_ref,
            ssid=ssid_name,
            station_label=station_label,
            security_policy=profile.security_policy,
            closed=False,
        )
        if assoc_ref in self._associations:
            raise WifiError(
                WifiReasonCode.BINDING_EXISTS,
                "association already exists for session",
            )
        self._associations[assoc_ref] = _AssociationEntry(binding)
        return binding

    def attach_external_association(
        self,
        context: WifiContext,
        *,
        session_id: str,
        ap_ref: str,
        station_label: str,
        evidence: ExternalAssociationEvidence,
    ) -> AssociationBinding:
        context.charge(STEP_CHARGES["attach_external_association"])
        self._require_open()
        if not isinstance(session_id, str) or not session_id:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "session_id must be a non-empty string",
            )
        if not isinstance(evidence, ExternalAssociationEvidence):
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "evidence must be an ExternalAssociationEvidence",
            )
        session_view = context.session_reader().lookup(session_id)
        if session_view is None or not session_view.secureable:
            raise WifiError(
                WifiReasonCode.SESSION_NOT_SECUREABLE,
                "session is missing or not secureable",
            )
        validate_opaque_ref(ap_ref, "ap")
        validate_station_label(station_label)
        self._reject_identity_smuggling(
            session_id, station_label=station_label, requirements=None
        )
        if evidence.station_label != station_label:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "external association evidence does not match request",
            )
        if self._live_association_for_session(session_id) is not None:
            raise WifiError(
                WifiReasonCode.BINDING_EXISTS,
                "session already has a live association",
            )
        ap_entry = self._require_ap_entry(ap_ref)
        profile = self._ssid_profile(ap_entry, evidence.ssid)
        if evidence.security_policy != profile.security_policy:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "external association evidence security policy does not "
                "match the ssid profile",
            )
        if evidence.state.lower() not in _LIVE_EXTERNAL_STATES:
            raise WifiError(
                WifiReasonCode.STATION_UNKNOWN,
                "external association is not in a live state",
            )
        self._require_availability(
            ap_entry, evidence.ssid, operation="attach_external_association"
        )
        ssid_count = self._live_association_count_for_ssid(ap_ref, evidence.ssid)
        if ssid_count >= profile.max_stations:
            raise WifiError(
                WifiReasonCode.WIFI_UNAVAILABLE,
                "ssid %r station capacity exhausted (%d/%d)"
                % (evidence.ssid, ssid_count, profile.max_stations),
            )
        ap_count = self._live_association_count_for_ap(ap_ref)
        if ap_count >= ap_entry.ap_view.max_associations:
            raise WifiError(
                WifiReasonCode.WIFI_UNAVAILABLE,
                "ap %r association capacity exhausted (%d/%d)"
                % (ap_entry.ap_view.name, ap_count,
                   ap_entry.ap_view.max_associations),
            )
        # Adopt: mint the association binding from the adapter-observed
        # evidence (the SAME sacred session_id; a NEW assoc_ref).
        self._sequence += 1
        assoc_ref = derive_assoc_ref(session_id, ap_ref, station_label, self._sequence)
        binding_id = derive_binding_id(session_id, assoc_ref)
        binding = AssociationBinding(
            session_id=session_id,
            assoc_ref=assoc_ref,
            binding_id=binding_id,
            ap_ref=ap_ref,
            ssid=evidence.ssid,
            station_label=station_label,
            security_policy=profile.security_policy,
            closed=False,
        )
        if assoc_ref in self._associations:
            raise WifiError(
                WifiReasonCode.BINDING_EXISTS,
                "association already exists",
            )
        entry = _AssociationEntry(binding)
        # The adopted external association is already authenticated on
        # the real path; mark it so establish_tunnel/egress work
        # immediately (mirrors the fivegc external-adoption mechanics).
        entry.state = AssociationState.AUTHENTICATED
        entry.auth_ref = "external:%s" % evidence.external_association_id
        self._associations[assoc_ref] = entry
        # Mirror fivegc: pre-establish the N3IWF tunnel so egress works
        # immediately on the adopted association.
        tunnel_ref = derive_tunnel_ref(binding_id, self._sequence)
        tunnel_binding = TunnelBinding(
            session_id=session_id,
            assoc_ref=assoc_ref,
            tunnel_ref=tunnel_ref,
            binding_id=binding_id,
            closed=False,
        )
        self._tunnels[tunnel_ref] = _TunnelEntry(tunnel_binding)
        return binding

    def observe_external_association(
        self, context: WifiContext, *, external_association_id: str
    ) -> ExternalAssociationEvidence:
        # Mirrors the fivegc reference engine: external observation is
        # unavailable in the reference model (the conformance peer on
        # a real path is the implementation that observes).
        raise WifiError(
            WifiReasonCode.WIFI_UNAVAILABLE,
            "external association observation is unavailable",
        )

    def authenticate(
        self,
        context: WifiContext,
        *,
        assoc_ref: str,
    ) -> AuthResult:
        context.charge(STEP_CHARGES["authenticate"])
        self._require_open()
        validate_opaque_ref(assoc_ref, "assoc")
        entry = self._live_association(assoc_ref)
        # Look up the AP profile (the credential MATERIAL stays in the
        # adapter; the reference models the slot-name lookup + a
        # deterministic auth_ref).  The real 802.1X/EAP or SAE
        # exchange (IEEE 802.1X-2020, IEEE 802.11-2020 Clause 12,
        # RFC 3748) is modeled by the conformance peer on a real path;
        # the reference marks auth success for a provisioned profile.
        ap_entry = self._require_ap_entry(entry.binding.ap_ref)
        self._require_availability(
            ap_entry, entry.binding.ssid, operation="authenticate"
        )
        # OPAQUE auth_ref (content-derived; the adapter's private auth
        # state is keyed by it; NEVER the credential material).
        entry.auth_ref = "%s:auth:%s" % (
            assoc_ref,
            derive_tunnel_ref(entry.binding.binding_id, self._sequence),
        )
        entry.state = AssociationState.AUTHENTICATED
        return AuthResult(
            success=True,
            auth_ref=entry.auth_ref,
            station_label=entry.binding.station_label,
        )

    def establish_tunnel(
        self,
        context: WifiContext,
        *,
        assoc_ref: str,
    ) -> TunnelBinding:
        context.charge(STEP_CHARGES["establish_tunnel"])
        self._require_open()
        validate_opaque_ref(assoc_ref, "assoc")
        entry = self._live_association(assoc_ref)
        if entry.state != AssociationState.AUTHENTICATED or entry.auth_ref is None:
            raise WifiError(
                WifiReasonCode.AUTHENTICATION_REJECTED,
                "association not authenticated",
            )
        ap_entry = self._require_ap_entry(entry.binding.ap_ref)
        self._require_availability(
            ap_entry, entry.binding.ssid, operation="establish_tunnel"
        )
        # Resource accounting (fail closed, never silently drop).
        live = self._live_tunnel_count(assoc_ref)
        if live >= MAX_TUNNELS_PER_ASSOCIATION:
            raise WifiError(
                WifiReasonCode.WIFI_UNAVAILABLE,
                "per-association tunnel capacity exhausted (%d/%d; the "
                "reference models one N3IWF IPsec tunnel per "
                "association per 3GPP TS 23.316)" % (live, MAX_TUNNELS_PER_ASSOCIATION),
            )
        # Content-derive the N3IWF TUNNEL identity -- distinct from the
        # sacred session_id AND from the assoc_ref by construction
        # (W021 identity invariant).  A re-establishment after release
        # mints a NEW tunnel_ref for the SAME session_id (sequence
        # bump).
        self._sequence += 1
        tunnel_ref = derive_tunnel_ref(entry.binding.binding_id, self._sequence)
        binding = TunnelBinding(
            session_id=entry.binding.session_id,
            assoc_ref=assoc_ref,
            tunnel_ref=tunnel_ref,
            binding_id=entry.binding.binding_id,
            closed=False,
        )
        if tunnel_ref in self._tunnels:
            raise WifiError(
                WifiReasonCode.BINDING_EXISTS,
                "tunnel already exists",
            )
        self._tunnels[tunnel_ref] = _TunnelEntry(binding)
        return binding

    def egress_frame(
        self,
        context: WifiContext,
        *,
        tunnel_ref: str,
        payload: bytes,
    ) -> bytes:
        context.charge(STEP_CHARGES["egress_frame"])
        self._require_open()
        if not isinstance(payload, (bytes, bytearray)):
            raise WifiError(
                WifiReasonCode.INVALID_INPUT, "payload must be bytes"
            )
        validate_opaque_ref(tunnel_ref, "tunnel")
        tunnel = self._tunnels.get(tunnel_ref)
        if tunnel is None or tunnel.released:
            raise WifiError(
                WifiReasonCode.TUNNEL_UNKNOWN,
                "tunnel %s not found" % tunnel_ref,
            )
        entry = self._live_association(tunnel.binding.assoc_ref)
        ap_entry = self._require_ap_entry(entry.binding.ap_ref)
        # Availability semantics: a deactivated SSID or an inactive AP
        # fails the data path CLOSED (WIFI_UNAVAILABLE) -- the access
        # path degrades loudly and never drops frames silently.
        self._require_availability(
            ap_entry, entry.binding.ssid, operation="egress_frame"
        )
        # In-memory model: return the payload bytes byte-identical
        # (the deterministic data path; the conformance peer carries
        # the real bytes over a real Wi-Fi/N3IWF path).
        return bytes(payload)

    def release_tunnel(
        self,
        context: WifiContext,
        *,
        tunnel_ref: str,
    ) -> None:
        context.charge(STEP_CHARGES["release_tunnel"])
        validate_opaque_ref(tunnel_ref, "tunnel")
        tunnel = self._tunnels.get(tunnel_ref)
        if tunnel is None or tunnel.released:
            raise WifiError(
                WifiReasonCode.TUNNEL_UNKNOWN,
                "tunnel %s not found" % tunnel_ref,
            )
        tunnel.released = True

    def app_session(
        self,
        context: WifiContext,
        *,
        session_id: str,
    ) -> Any:
        context.charge(STEP_CHARGES["app_session"])
        entry = self._live_association_for_session(session_id)
        if entry is None:
            raise WifiError(
                WifiReasonCode.BINDING_UNKNOWN,
                "no live association for session %s" % session_id,
            )
        tunnel = self._live_tunnel_for_association(entry.binding.assoc_ref)
        # The family's application-session facade (adapters.wifi.session
        # -- the a3 module).  The MANAGER binds itself + the injected
        # instant later (the documented _bind_manager / _set_now
        # internal protocol), so the facade's standard send() routes
        # through the binding's OWNING sandbox; the facade the
        # implementation returns is the AUTHORITATIVE application
        # object (the manager returns it verbatim -- it never
        # constructs a second facade).  Mirrors the accepted WORK-019
        # reference engine's AppSession construction.
        return WifiAppSession(
            destination=entry.binding.ssid,
            tunnel_ref=(
                tunnel.binding.tunnel_ref if tunnel is not None else ""
            ),
        )

    def health(self) -> str:
        # Availability aggregate over the SSID activation states
        # (mirrors the fivegc engine's ladder vocabulary):
        #   NOT_RUNNING  -- the access path is not open
        #   HEALTHY      -- at least one ACTIVE SSID can carry
        #   DEGRADED     -- provisioned but nothing active
        #   FAILED       -- open with an empty AP store: the access
        #                   path is down (nothing can ever carry)
        if not self._open:
            return "NOT_RUNNING"
        if self._active_ssid_count() >= 1:
            return "HEALTHY"
        if self._aps:
            return "DEGRADED"
        return "FAILED"

    def close(
        self,
        context: WifiContext,
        *,
        assoc_ref: str,
    ) -> None:
        context.charge(STEP_CHARGES["close"])
        validate_opaque_ref(assoc_ref, "assoc")
        entry = self._associations.get(assoc_ref)
        if entry is None:
            raise WifiError(
                WifiReasonCode.BINDING_UNKNOWN,
                "association %s not found" % assoc_ref,
            )
        if entry.state == AssociationState.RELEASED:
            raise WifiError(
                WifiReasonCode.ILLEGAL_STATE,
                "association already released",
            )
        # Fails closed while outstanding: live tunnels are never
        # silently discarded -- the caller releases them first.
        outstanding = self._live_tunnel_count(assoc_ref)
        if outstanding:
            raise WifiError(
                WifiReasonCode.ILLEGAL_STATE,
                "association has %d outstanding tunnel(s); release them "
                "before closing (close fails closed while tunnels are "
                "outstanding)" % outstanding,
            )
        entry.state = AssociationState.RELEASED

    # ------------------------------------------------------------------
    # Informational surfaces (NOT contract operations)
    # ------------------------------------------------------------------

    def capabilities(self) -> Tuple[str, ...]:
        """The honest capability ladder (informational; LOCK-017:
        reported, never authoritative).

        Mirrors the WORK-016 ``GenericAdapter.capabilities()`` ladder
        shape with honest Wi-Fi specifics: ``()`` while the access
        path is down; the boundary capabilities when open; the
        data-path capability additionally requires at least one
        ACTIVE SSID (a fully deactivated access path honestly cannot
        carry frames).
        """
        if not self._open:
            return ()
        caps: Tuple[str, ...] = (
            "capability.profile.wifi.non-3gpp-access",
            "capability.profile.wifi.association",
            "capability.profile.wifi.authentication",
            "capability.profile.wifi.n3iwf-tunnel",
        )
        if self._active_ssid_count() >= 1:
            caps = caps + ("capability.profile.wifi.data-path",)
        return caps

    # ------------------------------------------------------------------
    # Reference-model availability controls (NOT contract operations)
    # ------------------------------------------------------------------

    def set_ap_state(self, ap_ref: str, *, active: bool) -> None:
        """Reference-model availability control: move a provisioned AP
        between active and inactive (the deterministic stand-in for an
        operator availability transition; NOT a contract operation).

        Strict same-state transition: activating an ACTIVE ap (or
        deactivating an INACTIVE one) is an ILLEGAL_STATE rejection.
        Inactivating never kills live state silently -- existing
        associations/tunnels are preserved and every dependent
        operation fails closed with WIFI_UNAVAILABLE.
        """
        validate_opaque_ref(ap_ref, "ap")
        entry = self._require_ap_entry(ap_ref)
        target = ApState.ACTIVE if active else ApState.INACTIVE
        if entry.ap_view.state == target:
            raise WifiError(
                WifiReasonCode.ILLEGAL_STATE,
                "ap %r is already %s" % (entry.ap_view.name, target),
            )
        entry.ap_view = replace(entry.ap_view, state=target)

    def set_ssid_state(
        self, ap_ref: str, ssid_name: str, *, active: bool
    ) -> None:
        """Reference-model availability control: move one provisioned
        SSID between active and inactive (NOT a contract operation).

        Strict same-state transition: ILLEGAL_STATE on a no-op.
        Deactivation degrades loudly -- never kills silently: live
        associations are preserved and every dependent operation
        (authenticate, establish_tunnel, egress_frame) fails closed
        with WIFI_UNAVAILABLE until reactivation.
        """
        validate_opaque_ref(ap_ref, "ap")
        validate_ssid_name(ssid_name)
        entry = self._require_ap_entry(ap_ref)
        if ssid_name not in entry.ssid_states:
            raise WifiError(
                WifiReasonCode.SSID_UNKNOWN,
                "ssid %r is not on ap %r" % (ssid_name, entry.ap_view.name),
            )
        target = ApState.ACTIVE if active else ApState.INACTIVE
        if entry.ssid_states[ssid_name] == target:
            raise WifiError(
                WifiReasonCode.ILLEGAL_STATE,
                "ssid %r is already %s" % (ssid_name, target),
            )
        entry.ssid_states[ssid_name] = target
