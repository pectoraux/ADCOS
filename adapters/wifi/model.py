"""ADCOS Wi-Fi/non-3GPP access adapter domain model (WORK-021).

Value types for the Wi-Fi/non-3GPP access boundary (the new
``adapters/wifi`` sub-package within the frozen ``/adapters`` module
boundary -- ``spec/architecture.md`` §29; LOCK-001: the ADCOS core
encodes no single access technology; LOCK-016: external access
implementations remain behind adapter/provider interfaces; the W021
acceptance criterion itself: "no Wi-Fi chipset/vendor API or
non-3GPP implementation type crosses into core").

Central boundary (WORK-021 -- the identity invariant):

    WIFI ACCESS INTEGRATION
        != SESSION IDENTITY        (session_id sacred, from WORK-012;
                                    access-independent -- W021)
        != ASSOCIATION IDENTITY    (assoc_ref is the OPAQUE Wi-Fi
                                    association handle; BSSID /
                                    association-id material is NOT
                                    modeled -- adapter-side opaque)
        != TUNNEL IDENTITY         (tunnel_ref is the OPAQUE N3IWF
                                    tunnel handle; IPsec/NAS identity
                                    is NOT modeled -- adapter-private)
        != IDENTITY AUTHORITY      (WORK-004 facade; Wi-Fi/non-3GPP
                                    credentials access-specific,
                                    slot NAMES only)
        != RESOURCE AUTHORITY      (WORK-008; airtime/QoS = DATA)
        != POLICY AUTHORITY        (caller-supplied policy DATA)
        != TOPOLOGY AUTHORITY
        != ACCESS/VENDOR AUTHORITY (LOCK-016/017; concrete Wi-Fi
                                    stacks = adapters, behind the seam)
        != WI-FI STATE AUTHORITY   (station/association/tunnel/IPsec
                                    SA state lives in the adapter/
                                    conformance peer, NEVER in core)

Standards leverage (LOCK-018, mirroring the W017/W018/W019
discipline): the model uses IEEE 802.11-2020 / IEEE 802.1X-2020 /
RFC 3748 / 3GPP TS 23.316 / TS 24.302 / RFC 7296 / RFC 4301 reference
SHAPES as DATA with citations in docstrings -- no invented Wi-Fi or
crypto primitive, no vendor SDK, no chipset API, no IPsec state
machine exists in this module.

Value types validate their content at construction (raising
:class:`WifiError` with ``invalid-input``); the binding records
additionally enforce the W021 ref/session separation invariant at
construction (:func:`adapters.wifi.validation.assert_ref_session_separation`)
-- the identity invariant is structural, not procedural.

All instants are injected (WORK-003 ``parse_instant`` grammar); no
wall clock.  All ids are content-derived over canonical JSON
(``protocol.canonicalization.canonical_json_bytes``); no randomness,
no ``urandom``/``secrets``/``random`` anywhere in this module.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import WIFI_PREFIX, WifiError, WifiReasonCode
from .validation import (
    assert_ref_session_separation,
    validate_ap_name,
    validate_band,
    validate_credential_slot_name,
    validate_opaque_ref,
    validate_ssid_name,
    validate_station_count,
    validate_station_label,
)


# --------------------------------------------------------------------------
# Frozen vocabularies (standards shapes as DATA)
# --------------------------------------------------------------------------


class SecurityPolicy:
    """Frozen security-policy vocabulary.

    IEEE 802.11-2020 Clause 12 (RSN security) and IEEE 802.1X-2020
    (port-based network access control, EAPOL key management per
    RFC 3748 EAP) define the protection mechanisms; this vocabulary
    carries their standard NAMES as DATA.  No crypto, no key
    material, no vendor names live here; an adapter maps a policy
    name onto the standards-defined mechanism behind the boundary
    (LOCK-018: standard leverage, not reinvention).  ``open`` is
    carried honestly (no data protection); whether an open policy is
    acceptable is a POLICY decision, never a boundary judgment.
    """

    OPEN = "open"
    OWE = "owe"
    SAE = "sae"
    WPA2_ENTERPRISE = "wpa2-enterprise"
    WPA3_ENTERPRISE = "wpa3-enterprise"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.OPEN,
            cls.OWE,
            cls.SAE,
            cls.WPA2_ENTERPRISE,
            cls.WPA3_ENTERPRISE,
        )


class ApState:
    """Frozen AP lifecycle state (adapter-side projection)."""

    INACTIVE = "inactive"
    ACTIVE = "active"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.INACTIVE, cls.ACTIVE)


class AssociationState:
    """Frozen association lifecycle state (adapter-side projection).

    The full IEEE 802.11-2020 authentication/association state
    machine lives behind the adapter boundary; the model carries only
    these projection states.
    """

    ASSOCIATED = "associated"
    AUTHENTICATED = "authenticated"
    RELEASED = "released"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.ASSOCIATED, cls.AUTHENTICATED, cls.RELEASED)


class TunnelState:
    """Frozen N3IWF tunnel lifecycle state (adapter-side projection).

    The IPsec/IKEv2 security-association lifecycle (RFC 7296,
    RFC 4301) is adapter-private and deliberately NOT projected here.
    """

    ESTABLISHED = "established"
    RELEASED = "released"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.ESTABLISHED, cls.RELEASED)


class LinkMetricName:
    """Generic link-metric names for the Wi-Fi/non-3GPP access
    observation.

    The constant VALUES mirror WORK-016 ``adapters.model.LinkMetricName``
    (``link-up``, ``rx-bytes-total``, ``tx-bytes-total``,
    ``rx-error-count``, ``tx-error-count``, ``retransmit-count``) so a
    Wi-Fi/non-3GPP access observation maps 1:1 into the generic adapter
    metric vocabulary.  The SDK symbols are deliberately NOT imported
    here -- the wifi family stays import-light in ``model.py`` and the
    WORK-016 bridge performs the translation (radio/technology-specific
    counters stay inside implementations; measurement semantics are
    owned by WORK-026).

    Added in WORK-021-a3 (the sanctioned additive extension for the
    WORK-016 SDK bridge task); no pre-existing model content changed.
    """

    LINK_UP = "link-up"
    RX_BYTES_TOTAL = "rx-bytes-total"
    TX_BYTES_TOTAL = "tx-bytes-total"
    RX_ERROR_COUNT = "rx-error-count"
    TX_ERROR_COUNT = "tx-error-count"
    RETRANSMIT_COUNT = "retransmit-count"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (
            cls.LINK_UP,
            cls.RX_BYTES_TOTAL,
            cls.TX_BYTES_TOTAL,
            cls.RX_ERROR_COUNT,
            cls.TX_ERROR_COUNT,
            cls.RETRANSMIT_COUNT,
        )


def _validate_security_policy(value: str) -> str:
    if not isinstance(value, str) or value not in SecurityPolicy.values():
        raise WifiError(
            WifiReasonCode.INVALID_INPUT,
            "security policy must be one of %s "
            "(IEEE 802.11-2020 Clause 12 / IEEE 802.1X-2020)"
            % (list(SecurityPolicy.values()),),
        )
    return value


def _validate_state(value: str, vocabulary: Tuple[str, ...], label: str) -> str:
    if not isinstance(value, str) or value not in vocabulary:
        raise WifiError(
            WifiReasonCode.INVALID_INPUT,
            "%s must be one of %s" % (label, list(vocabulary)),
        )
    return value


def _validate_session_id(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise WifiError(
            WifiReasonCode.INVALID_INPUT,
            "session_id must be a non-empty string",
        )
    return value


# --------------------------------------------------------------------------
# Value types (IEEE/3GPP reference shapes as DATA; no state machine,
# no crypto, no vendor SDK)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class SsidProfile:
    """A provisioned SSID profile (IEEE 802.11-2020).

    ``ssid`` (name, §9.4.2.14 -- up to 32 octets), ``band`` (PHY
    band), ``security_policy`` (see :class:`SecurityPolicy`), and
    ``max_stations`` (bounded by the association identifier space).
    DATA only -- the boundary does not beacon, admit, or manage keys;
    a production AP does, behind the adapter boundary.
    """

    ssid: str
    band: str
    security_policy: str
    max_stations: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "ssid", validate_ssid_name(self.ssid))
        object.__setattr__(self, "band", validate_band(self.band))
        object.__setattr__(self, "security_policy", _validate_security_policy(self.security_policy))
        object.__setattr__(self, "max_stations", validate_station_count(self.max_stations))

    def to_dict(self) -> dict:
        return {
            "ssid": self.ssid,
            "band": self.band,
            "security_policy": self.security_policy,
            "max_stations": self.max_stations,
        }


@dataclass(frozen=True)
class ApDescriptor:
    """The provisionable AP profile (IEEE 802.11-2020): name, SSIDs,
    radio capabilities (bands + max concurrent associations).

    This is the profile ``provision_ap`` accepts.  It carries NO
    chipset, driver, or vendor capability -- only the standards-level
    radio shape (LOCK-016/017).
    """

    name: str
    ssids: Tuple[SsidProfile, ...]
    bands: Tuple[str, ...]
    max_associations: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", validate_ap_name(self.name))
        if not isinstance(self.ssids, tuple) or not self.ssids:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "ssids must be a non-empty tuple of SsidProfile",
            )
        if not isinstance(self.bands, tuple) or not self.bands:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "bands must be a non-empty tuple of PHY bands",
            )
        for band in self.bands:
            validate_band(band)
        if len(set(self.bands)) != len(self.bands):
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "bands must not repeat",
            )
        seen_ssids = []
        for profile in self.ssids:
            if not isinstance(profile, SsidProfile):
                raise WifiError(
                    WifiReasonCode.INVALID_INPUT,
                    "each ssid entry must be a SsidProfile",
                )
            if profile.band not in self.bands:
                raise WifiError(
                    WifiReasonCode.INVALID_INPUT,
                    "ssid %r band %r is not among the AP bands %s"
                    % (profile.ssid, profile.band, list(self.bands)),
                )
            if profile.ssid in seen_ssids:
                raise WifiError(
                    WifiReasonCode.INVALID_INPUT,
                    "ssid %r appears more than once in the AP profile" % profile.ssid,
                )
            seen_ssids.append(profile.ssid)
        object.__setattr__(self, "max_associations", validate_station_count(self.max_associations))

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "ssids": [s.to_dict() for s in self.ssids],
            "bands": list(self.bands),
            "max_associations": self.max_associations,
        }


@dataclass(frozen=True)
class StationDescriptor:
    """A station descriptor: an operator LABEL plus the security
    policy the station must use.

    The 802.11 station identity (MAC address, association id --
    IEEE 802.11-2020) is deliberately NOT modeled: station identity
    stays adapter-side opaque (W021 identity invariant).
    """

    label: str
    security_policy: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "label", validate_station_label(self.label))
        object.__setattr__(self, "security_policy", _validate_security_policy(self.security_policy))

    def to_dict(self) -> dict:
        return {"label": self.label, "security_policy": self.security_policy}


@dataclass(frozen=True)
class CredentialSlot:
    """A credential slot NAME (LOCK-023).

    The slot NAME carries NO material -- it is a label the adapter
    uses to look up its OWN private credential store (Wi-Fi
    passphrases/pre-shared keys, 802.1X/EAP credentials, N3IWF
    IPsec/IKEv2 credentials).  The boundary NEVER sees the material;
    :func:`adapters.wifi.validation.validate_credential_slot_name`
    rejects names that resemble secret material so an implementation
    cannot smuggle a key through the slot name.
    """

    slot_name: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "slot_name", validate_credential_slot_name(self.slot_name))

    def to_dict(self) -> dict:
        return {"slot_name": self.slot_name}


# --------------------------------------------------------------------------
# Contract return types (the boundary's outward-facing values)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ApView:
    """The result of ``provision_ap``: the observable AP projection.

    Carries the OPAQUE ``ap_ref`` (content-derived), the profile
    DATA, and the lifecycle state.  Opaque refs only -- no chipset,
    driver, or vendor state ever crosses (LOCK-016/017).
    """

    ap_ref: str
    name: str
    ssids: Tuple[SsidProfile, ...]
    bands: Tuple[str, ...]
    max_associations: int
    state: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "ap_ref", validate_opaque_ref(self.ap_ref, "ap"))
        object.__setattr__(self, "name", validate_ap_name(self.name))
        if not isinstance(self.ssids, tuple) or not self.ssids:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "ssids must be a non-empty tuple of SsidProfile",
            )
        for profile in self.ssids:
            if not isinstance(profile, SsidProfile):
                raise WifiError(
                    WifiReasonCode.INVALID_INPUT,
                    "each ssid entry must be a SsidProfile",
                )
        if not isinstance(self.bands, tuple) or not self.bands:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "bands must be a non-empty tuple of PHY bands",
            )
        object.__setattr__(self, "max_associations", validate_station_count(self.max_associations))
        object.__setattr__(self, "state", _validate_state(self.state, ApState.values(), "ap state"))

    def to_dict(self) -> dict:
        return {
            "ap_ref": self.ap_ref,
            "name": self.name,
            "ssids": [s.to_dict() for s in self.ssids],
            "bands": list(self.bands),
            "max_associations": self.max_associations,
            "state": self.state,
        }


@dataclass(frozen=True)
class AssociationBinding:
    """The result of ``bind_session``.

    The ADCOS ``session_id`` is SACRED; ``assoc_ref`` is the OPAQUE
    Wi-Fi association handle (content-derived over session_id + AP +
    station + sequence).  A re-association (an access change) mints a
    NEW ``assoc_ref`` for the SAME ``session_id`` -- the W021 identity
    invariant; the boundary NEVER collapses them.  The Wi-Fi
    association identity itself (BSSID, association id --
    IEEE 802.11-2020) is NOT modeled: it lives adapter-side, behind
    the opaque ref.  ``binding_id`` is the manager's binding key
    (content-derived; deliberately NOT part of the identity content
    so a rebind produces a new binding without minting a new
    session_id).  Mirrors the WORK-019 ``PduSessionBinding``.
    """

    session_id: str
    assoc_ref: str
    binding_id: str
    ap_ref: str
    ssid: str
    station_label: str
    security_policy: str
    closed: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "session_id", _validate_session_id(self.session_id))
        object.__setattr__(self, "assoc_ref", validate_opaque_ref(self.assoc_ref, "assoc"))
        object.__setattr__(self, "ap_ref", validate_opaque_ref(self.ap_ref, "ap"))
        if not isinstance(self.binding_id, str) or not self.binding_id:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "binding_id must be a non-empty string",
            )
        object.__setattr__(self, "ssid", validate_ssid_name(self.ssid))
        object.__setattr__(self, "station_label", validate_station_label(self.station_label))
        object.__setattr__(self, "security_policy", _validate_security_policy(self.security_policy))
        if not isinstance(self.closed, bool):
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "closed must be a boolean",
            )
        assert_ref_session_separation(self.assoc_ref, self.session_id)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "assoc_ref": self.assoc_ref,
            "binding_id": self.binding_id,
            "ap_ref": self.ap_ref,
            "ssid": self.ssid,
            "station_label": self.station_label,
            "security_policy": self.security_policy,
            "closed": self.closed,
        }


@dataclass(frozen=True)
class TunnelBinding:
    """The result of ``establish_tunnel``: the N3IWF tunnel binding
    (3GPP TS 23.316).

    Bound to the SACRED ``session_id`` over the association's opaque
    ``assoc_ref``; ``tunnel_ref`` is the OPAQUE tunnel handle.  The
    IPsec/NAS identity (IKEv2 security-association parameters and
    SPIs per RFC 7296, the IPsec architecture per RFC 4301, non-3GPP
    attach identifiers per 3GPP TS 24.302) is NOT modeled: it is
    adapter-private state behind the opaque ref.  A tunnel
    re-establishment mints a NEW ``tunnel_ref`` for the SAME
    ``session_id`` (W021 identity invariant).
    """

    session_id: str
    assoc_ref: str
    tunnel_ref: str
    binding_id: str
    closed: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "session_id", _validate_session_id(self.session_id))
        object.__setattr__(self, "assoc_ref", validate_opaque_ref(self.assoc_ref, "assoc"))
        object.__setattr__(self, "tunnel_ref", validate_opaque_ref(self.tunnel_ref, "tunnel"))
        if not isinstance(self.binding_id, str) or not self.binding_id:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "binding_id must be a non-empty string",
            )
        if not isinstance(self.closed, bool):
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "closed must be a boolean",
            )
        assert_ref_session_separation(self.tunnel_ref, self.session_id)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "assoc_ref": self.assoc_ref,
            "tunnel_ref": self.tunnel_ref,
            "binding_id": self.binding_id,
            "closed": self.closed,
        }


@dataclass(frozen=True)
class AssociationView:
    """The association projection that crosses toward observers
    (snapshots, health surfaces): the current observable state.

    Opaque refs only -- no BSSID, no association id, no chipset state
    (LOCK-016/017).  Carries the SACRED ``session_id`` because the
    whole point of the binding is the session/association mapping.
    """

    session_id: str
    assoc_ref: str
    binding_id: str
    ap_ref: str
    ssid: str
    station_label: str
    security_policy: str
    state: str
    closed: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "session_id", _validate_session_id(self.session_id))
        object.__setattr__(self, "assoc_ref", validate_opaque_ref(self.assoc_ref, "assoc"))
        object.__setattr__(self, "ap_ref", validate_opaque_ref(self.ap_ref, "ap"))
        if not isinstance(self.binding_id, str) or not self.binding_id:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "binding_id must be a non-empty string",
            )
        object.__setattr__(self, "ssid", validate_ssid_name(self.ssid))
        object.__setattr__(self, "station_label", validate_station_label(self.station_label))
        object.__setattr__(self, "security_policy", _validate_security_policy(self.security_policy))
        object.__setattr__(
            self, "state", _validate_state(self.state, AssociationState.values(), "association state")
        )
        if not isinstance(self.closed, bool):
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "closed must be a boolean",
            )
        assert_ref_session_separation(self.assoc_ref, self.session_id)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "assoc_ref": self.assoc_ref,
            "binding_id": self.binding_id,
            "ap_ref": self.ap_ref,
            "ssid": self.ssid,
            "station_label": self.station_label,
            "security_policy": self.security_policy,
            "state": self.state,
            "closed": self.closed,
        }


@dataclass(frozen=True)
class TunnelView:
    """The N3IWF tunnel projection that crosses toward observers.

    Opaque refs only -- the IPsec/IKEv2 security-association state
    (RFC 7296/RFC 4301) is adapter-private and NEVER projected
    (3GPP TS 23.316; LOCK-016/017).
    """

    session_id: str
    assoc_ref: str
    tunnel_ref: str
    state: str
    closed: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "session_id", _validate_session_id(self.session_id))
        object.__setattr__(self, "assoc_ref", validate_opaque_ref(self.assoc_ref, "assoc"))
        object.__setattr__(self, "tunnel_ref", validate_opaque_ref(self.tunnel_ref, "tunnel"))
        object.__setattr__(self, "state", _validate_state(self.state, TunnelState.values(), "tunnel state"))
        if not isinstance(self.closed, bool):
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "closed must be a boolean",
            )
        assert_ref_session_separation(self.tunnel_ref, self.session_id)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "assoc_ref": self.assoc_ref,
            "tunnel_ref": self.tunnel_ref,
            "state": self.state,
            "closed": self.closed,
        }


@dataclass(frozen=True)
class ExternalAssociationEvidence:
    """Adapter-observed, secret-free state from an external Wi-Fi
    path (a real AP or the WORK-021 conformance peer).

    ``external_association_id`` is an OPAQUE adapter-observed string;
    the underlying association identity (BSSID/association id) never
    crosses as itself.  Mirrors the WORK-019
    ``ExternalPduSessionEvidence``.
    """

    external_association_id: str
    station_label: str
    ssid: str
    security_policy: str
    state: str

    def __post_init__(self) -> None:
        if not isinstance(self.external_association_id, str) or not self.external_association_id:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "external_association_id must be a non-empty opaque string",
            )
        object.__setattr__(self, "station_label", validate_station_label(self.station_label))
        object.__setattr__(self, "ssid", validate_ssid_name(self.ssid))
        object.__setattr__(self, "security_policy", _validate_security_policy(self.security_policy))
        if not isinstance(self.state, str) or not self.state:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "state must be a non-empty string",
            )

    def to_dict(self) -> dict:
        return {
            "external_association_id": self.external_association_id,
            "station_label": self.station_label,
            "ssid": self.ssid,
            "security_policy": self.security_policy,
            "state": self.state,
        }


@dataclass(frozen=True)
class AuthResult:
    """The result of the 802.1X/SAE authentication phase
    (IEEE 802.1X-2020; IEEE 802.11-2020 Clause 12; RFC 3748 EAP).

    Carries success/failure and an OPAQUE ``auth_ref`` the adapter
    uses to look up its OWN private auth state.  The credential
    material (passphrases/pre-shared keys, EAP credentials, derived
    keys such as PMK/PTK/GTK) NEVER crosses the boundary -- only the
    opaque ``auth_ref`` (LOCK-023).  Mirrors the WORK-019
    ``AuthResult``.
    """

    success: bool
    auth_ref: str
    station_label: str

    def __post_init__(self) -> None:
        if not isinstance(self.success, bool):
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "success must be a boolean",
            )
        if not isinstance(self.auth_ref, str) or not self.auth_ref:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "auth_ref must be a non-empty opaque string",
            )
        object.__setattr__(self, "station_label", validate_station_label(self.station_label))

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "auth_ref": self.auth_ref,
            "station_label": self.station_label,
        }


@dataclass(frozen=True)
class Non3GppAccessObservation:
    """A technology-neutral link observation of the non-3GPP access
    path (DATA, never topology facts).

    Metric names follow the generic WORK-016 link-metric vocabulary
    as DATA (``link-up`` / ``rx-bytes-total`` / ``tx-bytes-total`` /
    ``rx-error-count`` / ``tx-error-count`` / ``retransmit-count``);
    radio-specific counters stay inside implementations and are
    reported through these generic measures, never as core state
    (architecture §25).  Mirrors the WORK-019 ``LinkMetricsSample``.
    """

    samples: Tuple[Tuple[str, int], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.samples, tuple):
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "samples must be a tuple of (metric, value) pairs",
            )
        for sample in self.samples:
            if not isinstance(sample, tuple) or len(sample) != 2:
                raise WifiError(
                    WifiReasonCode.INVALID_INPUT,
                    "each sample must be a (metric, value) pair",
                )
            name, value = sample
            if not isinstance(name, str) or not name:
                raise WifiError(
                    WifiReasonCode.INVALID_INPUT,
                    "sample metric names must be non-empty strings",
                )
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise WifiError(
                    WifiReasonCode.INVALID_INPUT,
                    "sample values must be non-negative integers",
                )

    def to_dict(self) -> dict:
        return {"samples": [[k, v] for k, v in self.samples]}


@dataclass(frozen=True)
class WifiEvent:
    """A Wi-Fi/non-3GPP access integration event (manager event log)."""

    event_type: str
    integration_id: str
    instant: str
    assoc_ref: str = ""
    tunnel_ref: str = ""
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "event_type": self.event_type,
            "integration_id": self.integration_id,
            "instant": self.instant,
            "assoc_ref": self.assoc_ref,
            "tunnel_ref": self.tunnel_ref,
            "detail": self.detail,
        }


# --------------------------------------------------------------------------
# Content-derived id derivation (deterministic; no randomness)
# --------------------------------------------------------------------------


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def derive_assoc_ref(
    session_id: str, ap_ref: str, station_label: str, sequence: int
) -> str:
    """Content-derive the OPAQUE Wi-Fi association ref.

    Distinct from the sacred ``session_id`` by construction: the
    content includes ``session_id`` + the Wi-Fi binding material (AP
    ref, station label) + a sequence, hashed to a 32-hex digest --
    the session_id is hash INPUT, never observable ref TEXT.  A
    re-association (access change) produces a NEW ``assoc_ref`` for
    the SAME ``session_id`` (W021 identity invariant).  The Wi-Fi
    association identity material (BSSID/association id) is NEVER
    part of the content -- it stays adapter-side opaque.
    """
    if isinstance(sequence, bool) or not isinstance(sequence, int):
        raise WifiError(
            WifiReasonCode.INVALID_INPUT,
            "sequence must be an integer",
        )
    material = canonical_json_bytes({
        "session_id": session_id,
        "ap_ref": ap_ref,
        "station_label": station_label,
        "sequence": sequence,
    })
    digest = _sha256_hex(material)
    return "%s:assoc:%s" % (WIFI_PREFIX, digest[:32])


def derive_binding_id(session_id: str, assoc_ref: str) -> str:
    """Content-derive a binding id (the manager's binding key)."""
    material = canonical_json_bytes({
        "session_id": session_id,
        "assoc_ref": assoc_ref,
    })
    return "%s:binding:%s" % (WIFI_PREFIX, _sha256_hex(material)[:32])


def derive_tunnel_ref(binding_id: str, sequence: int) -> str:
    """Content-derive the OPAQUE N3IWF tunnel ref.

    Deliberately NOT part of the identity content (mirrors the
    WORK-018/W019 binding_id/ref separation): a tunnel re-establish
    produces a new ref without minting a new session_id.  The
    IPsec/IKEv2 identity (RFC 7296/RFC 4301) never appears in the
    content -- the tunnel identity stays adapter-private.
    """
    if isinstance(sequence, bool) or not isinstance(sequence, int):
        raise WifiError(
            WifiReasonCode.INVALID_INPUT,
            "sequence must be an integer",
        )
    material = canonical_json_bytes({"binding_id": binding_id, "sequence": sequence})
    return "%s:tunnel:%s" % (WIFI_PREFIX, _sha256_hex(material)[:32])


def derive_ap_ref(descriptor: ApDescriptor) -> str:
    """Content-derive the OPAQUE AP ref (over the canonical profile)."""
    material = canonical_json_bytes({"ap": descriptor.to_dict()})
    return "%s:ap:%s" % (WIFI_PREFIX, _sha256_hex(material)[:32])


def derive_integration_id(instance_label: str) -> str:
    """Content-derive the integration instance id (the manager's id)."""
    if not isinstance(instance_label, str) or not instance_label:
        raise WifiError(
            WifiReasonCode.INVALID_INPUT,
            "instance_label must be a non-empty string",
        )
    material = canonical_json_bytes({"instance_label": instance_label})
    return "%s:%s" % (WIFI_PREFIX, _sha256_hex(material)[:16])


__all__ = [
    "SecurityPolicy",
    "ApState",
    "AssociationState",
    "TunnelState",
    "LinkMetricName",
    "SsidProfile",
    "ApDescriptor",
    "StationDescriptor",
    "CredentialSlot",
    "ApView",
    "AssociationBinding",
    "TunnelBinding",
    "AssociationView",
    "TunnelView",
    "ExternalAssociationEvidence",
    "AuthResult",
    "Non3GppAccessObservation",
    "WifiEvent",
    "derive_assoc_ref",
    "derive_binding_id",
    "derive_tunnel_ref",
    "derive_ap_ref",
    "derive_integration_id",
]
