"""ADCOS Wi-Fi/non-3GPP access adapter input validators (WORK-021).

Pure, stdlib-only validators for the Wi-Fi/non-3GPP domain value types.
No vendor SDK, no Wi-Fi chipset API, no IPsec/IKEv2 state machine, no
cryptographic material.  The validators check SHAPES only (IEEE
802.11-2020 / IEEE 802.1X-2020 / 3GPP TS 23.316 / TS 24.302 reference
shapes); they never decode, decrypt, or store credentials (LOCK-023:
credential slot NAMES only, never material).

Standards leverage (LOCK-018, mirroring the W017/W018/W019 discipline):
the validators use the Python standard library ``re`` module for shape
checking -- the stdlib is a standard implementation, not a reinvention.
The IEEE/3GPP/RFC reference shapes appear as DATA with citations in
docstrings; no invented Wi-Fi/crypto primitive exists in this module.

The W021 identity invariant is enforced here
(:func:`assert_ref_session_separation`):

    ADCOS session_id != Wi-Fi association identity != N3IWF tunnel
    identity != IPsec/NAS identity

The technology refs (``wifi:assoc:<hex>`` / ``wifi:tunnel:<hex>`` /
``wifi:ap:<hex>``) are OPAQUE handles minted over canonical content;
the underlying association (BSSID/association-id), tunnel, and
IPsec/NAS identity material is NEVER modeled (adapter-side opaque).

NOTE (selftest audit): this module is the enforcement-vocabulary file
-- its forbidden-token list exists to REJECT secret-like text.  The
WORK-021 selftest's credential scan excludes this file from its own
scan (the tokens appear here as rejection vocabulary, never as data),
mirroring how the WORK-019 selftest treats the fivegc validators.
"""

from __future__ import annotations

import re
from typing import Optional, Tuple

from .errors import WifiError, WifiReasonCode


#: Opaque technology-ref grammar (WORK-021): ``wifi:<kind>:<32 lowercase
#: hex>``, kind in {assoc, tunnel, ap}.  The hex is the leading 128
#: bits of a SHA-256 digest over canonical content (mirrors the fivegc
#: ref convention).  Structurally disjoint from the WORK-012 session_id
#: (``sha256:<64 hex>``) by construction.
_OPAQUE_REF_KINDS: Tuple[str, ...] = ("assoc", "tunnel", "ap")
_OPAQUE_REF_PATTERN = re.compile(r"^wifi:(assoc|tunnel|ap):[0-9a-f]{32}$")

#: IEEE 802.11-2020 §9.4.2.14 -- the SSID element carries 0..32 octets;
#: the adapter models 1..32 printable ASCII characters (no control
#: characters).  An SSID name is public beacon DATA, never a secret.
_SSID_NAME_PATTERN = re.compile(r"^[\x20-\x7e]{1,32}$")

#: Adapter-side station LABEL (1..64 characters, DNS-label-shaped).
#: The label is an operator-chosen handle; the 802.11 station identity
#: (MAC address, association id) is deliberately NOT modeled anywhere
#: in this family -- station identity stays adapter-side opaque.
_STATION_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,63}$")

#: AP name (1..64 printable ASCII, no control characters).
_AP_NAME_PATTERN = re.compile(r"^[\x21-\x7e][\x20-\x7e]{0,63}$")

#: IEEE 802.11-2020 PHY bands (2.4/5/6 GHz) -- frozen vocabulary.
_BAND_VALUES: Tuple[str, ...] = ("2.4ghz", "5ghz", "6ghz")

#: LOCK-023 -- credential-like text rejection vocabulary.  The token
#: list covers Wi-Fi pre-shared keys/passphrases, 802.1X/EAP credential
#: fragments, RADIUS-shared-secret fragments, and N3IWF IPsec/IKEv2
#: key-material fragments (PSK, PMK/PTK/GTK, MSK -- IEEE 802.11-2020
#: Clause 12 key names, RFC 3748 EAP key hierarchy, RFC 7296 IKEv2).
#: A string carrying any of these fragments is rejected so an
#: implementation cannot smuggle secret material through names,
#: labels, or refs (mirrors the fivegc credential-slot discipline).
#: Matching runs against the lowered text AND a separator-normalized
#: form (hyphen/underscore/dot/space collapsed to ``-``), so both
#: ``shared_secret`` and ``shared-secret`` spellings are caught.
_CREDENTIAL_LIKE_FORBIDDEN: Tuple[str, ...] = (
    "private_key", "secret_key", "password", "passphrase", "token",
    "api_key", "shared_secret", "psk", "pre_shared_key", "preshared",
    "pmk", "ptk", "gtk", "msk", "eap_password", "radius_secret",
    "ipsec_secret", "ike_psk", "sae_password", "sim_pin", "session_key",
)

_SEPARATOR_RUN = re.compile(r"[-_.\s]+")


def _normalized(text: str) -> str:
    return _SEPARATOR_RUN.sub("-", text.lower())


def validate_opaque_ref(value: str, expected_kind: Optional[str] = None) -> str:
    """Validate an opaque Wi-Fi/non-3GPP technology ref.

    Grammar: ``wifi:(assoc|tunnel|ap):[0-9a-f]{32}`` (hex lowercase,
    32 digits).  When ``expected_kind`` is given, the ref's kind
    segment must match it (an association binding must carry an
    ``assoc`` ref, a tunnel binding a ``tunnel`` ref).  Raises
    :class:`WifiError` for any other shape.  The ref is an OPAQUE
    handle: the underlying association (BSSID/association-id), tunnel,
    or IPsec/NAS identity material is NEVER carried in it.
    """
    if not isinstance(value, str) or not value:
        raise WifiError(
            WifiReasonCode.INVALID_INPUT,
            "opaque ref must be a non-empty string",
        )
    match = _OPAQUE_REF_PATTERN.fullmatch(value)
    if match is None:
        raise WifiError(
            WifiReasonCode.INVALID_INPUT,
            "opaque ref must match wifi:(assoc|tunnel|ap):<32 lowercase hex>",
        )
    if expected_kind is not None:
        if expected_kind not in _OPAQUE_REF_KINDS:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "expected_kind must be one of %s" % (list(_OPAQUE_REF_KINDS),),
            )
        if match.group(1) != expected_kind:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "opaque ref %s must be of kind %r" % (value, expected_kind),
            )
    return value


def assert_ref_session_separation(wifi_ref: str, session_id: str) -> None:
    """Enforce the W021 identity invariant at the ref/session seam.

    A Wi-Fi/non-3GPP technology ref must NEVER embed WORK-012
    ``session_id`` material, and a ``session_id`` must NEVER embed a
    technology ref: session identity and access identity are distinct
    axes.  ``session_id`` is sacred and access-independent; an access
    change re-binds the SAME ``session_id`` to a NEW association or
    tunnel ref; the boundary NEVER collapses them (the Wi-Fi analog of
    the fivegc R1 route/session separation mechanics).

    Raises :class:`WifiError` with reason
    ``WifiReasonCode.ACCESS_SESSION_COLLAPSE`` when either value
    embeds the other: full-string containment either way, the
    digest portion of a ``sha256:<hex>`` session id embedded in the
    ref, or the ref's hex tail embedded in the session digest (which
    catches truncated-digest smuggling such as a ref minted from the
    leading 32 hex of a session id).  Fragments shorter than 16 hex
    digits are not flagged (a 64-bit collision cannot occur by
    accident between honest content-derived values).
    """
    if not isinstance(wifi_ref, str) or not wifi_ref:
        raise WifiError(
            WifiReasonCode.INVALID_INPUT,
            "wifi ref must be a non-empty string",
        )
    if not isinstance(session_id, str) or not session_id:
        raise WifiError(
            WifiReasonCode.INVALID_INPUT,
            "session_id must be a non-empty string",
        )
    session_digest = session_id.split(":", 1)[1] if ":" in session_id else ""
    ref_hex = wifi_ref.rsplit(":", 1)[1] if ":" in wifi_ref else ""
    ref_hex = ref_hex if re.fullmatch(r"[0-9a-f]+", ref_hex or "") else ""
    collapsed = (
        wifi_ref == session_id
        or wifi_ref in session_id
        or session_id in wifi_ref
        or (len(session_digest) >= 16 and session_digest in wifi_ref)
        or (len(ref_hex) >= 16 and ref_hex in session_digest)
    )
    if collapsed:
        raise WifiError(
            WifiReasonCode.ACCESS_SESSION_COLLAPSE,
            "wifi ref %r and session_id collapse onto each other "
            "(W021 identity invariant: session_id is sacred and "
            "access-independent; the access ref must stay distinct)"
            % wifi_ref[:80],
        )


def reject_credential_like_text(text: str, *, label: str = "text") -> None:
    """Reject text carrying secret-like material (LOCK-023).

    Wi-Fi/non-3GPP credential material (pre-shared keys, passphrases,
    802.1X/EAP credentials, RADIUS shared secrets, N3IWF IPsec/IKEv2
    keys) lives ONLY in the adapter's private credential store.  Any
    caller-supplied string that RESEMBLES secret material (contains a
    forbidden token such as ``psk``/``password``/``pmk``) is rejected
    fail-closed so an implementation cannot smuggle a key through a
    name, label, or ref.
    """
    if not isinstance(text, str):
        raise WifiError(
            WifiReasonCode.INVALID_INPUT,
            "%s must be a string" % label,
        )
    lowered = text.lower()
    normalized = _normalized(text)
    for forbidden in _CREDENTIAL_LIKE_FORBIDDEN:
        if forbidden in lowered or _normalized(forbidden) in normalized:
            raise WifiError(
                WifiReasonCode.INVALID_INPUT,
                "%s must not resemble secret material "
                "(LOCK-023; forbidden token: %s)" % (label, forbidden),
            )


def validate_credential_slot_name(name: str) -> str:
    """Validate a credential slot NAME (LOCK-023).

    A slot NAME carries NO material -- it is a label the adapter uses
    to look up its OWN private credential store (Wi-Fi/802.1X and
    N3IWF IPsec credentials).  The boundary rejects names that LOOK
    like secret material so an implementation cannot smuggle a key
    through the slot name (mirrors the WORK-016/019 discipline).
    """
    if not isinstance(name, str) or not name:
        raise WifiError(
            WifiReasonCode.INVALID_INPUT,
            "credential_slot_name must be a non-empty string",
        )
    reject_credential_like_text(name, label="credential_slot_name")
    return name


def validate_ssid_name(value: str) -> str:
    """Validate an SSID name (IEEE 802.11-2020 §9.4.2.14).

    1..32 printable ASCII characters, no control characters (the SSID
    element carries up to 32 octets).  SSID names are public beacon
    DATA, never secrets; the grammar keeps them canonical and bounded.
    """
    if not isinstance(value, str) or not value:
        raise WifiError(
            WifiReasonCode.INVALID_INPUT,
            "ssid name must be a non-empty string",
        )
    if not _SSID_NAME_PATTERN.fullmatch(value):
        raise WifiError(
            WifiReasonCode.INVALID_INPUT,
            "ssid name must be 1..32 printable ASCII characters "
            "(IEEE 802.11-2020 §9.4.2.14, no control characters)",
        )
    return value


def validate_station_label(value: str) -> str:
    """Validate an adapter-side station LABEL.

    1..64 characters, starting alphanumeric, then ``[A-Za-z0-9._-]``.
    The label is an operator-chosen handle for the station; the 802.11
    station identity (MAC address, association id) is deliberately NOT
    modeled in this family -- station identity stays adapter-side
    opaque (W021 identity invariant).
    """
    if not isinstance(value, str) or not value:
        raise WifiError(
            WifiReasonCode.INVALID_INPUT,
            "station label must be a non-empty string",
        )
    if not _STATION_LABEL_PATTERN.fullmatch(value):
        raise WifiError(
            WifiReasonCode.INVALID_INPUT,
            "station label must be 1..64 characters matching "
            "[A-Za-z0-9][A-Za-z0-9._-]* (adapter-side opaque label)",
        )
    return value


def validate_ap_name(value: str) -> str:
    """Validate an AP name (the provisionable AP profile's name)."""
    if not isinstance(value, str) or not value:
        raise WifiError(
            WifiReasonCode.INVALID_INPUT,
            "ap name must be a non-empty string",
        )
    if not _AP_NAME_PATTERN.fullmatch(value):
        raise WifiError(
            WifiReasonCode.INVALID_INPUT,
            "ap name must be 1..64 printable ASCII characters "
            "(no control characters)",
        )
    return value


def validate_band(value: str) -> str:
    """Validate a PHY band (IEEE 802.11-2020: 2.4/5/6 GHz)."""
    if not isinstance(value, str) or not value:
        raise WifiError(
            WifiReasonCode.INVALID_INPUT,
            "band must be a non-empty string",
        )
    if value not in _BAND_VALUES:
        raise WifiError(
            WifiReasonCode.INVALID_INPUT,
            "band must be one of %s (IEEE 802.11-2020 PHY bands)"
            % (list(_BAND_VALUES),),
        )
    return value


def validate_station_count(value: int) -> int:
    """Validate a station/association count bound.

    1..2007 -- the IEEE 802.11-2020 association identifier (AID)
    space.  DATA only: the boundary does not schedule airtime or
    enforce admission control (a production AP does, behind the
    adapter boundary).
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise WifiError(
            WifiReasonCode.INVALID_INPUT,
            "station count must be an integer",
        )
    if not (1 <= value <= 2007):
        raise WifiError(
            WifiReasonCode.INVALID_INPUT,
            "station count must be in [1, 2007] "
            "(IEEE 802.11-2020 association identifier space)",
        )
    return value


__all__ = [
    "validate_opaque_ref",
    "assert_ref_session_separation",
    "reject_credential_like_text",
    "validate_credential_slot_name",
    "validate_ssid_name",
    "validate_station_label",
    "validate_ap_name",
    "validate_band",
    "validate_station_count",
]
