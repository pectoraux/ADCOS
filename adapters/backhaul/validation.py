"""ADCOS backhaul adapter input validators (WORK-022).

Pure, stdlib-only validators for the backhaul domain value types.  No
vendor SDK, no modem/terminal API, no PHY state machine, no
cryptographic material.  The validators check SHAPES only (IEEE
802.3-2018 Ethernet, ITU-T G.709/OTN fiber, ITU-R microwave,
satellite-access profile reference shapes); they never decode,
decrypt, or store credentials (LOCK-023: credential slot NAMES only,
never material).

Standards leverage (LOCK-018, mirroring the W017/W018/W019/W021
discipline): the validators use the Python standard library ``re``
module for shape checking -- the stdlib is a standard implementation,
not a reinvention.  The IEEE/ITU-T/ITU-R reference shapes appear as
DATA with citations in docstrings; no invented backhaul/crypto
primitive exists in this module.

The W022 identity invariant is enforced here
(:func:`assert_ref_session_separation`):

    ADCOS session_id != backhaul link identity != bearer identity !=
    allocation identity != interface/port identity

The technology refs (``backhaul:link:<hex>`` /
``backhaul:bearer:<hex>`` / ``backhaul:alloc:<hex>``) are OPAQUE
handles minted over canonical content; the underlying port, circuit,
radio-link, terminal, and modem identity material is NEVER modeled
(adapter-side opaque).

NOTE (selftest audit): this module is the enforcement-vocabulary file
-- its forbidden-token list exists to REJECT secret-like text.  The
WORK-022 selftest's credential scan excludes this file from its own
scan (the tokens appear here as rejection vocabulary, never as data),
mirroring how the WORK-019/W021 selftests treat their validators.
"""

from __future__ import annotations

import re
from typing import Optional, Tuple

from .errors import BackhaulError, BackhaulReasonCode


#: Opaque technology-ref grammar (WORK-022): ``backhaul:<kind>:<32
#: lowercase hex>``, kind in {link, bearer, alloc}.  The hex is the
#: leading 128 bits of a SHA-256 digest over canonical content
#: (mirrors the fivegc/wifi ref convention).  Structurally disjoint
#: from the WORK-012 session_id (``sha256:<64 hex>``) by construction.
_OPAQUE_REF_KINDS: Tuple[str, ...] = ("link", "bearer", "alloc")
_OPAQUE_REF_PATTERN = re.compile(
    r"^backhaul:(link|bearer|alloc):[0-9a-f]{32}$"
)

#: Link name (1..64 printable ASCII, no control characters).  The link
#: name is operator-chosen DATA; the underlying port/circuit identity
#: (interface index, slot/port, VLAN, circuit id) is deliberately NOT
#: modeled anywhere in this family -- link identity stays adapter-side
#: opaque.
_LINK_NAME_PATTERN = re.compile(r"^[\x21-\x7e][\x20-\x7e]{0,63}$")

#: Adapter-side endpoint LABEL (1..64 characters, DNS-label-shaped).
#: The label names a link endpoint (a port on the operator's side);
#: the physical interface identity (MAC address, interface name,
#: slot/port) is deliberately NOT modeled -- endpoint identity stays
#: adapter-side opaque (W022 identity invariant).
_ENDPOINT_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,63}$")

#: WORK-011 path reference grammar (opaque DATA).  A routing path id
#: is a content-derived ``sha256:<64 hex>`` fingerprint (WORK-011
#: ``routing.model.derive_path_id``); the backhaul family CONSUMES it
#: as an opaque reference and never re-derives, scores, or branches on
#: paths (no second routing/scoring engine).
_PATH_REF_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")

#: Backhaul technology profiles -- frozen classification vocabulary
#: (registry DATA, never core branching).  Ethernet per IEEE
#: 802.3-2018; fiber/optical transport per ITU-T G.709/G.7091; fixed
#: microwave per ITU-R F-series radio-relay concepts; satellite access
#: per the ITU-R G.8281-shaped satellite transport concepts.  The
#: profile classifies a link's technology family as DATA; no core
#: state machine branches on it.
_PROFILE_VALUES: Tuple[str, ...] = ("ethernet", "fiber", "microwave", "satellite")

#: LOCK-023 -- credential-like text rejection vocabulary.  The token
#: list covers link/terminal/modem management credentials (SNMP/NETCONF
#: community strings and shared secrets, terminal admin passphrases,
#: modem SIM/PSK material, 802.1X/EAPOL wired-access credentials, and
#: IPsec/IKE key material where a protected backhaul uses it).  A
#: string carrying any of these fragments is rejected so an
#: implementation cannot smuggle secret material through names,
#: labels, or refs.  Matching runs against the lowered text AND a
#: separator-normalized form (hyphen/underscore/dot/space collapsed to
#: ``-``), so both ``shared_secret`` and ``shared-secret`` spellings
#: are caught.
_CREDENTIAL_LIKE_FORBIDDEN: Tuple[str, ...] = (
    "private_key", "secret_key", "password", "passphrase", "token",
    "api_key", "shared_secret", "community_string", "psk",
    "pre_shared_key", "preshared", "sim_pin", "session_key",
    "eap_password", "ipsec_secret", "ike_psk", "terminal_password",
    "modem_pin", "snmp_community",
)

_SEPARATOR_RUN = re.compile(r"[-_.\s]+")


def _normalized(text: str) -> str:
    return _SEPARATOR_RUN.sub("-", text.lower())


def validate_opaque_ref(value: str, expected_kind: Optional[str] = None) -> str:
    """Validate an opaque backhaul technology ref.

    Grammar: ``backhaul:(link|bearer|alloc):[0-9a-f]{32}`` (hex
    lowercase, 32 digits).  When ``expected_kind`` is given, the ref's
    kind segment must match it (a link view must carry a ``link`` ref,
    a binding a ``bearer`` ref, an allocation an ``alloc`` ref).
    Raises :class:`BackhaulError` for any other shape.  The ref is an
    OPAQUE handle: the underlying port/circuit/radio-link/terminal or
    modem identity material is NEVER carried in it.
    """
    if not isinstance(value, str) or not value:
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "opaque ref must be a non-empty string",
        )
    match = _OPAQUE_REF_PATTERN.fullmatch(value)
    if match is None:
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "opaque ref must match "
            "backhaul:(link|bearer|alloc):<32 lowercase hex>",
        )
    if expected_kind is not None:
        if expected_kind not in _OPAQUE_REF_KINDS:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "expected_kind must be one of %s"
                % (list(_OPAQUE_REF_KINDS),),
            )
        if match.group(1) != expected_kind:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "opaque ref %s must be of kind %r" % (value, expected_kind),
            )
    return value


def assert_ref_session_separation(
    backhaul_ref: str, session_id: str
) -> None:
    """Enforce the W022 identity invariant at the ref/session seam.

    A backhaul technology ref (link/bearer/allocation identity) must
    NEVER embed WORK-012 ``session_id`` material, and a ``session_id``
    must NEVER embed a technology ref: session identity and backhaul
    identity are distinct axes.  ``session_id`` is sacred and
    access-independent; a backhaul change (Ethernet -> satellite,
    circuit re-homing, bearer re-establishment) re-binds the SAME
    ``session_id`` to a NEW bearer ref; the boundary NEVER collapses
    them (the backhaul analog of the fivegc R1 and wifi W021
    separation mechanics).

    Raises :class:`BackhaulError` with reason
    ``BackhaulReasonCode.ACCESS_SESSION_COLLAPSE`` when either value
    embeds the other: full-string containment either way, the digest
    portion of a ``sha256:<hex>`` session id embedded in the ref, or
    the ref's hex tail embedded in the session digest (which catches
    truncated-digest smuggling such as a ref minted from the leading
    32 hex of a session id).  Fragments shorter than 16 hex digits are
    not flagged (a 64-bit collision cannot occur by accident between
    honest content-derived values).
    """
    if not isinstance(backhaul_ref, str) or not backhaul_ref:
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "backhaul ref must be a non-empty string",
        )
    if not isinstance(session_id, str) or not session_id:
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "session_id must be a non-empty string",
        )
    session_digest = (
        session_id.split(":", 1)[1] if ":" in session_id else ""
    )
    ref_hex = (
        backhaul_ref.rsplit(":", 1)[1] if ":" in backhaul_ref else ""
    )
    ref_hex = (
        ref_hex if re.fullmatch(r"[0-9a-f]+", ref_hex or "") else ""
    )
    collapsed = (
        backhaul_ref == session_id
        or backhaul_ref in session_id
        or session_id in backhaul_ref
        or (len(session_digest) >= 16 and session_digest in backhaul_ref)
        or (len(ref_hex) >= 16 and ref_hex in session_digest)
    )
    if collapsed:
        raise BackhaulError(
            BackhaulReasonCode.ACCESS_SESSION_COLLAPSE,
            "backhaul ref %r and session_id collapse onto each other "
            "(W022 identity invariant: session_id is sacred and "
            "access-independent; the backhaul ref must stay distinct)"
            % backhaul_ref[:80],
        )


def reject_credential_like_text(text: str, *, label: str = "text") -> None:
    """Reject text carrying secret-like material (LOCK-023).

    Backhaul credential material (management-plane community strings,
    terminal/modem admin credentials, PSKs, wired-access 802.1X
    credentials, protected-backhaul IPsec/IKEv2 keys) lives ONLY in
    the adapter's private credential store.  Any caller-supplied
    string that RESEMBLES secret material (contains a forbidden token
    such as ``psk``/``password``/``community_string``) is rejected
    fail-closed so an implementation cannot smuggle a key through a
    name, label, or ref.
    """
    if not isinstance(text, str):
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "%s must be a string" % label,
        )
    lowered = text.lower()
    normalized = _normalized(text)
    for forbidden in _CREDENTIAL_LIKE_FORBIDDEN:
        if forbidden in lowered or _normalized(forbidden) in normalized:
            raise BackhaulError(
                BackhaulReasonCode.INVALID_INPUT,
                "%s must not resemble secret material "
                "(LOCK-023; forbidden token: %s)" % (label, forbidden),
            )


def validate_credential_slot_name(name: str) -> str:
    """Validate a credential slot NAME (LOCK-023).

    A slot NAME carries NO material -- it is a label the adapter uses
    to look up its OWN private credential store (link/terminal/modem
    management credentials).  The boundary rejects names that LOOK
    like secret material so an implementation cannot smuggle a key
    through the slot name (mirrors the WORK-016/019/021 discipline).
    """
    if not isinstance(name, str) or not name:
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "credential_slot_name must be a non-empty string",
        )
    reject_credential_like_text(name, label="credential_slot_name")
    return name


def validate_link_name(value: str) -> str:
    """Validate a link name (the provisionable link profile's name)."""
    if not isinstance(value, str) or not value:
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "link name must be a non-empty string",
        )
    if not _LINK_NAME_PATTERN.fullmatch(value):
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "link name must be 1..64 printable ASCII characters "
            "(no control characters)",
        )
    return value


def validate_endpoint_label(value: str) -> str:
    """Validate an adapter-side endpoint LABEL.

    1..64 characters, starting alphanumeric, then ``[A-Za-z0-9._-]``.
    The label is an operator-chosen handle for a link endpoint (a
    port); the physical interface identity (MAC address, interface
    name, slot/port) is deliberately NOT modeled in this family --
    endpoint identity stays adapter-side opaque (W022 identity
    invariant).
    """
    if not isinstance(value, str) or not value:
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "endpoint label must be a non-empty string",
        )
    if not _ENDPOINT_LABEL_PATTERN.fullmatch(value):
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "endpoint label must be 1..64 characters matching "
            "[A-Za-z0-9][A-Za-z0-9._-]* (adapter-side opaque label)",
        )
    return value


def validate_profile(value: str) -> str:
    """Validate a backhaul technology profile classification (DATA).

    One of ``ethernet`` / ``fiber`` / ``microwave`` / ``satellite``.
    The profile is REGISTRY DATA classifying the link's technology
    family (IEEE 802.3-2018, ITU-T G.709, ITU-R microwave
    radio-relay, ITU-R satellite transport concepts as citations);
    it never becomes core branching (the same contract path serves
    every profile).
    """
    if not isinstance(value, str) or not value:
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "profile must be a non-empty string",
        )
    if value not in _PROFILE_VALUES:
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "profile must be one of %s (backhaul technology "
            "classification DATA; IEEE 802.3-2018 / ITU-T G.709 / "
            "ITU-R microwave / ITU-R satellite reference families)"
            % (list(_PROFILE_VALUES),),
        )
    return value


def validate_path_ref(value: str) -> str:
    """Validate a WORK-011 path reference (opaque DATA).

    Grammar: ``sha256:<64 lowercase hex>`` -- the WORK-011 content-
    derived path fingerprint (``routing.model.derive_path_id``).  The
    backhaul family CONSUMES path references as opaque binding DATA
    (which routed path a bearer serves); it never re-derives, scores,
    or branches on paths (no second routing/scoring engine -- the
    WORK-011 engine stays the single routing authority).
    """
    if not isinstance(value, str) or not value:
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "path_ref must be a non-empty string",
        )
    if not _PATH_REF_PATTERN.fullmatch(value):
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "path_ref must match sha256:<64 lowercase hex> (the WORK-011 "
            "content-derived path fingerprint, consumed as opaque DATA)",
        )
    return value


def validate_capacity_bps(value: int) -> int:
    """Validate a link capacity / allocation quantity in integer bps.

    1..(1 Tbps) expressed in the WORK-008 ``backhaul`` resource kind's
    integer BASE unit (bps).  DATA only: the boundary does not schedule
    capacity or enforce admission control (a production
    switch/terminal does, behind the adapter boundary); the value maps
    into the WORK-008 canonical resource units and never creates a
    second capacity/accounting authority.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "capacity must be an integer bps quantity (WORK-008 "
            "backhaul-kind base unit)",
        )
    if not (1 <= value <= 1_000_000_000_000):
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "capacity must be in [1, 1e12] bps (integer base units)",
        )
    return value


def validate_bearer_count(value: int) -> int:
    """Validate a bearer count bound.

    1..4094 -- the IEEE 802.1Q-2022 VLAN identifier space upper bound
    is used as the deterministic concurrent-bearer bound DATA (a
    production element enforces its own table sizes behind the seam).
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "bearer count must be an integer",
        )
    if not (1 <= value <= 4094):
        raise BackhaulError(
            BackhaulReasonCode.INVALID_INPUT,
            "bearer count must be in [1, 4094] "
            "(IEEE 802.1Q-2022 VLAN identifier space bound, DATA)",
        )
    return value


__all__ = [
    "validate_opaque_ref",
    "assert_ref_session_separation",
    "reject_credential_like_text",
    "validate_credential_slot_name",
    "validate_link_name",
    "validate_endpoint_label",
    "validate_profile",
    "validate_path_ref",
    "validate_capacity_bps",
    "validate_bearer_count",
]
