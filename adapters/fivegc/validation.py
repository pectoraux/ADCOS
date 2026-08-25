"""ADCOS 5G Core integration input validators (WORK-019).

Pure, stdlib-only validators for the 5G Core domain value types.  No
vendor SDK, no 5G Core state machine, no cryptographic material.  The
validators check SHAPES only (3GPP TS 23.501 / 33.501 / 29.500
reference shapes); they never decode, decrypt, or store credentials
(LOCK-023: credential slot NAMES only, never material).

Standards leverage (LOCK-018, mirroring the W017/W018 discipline):
the validators use the Python standard library ``re`` module for shape
checking -- the stdlib is a standard implementation, not a reinvention.
The 3GPP reference shapes appear as DATA with TS citations in
docstrings; no invented 5G/crypto primitive exists in this module.
"""

from __future__ import annotations

import re
from typing import Optional

from .errors import FiveGCoreError, FiveGCoreReasonCode


#: 3GPP TS 23.501 §2.4 / TS 22.501 §2.3 -- SUPI shapes: IMSI (15-16
#: digits, MCC+MNC+MSIN), NAI (RFC 4182 realm), GCI, GLI.  The
#: conformance scenarios use the IMSI shape; the others are accepted
#: opaquely (the boundary never interprets SUPI semantics).
_SUPI_PATTERN = re.compile(r"^(imsi-\d{15,16}|nai-[A-Za-z0-9._\-]+@[A-Za-z0-9.\-]+|gci-[A-Fa-f0-9]+|gli-[A-Fa-f0-9]+)$")

#: 3GPP TS 23.501 §5.15 -- S-NSSAI: SST is one octet (0..255); SD is
#: three octets (6 hex digits) when present.
_SNSSAI_SST_PATTERN = re.compile(r"^\d{1,3}$")
_SNSSAI_SD_PATTERN = re.compile(r"^[A-Fa-f0-9]{6}$")

#: 3GPP TS 23.501 §5.6.1 -- DNN: a DNS-label-shaped name (subset; the
#: boundary never resolves a DNN).
_DNN_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]{0,253}$")

#: 3GPP TS 23.501 §5.7.3 / §5.7.2 -- QFI: 0..63 (6 bits); 5QI maps to
#: standardized QoS characteristics (DATA, not enforced here).

#: 3GPP TS 23.501 §5.6.2 -- PDU session id: 0..255 (one octet).  The
#: integration-layer PduSessionId is a content-derived string carrying
#: this octet (distinct from the WORK-012 session_id -- R1 invariant).

#: LOCK-023 -- credential slot NAME vocabulary.  A slot NAME carries
#: NO material; the boundary rejects names that LOOK like secret
#: material so an implementation cannot smuggle a key through the slot
#: name.  (Mirrors the WORK-016 adapter SDK's credential-slot
#: discipline.)
_CREDENTIAL_SLOT_FORBIDDEN = (
    "private_key", "secret_key", "password", "token", "api_key",
    "shared_secret", "opc", "k_", "ausf_key", "rand", "autn", "xres",
    "k_asme", "kausrp", "knasf", "kamf", "impi_key", "subscription_key",
)


def validate_supi_text(value: str) -> str:
    """Validate and return a SUPI text (3GPP TS 23.501 §2.4).

    The boundary never interprets SUPI semantics; this checks the SHAPE
    only.  Raises :class:`FiveGCoreError` for a malformed SUPI.
    """
    if not isinstance(value, str) or not value:
        raise FiveGCoreError(
            FiveGCoreReasonCode.INVALID_INPUT,
            "supi must be a non-empty string",
        )
    if not _SUPI_PATTERN.match(value):
        raise FiveGCoreError(
            FiveGCoreReasonCode.INVALID_INPUT,
            "supi must match the 3GPP TS 23.501 §2.4 shape "
            "(imsi-<digits> | nai-<realm> | gci-<hex> | gli-<hex>)",
        )
    return value


def validate_snssai(sst: int, sd: Optional[str] = None) -> "tuple":
    """Validate an S-NSSAI (3GPP TS 23.501 §5.15).

    ``sst`` is one octet (0..255); ``sd`` is three octets (6 hex) when
    present.  Returns the canonical ``(sst, sd)`` tuple.  Raises
    :class:`FiveGCoreError` for a malformed S-NSSAI.
    """
    if isinstance(sst, bool) or not isinstance(sst, int):
        raise FiveGCoreError(
            FiveGCoreReasonCode.INVALID_INPUT,
            "sst must be an integer",
        )
    if not (0 <= sst <= 255):
        raise FiveGCoreError(
            FiveGCoreReasonCode.INVALID_INPUT,
            "sst must be in [0, 255] (3GPP TS 23.501 §5.15)",
        )
    if sd is not None:
        if not isinstance(sd, str) or not _SNSSAI_SD_PATTERN.match(sd):
            raise FiveGCoreError(
                FiveGCoreReasonCode.INVALID_INPUT,
                "sd must be 6 hex digits (3GPP TS 23.501 §5.15)",
            )
        sd = sd.lower()
    return (sst, sd)


def validate_dnn_text(value: str) -> str:
    """Validate a DNN (3GPP TS 23.501 §5.6.1)."""
    if not isinstance(value, str) or not value:
        raise FiveGCoreError(
            FiveGCoreReasonCode.INVALID_INPUT,
            "dnn must be a non-empty string",
        )
    if not _DNN_PATTERN.match(value):
        raise FiveGCoreError(
            FiveGCoreReasonCode.INVALID_INPUT,
            "dnn must match the 3GPP TS 23.501 §5.6.1 DNN shape",
        )
    return value


def validate_qfi(value: int) -> int:
    """Validate a QFI (3GPP TS 23.501 §5.7.3)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise FiveGCoreError(
            FiveGCoreReasonCode.INVALID_INPUT,
            "qfi must be an integer",
        )
    if not (0 <= value <= 63):
        raise FiveGCoreError(
            FiveGCoreReasonCode.INVALID_INPUT,
            "qfi must be in [0, 63] (3GPP TS 23.501 §5.7.3)",
        )
    return value


def validate_pdu_session_id_octet(value: int) -> int:
    """Validate a PDU session id octet (3GPP TS 23.501 §5.6.2)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise FiveGCoreError(
            FiveGCoreReasonCode.INVALID_INPUT,
            "pdu session id octet must be an integer",
        )
    if not (0 <= value <= 255):
        raise FiveGCoreError(
            FiveGCoreReasonCode.INVALID_INPUT,
            "pdu session id octet must be in [0, 255] (3GPP TS 23.501 §5.6.2)",
        )
    return value


def validate_credential_slot_name(name: str) -> str:
    """Validate a credential slot NAME (LOCK-023).

    A slot NAME carries NO material -- it is a label the adapter uses to
    look up its OWN private credential store.  The boundary rejects
    names that LOOK like secret material so an implementation cannot
    smuggle a key through the slot name (mirrors the WORK-016 adapter
    SDK's credential-slot discipline).
    """
    if not isinstance(name, str) or not name:
        raise FiveGCoreError(
            FiveGCoreReasonCode.INVALID_INPUT,
            "credential_slot_name must be a non-empty string",
        )
    lowered = name.lower()
    for forbidden in _CREDENTIAL_SLOT_FORBIDDEN:
        if forbidden in lowered:
            raise FiveGCoreError(
                FiveGCoreReasonCode.INVALID_INPUT,
                "credential_slot_name must not resemble secret material "
                "(LOCK-023; forbidden token: %s)" % forbidden,
            )
    return name


def validate_nf_url(url: str) -> str:
    """Validate an NF endpoint URL (3GPP TS 29.500 §4.2 -- SBi)."""
    if not isinstance(url, str) or not url:
        raise FiveGCoreError(
            FiveGCoreReasonCode.INVALID_INPUT,
            "nf url must be a non-empty string",
        )
    if not (url.startswith("http://") or url.startswith("https://")):
        raise FiveGCoreError(
            FiveGCoreReasonCode.INVALID_INPUT,
            "nf url must be an http(s) URL (3GPP TS 29.500 §4.2 SBi)",
        )
    return url


__all__ = [
    "validate_supi_text",
    "validate_snssai",
    "validate_dnn_text",
    "validate_qfi",
    "validate_pdu_session_id_octet",
    "validate_credential_slot_name",
    "validate_nf_url",
]
