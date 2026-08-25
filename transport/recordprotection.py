"""ADCOS transport record protection (WORK-017): the
profile-cryptography seam.

THE STANDARDS BOUNDARY (LOCK-018)
=================================

This module draws the boundary the WORK-017 review required between
ADCOS transport SEMANTICS and profile-specific CRYPTOGRAPHY:

    ADCOS TRANSPORT CONTRACT (core semantics — frozen, testable)
        negotiation, replay windows, downgrade detection, key
        lifecycle, identity binding, session binding, lifecycle,
        failure isolation
                    |
                    |  behind :class:`transport.contract.TransportContract`,
                    |  INSIDE implementations (never in core semantics)
                    v
    RECORD PROTECTION (this seam — replaceable per implementation)
        reference model:   integrity-only, NON-confidential (below)
        production:        the profile's STANDARD record protection
                           (TLS 1.3 record protection, RFC 8446
                           section 5.2; QUIC packet protection,
                           RFC 9001 section 5.4; IPsec ESP, RFC 4303
                           section 3.3.3; WireGuard-class), supplied
                           by a concrete implementation of this ABC

The built-in :class:`ReferenceRecordProtection` is the deterministic
offline model used by
:class:`transport.contract.ModeledTransportEngine` and by CI.  It
provides:

- **integrity + origin authentication** — HMAC-SHA256 (IETF RFC 2104)
  in its standard MAC role, keyed by the HKDF-derived direction key,
  over (domain label, generation, sequence, payload);
- **binding** — the tag covers generation and sequence, so a record
  can never be replayed across generations or reordered undetected;
- **NO confidentiality, by design and by declaration** — the payload
  rides VISIBLE in ``wire_payload`` and every frame self-declares
  ``protection_model="reference-mac-only"``.  This is a reference
  model of the frame CONTRACT (member shape, tag coverage, replay
  window, generation isolation), not a secure record-protection
  scheme, and it composes no new cryptographic construction: one
  standard primitive (HMAC-SHA256) in its standard role.

Confidentiality in production is a PROFILE property (declared as data
by the profile catalog, ``transport.profiles``) delivered by the
profile's standard record protection behind this seam.  ADCOS defines
no record-protection construction of its own (LOCK-018: standard
leverage over reinvention); the transport selftest mechanically
audits this module for exactly that property.
"""

from __future__ import annotations

import abc
import hashlib
import hmac
from typing import Dict, Mapping

from .errors import TransportError, TransportReasonCode

#: Protection-model id of the built-in reference model.  Frames
#: self-describe with this marker; a foreign model id is rejected
#: fail-closed by the reference engine (each implementation enforces
#: its own model's semantics — core validates structure only).
REFERENCE_PROTECTION_MODEL = "reference-mac-only"

#: Domain-separation label for the reference frame MAC.
_REFERENCE_MAC_DOMAIN = b"adcos-transport/reference-frame/v1"


def _mac_input(generation: int, sequence: int, payload: bytes) -> bytes:
    return (
        _REFERENCE_MAC_DOMAIN
        + generation.to_bytes(8, "big")
        + sequence.to_bytes(8, "big")
        + payload
    )


class RecordProtection(abc.ABC):
    """The replaceable record-protection seam inside transport
    implementations.

    A transport implementation (a
    :class:`transport.contract.TransportContract` satisfying class)
    composes ONE record-protection object and delegates frame-level
    member production and verification to it.  The seam contract:

    - ``protect_record`` returns a mapping of STRING members that the
      engine merges into the frame after the core members
      (``transport_id``, ``generation``, ``sequence``);
    - ``unprotect_record`` receives the fully validated frame view
      and MUST fail closed (raise) on any model or tag mismatch;
    - implementations own their model identifier; every frame they
      produce carries it under ``protection_model`` so records are
      self-describing about the protection they actually have;
    - nothing here may leak into core semantics: the manager, the
      sandbox, validation, and serialization know the STRUCTURAL
      frame contract only (see ``transport.validation``).

    Production implementations wrap their profile's standard record
    protection (TLS 1.3 / QUIC / IPsec ESP / WireGuard-class) behind
    this ABC; the reference model below exists so the deterministic
    offline CI battery can exercise the full frame contract without
    any third-party cryptography.
    """

    @abc.abstractmethod
    def model_id(self) -> str:
        """The protection-model identifier frames self-declare with."""

    @abc.abstractmethod
    def protect_record(
        self,
        direction_key: bytes,
        generation: int,
        sequence: int,
        payload: bytes,
    ) -> Dict[str, str]:
        """Produce this model's frame members for one outbound record."""

    @abc.abstractmethod
    def unprotect_record(
        self,
        direction_key: bytes,
        generation: int,
        sequence: int,
        frame: Mapping[str, object],
    ) -> bytes:
        """Verify and decode one inbound record (fail closed)."""


class ReferenceRecordProtection(RecordProtection):
    """The integrity-only reference record model.

    HMAC-SHA256 (RFC 2104) over (domain, generation, sequence,
    payload) keyed by the direction key — the standard MAC role, and
    the ONLY cryptographic operation in this model.  The payload is
    carried visibly (``wire_payload``); the model id
    (``reference-mac-only``) declares that on every frame.  There is
    deliberately no confidentiality here: confidentiality is supplied
    by production profile implementations behind this seam, never
    modeled by an ad-hoc construction (LOCK-018).
    """

    __slots__ = ()

    def model_id(self) -> str:
        return REFERENCE_PROTECTION_MODEL

    def protect_record(
        self,
        direction_key: bytes,
        generation: int,
        sequence: int,
        payload: bytes,
    ) -> Dict[str, str]:
        if not isinstance(direction_key, (bytes, bytearray)) or not direction_key:
            raise ValueError("direction key must be non-empty bytes")
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
            raise ValueError("generation must be a non-negative integer")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
            raise ValueError("sequence must be a positive integer")
        if not isinstance(payload, (bytes, bytearray)) or not payload:
            raise ValueError("record payload must be non-empty bytes")
        tag = hmac.new(
            bytes(direction_key), _mac_input(generation, sequence, bytes(payload)), hashlib.sha256
        ).hexdigest()
        return {
            "protection_model": REFERENCE_PROTECTION_MODEL,
            "wire_payload": bytes(payload).hex(),
            "integrity_tag": tag,
        }

    def unprotect_record(
        self,
        direction_key: bytes,
        generation: int,
        sequence: int,
        frame: Mapping[str, object],
    ) -> bytes:
        if not isinstance(direction_key, (bytes, bytearray)) or not direction_key:
            raise ValueError("direction key must be non-empty bytes")
        model = frame.get("protection_model")
        if model != REFERENCE_PROTECTION_MODEL:
            raise TransportError(
                TransportReasonCode.INTEGRITY_REJECTED,
                "frame protection model %r is not %r (this engine serves "
                "exactly one record model; foreign models fail closed)"
                % (model, REFERENCE_PROTECTION_MODEL),
            )
        try:
            payload = bytes.fromhex(str(frame["wire_payload"]))
            tag = bytes.fromhex(str(frame["integrity_tag"]))
        except ValueError as error:
            raise TransportError(
                TransportReasonCode.INTEGRITY_REJECTED,
                "frame members are not valid hex: %s" % error,
            ) from error
        if not payload:
            raise TransportError(
                TransportReasonCode.INTEGRITY_REJECTED,
                "frame wire_payload must be non-empty",
            )
        expected = hmac.new(
            bytes(direction_key), _mac_input(generation, sequence, payload), hashlib.sha256
        ).digest()
        if not hmac.compare_digest(expected, tag):
            raise TransportError(
                TransportReasonCode.INTEGRITY_REJECTED,
                "frame integrity tag mismatch — tampered or forged record",
            )
        return payload
