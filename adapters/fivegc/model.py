"""ADCOS 5G Core integration domain model (WORK-019).

Value types for the 5G Core integration boundary (the new
``adapters/fivegc`` sub-package within the frozen ``/adapters`` module
boundary -- ``spec/architecture.md`` §29; LOCK-002 frozen,
non-negotiable: ``5G NR is implemented through an access adapter.
3GPP RAN/core functions remain outside the ADCOS core domain.`` and
the W019 acceptance criterion itself: ``5G Core state remains outside
ADCOS core authority`` / ``5G authentication credentials remain
access-specific``).

Standards leverage (LOCK-018, mirroring the W017/W018 discipline):
the model uses 3GPP TS 23.501 / 33.501 / 29.500 reference SHAPES as
DATA with TS citations in docstrings -- no invented 5G/crypto
primitive, no vendor SDK, no 5G Core state machine exists in this
module.  The boundary never imports 5G Core types, credentials, or
state machines into the ADCOS core (LOCK-002/016; verified by the
WORK-019 selftest's no-core-5GC-leakage audit).

Central boundary (WORK-019):

    FIVEGC INTEGRATION
        != SESSION IDENTITY        (session_id sacred, from WORK-012)
        != 5G ROUTE IDENTITY        (pdu_session_id is 5G route identity;
                                     never collapses onto session_id)
        != IDENTITY AUTHORITY       (WORK-004 facade; 5G credentials
                                     access-specific, slot NAMES only)
        != RESOURCE AUTHORITY      (WORK-008; 5GC bearer/QoS = DATA)
        != POLICY AUTHORITY         (caller-supplied policy DATA)
        != TOPOLOGY AUTHORITY
        != ACCESS/VENDOR AUTHORITY  (LOCK-016; concrete 5G Core stacks
                                     = adapters, behind the seam)
        != 5GC STATE AUTHORITY      (5GC NF state lives in the
                                     adapter/conformance peer, NEVER
                                     in ADCOS core)

All instants are injected (WORK-003 ``parse_instant`` grammar); no
wall clock.  All ids are content-derived over canonical JSON
(``protocol.canonicalization.canonical_json_bytes``); no randomness,
no ``urandom``/``secrets``/``random`` anywhere in this module.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, List, Optional, Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import FIVEGC_PREFIX
from .validation import (
    validate_credential_slot_name,
    validate_dnn_text,
    validate_nf_url,
    validate_pdu_session_id_octet,
    validate_qfi,
    validate_snssai,
    validate_supi_text,
)


# --------------------------------------------------------------------------
# Value types (3GPP reference shapes as DATA; no state machine, no crypto)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Snssai:
    """S-NSSAI (3GPP TS 23.501 §5.15).

    ``sst`` (Slice/Service Type) is one octet (0..255); ``sd`` (Slice
    Differentiator) is three octets (6 hex) when present.  DATA only --
    the boundary never resolves slice membership.
    """

    sst: int
    sd: Optional[str] = None

    def __post_init__(self) -> None:
        sst, sd = validate_snssai(self.sst, self.sd)
        object.__setattr__(self, "sst", sst)
        object.__setattr__(self, "sd", sd)

    def to_dict(self) -> dict:
        return {"sst": self.sst, "sd": self.sd}


@dataclass(frozen=True)
class Dnn:
    """Data Network Name (3GPP TS 23.501 §5.6.1)."""

    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", validate_dnn_text(self.value))

    def to_dict(self) -> dict:
        return {"value": self.value}


@dataclass(frozen=True)
class Qfi:
    """QoS Flow Identifier (3GPP TS 23.501 §5.7.3).  0..63."""

    value: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", validate_qfi(self.value))

    def to_dict(self) -> dict:
        return {"value": self.value}


@dataclass(frozen=True)
class Supi:
    """Subscription Permanent Identifier (3GPP TS 23.501 §2.4).

    SHAPE only -- the boundary never interprets SUPI semantics and never
    stores credential material.  Accepted shapes: ``imsi-<digits>``,
    ``nai-<realm>``, ``gci-<hex>``, ``gli-<hex>``.
    """

    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", validate_supi_text(self.value))

    def to_dict(self) -> dict:
        return {"value": self.value}


@dataclass(frozen=True)
class Suci:
    """Subscription Concealed Identifier (3GPP TS 33.501 §6.12.2).

    An OPAQUE blob carrier.  The boundary NEVER decrypts a SUCI; it is
    passed through to the 5G Core's SIDF (Subscription Identifier
    De-concealing Function), which lives behind the adapter boundary.
    No crypto, no key material in this module.
    """

    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or not self.value:
            raise ValueError("suci must be a non-empty opaque string")
        object.__setattr__(self, "value", self.value)

    def to_dict(self) -> dict:
        return {"value": self.value}


@dataclass(frozen=True)
class QosFlowSpec:
    """A QoS flow specification (3GPP TS 23.501 §5.7.2/§5.7.3).

    DATA only -- the boundary carries the 5QI/ARP/GFBR/MFBR shapes; it
    does not enforce QoS (a production 5G Core's SMF/UPF does, behind
    the adapter boundary).
    """

    five_qi: Qfi
    arp_priority: int = 0
    gfbr_uplink: int = 0
    mfbr_uplink: int = 0

    def __post_init__(self) -> None:
        if isinstance(self.arp_priority, bool) or not isinstance(self.arp_priority, int):
            raise ValueError("arp_priority must be an integer")
        if not (0 <= self.arp_priority <= 15):
            raise ValueError("arp_priority must be in [0, 15] (3GPP TS 23.501 §5.7.3 ARP)")

    def to_dict(self) -> dict:
        return {
            "five_qi": self.five_qi.to_dict(),
            "arp_priority": self.arp_priority,
            "gfbr_uplink": self.gfbr_uplink,
            "mfbr_uplink": self.mfbr_uplink,
        }


@dataclass(frozen=True)
class NfEndpoint:
    """A 5G Core NF endpoint (3GPP TS 29.500 §4.2 -- SBi).

    The Open5GSAdapter is constructed with an ``NfEndpoint`` pointing at
    a real 5G Core's SBi base URL (a real Open5GS deployment, or the
    WORK-019 conformance NF peer).  Pointing the adapter at a different
    5G Core is an endpoint config change, NOT a core change.
    """

    nf_type: str
    url: str

    def __post_init__(self) -> None:
        if not isinstance(self.nf_type, str) or not self.nf_type:
            raise ValueError("nf_type must be a non-empty string")
        object.__setattr__(self, "url", validate_nf_url(self.url))

    def to_dict(self) -> dict:
        return {"nf_type": self.nf_type, "url": self.url}


@dataclass(frozen=True)
class PduSessionId:
    """A 5G Core PDU session route identity (3GPP TS 23.501 §5.6.2).

    Content-derived over the binding material (session_id + supi +
    snssai + dnn + sequence).  This is the 5G ROUTE identity -- it is
    DISTINCT from the WORK-012 ``session_id`` (R1 invariant: a route
    change produces a NEW ``PduSessionId`` bound to the SAME sacred
    ``session_id``; the boundary NEVER collapses them).  Mirrors the
    WORK-018 ``FlowLabel`` / ``IPFlow`` route/session separation.
    """

    value: str

    def to_dict(self) -> dict:
        return {"value": self.value}


@dataclass(frozen=True)
class CredentialSlot:
    """A credential slot NAME (LOCK-023).

    The slot NAME carries NO material -- it is a label the adapter uses
    to look up its OWN private credential store (5G K/OPC/RAND/AUTN/
    XRES*).  The boundary NEVER sees the material; the
    :func:`validate_credential_slot_name` rejects names that resemble
    secret material so an implementation cannot smuggle a key through
    the slot name.
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
class SubscriberRecord:
    """The result of ``provision_subscriber``.

    Carries the opaque ``subscriber_ref`` (content-derived), the SUPI,
    the subscribed S-NSSAI/DNN, and the credential slot NAME ONLY --
    NEVER the credential material (LOCK-023).  Mirrors the WORK-018
    secret-free :class:`SessionView` projection.
    """

    subscriber_ref: str
    supi: Supi
    subscribed_snssai: Snssai
    subscribed_dnn: Dnn
    credential_slot_name: str

    def to_dict(self) -> dict:
        return {
            "subscriber_ref": self.subscriber_ref,
            "supi": self.supi.to_dict(),
            "subscribed_snssai": self.subscribed_snssai.to_dict(),
            "subscribed_dnn": self.subscribed_dnn.to_dict(),
            "credential_slot_name": self.credential_slot_name,
        }


@dataclass(frozen=True)
class PduSessionBinding:
    """The result of ``bind_session``.

    The ADCOS ``session_id`` is SACRED; the 5G ``pdu_session_id`` is the
    ROUTE identity (content-derived, mutable on a re-route).  The
    ``pdu_session_ref`` is the opaque handle the manager keys bindings
    by (content-derived; deliberately NOT part of the identity content
    so a rebind produces a new ref without minting a new session_id).
    Mirrors the WORK-018 :class:`SessionIPBinding` exactly.
    """

    session_id: str
    pdu_session_id: PduSessionId
    pdu_session_ref: str
    binding_id: str
    supi: Supi
    snssai: Snssai
    dnn: Dnn
    closed: bool = False

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "pdu_session_id": self.pdu_session_id.to_dict(),
            "pdu_session_ref": self.pdu_session_ref,
            "binding_id": self.binding_id,
            "supi": self.supi.to_dict(),
            "snssai": self.snssai.to_dict(),
            "dnn": self.dnn.to_dict(),
            "closed": self.closed,
        }


@dataclass(frozen=True)
class ExternalPduSessionEvidence:
    """Adapter-observed, secret-free state from an external 5GC."""

    external_pdu_session_id: str
    supi: Supi
    dnn: Dnn
    snssai: Snssai
    ue_ipv4: str
    state: str

    def to_dict(self) -> dict:
        return {
            "external_pdu_session_id": self.external_pdu_session_id,
            "supi": self.supi.to_dict(),
            "dnn": self.dnn.to_dict(),
            "snssai": self.snssai.to_dict(),
            "ue_ipv4": self.ue_ipv4,
            "state": self.state,
        }


@dataclass(frozen=True)
class PduSessionView:
    """The established PDU session view (3GPP TS 23.501 §5.6.6).

    Returned by ``establish_pdu_session``.  Carries the UE IPv6 address,
    the QoS flows mapped for the session, the SMF instance id, and the
    data-plane endpoint (host, port) the conformance peer exposes for
    the byte-carrying path.  DATA only; the boundary does not enforce
    QoS or forward packets (a production SMF/UPF does, behind the seam).
    """

    pdu_session_ref: str
    ue_ipv6: str
    qos_flows: Tuple[QosFlowSpec, ...]
    smf_instance_id: str
    data_endpoint: Optional[Tuple[str, int]] = None

    def to_dict(self) -> dict:
        return {
            "pdu_session_ref": self.pdu_session_ref,
            "ue_ipv6": self.ue_ipv6,
            "qos_flows": [q.to_dict() for q in self.qos_flows],
            "smf_instance_id": self.smf_instance_id,
            "data_endpoint": list(self.data_endpoint) if self.data_endpoint is not None else None,
        }


@dataclass(frozen=True)
class AuthResult:
    """The result of 5G AKA authentication (3GPP TS 33.501 §6.1).

    Carries success/failure and an OPAQUE ``auth_ref`` the adapter uses
    to look up its OWN private auth state.  The credential material
    (K/OPC/RAND/AUTN/XRES*/K_seaf/K_amf) NEVER crosses the boundary --
    only the slot name + the opaque auth_ref (LOCK-023).
    """

    success: bool
    auth_ref: str
    supi: Supi

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "auth_ref": self.auth_ref,
            "supi": self.supi.to_dict(),
        }


@dataclass(frozen=True)
class LinkMetricsSample:
    """A generic 5G Core link-metric sample (DATA, not topology facts)."""

    samples: Tuple[Tuple[str, int], ...] = ()

    def to_dict(self) -> dict:
        return {"samples": [[k, v] for k, v in self.samples]}


@dataclass(frozen=True)
class FiveGCEvent:
    """A 5G Core integration event (manager event log)."""

    event_type: str
    integration_id: str
    instant: str
    pdu_session_ref: str = ""
    subscriber_ref: str = ""
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "event_type": self.event_type,
            "integration_id": self.integration_id,
            "instant": self.instant,
            "pdu_session_ref": self.pdu_session_ref,
            "subscriber_ref": self.subscriber_ref,
            "detail": self.detail,
        }


# --------------------------------------------------------------------------
# Content-derived id derivation (deterministic; no randomness)
# --------------------------------------------------------------------------


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def derive_pdu_session_id(
    session_id: str, supi: Supi, snssai: Snssai, dnn: Dnn, sequence: int
) -> PduSessionId:
    """Content-derive a 5G PDU session route identity.

    Distinct from the sacred ``session_id`` by construction (the
    content includes ``session_id`` + the 5G-specific binding material
    + a sequence).  A re-route produces a NEW ``PduSessionId`` for the
    SAME ``session_id`` (R1 invariant).
    """
    if isinstance(sequence, bool) or not isinstance(sequence, int):
        raise ValueError("sequence must be an integer")
    material = canonical_json_bytes({
        "session_id": session_id,
        "supi": supi.value,
        "snssai": snssai.to_dict(),
        "dnn": dnn.value,
        "sequence": sequence,
    })
    digest = _sha256_hex(material)
    return PduSessionId(value="%s:pdu:%s" % (FIVEGC_PREFIX, digest[:32]))


def derive_binding_id(session_id: str, pdu_session_id: PduSessionId) -> str:
    """Content-derive a binding id (the manager's binding key)."""
    material = canonical_json_bytes({
        "session_id": session_id,
        "pdu_session_id": pdu_session_id.value,
    })
    return "%s:binding:%s" % (FIVEGC_PREFIX, _sha256_hex(material)[:32])


def derive_pdu_session_ref(binding_id: str, sequence: int) -> str:
    """Content-derive an opaque PDU session ref (deliberately NOT part
    of the identity content, so a rebind produces a new ref without
    minting a new session_id -- mirrors the WORK-018 binding_id/ref
    separation)."""
    material = canonical_json_bytes({"binding_id": binding_id, "sequence": sequence})
    return "%s:ref:%s" % (FIVEGC_PREFIX, _sha256_hex(material)[:32])


def derive_subscriber_ref(supi: Supi) -> str:
    """Content-derive an opaque subscriber ref."""
    material = canonical_json_bytes({"supi": supi.value})
    return "%s:subscriber:%s" % (FIVEGC_PREFIX, _sha256_hex(material)[:32])


def derive_integration_id(instance_label: str) -> str:
    """Content-derive the integration instance id (the manager's id)."""
    if not isinstance(instance_label, str) or not instance_label:
        raise ValueError("instance_label must be a non-empty string")
    material = canonical_json_bytes({"instance_label": instance_label})
    return "%s:%s" % (FIVEGC_PREFIX, _sha256_hex(material)[:16])


__all__ = [
    "Snssai",
    "Dnn",
    "Qfi",
    "Supi",
    "Suci",
    "QosFlowSpec",
    "NfEndpoint",
    "PduSessionId",
    "CredentialSlot",
    "SubscriberRecord",
    "PduSessionBinding",
    "ExternalPduSessionEvidence",
    "PduSessionView",
    "AuthResult",
    "LinkMetricsSample",
    "FiveGCEvent",
    "derive_pdu_session_id",
    "derive_binding_id",
    "derive_pdu_session_ref",
    "derive_subscriber_ref",
    "derive_integration_id",
]
