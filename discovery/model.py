"""Discovery observation model (WORK-006).

A ``DiscoveryObservation`` is an authenticated, attributable record that a
Node was observed through a discovery mechanism at a particular time and
context. It is NOT identity, trust, topology authority, a route, or a
resource-availability statement — those decisions belong to later layers
(WORK-007+).

Field set per the WORK-006 handoff conceptual model:

    observation_id        deterministic fingerprint of the signed content
                          (sha256 of the canonical unsigned bytes — NOT
                          independently settable, NOT random)
    sender_node_id        the observing node (canonical WORK-004 NodeID)
    observed_node_id      the peer being observed (canonical NodeID)
    issued_at             RFC 3339 UTC — when the observation was made
    freshness_until       RFC 3339 UTC — the observation is current until
                          this instant (after = stale)
    sequence              per-(sender, observed) monotonic integer
    source_type           "local" | "bootstrap" (provenance marker)
    source_context        opaque technology-neutral dict (interface, ref…)
    advertised_capability_references
                          optional opaque capability-id references
                          (WORK-005 vocabulary; never reinterpreted here)
    observed_endpoints    bounded, technology-neutral endpoint descriptors
    schema_version        MAJOR.MINOR
    signature             opaque hex (WORK-004 provider seam over WORK-003
                          canonical signature input)

The ``observation_id`` and ``signature`` members are EXCLUDED from the
signature input; ``observation_id`` is a derived fingerprint of the signed
content, so tampering with any signed member invalidates both the
signature and the observation_id.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Tuple

from identity.node_id import NodeIdError, parse_node_id
from protocol.canonicalization import CanonicalizationError, canonical_json_bytes
from protocol.temporal import TemporalError, parse_instant


class DiscoveryError(ValueError):
    """Raised when a discovery observation violates its contract (fail
    closed). ``code`` is a stable machine-readable reason."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


SCHEMA_VERSION_PATTERN = "^[0-9]+\\.[0-9]+$"
_OBSERVATION_ID_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")

#: Provenance marker for how an observation reached the local node.
#: Bootstrap-sourced observations are NEVER silently equivalent to direct
#: local observations (the bootstrap node is not an authority).
class SourceType:
    LOCAL = "local"
    BOOTSTRAP = "bootstrap"

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        return (cls.LOCAL, cls.BOOTSTRAP)


def _signed_view(observation: "DiscoveryObservation") -> dict:
    """The security-critical content covered by the signature: every
    semantic member EXCEPT ``observation_id`` and ``signature``.

    ``observation_id`` is a derived fingerprint of this content, so it
    is excluded from the signed bytes (and excluded from its own
    derivation) — no circular dependency.
    """
    document = observation.to_dict()
    document.pop("observation_id", None)
    document.pop("signature", None)
    return document


def observation_signature_input(observation: "DiscoveryObservation") -> bytes:
    """Deterministic canonical signature-input bytes (WORK-003
    canonicalization; covers every signed semantic member)."""
    try:
        return canonical_json_bytes(_signed_view(observation))
    except CanonicalizationError as error:
        raise DiscoveryError(
            "canonicalization",
            "observation is not canonically representable: %s" % error,
        ) from error


def _derive_observation_id(observation: "DiscoveryObservation") -> str:
    """Deterministic fingerprint: sha256 of the canonical signed bytes."""
    return "sha256:" + hashlib.sha256(
        observation_signature_input(observation)
    ).hexdigest()


@dataclass(frozen=True)
class DiscoveryObservation:
    """An authenticated discovery observation record.

    ``observation_id`` is auto-derived from the signed content; if a
    non-empty value is supplied it MUST equal the derived value (fail
    closed on mismatch — prevents observation_id spoofing).
    """

    sender_node_id: str
    observed_node_id: str
    issued_at: str
    freshness_until: str
    sequence: int
    source_type: str
    source_context: Mapping[str, Any] = field(default_factory=dict)
    advertised_capability_references: Tuple[str, ...] = ()
    observed_endpoints: Tuple[Mapping[str, Any], ...] = ()
    schema_version: str = "1.0"
    signature: str = ""
    observation_id: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.schema_version, str):
            raise DiscoveryError("schema-version", "schema_version must be a string")
        if re.fullmatch(SCHEMA_VERSION_PATTERN, self.schema_version) is None:
            raise DiscoveryError(
                "schema-version", "schema_version %r must be MAJOR.MINOR" % self.schema_version
            )
        # NodeID binding through the accepted WORK-004 parser — no
        # duplicated identity grammar. Near-miss and malformed values fail
        # closed on both construction paths.
        try:
            parse_node_id(self.sender_node_id)
        except NodeIdError as error:
            raise DiscoveryError(
                "sender-node-id",
                "sender_node_id must be a canonical ADCOS NodeID: %s" % error,
            ) from error
        try:
            parse_node_id(self.observed_node_id)
        except NodeIdError as error:
            raise DiscoveryError(
                "observed-node-id",
                "observed_node_id must be a canonical ADCOS NodeID: %s" % error,
            ) from error
        # Temporal: RFC 3339 UTC; freshness_until >= issued_at.
        try:
            issued = parse_instant(self.issued_at)
            fresh = parse_instant(self.freshness_until)
        except TemporalError as error:
            raise DiscoveryError("temporal", str(error)) from error
        if fresh < issued:
            raise DiscoveryError(
                "temporal",
                "freshness_until %s is before issued_at %s"
                % (self.freshness_until, self.issued_at),
            )
        # Sequence: per-(sender, observed) monotonic integer.
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int):
            raise DiscoveryError("sequence", "sequence must be an integer")
        if self.sequence < 1:
            raise DiscoveryError("sequence", "sequence must be >= 1")
        # Source provenance marker.
        if self.source_type not in SourceType.values():
            raise DiscoveryError(
                "source-type",
                "source_type %r must be one of %s" % (self.source_type, SourceType.values()),
            )
        if not isinstance(self.source_context, Mapping):
            raise DiscoveryError("source-context", "source_context must be an object")
        # Capability references: opaque strings — NEVER classified or
        # reinterpreted by the discovery layer (no second vocabulary
        # authority — the WORK-002 capability registry owns that).
        for ref in self.advertised_capability_references:
            if not isinstance(ref, str) or not ref:
                raise DiscoveryError(
                    "capability-ref", "capability references must be non-empty strings"
                )
        # Observed endpoints: bounded, technology-neutral descriptors.
        if not isinstance(self.observed_endpoints, tuple):
            raise DiscoveryError("endpoints", "observed_endpoints must be a tuple")
        for endpoint in self.observed_endpoints:
            if not isinstance(endpoint, Mapping):
                raise DiscoveryError(
                    "endpoints", "each observed endpoint must be an object"
                )
            if "transport" not in endpoint or not isinstance(endpoint["transport"], str):
                raise DiscoveryError(
                    "endpoints",
                    "each observed endpoint must carry a string 'transport' marker "
                    "(technology-neutral)",
                )
        if not isinstance(self.signature, str):
            raise DiscoveryError("signature", "signature must be an opaque string")
        # observation_id: derived fingerprint. Auto-assign when empty;
        # fail closed when a non-empty value does not match the derived
        # fingerprint (prevents observation_id spoofing).
        derived = _derive_observation_id(self)
        if not self.observation_id:
            object.__setattr__(self, "observation_id", derived)
        elif self.observation_id != derived:
            raise DiscoveryError(
                "observation-id",
                "observation_id %r does not match the derived fingerprint %r "
                "— tamper-resistant identifier" % (self.observation_id, derived),
            )

    @property
    def derived_observation_id(self) -> str:
        """The deterministic fingerprint of this observation's signed
        content (sha256 of the canonical signature input)."""
        return _derive_observation_id(self)

    def to_dict(self) -> dict:
        """Canonical field shape (for WORK-003 canonicalization and
        envelope payload transport). Members are ordered by the
        canonicalization machinery; the field SET is frozen."""
        return {
            "observation_id": self.observation_id,
            "sender_node_id": self.sender_node_id,
            "observed_node_id": self.observed_node_id,
            "issued_at": self.issued_at,
            "freshness_until": self.freshness_until,
            "sequence": self.sequence,
            "source_type": self.source_type,
            "source_context": dict(self.source_context),
            "advertised_capability_references": list(self.advertised_capability_references),
            "observed_endpoints": [dict(ep) for ep in self.observed_endpoints],
            "schema_version": self.schema_version,
            "signature": self.signature,
        }

    def __repr__(self) -> str:
        return (
            "DiscoveryObservation(sender=%s, observed=%s, seq=%d, "
            "source=%s, fresh_until=%s)"
            % (
                self.sender_node_id[:32] + ("…" if len(self.sender_node_id) > 32 else ""),
                self.observed_node_id[:32] + ("…" if len(self.observed_node_id) > 32 else ""),
                self.sequence,
                self.source_type,
                self.freshness_until,
            )
        )


def observation_from_mapping(data: object) -> DiscoveryObservation:
    """Build an observation from a mapping, failing closed on every
    contract violation (missing members, wrong types, malformed NodeIDs,
    impossible temporal, bad sequence, bad source)."""
    if not isinstance(data, Mapping):
        raise DiscoveryError("observation", "discovery observation must be a JSON object")
    required = (
        "sender_node_id",
        "observed_node_id",
        "issued_at",
        "freshness_until",
        "sequence",
        "source_type",
        "source_context",
        "advertised_capability_references",
        "observed_endpoints",
        "schema_version",
        "signature",
    )
    for member in required:
        if member not in data:
            raise DiscoveryError("missing", "required member %r is absent" % member)
    for field_name in ("advertised_capability_references", "observed_endpoints"):
        if not isinstance(data[field_name], list):
            raise DiscoveryError(field_name, "%s must be an array" % field_name)
    if not isinstance(data["source_context"], Mapping):
        raise DiscoveryError("source-context", "source_context must be an object")
    observation_id = data.get("observation_id", "")
    if observation_id is None:
        observation_id = ""
    if not isinstance(observation_id, str):
        raise DiscoveryError("observation-id", "observation_id must be a string when present")
    return DiscoveryObservation(
        sender_node_id=data["sender_node_id"],
        observed_node_id=data["observed_node_id"],
        issued_at=data["issued_at"],
        freshness_until=data["freshness_until"],
        sequence=data["sequence"],
        source_type=data["source_type"],
        source_context=dict(data["source_context"]),
        advertised_capability_references=tuple(data["advertised_capability_references"]),
        observed_endpoints=tuple(data["observed_endpoints"]),
        schema_version=data["schema_version"],
        signature=data["signature"],
        observation_id=observation_id,
    )
