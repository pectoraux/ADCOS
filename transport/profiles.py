"""ADCOS secure transport profiles (WORK-017): the profile catalog.

Secure transport profiles are DATA, never core domain types (LOCK-001
in the transport direction; architecture section 25 rule 9: "No fixed
transport. QUIC/UDP/IPsec/etc. are adapters beneath stable session
semantics").  The catalog lives in this module — not under ``spec/`` —
because the specification tree is byte-frozen against ``origin/main``
by the established frozen-document gate; the shape deliberately
mirrors the WORK-002 registries (``id_grammar``, ``entries``,
``unknown_id_policy``) so a future migration into a machine-readable
registry file is additive.

Catalog families (WORK-017 objective: "transport mappings for secure
control/user paths, starting with TLS 1.3/QUIC and standard IP tunnels
where required"; architecture section 3 current anchors: IETF QUIC,
TLS, IPsec/WireGuard-class secure transports):

- ``transport.tls.v1-3``       — TLS 1.3 (IETF RFC 8446)
- ``transport.quic.v1``        — QUIC v1 with integrated TLS 1.3
                                 (IETF RFC 9000/9001)
- ``transport.tunnel.ipsec.v1``  — standard IP tunnel, IPsec/ESP class
- ``transport.tunnel.wireguard.v1`` — standard IP tunnel,
  WireGuard-class
- ``transport.generic.experimental`` — triage profile for experimental
  transport mappings (the section 10.5 generic-adapter pattern applied
  to transport)

Each entry declares STRUCTURAL PROPERTIES only (integrity,
confidentiality, forward secrecy, replay protection, multipath
capability, security rank).  No core state machine branches on a
profile identifier: negotiation is property/policy driven
(:func:`negotiate_transport_profiles`) and the identifiers ride as
explicit metadata (LOCK-015 — cryptographic/transport agility).

Profile entries are NEGOTIATION DATA describing standard
technologies, not implementations of them: selecting
``transport.tls.v1-3`` binds the transcript/key-schedule semantics to
that profile's declared properties — it does not make the serving
engine a TLS 1.3 implementation (the built-in engine is the
deterministic transport-contract REFERENCE MODEL; see
:mod:`transport.recordprotection` for the profile-cryptography
boundary and :mod:`transport.contract` for the engine's scope).

Unknown well-formed identifiers are UNKNOWN (preserved verbatim, never
coerced, fail closed on use); malformed identifiers are INVALID — the
WORK-002 unknown-ID semantics, unchanged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, FrozenSet, Mapping, Optional, Sequence, Tuple

from .errors import TransportError, TransportReasonCode

#: Registry-mirroring grammar for transport profile identifiers.
PROFILE_ID_GRAMMAR = r"^transport(\.[a-z0-9][a-z0-9-]*){2,}$"

_PROFILE_ID_RE = re.compile(PROFILE_ID_GRAMMAR)

#: Frozen public members of a profile's properties view (the closed
#: projection carried in offers' policy checks, security state, and wire
#: views; changing the set is a deliberate vocabulary change).
PROFILE_PROPERTIES: Tuple[str, ...] = (
    "profile_id",
    "family",
    "security_rank",
    "integrity",
    "confidentiality",
    "forward_secrecy",
    "replay_protection",
    "multipath_capable",
)

#: Frozen replay-protection modes.
REPLAY_MODES: Tuple[str, ...] = (
    "record-window",   # per-record sequence window (TLS 1.3 / QUIC style)
    "packet-window",   # per-packet anti-replay window (IPsec/ESP style)
)


@dataclass(frozen=True)
class TransportProfile:
    """A registered (or explicitly supplied) secure transport profile."""

    profile_id: str
    family: str
    security_rank: int
    integrity: bool
    confidentiality: bool
    forward_secrecy: bool
    replay_protection: str
    multipath_capable: bool
    status: str
    description: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.profile_id, str) or _PROFILE_ID_RE.fullmatch(self.profile_id) is None:
            raise TransportError(
                TransportReasonCode.PROFILE_INVALID,
                "profile id %r must match the transport profile grammar" % (self.profile_id,),
            )
        if not isinstance(self.family, str) or not self.family:
            raise TransportError(
                TransportReasonCode.PROFILE_INVALID,
                "profile %r must declare a non-empty family" % (self.profile_id,),
            )
        if isinstance(self.security_rank, bool) or not isinstance(self.security_rank, int):
            raise TransportError(
                TransportReasonCode.PROFILE_INVALID,
                "profile %r security_rank must be an integer" % (self.profile_id,),
            )
        if self.security_rank < 0:
            raise TransportError(
                TransportReasonCode.PROFILE_INVALID,
                "profile %r security_rank must be non-negative" % (self.profile_id,),
            )
        if self.replay_protection not in REPLAY_MODES:
            raise TransportError(
                TransportReasonCode.PROFILE_INVALID,
                "profile %r replay_protection must be one of %s"
                % (self.profile_id, list(REPLAY_MODES)),
            )

    def satisfies(self, policy: "TransportSecurityPolicy") -> bool:
        """Does this profile satisfy the policy floor? (property data only)"""
        if policy.require_integrity and not self.integrity:
            return False
        if policy.require_confidentiality and not self.confidentiality:
            return False
        if policy.require_forward_secrecy and not self.forward_secrecy:
            return False
        if policy.require_multipath and not self.multipath_capable:
            return False
        if self.security_rank < policy.minimum_rank:
            return False
        if policy.allowed_families is not None and self.family not in policy.allowed_families:
            return False
        return True

    def properties_view(self) -> Dict[str, object]:
        """The public structural-property projection (pure data)."""
        return {
            "profile_id": self.profile_id,
            "family": self.family,
            "security_rank": self.security_rank,
            "integrity": self.integrity,
            "confidentiality": self.confidentiality,
            "forward_secrecy": self.forward_secrecy,
            "replay_protection": self.replay_protection,
            "multipath_capable": self.multipath_capable,
        }

    def __repr__(self) -> str:  # data-only by construction
        return (
            "TransportProfile(profile_id=%r, family=%r, rank=%d, status=%r)"
            % (self.profile_id, self.family, self.security_rank, self.status)
        )


@dataclass(frozen=True)
class TransportSecurityPolicy:
    """The minimum security floor keys may be used under (session/identity
    policy binding — WORK-017 acceptance criterion 2).

    This is a small frozen DATA contract consumed by profile
    negotiation and the key schedule transcript; it is deliberately
    NOT the WORK-010 policy engine (WORK-017's declared dependencies
    are WORK-003/WORK-004/WORK-012 only).  The default floor requires
    integrity and replay protection — the security-critical minimum of
    architecture section 19 — and leaves confidentiality, forward
    secrecy, multipath, and family restriction to the caller.
    """

    require_integrity: bool = True
    require_confidentiality: bool = False
    require_forward_secrecy: bool = False
    require_multipath: bool = False
    minimum_rank: int = 0
    allowed_families: Optional[FrozenSet[str]] = None
    policy_id: str = "transport.policy.default"

    def __post_init__(self) -> None:
        if isinstance(self.minimum_rank, bool) or not isinstance(self.minimum_rank, int):
            raise TransportError(
                TransportReasonCode.POLICY_INVALID,
                "minimum_rank must be an integer",
            )
        if self.minimum_rank < 0:
            raise TransportError(
                TransportReasonCode.POLICY_INVALID,
                "minimum_rank must be non-negative",
            )
        if not self.require_integrity:
            raise TransportError(
                TransportReasonCode.POLICY_INVALID,
                "integrity cannot be waived: architecture section 19 requires "
                "authenticated, replay-protected channels for ADCOS transports",
            )
        if not isinstance(self.policy_id, str) or not self.policy_id:
            raise TransportError(
                TransportReasonCode.POLICY_INVALID,
                "policy_id must be a non-empty string",
            )
        if self.allowed_families is not None and not isinstance(self.allowed_families, frozenset):
            raise TransportError(
                TransportReasonCode.POLICY_INVALID,
                "allowed_families must be a frozenset or None",
            )

    def transcript_view(self) -> Dict[str, object]:
        """The canonical transcript projection of the policy floor.

        Secret-rejecting by construction: only booleans, integers, and
        sorted family identifiers — there is no field able to carry
        secret material (LOCK-023).
        """
        families: Optional[Tuple[str, ...]] = None
        if self.allowed_families is not None:
            families = tuple(sorted(self.allowed_families))
        return {
            "policy_id": self.policy_id,
            "require_integrity": self.require_integrity,
            "require_confidentiality": self.require_confidentiality,
            "require_forward_secrecy": self.require_forward_secrecy,
            "require_multipath": self.require_multipath,
            "minimum_rank": self.minimum_rank,
            "allowed_families": families,
        }


#: The frozen initial catalog (WORK-017 objective: TLS 1.3 / QUIC /
#: standard IP tunnels; architecture section 3 anchors).  Adding an
#: entry is additive data; changing a declared property of an existing
#: entry is a deliberate vocabulary change.
_INITIAL_CATALOG: Tuple[TransportProfile, ...] = (
    TransportProfile(
        profile_id="transport.tls.v1-3",
        family="tls",
        security_rank=90,
        integrity=True,
        confidentiality=True,
        forward_secrecy=True,
        replay_protection="record-window",
        multipath_capable=False,
        status="active",
        description=(
            "TLS 1.3 (IETF RFC 8446) secure transport profile for "
            "control and user paths: record-layer integrity and "
            "confidentiality, ephemeral-DH forward secrecy by default, "
            "per-record sequence replay windows, downgrade-protected "
            "negotiation."
        ),
    ),
    TransportProfile(
        profile_id="transport.quic.v1",
        family="quic",
        security_rank=95,
        integrity=True,
        confidentiality=True,
        forward_secrecy=True,
        replay_protection="record-window",
        multipath_capable=True,
        status="active",
        description=(
            "QUIC v1 (IETF RFC 9000) with integrated TLS 1.3 key "
            "schedule (RFC 9001): stream and datagram transport with "
            "record-window replay protection, forward secrecy, and "
            "multipath-capable session mobility (architecture section "
            "13 lists a multipath-capable QUIC implementation as a "
            "standards-compatible mechanism behind the Session "
            "Manager)."
        ),
    ),
    TransportProfile(
        profile_id="transport.tunnel.ipsec.v1",
        family="tunnel.ipsec",
        security_rank=85,
        integrity=True,
        confidentiality=True,
        forward_secrecy=True,
        replay_protection="packet-window",
        multipath_capable=True,
        status="active",
        description=(
            "Standard IP tunnel, IPsec/ESP class (IETF RFC 4301 "
            "family): tunnel-mode packet protection with per-packet "
            "anti-replay windows for cross-access user paths "
            "(architecture section 5.5 standard tunneling primitives)."
        ),
    ),
    TransportProfile(
        profile_id="transport.tunnel.wireguard.v1",
        family="tunnel.wireguard",
        security_rank=80,
        integrity=True,
        confidentiality=True,
        forward_secrecy=True,
        replay_protection="packet-window",
        multipath_capable=False,
        status="active",
        description=(
            "Standard IP tunnel, WireGuard-class: UDP-encapsulated "
            "tunnel-mode packet protection with per-packet anti-replay "
            "windows (architecture section 3 anchor 'IPsec/WireGuard-"
            "class secure transports')."
        ),
    ),
    TransportProfile(
        profile_id="transport.generic.experimental",
        family="generic",
        security_rank=10,
        integrity=True,
        confidentiality=False,
        forward_secrecy=False,
        replay_protection="record-window",
        multipath_capable=False,
        status="active",
        description=(
            "Generic profile for experimental and not-yet-registered "
            "transport mappings (the architecture section 10.5 "
            "generic-adapter pattern applied to transport): a mapping "
            "can be trialed through the full transport interface "
            "BEFORE a dedicated profile entry exists.  Weak by "
            "declaration — only a floor-less policy can select it."
        ),
    ),
)

_INITIAL_CATALOG_MAP: Dict[str, TransportProfile] = {
    profile.profile_id: profile for profile in _INITIAL_CATALOG
}


class TransportProfileSet:
    """The set of transport profiles available to a consumer.

    The default set is the frozen initial catalog; callers may supply
    explicit additional profiles (tests and future registered
    profiles).  Unknown identifiers remain UNKNOWN and fail closed for
    operations — exactly the WORK-002 registry semantics.
    """

    def __init__(self, profiles: Mapping[str, TransportProfile]) -> None:
        self._profiles: Dict[str, TransportProfile] = dict(profiles)

    @classmethod
    def load_default(cls) -> "TransportProfileSet":
        return cls(_INITIAL_CATALOG_MAP)

    def with_explicit_profile(self, profile: TransportProfile) -> "TransportProfileSet":
        """Return a new set additionally containing an explicitly supplied
        profile definition.  The identifier is metadata; nothing is
        coerced."""
        merged = dict(self._profiles)
        merged[profile.profile_id] = profile
        return TransportProfileSet(merged)

    def get(self, profile_id: str) -> TransportProfile:
        profile = self._profiles.get(profile_id)
        if profile is None:
            classification = self.classify(profile_id)
            raise TransportError(
                TransportReasonCode.PROFILE_UNKNOWN,
                "profile %r is %s; known profiles: %s"
                % (profile_id, classification, sorted(self._profiles)),
            )
        return profile

    def classify(self, profile_id: str) -> str:
        """known / unknown / invalid classification (never coerced)."""
        if not isinstance(profile_id, str):
            return "invalid"
        if profile_id in self._profiles:
            return "known"
        if _PROFILE_ID_RE.fullmatch(profile_id) is not None:
            return "unknown"
        return "invalid"

    def profile_ids(self) -> FrozenSet[str]:
        return frozenset(self._profiles)


@dataclass(frozen=True)
class NegotiationOutcome:
    """Deterministic result of transport profile negotiation."""

    selected: Optional[TransportProfile]
    reason: str
    offered: Tuple[str, ...]
    eligible: Tuple[str, ...]

    @property
    def ok(self) -> bool:
        return self.selected is not None


def negotiate_transport_profiles(
    local_profiles: Sequence[str],
    remote_profiles: Sequence[str],
    policy: TransportSecurityPolicy,
    *,
    profile_set: Optional[TransportProfileSet] = None,
) -> NegotiationOutcome:
    """Deterministically select the mutually supported, policy-satisfying
    profile with the HIGHEST security rank (ties broken by sorted
    identifier).

    Documented contract (downgrade resistance): the selection rule is
    maximal by rank, never "first offered" and never attacker-ordered;
    unknown/invalid identifiers are never matched (an unknown
    identifier offered by both sides is still unknown and cannot be
    negotiated into a known profile).  No eligible intersection
    yields ``reason='no-eligible-profile'``.
    """
    profiles = profile_set or TransportProfileSet.load_default()
    if not isinstance(local_profiles, (list, tuple)) or not isinstance(
        remote_profiles, (list, tuple)
    ):
        raise TransportError(
            TransportReasonCode.INVALID_INPUT,
            "offered profile sets must be sequences of identifiers",
        )

    def _classify_all(offered: Sequence[str], side: str) -> FrozenSet[str]:
        known: FrozenSet[str] = frozenset()
        for identifier in offered:
            if not isinstance(identifier, str):
                raise TransportError(
                    TransportReasonCode.INVALID_INPUT,
                    "%s offered profile identifiers must be strings" % side,
                )
            classification = profiles.classify(identifier)
            if classification == "invalid":
                raise TransportError(
                    TransportReasonCode.PROFILE_INVALID,
                    "%s offered malformed (invalid) profile id %r" % (side, identifier),
                )
            if classification == "known":
                known = known | {identifier}
        return known

    known_local = _classify_all(local_profiles, "local")
    known_remote = _classify_all(remote_profiles, "remote")
    mutual = known_local & known_remote
    eligible = tuple(
        sorted(
            identifier
            for identifier in mutual
            if profiles.get(identifier).satisfies(policy)
        )
    )
    if not eligible:
        return NegotiationOutcome(
            selected=None,
            reason="no-eligible-profile",
            offered=tuple(sorted(set(local_profiles))),
            eligible=(),
        )
    # Max rank, lexicographic tie-break — deterministic and independent
    # of the order in which either side (or an attacker) listed profiles.
    best = sorted(
        eligible,
        key=lambda identifier: (-profiles.get(identifier).security_rank, identifier),
    )[0]
    return NegotiationOutcome(
        selected=profiles.get(best),
        reason="selected",
        offered=tuple(sorted(set(local_profiles))),
        eligible=eligible,
    )


def classify_transport_profile_id(profile_id: str) -> str:
    """Classify a transport profile identifier against the default catalog."""
    return TransportProfileSet.load_default().classify(profile_id)


def registered_transport_profiles() -> Tuple[str, ...]:
    """Sorted profile ids of the frozen initial catalog (introspection/tests)."""
    return tuple(sorted(_INITIAL_CATALOG_MAP))


def default_profile_offers() -> Tuple[str, ...]:
    """Sorted ids of ACTIVE default-catalog profiles usable as a default offer."""
    return tuple(
        sorted(
            profile.profile_id
            for profile in _INITIAL_CATALOG
            if profile.status == "active"
        )
    )
