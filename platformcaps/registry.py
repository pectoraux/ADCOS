"""WORK-050 platform capability registry (W050.1).

The REGISTRY layer of the versioned platform capability
declarations: :class:`PlatformCapabilityRegistry` holds a set of
immutable :class:`~platformcaps.model.PlatformProfile` rows keyed
by their opaque ``platform_id`` and answers EXACTLY the W050.1
question:

    Do we now have a strict, immutable, addressable, versioned
    platform capability registry that does not create a second
    authority?

Registry invariants (frozen, all enforced at construction):

1. IMMUTABLE — the registry OBJECT is frozen at construction:
   the row mapping is a read-only proxy; profiles are frozen
   dataclasses; and the registry itself rejects every
   post-construction state mutation — attribute assignment
   (including private slots and ``__class__`` reassignment),
   attribute deletion, and re-initialization all raise, and
   ``__init__`` writes state through the base-object setter
   ONLY (so the public ``__setattr__``/``__delattr__`` raise
   unconditionally, the same guarantee class as the frozen
   dataclasses the rows use; the deliberate
   ``object.__setattr__`` escape hatch is outside the
   contract).  A new registry version is a new registry
   instance (the versioned auditable history of registry
   versions belongs to the later history stage, not here).
2. VERSIONED — every registry carries a ``registry_version``
   from the frozen ``major.minor`` grammar; rows are meaningful
   only within their registry version.
3. CONTENT-ADDRESSED — the whole registry has a ``content_digest``
   (SHA-256 over the canonical JSON of its canonical form) and
   every row has its own profile ``content_digest``; the digest
   IS the address of the exact declaration content.
4. CANONICALIZED — the serialized form is the canonical form
   (profiles sorted by platform_id; all token sets in their
   sorted, deduplicated canonical order), produced with the
   shared canonical JSON machinery (protocol.canonicalization).
5. DETERMINISTIC — identical declaration content yields
   byte-identical serialization and digests, regardless of input
   order, repeat count, or hash-seed configuration; iteration
   order is always the canonical sorted order.
6. CONFLICTING-DUPLICATE REJECTION — two rows with the same
   ``platform_id`` but different content fail closed
   (DUPLICATE_CONFLICT; never first-wins, never silent merge).
7. IDENTICAL-DUPLICATE IDEMPOTENCE — two rows with the same
   ``platform_id`` AND identical content collapse to one row
   (idempotent ingestion; the digest is unchanged).

The fail-closed default (frozen): a platform id that does not
resolve raises UNKNOWN_PLATFORM — an unregistered platform is
NEVER implicitly ``supported`` (no platform label, OS name,
socket capability, or tethering-API presence is ever converted
into a capability state; the only capability source is an
explicit registry row).

Authority boundary (frozen, W050): this registry is a
descriptive/capability DECLARATION authority only — advisory
capability input that WORK-048/W049 may consume.  It is not
routing, NetworkPath, session, identity, transport, commercial,
usage, payment, marketplace, or enforcement authority; it does
not implement W048/W049 enforcement, does not evaluate
compatibility (the later evaluation stage), and does not journal
history (the later history stage).
"""

from __future__ import annotations

import hashlib
import re
from types import MappingProxyType
from typing import Any, Dict, Iterable, Mapping, Tuple

from protocol.canonicalization import canonical_json_bytes

from .errors import PlatformCapabilityError, PlatformCapabilityReasonCode
from .model import SCHEMA_VERSION, PlatformProfile

_REGISTRY_VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+$")


def _require_registry_version(value: object) -> str:
    if (
        not isinstance(value, str)
        or not _REGISTRY_VERSION_PATTERN.match(value)
    ):
        raise PlatformCapabilityError(
            PlatformCapabilityReasonCode.VERSION_INVALID,
            "registry version %r must match the frozen grammar "
            "'major.minor' (two dot-separated non-negative integers; "
            "never coerced)" % (value,),
        )
    return value


def _require_profile_sequence(value: object) -> Tuple[PlatformProfile, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, (tuple, list)):
        raise PlatformCapabilityError(
            PlatformCapabilityReasonCode.INVALID_INPUT,
            "registry profiles must be a sequence of PlatformProfile "
            "instances",
        )
    profiles = tuple(value)
    for profile in profiles:
        if not isinstance(profile, PlatformProfile):
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.INVALID_INPUT,
                "registry profiles entries must be PlatformProfile "
                "instances (got %s)" % type(profile).__name__,
            )
    return profiles


class PlatformCapabilityRegistry:
    """The immutable, versioned, content-addressed platform
    capability registry (W050.1).

    Construct from an explicit version and an iterable of
    :class:`PlatformProfile` rows.  Construction performs the
    full fail-closed duplicate discipline (identical duplicates
    collapse; conflicting duplicates raise) and then freezes the
    REGISTRY OBJECT ITSELF — after construction there is no
    mutation surface: ``__setattr__`` and ``__delattr__`` reject
    every attribute mutation unconditionally (private slots,
    new attributes, ``__class__`` reassignment), and
    re-invoking ``__init__`` on a constructed instance raises
    as well.  Construction is the only writer (it uses the
    base-object setter, never the public assignment surface).
    """

    __slots__ = ("_frozen", "_profiles_by_id", "_registry_version")

    def __init__(
        self,
        registry_version: str,
        profiles: Iterable[PlatformProfile] = (),
    ) -> None:
        if getattr(self, "_frozen", False):
            # re-initialization of a constructed registry is a
            # mutation of frozen state — rejected like every
            # other post-construction write
            raise AttributeError(
                "PlatformCapabilityRegistry is frozen after "
                "construction: re-initialization is rejected "
                "(a new registry version is a new instance)"
            )
        version = _require_registry_version(registry_version)
        rows = _require_profile_sequence(profiles)
        by_id: Dict[str, PlatformProfile] = {}
        for profile in rows:
            known = by_id.get(profile.identity.platform_id)
            if known is not None:
                if known.to_dict() != profile.to_dict():
                    raise PlatformCapabilityError(
                        PlatformCapabilityReasonCode.DUPLICATE_CONFLICT,
                        "conflicting registry rows for platform %r "
                        "(same platform_id, different declaration "
                        "content; fail closed — never first-wins, never "
                        "a silent merge)" % (profile.identity.platform_id,),
                    )
                # identical duplicate: idempotent (collapsed; the
                # canonical content and digest are unchanged)
                continue
            by_id[profile.identity.platform_id] = profile
        # The freeze itself: construction is the ONLY writer, and
        # it writes through the base-object setter exclusively —
        # the public __setattr__/__delattr__ below raise
        # unconditionally, so from here on no ordinary attribute
        # operation can touch this state.  The frozen flag is
        # written LAST (it is what makes __init__ re-invocation
        # fail closed as well).
        object.__setattr__(self, "_registry_version", version)
        object.__setattr__(self, "_profiles_by_id", MappingProxyType(by_id))
        object.__setattr__(self, "_frozen", True)

    def __setattr__(self, name: str, value: object) -> None:
        # Unconditional: there is no post-construction mutation
        # surface on the registry object itself (the frozen
        # invariant — enforced, not merely documented).
        raise AttributeError(
            "PlatformCapabilityRegistry is frozen after "
            "construction: attribute assignment %r is rejected "
            "(immutable registry; a new registry version is a "
            "new instance)" % (name,)
        )

    def __delattr__(self, name: str) -> None:
        raise AttributeError(
            "PlatformCapabilityRegistry is frozen after "
            "construction: attribute deletion %r is rejected "
            "(immutable registry)" % (name,)
        )

    @property
    def registry_version(self) -> str:
        """The registry's frozen version (``major.minor``)."""
        return self._registry_version

    def platform_ids(self) -> Tuple[str, ...]:
        """All registered platform ids, in canonical sorted order."""
        return tuple(sorted(self._profiles_by_id))

    def profiles(self) -> Tuple[PlatformProfile, ...]:
        """All rows, in canonical platform_id order (the
        deterministic iteration order)."""
        return tuple(
            self._profiles_by_id[platform_id]
            for platform_id in sorted(self._profiles_by_id)
        )

    def profile(self, platform_id: str) -> PlatformProfile:
        """The row for one platform id.

        Fail closed: an id that does not resolve raises
        UNKNOWN_PLATFORM (an unregistered platform is never
        implicitly supported)."""
        if not isinstance(platform_id, str) or not platform_id:
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.INVALID_INPUT,
                "platform_id must be a non-empty string",
            )
        row = self._profiles_by_id.get(platform_id)
        if row is None:
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.UNKNOWN_PLATFORM,
                "platform %r is not registered in registry version %s "
                "(unregistered platforms read UNKNOWN and fail closed — "
                "never implicitly supported)"
                % (platform_id, self._registry_version),
            )
        return row

    def has_platform(self, platform_id: str) -> bool:
        """Whether one platform id resolves (membership only; it
        never implies any capability state)."""
        if not isinstance(platform_id, str) or not platform_id:
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.INVALID_INPUT,
                "platform_id must be a non-empty string",
            )
        return platform_id in self._profiles_by_id

    def to_dict(self) -> Dict[str, Any]:
        """The canonical deterministic serialization: schema
        version, registry version, and rows in platform_id order
        (each row in its canonical form)."""
        return {
            "schema_version": SCHEMA_VERSION,
            "registry_version": self._registry_version,
            "profiles": [profile.to_dict() for profile in self.profiles()],
        }

    @classmethod
    def from_dict(cls, data: object) -> "PlatformCapabilityRegistry":
        """Reconstruct a registry from its canonical serialized
        form (fail closed: wrong shape, wrong schema version, or
        invalid rows are all rejected — never best-effort)."""
        if not isinstance(data, Mapping):
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.INVALID_INPUT,
                "registry must be a mapping",
            )
        schema_version = data.get("schema_version")
        if schema_version != SCHEMA_VERSION:
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.SCHEMA_INVALID,
                "registry schema_version %r is not %r (this "
                "implementation reads exactly one schema; fail closed, "
                "never best-effort)" % (schema_version, SCHEMA_VERSION),
            )
        profiles_value = data.get("profiles", ())
        if isinstance(profiles_value, (str, bytes)) or not isinstance(
            profiles_value, (tuple, list)
        ):
            raise PlatformCapabilityError(
                PlatformCapabilityReasonCode.INVALID_INPUT,
                "registry profiles must be a sequence",
            )
        profiles = tuple(
            PlatformProfile.from_dict(item) for item in profiles_value
        )
        return cls(
            registry_version=data.get("registry_version"),
            profiles=profiles,
        )

    def content_digest(self) -> str:
        """The content address of this exact registry content:
        SHA-256 over the canonical JSON bytes of ``to_dict``
        (version + rows in canonical order)."""
        return "sha256:" + hashlib.sha256(
            canonical_json_bytes(self.to_dict())
        ).hexdigest()

    def __len__(self) -> int:
        return len(self._profiles_by_id)

    def __contains__(self, platform_id: object) -> bool:
        if not isinstance(platform_id, str):
            return False
        return platform_id in self._profiles_by_id

    def __repr__(self) -> str:
        return (
            "PlatformCapabilityRegistry(version=%r, platforms=%d, "
            "digest=%s)"
            % (
                self._registry_version,
                len(self._profiles_by_id),
                self.content_digest()[:23],
            )
        )


__all__ = ["PlatformCapabilityRegistry"]
