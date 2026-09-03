"""WORK-049 platform-adapter boundary (the frozen architecture rule).

    platform-specific mechanism
            ↓
        platform adapter
            ↓
    platform-neutral client core

The platform-neutral client core (model/state/capability/events/
gateway/projection/privacy/provider/buyer/runtime modules) depends
ONLY on the :class:`PlatformAdapter` contract below — never on an
Android SDK, an iOS SDK, a router vendor API, or any OS-specific
networking implementation.  Those dependencies belong INSIDE
concrete adapters, which are supplied per platform and are
PHYSICAL-class evidence when real (the deterministic sandbox
adapter in :mod:`client.sandbox` is SOFTWARE-class evidence only).

The conceptual surface (frozen in docs/WORK-049-handoff.md; the
exact method surface follows this repository's injected-seam
convention — every concrete adapter IS-A PlatformAdapter and is
type-checked at injection):

    capabilities()        — explicit capability report (ACR-012
                            vocabulary; the ONLY capability source)
    provider_support()    — provider-mode capability value
    buyer_support()       — buyer-mode capability value
    local_permissions()   — the platform permission grants
    secure_storage_*()    — the platform secure-storage boundary
                            (secrets NEVER transit plain storage
                            or logs)
    network_attach()      — local platform attach (a LOCAL action;
                            never a canonical activation)
    network_detach()      — local platform detach (the LOCAL
                            fail-safe leg of emergency stop)
    notification()        — platform notification emission
    lifecycle()           — platform lifecycle phase reports

Every adapter result is a bounded :class:`AdapterResult` (no
payload bytes, no credentials, no sensitive values — the privacy
model applies to the adapter surface exactly as to events).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple

from .capability import AdapterCapabilitySnapshot
from .errors import ClientError, ClientReasonCode


@dataclass(frozen=True)
class AdapterResult:
    """One bounded platform-adapter operation result.

    ``ok`` is the operation outcome; ``action`` names the adapter
    operation; ``detail`` is a bounded, non-sensitive description.
    Results never carry payload bytes, credentials, or locations.
    """

    ok: bool
    action: str
    detail: str

    def __post_init__(self) -> None:
        if not isinstance(self.ok, bool):
            raise ClientError(
                ClientReasonCode.INVALID_INPUT,
                "adapter result ok must be a boolean",
            )
        for label, value in (("action", self.action), ("detail", self.detail)):
            if not isinstance(value, str) or not value:
                raise ClientError(
                    ClientReasonCode.INVALID_INPUT,
                    "adapter result %s must be a non-empty string" % label,
                )

    def to_dict(self) -> Dict[str, str]:
        return {"ok": "true" if self.ok else "false", "action": self.action, "detail": self.detail}


#: The frozen platform lifecycle phases the adapter may report.
LIFECYCLE_PHASES: Tuple[str, ...] = (
    "boot",
    "foreground",
    "background",
    "shutdown",
)

#: The frozen local permission vocabulary (platform grant labels).
LOCAL_PERMISSIONS: Tuple[str, ...] = (
    "notification",
    "background-network",
    "secure-storage",
    "location-coarse",
)


class PlatformAdapter:
    """The platform-adapter contract (the isolation boundary).

    A concrete adapter encapsulates EVERY platform-specific
    mechanism.  The neutral client core never imports a concrete
    adapter module — adapters are INJECTED (the sandbox adapter in
    ``client/sandbox.py`` exists for deterministic SOFTWARE
    verification; real platform adapters are separately governed
    PHYSICAL evidence).
    """

    def capabilities(self) -> AdapterCapabilitySnapshot:
        """The explicit capability report (the ONLY capability source).

        No implicit platform assumption may exist anywhere: the
        report is DATA, and UNKNOWN/UNSUPPORTED fail closed."""
        raise NotImplementedError

    def provider_support(self) -> str:
        """Provider-mode capability value (ACR-012 vocabulary)."""
        raise NotImplementedError

    def buyer_support(self) -> str:
        """Buyer-mode capability value (ACR-012 vocabulary)."""
        raise NotImplementedError

    def local_permissions(self) -> Tuple[str, ...]:
        """The platform permission grants (frozen labels)."""
        raise NotImplementedError

    def secure_storage_put(self, key: str, value: str) -> AdapterResult:
        """Store one secret through the platform secure-storage
        boundary (values never transit events/logs/plain state)."""
        raise NotImplementedError

    def secure_storage_get(self, key: str) -> str:
        """Read one secret from the platform secure-storage boundary.

        Raises :class:`ClientError` (STALE_STATE/UNKNOWN
        resolution) when the secret is absent — never a fabricated
        value."""
        raise NotImplementedError

    def secure_storage_delete(self, key: str) -> AdapterResult:
        """Remove one secret from the platform secure-storage boundary."""
        raise NotImplementedError

    def network_attach(self, path_ref: str) -> AdapterResult:
        """Attach the local platform to a referenced connectivity
        path (a LOCAL action requested by the client; the
        canonical activation authority stays W041 — this never
        activates a NetworkPath)."""
        raise NotImplementedError

    def network_detach(self, path_ref: str) -> AdapterResult:
        """Detach the local platform from a referenced path (the
        LOCAL fail-safe leg of the provider emergency stop)."""
        raise NotImplementedError

    def notification(self, event_kind: str) -> AdapterResult:
        """Emit one platform notification for a client event kind."""
        raise NotImplementedError

    def lifecycle(self, phase: str) -> AdapterResult:
        """Report one platform lifecycle phase transition."""
        raise NotImplementedError


def require_adapter(adapter: object) -> PlatformAdapter:
    """Type-check an injected adapter (the injection seam)."""
    if not isinstance(adapter, PlatformAdapter):
        raise ClientError(
            ClientReasonCode.INVALID_INPUT,
            "the client requires a PlatformAdapter (the platform-specific "
            "mechanism boundary); got %s" % type(adapter).__name__,
        )
    return adapter
