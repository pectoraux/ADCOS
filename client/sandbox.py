"""WORK-049 deterministic sandbox platform adapter (SOFTWARE only).

The sandbox adapter is the deterministic, pure-Python SOFTWARE
test double for the :class:`~client.adapters.PlatformAdapter`
contract (the W048 ``containment/sandbox.py`` precedent): it
simulates platform behavior with plain in-memory data, imports no
OS/SDK mechanism, makes no network/OS call, reads no wall clock,
and produces no randomness.  Every result it reports is
SOFTWARE-class evidence — real Android/desktop/router-class
adapter behavior is PHYSICAL-class, separately governed, and NOT
claimed here.

The client core never imports this module: the battery injects
it exactly like a real platform adapter would be injected.
"""

from __future__ import annotations

from typing import Dict, Tuple

from .adapters import (
    AdapterResult,
    LIFECYCLE_PHASES,
    PlatformAdapter,
)
from .capability import AdapterCapabilitySnapshot
from .errors import ClientError, ClientReasonCode


class SandboxPlatformAdapter(PlatformAdapter):
    """A deterministic in-memory platform adapter (SOFTWARE).

    ``provider_support`` / ``buyer_support`` / ``restrictions``
    configure the reported capability (ACR-012 vocabulary; the
    default is UNKNOWN for both modes — fail closed unless the
    platform is explicitly declared capable, mirroring the
    containment capability default).

    ``fail_attach`` / ``fail_detach`` / ``fail_storage`` are the
    battery's failure-injection seams (deterministic failure
    modes for the fail-closed proofs).
    """

    def __init__(
        self,
        *,
        platform_id: str,
        provider_support: str = "unknown",
        buyer_support: str = "unknown",
        restrictions: Tuple[str, ...] = (),
        mechanism: str = "sandbox-mechanism",
        permissions: Tuple[str, ...] = (),
        fail_attach: bool = False,
        fail_detach: bool = False,
        fail_storage: bool = False,
    ) -> None:
        self._snapshot = AdapterCapabilitySnapshot(
            platform_id=platform_id,
            provider_support=provider_support,
            buyer_support=buyer_support,
            restrictions=restrictions,
            mechanism=mechanism,
        )
        self._permissions: Tuple[str, ...] = tuple(
            sorted(set(permissions))
        )
        self._fail_attach = fail_attach
        self._fail_detach = fail_detach
        self._fail_storage = fail_storage
        self._storage: Dict[str, str] = {}
        self._attached: Tuple[str, ...] = ()
        self._detach_log: Tuple[str, ...] = ()
        self._notifications: Tuple[str, ...] = ()
        self._lifecycle: Tuple[str, ...] = ()

    # -- the capability surface ------------------------------------------

    def capabilities(self) -> AdapterCapabilitySnapshot:
        return self._snapshot

    def provider_support(self) -> str:
        return self._snapshot.provider_support

    def buyer_support(self) -> str:
        return self._snapshot.buyer_support

    def local_permissions(self) -> Tuple[str, ...]:
        return self._permissions

    # -- the secure-storage surface ---------------------------------------

    def secure_storage_put(self, key: str, value: str) -> AdapterResult:
        if self._fail_storage:
            return AdapterResult(
                False, "secure_storage_put", "sandbox storage failure injected"
            )
        if not isinstance(key, str) or not key or not isinstance(value, str):
            return AdapterResult(
                False, "secure_storage_put", "invalid key/value shape"
            )
        self._storage[key] = value
        return AdapterResult(
            True, "secure_storage_put", "secret stored through the sandbox boundary"
        )

    def secure_storage_get(self, key: str) -> str:
        if key not in self._storage:
            raise ClientError(
                ClientReasonCode.STALE_STATE,
                "secret %r is not present in the platform secure-storage "
                "boundary (never fabricated)" % key,
            )
        return self._storage[key]

    def secure_storage_delete(self, key: str) -> AdapterResult:
        if self._fail_storage:
            return AdapterResult(
                False, "secure_storage_delete", "sandbox storage failure injected"
            )
        self._storage.pop(key, None)
        return AdapterResult(
            True, "secure_storage_delete", "secret removed"
        )

    # -- the network attach/detach surface --------------------------------

    def network_attach(self, path_ref: str) -> AdapterResult:
        if self._fail_attach:
            return AdapterResult(
                False,
                "network_attach",
                "sandbox attach failure injected (failed platform handoff "
                "=> deny activation)",
            )
        if not isinstance(path_ref, str) or not path_ref:
            return AdapterResult(
                False, "network_attach", "path reference required"
            )
        if path_ref not in self._attached:
            self._attached = self._attached + (path_ref,)
        return AdapterResult(
            True, "network_attach", "local platform attached to the path"
        )

    def network_detach(self, path_ref: str) -> AdapterResult:
        if self._fail_detach:
            return AdapterResult(
                False,
                "network_detach",
                "sandbox detach failure injected (local fail-safe reported "
                "failed; canonical stop still requested)",
            )
        self._attached = tuple(
            ref for ref in self._attached if ref != path_ref
        )
        self._detach_log = self._detach_log + (path_ref,)
        return AdapterResult(
            True, "network_detach", "local platform detached from the path"
        )

    def notification(self, event_kind: str) -> AdapterResult:
        if not isinstance(event_kind, str) or not event_kind:
            return AdapterResult(
                False, "notification", "event kind required"
            )
        self._notifications = self._notifications + (event_kind,)
        return AdapterResult(
            True, "notification", "platform notification emitted"
        )

    def lifecycle(self, phase: str) -> AdapterResult:
        if phase not in LIFECYCLE_PHASES:
            return AdapterResult(
                False,
                "lifecycle",
                "phase %r is outside the frozen lifecycle vocabulary"
                % (phase,),
            )
        self._lifecycle = self._lifecycle + (phase,)
        return AdapterResult(
            True, "lifecycle", "platform lifecycle phase reported"
        )

    # -- deterministic sandbox inspection (battery-only reads) -------------

    def attached_paths(self) -> Tuple[str, ...]:
        return self._attached

    def detach_log(self) -> Tuple[str, ...]:
        """Every local fail-safe detach call (battery inspection)."""
        return self._detach_log

    def notifications(self) -> Tuple[str, ...]:
        return self._notifications

    def lifecycle_log(self) -> Tuple[str, ...]:
        return self._lifecycle

    def storage_keys(self) -> Tuple[str, ...]:
        """The KEYS only — values never leave the storage boundary."""
        return tuple(sorted(self._storage))
