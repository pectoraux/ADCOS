"""Discovery service — the local-first announce/receive flow (WORK-006).

``DiscoveryService`` composes a credential-bearing identity (WORK-004),
a discovery store (convergence), and a transport (loopback UDP or
in-memory bus) to implement the local announce/receive cycle:

    local peer discovery
            ↓
    optional bootstrap assistance (additive, non-authoritative)
            ↓
    no Internet required for local convergence

The service produces and verifies signed discovery observations through
the WORK-004 provider seam. It does NOT decide trust, routing, reach
truth, resource availability, or topology authority — those are later
layers (WORK-007+). A discovered peer is an authenticated observation,
nothing more.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Iterable, List, Optional, Tuple

from identity.credentials import CredentialReference
from identity.node_id import NodeID
from identity.provider import SignatureProvider
from identity.store import CredentialStore

from .bootstrap import BootstrapSource, poll_bootstrap
from .convergence import DiscoveryStore, MergeResult
from .model import DiscoveryError, DiscoveryObservation, SourceType
from .serialization import observation_from_bytes, observation_to_bytes
from .signing import sign_observation, verify_observation
from .transport import Address, DiscoveryTransport


class DiscoveryServiceError(ValueError):
    """Raised when a discovery service operation fails (fail closed)."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


class DiscoveryService:
    """Composes identity + store + transport for the local announce/
    receive cycle. Local-first; bootstrap is additive."""

    def __init__(
        self,
        *,
        sender_node_id: str,
        store: CredentialStore,
        provider: SignatureProvider,
        credential: CredentialReference,
        transport: DiscoveryTransport,
        local_store: DiscoveryStore,
        bootstrap: Optional[BootstrapSource] = None,
    ) -> None:
        self._sender_node_id = sender_node_id
        self._store = store
        self._provider = provider
        self._credential = credential
        self._transport = transport
        self._local_store = local_store
        self._bootstrap = bootstrap

    def build_observation(
        self,
        *,
        observed_node_id: str,
        issued_at: str,
        freshness_until: str,
        sequence: int,
        observed_endpoints: Iterable[dict],
        advertised_capability_references: Iterable[str] = (),
        source_type: str = SourceType.LOCAL,
        source_context: Optional[dict] = None,
    ) -> DiscoveryObservation:
        """Build (but not yet sign) a discovery observation."""
        return DiscoveryObservation(
            sender_node_id=self._sender_node_id,
            observed_node_id=observed_node_id,
            issued_at=issued_at,
            freshness_until=freshness_until,
            sequence=sequence,
            source_type=source_type,
            source_context=dict(source_context) if source_context else {},
            advertised_capability_references=tuple(advertised_capability_references),
            observed_endpoints=tuple(observed_endpoints),
        )

    def sign(self, observation: DiscoveryObservation) -> DiscoveryObservation:
        """Sign an observation through the WORK-004 provider seam."""
        return sign_observation(
            observation, store=self._store, provider=self._provider, credential=self._credential
        )

    def announce(
        self,
        observation: DiscoveryObservation,
        *,
        to: Address,
    ) -> None:
        """Sign (if unsigned) and send an observation to a peer address
        over the configured transport."""
        if not observation.signature:
            observation = self.sign(observation)
        blob = observation_to_bytes(observation)
        self._transport.send(blob, to=to)

    def receive(
        self,
        *,
        now: datetime,
        clock_skew: timedelta = timedelta(seconds=0),
        timeout_ms: int = 0,
    ) -> List[MergeResult]:
        """Receive pending observations from the transport and merge them
        into the local store with verification. Returns the merge results
        (one per received observation).

        Each observation is verified with the SENDER's credential (resolved
        from the store by the observation's ``sender_node_id``), not the
        receiver's own credential — the receiver is NOT the sender. If the
        sender's credential cannot be resolved, verification fails closed
        (the receiver has no provenance basis to accept it)."""
        results: List[MergeResult] = []
        while True:
            incoming = self._transport.recv(timeout_ms=timeout_ms)
            if incoming is None:
                break
            data, _addr = incoming
            try:
                observation = observation_from_bytes(data)
            except Exception as error:
                # Malformed envelope fails safely — no crash, no merge.
                results.append(MergeResult(
                    False, "malformed-envelope",
                    "observation bytes failed to parse: %s" % error,
                ))
                continue
            sender_credential = self._resolve_credential(observation.sender_node_id)
            if sender_credential is None:
                results.append(MergeResult(
                    False, "verification-failed",
                    "sender credential not resolvable for %s" % observation.sender_node_id,
                ))
                continue
            result = self._local_store.merge_with_verification(
                observation,
                store=self._store,
                provider=self._provider,
                credential=sender_credential,
                now=now,
                clock_skew=clock_skew,
            )
            results.append(result)
        return results

    def poll_bootstrap(self, *, now: datetime, clock_skew: timedelta = timedelta(seconds=0)) -> List[MergeResult]:
        """Poll the bootstrap source and merge its observations. Returns
        the merge results. Bootstrap failure is non-fatal — local
        discovery continues. Each bootstrap observation is verified
        with the SENDER's credential (resolved by sender_node_id)."""
        if self._bootstrap is None:
            return []
        candidates = poll_bootstrap(self._bootstrap)
        results: List[MergeResult] = []
        for observation in candidates:
            sender_credential = self._resolve_credential(observation.sender_node_id)
            if sender_credential is None:
                results.append(MergeResult(
                    False, "verification-failed",
                    "bootstrap sender credential not resolvable for %s"
                    % observation.sender_node_id,
                ))
                continue
            result = self._local_store.merge_with_verification(
                observation,
                store=self._store,
                provider=self._provider,
                credential=sender_credential,
                now=now,
                clock_skew=clock_skew,
            )
            results.append(result)
        return results

    def _resolve_credential(self, sender_node_id: str) -> Optional[CredentialReference]:
        """Resolve an ACTIVE credential for the given sender NodeID from the
        store. Returns None if no active credential is known for that node —
        verification then fails closed (the receiver has no provenance basis
        to accept the observation). This is NOT trust policy: it is a
        credential lookup for signature verification only."""
        from identity.lifecycle import LifecycleState
        for record in self._store.list_records():
            if (record.node_id.text == sender_node_id
                    and record.status is LifecycleState.ACTIVE):
                return record.reference
        return None

    @property
    def local_store(self) -> DiscoveryStore:
        return self._local_store

    @property
    def transport(self) -> DiscoveryTransport:
        return self._transport
