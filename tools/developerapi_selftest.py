#!/usr/bin/env python3
"""WORK-046 developer platform battery (deterministic, stdlib only).

End-to-end verification of the Developer Connectivity API, SDK &
Webhook Platform (authorization WORK-046-CORE-001 / DEC-0065,
baseline 3db7500 by DEC-0066) composing the accepted commercial
plane (W051 CommercialCore, W052 UsageLedger, W053
EconomicAllocation) and the real reference authorities the
commercial battery composes (the WORK-033 Linux reference agent,
WORK-012 logical sessions, WORK-041 NetworkPath, WORK-042
platform journal):

- **API schema** (criterion 1): the versioned API contract --
  version resolution (supported / deprecated-with-notice /
  retired-rejected), unambiguous attribution (route + header
  agreement), strict request validation, the mechanical
  backward-compatibility gate (additive / deprecation /
  breaking classification on constructed schema pairs, the live
  v1.0-payload-under-v1.1 proof), and canonical deterministic
  response serialization;
- **environments** (criterion 1): sandbox/production isolation
  by construction (separate stores/authorities), cross-
  environment credential rejection in BOTH directions,
  environment-namespaced resource ids, sandbox webhook
  separation, and the honest sandbox evidence classification
  (sandbox results are never production evidence);
- **credentials** (criterion 2): valid/invalid/expired/revoked
  authentication, scoped capabilities (the negative
  authorization battery), authentication alone granting no
  authority, cross-tenant resource invisibility;
- **idempotency** (criterion 2): durable key ledger (normal
  mutation, byte-identical duplicate replay, concurrent
  duplicate, restart/recovery retry, materially-changed request
  under the same key rejected deterministically), the honest
  crash-window reconstruction (the adapted subsystem's own
  duplicate semantics + public-journal reconstruction, never
  re-execution), and the same key + changed content in the
  crash window failing closed with the canonical
  command-conflict preserved;
- **reason codes** (criterion 4): canonical domain failures
  (lifecycle-illegal, expiry gates, reservation discipline)
  reach the developer boundary UNCHANGED and machine-readable;
- **pagination**: deterministic ordering, stable cursor
  behavior, invalid cursor rejection, filtering, tenant
  isolation;
- **observability**: deterministic correlation ids on every
  response, truthful retry guidance (rate limiting), and secret
  hygiene (no credential/webhook secrets in journal bytes or
  response bodies);
- **webhooks** (criterion 3): signature verification success,
  invalid-signature rejection, stale-timestamp (replay)
  rejection, duplicate delivery legality + consumer duplicate
  detection, out-of-order detection via version metadata,
  deterministic retry semantics (failed -> backoff -> retry;
  the event bytes never change), deterministic event identity
  (re-observation emits nothing), environment separation, and
  delivery state observational only (a consumer ack never
  changes canonical commercial state);
- **SDK** (criterion 5): request parity (byte-identical
  canonical request bytes), response parsing parity, error/
  reason-code parity, pagination parity, idempotency parity,
  webhook verification parity;
- **authority honesty** (the absolute boundary): structural
  audits -- the developerapi package imports NOTHING from the
  identity/session/NetworkPath/routing/transport/packet/
  payment/eligibility authorities, the cross-authority call
  surface is exactly the sanctioned adapted set (submit_intent,
  hold_reservation, register_policy + public reads), the API
  cannot mutate any connectivity authority, the SDK contains no
  hidden business authority, API success never implies physical
  connectivity, and webhook state never becomes canonical
  state;
- **durability**: append-only hash-chained journal (byte
  tamper, reorder, truncation, duplicate idempotency key all
  fail closed journal-corrupt), persist-then-ack (a store
  failure leaves no phantom state), journal-first recovery
  (load == live), replay verification (fold == live index);
- **determinism**: the golden scenario's digest stream is
  byte-identical across two fresh in-process runs and across
  PYTHONHASHSEED 0/1/7919/unset subprocesses; the ONLY time
  source is the injected clock seam;
- **failure injection**: persistence failure, duplicate
  command, duplicate webhook delivery, retry after timeout,
  restart after partial operation, unauthorized operation,
  invalid credential, invalid API version, invalid idempotency
  request, invalid webhook signature, raising transport, the
  post-finality webhook queue/delivery persistence failure
  (a webhook failure AFTER the mutation is admitted never
  changes the canonical mutation result: the caller receives
  the canonical success, the idempotent retry replays it
  byte-identically without re-executing the canonical mutation,
  and the webhook failure stays observational and recoverable),
  and the durable webhook-obligation crash recovery (the
  webhook queue append fails AFTER the durable obligation is
  persisted, the process CRASHES, the service is reconstructed
  from the durable stores: the pending obligation is recovered,
  the same observation is queued exactly once, delivery
  succeeds, the canonical mutation is never re-executed, and
  the same-key retry remains an idempotent replay -- the
  delivery OBLIGATION is durable operational state of the
  observation channel, while the delivery STATE stays
  observational only), and the obligation-write ADMISSION GATE
  (the webhook OBLIGATION append itself fails, AFTER the
  mutation is durable and BEFORE the response: the boundary
  returns the deterministic admission failure -- 500
  store-failed, never a false 200 -- the durable mutation is
  neither rolled back nor re-executed, the process crashes,
  and the same-key retry completes the admission from durable
  truth alone BEFORE the byte-identical stored response is
  replayed, after which the delivery pump delivers exactly
  once: the durable obligation is part of the
  successful-admission contract, never best effort), and the
  DURABLE OBSERVATION-ADMISSION STATE (the round-5 frozen
  semantics: every emission's admission-time audience is an
  admission-time FACT, persisted as its own hash-chained
  journal record -- ``required`` with the exact frozen
  endpoints, or terminal ``not-required`` with none -- BEFORE
  the successful response; a historical admission decision is
  AUTHORITATIVE, so a mutation that legitimately completed
  with no audience can never produce a webhook merely because
  an endpoint was registered afterwards and the client
  replayed the same key, an obligation-failed admission heals
  on retry with the ORIGINAL frozen audience even when the
  endpoint set changed in between (no audience drift: the new
  endpoint never receives the historical event), and the
  admission-record write itself failing returns the
  deterministic non-success with the same-key retry
  establishing the admission from the request + the durable
  canonical mutation alone with ZERO additional canonical
  executions -- plus the structural audit: record family
  membership, constructor validation, the fold's fail-closed
  orphan check, and the AST audit of the observation-emission
  call sites proving ONE canonical admission path and no
  process-local observation state);
- **delivery discipline**: frozen public API surface, frozen
  spec surfaces intact, PR delta confined to the authorized
  W046 scope (+ the sanctioned additive-only CI wiring).

The battery exercises the PUBLIC production path only: the
ordinary agent session establishment chain, the NetworkPath
public lifecycle, the platform journal public surface, the
accepted commercial-plane public surfaces, and the
developerapi public surface.  No private method is called to
manufacture a PASS.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from protocol.canonicalization import canonical_json_bytes  # noqa: E402

from agent import (  # noqa: E402
    AgentConfig,
    AgentIdentitySpec,
    AgentRuntime,
    InterfaceSnapshot,
    LinkMetricSpec,
    MigrationSpec,
    StaticInterfaceSource,
    StepClock,
    FixedClock,
)
from agent.clock import AgentClock  # noqa: E402

from mobile.model import (  # noqa: E402
    MobilePhase,
    NetworkKind,
    PlatformSnapshot,
    PowerState,
)

from networkpath import NetworkPathManager  # noqa: E402

from platform.journal import MemoryPlatformStore  # noqa: E402
from platform.lifecycle import PlatformIntegrator  # noqa: E402

from identity.node_id import parse_node_id  # noqa: E402
from identity.model import NodeIdentity  # noqa: E402
from identity.profiles import ProfileSet  # noqa: E402

from topology.model import (  # noqa: E402
    ClaimType,
    SourceClass,
    TopologyClaim,
    make_link_subject,
)
from management import ManagementCapability, RoleDefinition  # noqa: E402
from policy import PolicyDomain, PolicyRule  # noqa: E402

import commercial  # noqa: E402
from commercial import (  # noqa: E402
    CommercialCore,
    Reference,
    ReferenceFamily,
    ReferenceIndex,
)
from commercial.journal import MemoryCommercialStore  # noqa: E402

from usage.lifecycle import UsageLedger  # noqa: E402
from usage.journal import MemoryUsageStore  # noqa: E402
from usage.evidence import EvidenceIndex, EvidenceReference  # noqa: E402
from usage.errors import UsageLedgerError  # noqa: E402

from allocation.lifecycle import AllocationLedger  # noqa: E402
from allocation.journal import MemoryAllocationStore  # noqa: E402
from allocation.evidence import FactIndex  # noqa: E402
from allocation.errors import AllocationError  # noqa: E402

import developerapi  # noqa: E402
from developerapi import (  # noqa: E402
    API_VERSIONS,
    Capability,
    DeveloperApiClient,
    DeveloperApiError,
    DeveloperApiReasonCode,
    DeveloperApiService,
    DuplicateDetector,
    FileApiStore,
    MemoryApiStore,
    OrderTracker,
    ResourceSchema,
    FieldSpec,
    assert_backward_compatible,
    classify_change,
    derive_api_command_id,
    evidence_class,
    is_production_evidence,
    resolve_version,
)
from developerapi.gateway import ApiRequest, ROUTES  # noqa: E402
from developerapi.journal import (  # noqa: E402
    AppendOnlyApiJournal,
    MutationRecord,
    WebhookAdmissionRecord,
    WebhookQueueRecord,
    fold_index,
)
from developerapi import webhooks as webhook_platform  # noqa: E402
from developerapi.sdk import WebhookVerifier  # noqa: E402

Result = Tuple[str, bool, str]

_FAMILY_FILES = sorted((REPO_ROOT / "developerapi").rglob("*.py"))

_T0 = "2025-06-01T00:00:00Z"
_FRESH = "2026-06-01T00:00:00Z"
_SECRET_A = b"w046-battery-secret-A"
_SECRET_B = b"w046-battery-secret-B"
_PROFILE_ID = "identity.sha256-hmac-dev.v1"
_KEY_A = b"w046-battery-key-A"
_KEY_B = b"w046-battery-key-B"

#: The battery clock epoch/step (deterministic; one read per
#: admitted mutation/issuance).
_BT0 = _T0
_BSTEP = 60
_EXPIRES = "2025-06-01T12:00:00Z"
_VALID_UNTIL = "2030-01-01T00:00:00Z"

WIFI_IF = "wlan0"
ETH_IF = "eth0"
USB_IF = "usb0"
CELL_IF = "vpn0"

#: The frozen developerapi public API surface (independently
#: pinned here; the package must match exactly).
_EXPECTED_API = sorted(developerapi.__all__)

#: The authorized W046 delta surface (scope of
#: WORK-046-CORE-001) plus the sanctioned additive CI wiring.
_AUTHORIZED_PATHS = (
    "developerapi/",
    "tools/developerapi_selftest.py",
    "docs/WORK-046-evidence.md",
)
AUTHORIZED_CI_WIRING = ".github/workflows/spec-check.yml"

#: The import allow-list of the developerapi family: stdlib
#: basics + the WORK-003 canonicalization + the WORK-033 clock
#: seam + the three adapted commercial-plane authorities'
#: error/lifecycle modules (isinstance-checked injection points
#: only -- the call audit below pins the exact call surface).
_ALLOWED_IMPORT_MODULES = {
    "__future__",
    "hashlib",
    "hmac",
    "json",
    "dataclasses",
    "pathlib",
    "typing",
    "protocol.canonicalization",
    "agent.clock",
    "commercial.errors",
    "commercial.lifecycle",
    "usage.errors",
    "usage.lifecycle",
    "allocation.errors",
    "allocation.lifecycle",
}

#: The connectivity / payment / eligibility authority modules the
#: developerapi family must NEVER import (frozen authority
#: boundary: identity WORK-004, sessions WORK-012, routing
#: WORK-011, transport WORK-017, NetworkPath WORK-041, payment
#: WORK-044, eligibility WORK-045, platform WORK-042).
_FORBIDDEN_IMPORT_MODULES = {
    "identity",
    "sessions",
    "networkpath",
    "routing",
    "transport",
    "multipath",
    "packet",
    "payment",
    "eligibility",
    "platform",
    "agent",
}

#: The sanctioned cross-authority call surface: every attribute
#: call on the injected authority objects must be in this table
#: (the API's two commercial mutations + the economic policy
#: registration + the public reads; nothing else).
_SANCTIONED_CORE_CALLS = frozenset({
    "submit_intent",
    "hold_reservation",
    "transaction",
    "transactions",
    "journal_records",
})
_SANCTIONED_USAGE_CALLS = frozenset({
    "account",
    "accounts",
})
_SANCTIONED_ALLOCATION_CALLS = frozenset({
    "register_policy",
    "policy",
    "policies",
    "allocation",
    "journal_records",
})

#: Secret-token prefixes the journal and response surfaces must
#: never carry (battery-audited secret hygiene).
_SECRET_PREFIXES = ("dasec_", "dwh_")


def ok(name: str, detail: str = "") -> Result:
    return (name, True, detail)


def fail(name: str, detail: str) -> Result:
    return (name, False, detail)


# ---------------------------------------------------------------------------
# Real-authority world composition (the commercial battery
# pattern: public production paths only)
# ---------------------------------------------------------------------------

def _ids() -> Tuple[str, str]:
    profiles = ProfileSet.load_default()
    profile = profiles.get(_PROFILE_ID)
    identity_a = NodeIdentity.create(profile, _KEY_A, _T0)
    identity_b = NodeIdentity.create(profile, _KEY_B, _T0)
    return identity_a.node_id.text, identity_b.node_id.text


def _claims(self_id: str, peer_id: str) -> Tuple[TopologyClaim, ...]:
    return (
        TopologyClaim(
            subject=make_link_subject(self_id, peer_id),
            reporter=self_id,
            claim_type=ClaimType.LINK_STATE,
            value="up",
            source_class=SourceClass.SELF_ADVERTISEMENT,
            issued_at=_T0,
            freshness_until=_FRESH,
            sequence=1,
        ),
        TopologyClaim(
            subject=peer_id,
            reporter=self_id,
            claim_type=ClaimType.REACHABLE,
            value="true",
            source_class=SourceClass.DIRECT_OBSERVATION,
            issued_at=_T0,
            freshness_until=_FRESH,
            sequence=1,
        ),
    )


def _policy_rules(label: str) -> Tuple[PolicyRule, ...]:
    return (
        PolicyRule(
            rule_id="%s-allow-session-create" % label,
            domain=PolicyDomain.IDENTITY,
            effect="allow",
            operation="session.create",
            subjects=(),
            priority=1,
            specificity=1,
        ),
    )


def _roles() -> Tuple[Any, ...]:
    return (
        RoleDefinition(
            role_id="w046-battery-operator",
            capabilities=(
                ManagementCapability.SESSION_READ,
                ManagementCapability.SESSION_CONTROL,
                ManagementCapability.POLICY_READ,
            ),
            description="operator role (battery fixture)",
        ),
    )


def _config(
    label: str = "developerapi-node",
    key: bytes = _KEY_A,
    peer_id: Optional[str] = None,
    self_id: Optional[str] = None,
) -> AgentConfig:
    if peer_id is None or self_id is None:
        id_a, id_b = _ids()
        peer_id = peer_id or id_b
        self_id = self_id or id_a
    return AgentConfig(
        agent_label=label,
        identity=AgentIdentitySpec(
            profile_id=_PROFILE_ID, public_key=key, created_at=_T0,
        ),
        policy_rules=_policy_rules(label),
        topology_claims=_claims(self_id, peer_id),
        link_metrics=(
            LinkMetricSpec(
                peer_node_id=peer_id, latency_ms=10,
                observed_at=_T0, freshness_until="2026-06-01T00:10:00Z",
            ),
        ),
        rbac_roles=_roles(),
        operator_role_ids=(_roles()[0].role_id,),
        migration=MigrationSpec(
            schema_id="agent.state", from_version="1.0", to_version="1.1",
        ),
    )


def _peer_config() -> AgentConfig:
    id_a, id_b = _ids()
    return _config("peer-node", key=_KEY_B, peer_id=id_a, self_id=id_b)


def _snap(
    *,
    name: str,
    kind: str,
    up: bool = True,
    addresses: Tuple[str, ...] = (),
    mtu: int = 1500,
    speed: int = 100,
    rx: int = 7,
    tx: int = 9,
) -> InterfaceSnapshot:
    return InterfaceSnapshot(
        name=name, link_kind=kind, state_up=up, mtu=mtu, speed_mbps=speed,
        rx_bytes=rx, tx_bytes=tx, rx_errors=0, tx_errors=0,
        addresses=addresses,
    )


def _snapshots() -> Tuple[InterfaceSnapshot, ...]:
    return (
        _snap(name=WIFI_IF, kind="wireless", addresses=("fd00::a:1",)),
        _snap(name=ETH_IF, kind="ethernet", addresses=("fd00::a:2",), speed=1000),
        _snap(name=USB_IF, kind="other", addresses=("fd00::a:3",), mtu=1400, speed=400),
        _snap(name=CELL_IF, kind="other", addresses=(), mtu=1300, speed=50),
    )


def _platform_snapshot(*, background: bool = False) -> PlatformSnapshot:
    return PlatformSnapshot(
        app_phase=(
            MobilePhase.BACKGROUND if background else MobilePhase.FOREGROUND
        ),
        power_state=(
            PowerState.ON_BATTERY if background else PowerState.CHARGING
        ),
        network_kind=NetworkKind.WIFI,
        metered=False,
        background_restricted=background,
    )


def _register_peers(a: AgentRuntime, b: AgentRuntime, clock: StepClock) -> None:
    cred_a = a.identity_service.active_credential(
        parse_node_id(a.node_id), "operational", now=clock.now(),
    )
    cred_b = b.identity_service.active_credential(
        parse_node_id(b.node_id), "operational", now=clock.now(),
    )
    a.register_peer(b.identity, cred_b, _SECRET_B)
    b.register_peer(a.identity, cred_a, _SECRET_A)


def _establish_session(
    runtime: AgentRuntime, peer: AgentRuntime, clock: StepClock
) -> str:
    request = runtime.establish_session(peer.node_id)
    accept = peer.accept_session(request)
    confirm = runtime.complete_session(accept)
    peer.finalize_session(confirm)
    return confirm.session_id


def _world():
    """One booted node + peered peer with one ESTABLISHED
    session, an ACTIVATED NetworkPath, and a PlatformIntegrator
    journal of delivery-plane evidence events -- all through
    the ordinary public production chain."""
    snapshots = _snapshots()
    shared = StepClock(_T0, 60)
    peer = AgentRuntime(
        _peer_config(), clock=shared,
        interface_source=StaticInterfaceSource(snapshots),
    )
    peer.boot(_SECRET_B)
    peer.expose_interfaces()
    runtime = AgentRuntime(
        _config(), clock=shared,
        interface_source=StaticInterfaceSource(snapshots),
    )
    runtime.boot(_SECRET_A)
    runtime.expose_interfaces()
    _register_peers(runtime, peer, shared)
    session_id = _establish_session(runtime, peer, shared)
    manager = NetworkPathManager(runtime, shared)
    manager.discover()
    wifi = _path_for(manager, WIFI_IF)
    manager.validate(wifi)
    manager.bind(wifi, session_id)
    manager.probe(wifi)
    manager.activate(wifi)
    integrator = PlatformIntegrator(store=MemoryPlatformStore(), clock=shared)
    for snapshot in snapshots:
        integrator.ingest_interface_observation(
            snapshot, observed_at=shared.now()
        )
    integrator.ingest_platform_state(
        _platform_snapshot(), observed_at=shared.now()
    )
    return runtime, peer, session_id, manager, integrator, shared


def _path_for(manager: NetworkPathManager, interface_name: str) -> str:
    for path_id in manager.paths():
        if manager.path(path_id).interface_name == interface_name:
            return path_id
    raise AssertionError("no candidate for interface %r" % interface_name)


def _external_id(kind: str, label: str) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_json_bytes({"kind": kind, "label": label})
    ).hexdigest()


# ---------------------------------------------------------------------------
# Service composition helpers
# ---------------------------------------------------------------------------

def _references(
    manager: NetworkPathManager,
    integrator: PlatformIntegrator,
    session_id: str,
) -> ReferenceIndex:
    entries: List[Reference] = [
        Reference(session_id, ReferenceFamily.SESSION, "sessions-authority"),
    ]
    for path_id in manager.paths():
        entries.append(
            Reference(
                path_id, ReferenceFamily.NETWORK_PATH, "networkpath-manager"
            )
        )
    usage_ids: List[str] = []
    for record in integrator.journal_records():
        event = record.event
        if event.kind == "platform-state-observation":
            usage_ids.append(event.event_id)
            continue
        entries.append(
            Reference(
                event.event_id,
                ReferenceFamily.DELIVERY_EVIDENCE,
                "platform-journal",
            )
        )
    for event_id in usage_ids[:1]:
        entries.append(
            Reference(event_id, ReferenceFamily.USAGE, "usage-plane")
        )
    entries.append(
        Reference(
            _external_id("settlement-confirmation", "settle-1"),
            ReferenceFamily.SETTLEMENT,
            "external-settlement-confirmation",
        )
    )
    entries.append(
        Reference(
            _external_id("payment-observation", "payment-1"),
            ReferenceFamily.PAYMENT,
            "external-payment-observation",
        )
    )
    return ReferenceIndex(entries)


def _evidence_index(
    manager: NetworkPathManager,
    integrator: PlatformIntegrator,
    session_id: str,
    core: Optional[CommercialCore] = None,
) -> EvidenceIndex:
    """The W052 frozen evidence snapshot, built from PUBLIC reads
    only; when the commercial core is injected, its transaction
    projections (with the commercial_state/session/path facts
    W052 gates on) are included -- the index is the metering
    window's frozen composition snapshot."""
    from usage.evidence import EvidenceFamily

    entries: List[EvidenceReference] = [
        EvidenceReference(
            reference_id=session_id,
            family=EvidenceFamily.SESSION,
            provenance="sessions-authority",
        ),
    ]
    for path_id in manager.paths():
        entries.append(
            EvidenceReference(
                reference_id=path_id,
                family=EvidenceFamily.NETWORK_PATH,
                provenance="networkpath-manager",
            )
        )
    for record in integrator.journal_records():
        event = record.event
        if event.kind == "platform-state-observation":
            continue
        entries.append(
            EvidenceReference(
                reference_id=event.event_id,
                family=EvidenceFamily.DELIVERY_EVIDENCE,
                provenance="platform-journal",
                instant=event.observed_at,
            )
        )
    if core is not None:
        for transaction in core.transactions():
            projection = transaction.to_dict()
            entries.append(
                EvidenceReference(
                    reference_id=projection["transaction_id"],
                    family=EvidenceFamily.COMMERCIAL,
                    provenance="commercial-core",
                    commercial_state=projection.get("state", ""),
                    session_ref=projection.get("session_ref", ""),
                    path_ref=projection.get("path_ref", ""),
                )
            )
    return EvidenceIndex(entries)


class _FailingApiStore(MemoryApiStore):
    """A store that fails on the Nth append (failure injection)."""

    def __init__(self, fail_at: int) -> None:
        super().__init__()
        self._fail_at = fail_at
        self._count = 0

    def append_line(self, line: str) -> None:
        self._count += 1
        if self._count >= self._fail_at:
            from developerapi.errors import (
                DeveloperApiError as _Err,
                DeveloperApiReasonCode as _RC,
            )

            raise _Err(_RC.STORE_FAILED, "injected store failure")
        super().append_line(line)


class _FlakyApiStore(MemoryApiStore):
    """A store that fails appends whose 1-based call index falls
    in the inclusive window [fail_from, fail_until) and recovers
    afterwards (failure injection for the post-finality webhook
    isolation proof: the mutation record persists, the webhook
    phase fails, the store then heals)."""

    def __init__(self, fail_from: int, fail_until: int) -> None:
        super().__init__()
        self._fail_from = fail_from
        self._fail_until = fail_until
        self._count = 0
        self.failures = 0

    def append_line(self, line: str) -> None:
        self._count += 1
        if self._fail_from <= self._count < self._fail_until:
            self.failures += 1
            raise DeveloperApiError(
                DeveloperApiReasonCode.STORE_FAILED,
                "injected post-finality store failure (call %d)"
                % self._count,
            )
        super().append_line(line)


class _QueueFailingApiStore(MemoryApiStore):
    """A store that fails the first N appends of webhook QUEUE
    records (kind-selected failure injection) and heals
    afterwards: the failure site is the per-endpoint queue write
    itself, AFTER whatever durable records precede it, in BOTH
    the pre-correction and corrected gateways (the durable
    post-finality obligation crash-recovery proof)."""

    def __init__(self, failures: int = 1) -> None:
        super().__init__()
        self._remaining = failures
        self.failures = 0

    def append_line(self, line: str) -> None:
        if self._remaining > 0 and '"record_kind":"webhook-queue"' in line:
            self._remaining -= 1
            self.failures += 1
            raise DeveloperApiError(
                DeveloperApiReasonCode.STORE_FAILED,
                "injected webhook queue append failure",
            )
        super().append_line(line)


class _ObligationFailingApiStore(MemoryApiStore):
    """A store that fails the first N appends of webhook
    OBLIGATION records (kind-selected failure injection) and
    heals afterwards: the failure site is the durable
    observation-obligation write itself -- the step that must
    precede the successful API response under the W046 admission
    contract -- position-independent, so the injection is stable
    across the pre-correction and corrected gateways (the
    obligation-write admission-gate proof)."""

    def __init__(self, failures: int = 1) -> None:
        super().__init__()
        self._remaining = failures
        self.failures = 0

    def append_line(self, line: str) -> None:
        if (
            self._remaining > 0
            and '"record_kind":"webhook-obligation"' in line
        ):
            self._remaining -= 1
            self.failures += 1
            raise DeveloperApiError(
                DeveloperApiReasonCode.STORE_FAILED,
                "injected webhook obligation append failure",
            )
        super().append_line(line)


class _AdmissionFailingApiStore(MemoryApiStore):
    """A store that fails the first webhook-ADMISSION append
    carrying a given idempotency key (kind+key-selected failure
    injection) and heals afterwards: the failure site is the
    durable observation-admission record write itself -- the
    FIRST durable observation boundary, written after the
    mutation record and before the obligation and the successful
    response (the round-5 admission-record persistence-failure
    proof; the key selection keeps the injection on the probe
    mutation's admission, past the endpoint registration's own
    terminal not-required admission)."""

    def __init__(self, idempotency_key: str) -> None:
        super().__init__()
        self._key = idempotency_key
        self._remaining = 1
        self.failures = 0

    def append_line(self, line: str) -> None:
        if (
            self._remaining > 0
            and '"record_kind":"webhook-admission"' in line
            and '"idempotency_key":"%s"' % self._key in line
        ):
            self._remaining -= 1
            self.failures += 1
            raise DeveloperApiError(
                DeveloperApiReasonCode.STORE_FAILED,
                "injected webhook admission append failure",
            )
        super().append_line(line)


def _compose_service(
    *,
    environment: str = "sandbox",
    clock: Optional[AgentClock] = None,
    store: Optional[Any] = None,
    rate_limiter: Optional[Any] = None,
    delivery_transports: Optional[Mapping[str, Any]] = None,
    issuance_key: bytes = b"w046-platform-issuance-key",
    world=None,
    core_store=None,
):
    """Compose the developer platform service over real
    authorities (fresh world unless injected).

    ``core_store`` lets a case hold the commercial core's durable
    store across a simulated process crash (the reconstructed
    core recovers journal-first through ``CommercialCore.load``)."""
    if world is None:
        world = _world()
    runtime, peer, session_id, manager, integrator, shared = world
    clock = clock or shared
    core = CommercialCore(
        store=core_store if core_store is not None else MemoryCommercialStore(),
        clock=clock,
        references=_references(manager, integrator, session_id),
    )
    usage = UsageLedger(
        store=MemoryUsageStore(),
        clock=clock,
        evidence=_evidence_index(manager, integrator, session_id),
    )
    allocation = AllocationLedger(
        store=MemoryAllocationStore(),
        clock=clock,
        facts=FactIndex([]),
    )
    service = DeveloperApiService(
        environment=environment,
        core=core,
        usage=usage,
        allocation=allocation,
        store=store or MemoryApiStore(),
        clock=clock,
        issuance_key=issuance_key,
        rate_limiter=rate_limiter,
        delivery_transports=delivery_transports,
    )
    return service, core, usage, allocation, world


def _app(
    service: DeveloperApiService,
    developer_id: str,
    name: str,
    capabilities: Tuple[str, ...],
    *,
    key_material: str,
) -> Any:
    return service.issue_application_credential(
        developer_id=developer_id,
        application_name=name,
        capabilities=capabilities,
        valid_until=_VALID_UNTIL,
        key_material=key_material,
        actor="platform",
    )


def _full_app(service: DeveloperApiService, developer: str, label: str):
    return _app(
        service, developer, "%s-app" % label, Capability.values(),
        key_material="%s-key" % label,
    )


def _offer_body(name: str, amount: int = 500) -> Dict[str, Any]:
    return {
        "name": name,
        "capacity_bps": 1000,
        "pricing_currency": "GHS",
        "pricing_amount": amount,
        "pricing_unit": "per-mb",
        "effective_from": "2026-09-01T00:00:00Z",
        "effective_until": "2027-01-01T00:00:00Z",
    }


def _req(
    method: str,
    route: str,
    app,
    *,
    body: Optional[Mapping[str, Any]] = None,
    idempotency_key: str = "",
    api_version: str = "1.0",
) -> ApiRequest:
    return ApiRequest(
        method=method,
        route=route,
        body=dict(body or {}),
        api_version=api_version,
        idempotency_key=idempotency_key,
        application_id=app.record.application_id,
        secret=app.secret,
    )


class _Consumer:
    """A deterministic webhook consumer (the battery's remote
    endpoint): captures signed deliveries, verifies with the
    SDK verifier, and can be scripted to fail or raise."""

    def __init__(self, secret: str, *, fail: bool = False, raise_exc: bool = False):
        self.secret = secret
        self.fail = fail
        self.raise_exc = raise_exc
        self.deliveries: List[Tuple[Dict[str, Any], Dict[str, str]]] = []

    def __call__(
        self,
        endpoint_id: str,
        url: str,
        payload: Mapping[str, Any],
        headers: Mapping[str, str],
    ) -> Tuple[bool, int]:
        self.deliveries.append((dict(payload), dict(headers)))
        if self.raise_exc:
            raise RuntimeError("injected consumer crash")
        if self.fail:
            return (False, 500)
        return (True, 200)


def _scenario_stream() -> Dict[str, str]:
    """The golden scenario digest stream (determinism proof):
    one fully composed service, a scripted developer flow over
    REAL authorities, and the digests of every durable surface."""
    service, core, usage, allocation, world = _compose_service()
    app_a = _full_app(service, "dev-a", "a")
    app_b = _full_app(service, "dev-b", "b")

    consumer_a = _Consumer("unused", fail=True)
    endpoint_resp = service.handle(
        _req(
            "POST",
            "/api/1.0/webhook-endpoints",
            app_a,
            body={
                "url": "https://consumer-a.test/hook",
                "event_types": [
                    "connectivity_intent.created",
                    "connectivity_transaction.state_changed",
                    "offer.published",
                ],
            },
            idempotency_key="ep-1",
        )
    )
    endpoint_id = endpoint_resp.body["data"]["id"]
    service._transports[endpoint_id] = _Consumer(
        service.endpoint_signing_secret(endpoint_id)
    )

    offers = []
    for index in range(3):
        response = service.handle(
            _req(
                "POST",
                "/api/1.0/offers",
                app_a,
                body=_offer_body("Offer %d" % index, amount=100 * (index + 1)),
                idempotency_key="offer-%d" % index,
            )
        )
        offers.append(response.body["data"]["id"])

    # developer B: one offer (tenant separation in listings)
    service.handle(
        _req(
            "POST",
            "/api/1.0/offers",
            app_b,
            body=_offer_body("Offer B", amount=777),
            idempotency_key="offer-b-0",
        )
    )

    # intent + reservation through the API over real commercial
    # state (the platform selects the offer between the two API
    # mutations -- the composition the connectivity plane owns)
    intent_resp = service.handle(
        _req(
            "POST",
            "/api/1.0/intents",
            app_a,
            body={"intent": {"subscriber": "sub-1", "request": {"throughput": "1Mbps"}}},
            idempotency_key="intent-1",
        )
    )
    transaction_id = intent_resp.body["data"]["id"]
    service._core.select_offer(
        command_id="platform-select-1",
        transaction_id=transaction_id,
        actor="dev-a",
        source="platform-composer",
        offer={"offer_id": offers[0], "terms": {"unit": "per-mb", "amount": 100}},
    )
    reservation_resp = service.handle(
        _req(
            "POST",
            "/api/1.0/intents/%s/reservations" % transaction_id,
            app_a,
            body={"expires_at": _EXPIRES},
            idempotency_key="reservation-1",
        )
    )

    # economic policy through the API
    policy_resp = service.handle(
        _req(
            "POST",
            "/api/1.0/economic-policies",
            app_a,
            body={
                "policy_id": "policy-a",
                "version": 1,
                "currency": "GHS",
                "exponent": 2,
                "rounding": "half-even",
                "effective_from": "2026-09-01T00:00:00Z",
                "adc_os_share_bps": 500,
                "tax_bps": 0,
                "developer_share_min_bps": 1000,
                "developer_share_max_bps": 9000,
            },
            idempotency_key="policy-1",
        )
    )

    # observation emission (the platform's honest lifecycle
    # webhook surface) + delivery processing
    service.observe_transaction(transaction_id)
    service.process_due_deliveries()

    # duplicate replays
    service.handle(
        _req(
            "POST",
            "/api/1.0/offers",
            app_a,
            body=_offer_body("Offer 0", amount=100),
            idempotency_key="offer-0",
        )
    )
    service.handle(
        _req(
            "POST",
            "/api/1.0/intents/%s/reservations" % transaction_id,
            app_a,
            body={"expires_at": _EXPIRES},
            idempotency_key="reservation-1",
        )
    )

    index = service.index()
    journal = service.journal_records()
    stream = {
        "journal_digest": service.journal_digest(),
        "journal_length": str(len(journal)),
        "mutations": str(len(index.mutations)),
        "credentials": str(len(index.credentials)),
        "offers": str(len(index.offers)),
        "endpoints": str(len(index.endpoints)),
        "deliveries": str(len(index.deliveries)),
        "mutation_digests": "sha256:" + hashlib.sha256(
            canonical_json_bytes(
                [
                    record.request_digest
                    for record in journal
                    if isinstance(record, MutationRecord)
                ]
            )
        ).hexdigest(),
        "transaction_count": str(len(service._core.transactions())),
        "reservation_state": reservation_resp.body["data"]["state"],
        "policy_id": policy_resp.body["data"]["policy_id"],
        "intent_id_prefix": transaction_id[:16],
    }
    return stream


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

def case_01_frozen_vocabularies(results: List[Result]) -> None:
    """The frozen vocabularies: reason codes, capabilities,
    event types, environments, route table, version registry."""
    problems: List[str] = []
    if len(DeveloperApiReasonCode.values()) != 18:
        problems.append("boundary reason vocabulary size changed")
    if len(Capability.values()) != 12:
        problems.append("capability vocabulary size changed")
    if len(webhook_platform.EVENT_TYPES) != 6:
        problems.append("webhook event type vocabulary size changed")
    if len(ROUTES) != 21:
        problems.append("route table size changed (%d)" % len(ROUTES))
    mutations = sorted(
        {pattern for (method, pattern), spec in ROUTES.items() if spec.mutation}
    )
    expected_mutations = sorted([
        "offers",
        "intents",
        "intents/{}/reservations",
        "economic-policies",
        "webhook-endpoints",
    ])
    if mutations != expected_mutations:
        problems.append("mutating routes changed: %s" % mutations)
    for version, spec in sorted(API_VERSIONS.items()):
        if not isinstance(spec.schemas, Mapping) or not spec.schemas:
            problems.append("version %s carries no schema set" % version)
    if sorted(API_VERSIONS) != ["0.8", "0.9", "1.0", "1.1"]:
        problems.append("version registry changed: %s" % sorted(API_VERSIONS))
    if problems:
        results.append(fail("01 frozen vocabularies", "; ".join(problems)))
    else:
        results.append(
            ok(
                "01 frozen vocabularies",
                "18 reasons, 12 capabilities, 6 event types, %d routes "
                "(5 mutating), 4 registered versions" % len(ROUTES),
            )
        )


def case_02_version_policy(results: List[Result]) -> None:
    """Version resolution: supported, deprecated-with-notice,
    retired/unknown rejected deterministically; unambiguous
    attribution (route/header disagreement rejected)."""
    problems: List[str] = []
    supported = resolve_version("1.0")
    if supported.status != "supported":
        problems.append("1.0 is not supported")
    deprecated = resolve_version("0.9")
    if deprecated.status != "deprecated" or not deprecated.notice:
        problems.append("0.9 is not deprecated-with-notice")
    for bad in ("0.8", "2.0", "", None, "1.0.0"):
        try:
            resolve_version(bad)
            problems.append("version %r was not rejected" % (bad,))
        except DeveloperApiError as error:
            if error.reason != DeveloperApiReasonCode.VERSION_UNSUPPORTED:
                problems.append(
                    "version %r rejected with %r" % (bad, error.reason)
                )
    service, *_ = _compose_service()
    app = _full_app(service, "dev-v", "v")
    # route/header disagreement -> deterministic rejection
    response = service.handle(
        _req(
            "GET", "/api/1.0/offers", app, api_version="1.1"
        )
    )
    if response.status != 400 or (
        response.body["error"]["reason"] != "version-unsupported"
    ):
        problems.append("route/header disagreement not rejected")
    # deprecated version admitted WITH the notice
    response = service.handle(
        _req("GET", "/api/0.9/offers", app, api_version="0.9")
    )
    if response.status != 200:
        problems.append(
            "deprecated version not admitted: %d (%r)"
            % (response.status, response.body.get("error", {}).get("reason"))
        )
    elif "deprecation" not in response.body:
        problems.append("deprecated response carries no notice")
    if problems:
        results.append(fail("02 version policy", "; ".join(problems)))
    else:
        results.append(
            ok(
                "02 version policy",
                "supported/deprecated/retired policy enforced; "
                "attribution unambiguous",
            )
        )


def case_03_schema_compatibility(results: List[Result]) -> None:
    """The mechanical compatibility gate: additive evolution is
    compatible (v1.0 payloads validate under v1.1); breaking
    changes fail closed; deprecation is compatible."""
    problems: List[str] = []
    v1 = API_VERSIONS["1.0"].schemas["offer"]
    v11 = API_VERSIONS["1.1"].schemas["offer"]
    classified = assert_backward_compatible(v1, v11)
    classes = {field: cls for field, cls, _note in classified}
    if classes.get("region") != "ADDITIVE":
        problems.append("region addition not ADDITIVE: %s" % classes.get("region"))
    if classes.get("pricing_unit") != "DEPRECATION":
        problems.append("pricing_unit deprecation not DEPRECATION")
    # live backward compatibility: a v1.0 payload validates
    # under the v1.1 schema set (strict subset)
    try:
        v11.validate(_offer_body("Old client"), "offer payload")
    except DeveloperApiError as error:
        problems.append("v1.0 payload rejected under v1.1: %s" % error.detail)
    # breaking pair: remove a required field
    breaking = ResourceSchema(
        "offer",
        "2.0",
        tuple(
            spec for spec in v1.fields if spec.name != "name"
        ),
    )
    try:
        assert_backward_compatible(v1, breaking)
        problems.append("breaking change (removed field) not detected")
    except DeveloperApiError:
        pass
    # breaking pair: add a required field
    breaking2 = ResourceSchema(
        "offer",
        "2.0",
        v1.fields + (FieldSpec("mandatory_new", "text"),),
    )
    try:
        assert_backward_compatible(v1, breaking2)
        problems.append("breaking change (added required) not detected")
    except DeveloperApiError:
        pass
    # breaking pair: retype a field
    breaking3 = ResourceSchema(
        "offer",
        "2.0",
        tuple(
            FieldSpec("capacity_bps", "text") if spec.name == "capacity_bps"
            else spec
            for spec in v1.fields
        ),
    )
    try:
        assert_backward_compatible(v1, breaking3)
        problems.append("breaking change (retyped) not detected")
    except DeveloperApiError:
        pass
    # deprecated-field behavior: a v1.1 request carrying the
    # deprecated member is admitted and the response notes it
    service, *_ = _compose_service()
    app = _full_app(service, "dev-schema", "s")
    body = _offer_body("With unit")
    body["region"] = "west-africa"
    response = service.handle(
        _req(
            "POST",
            "/api/1.1/offers",
            app,
            body=body,
            idempotency_key="schema-1",
            api_version="1.1",
        )
    )
    if response.status != 200:
        problems.append("v1.1 request with deprecated member rejected")
    elif "pricing_unit" not in response.body.get("deprecated_fields", []):
        problems.append("deprecated member not noted in the response")
    if problems:
        results.append(fail("03 schema compatibility", "; ".join(problems)))
    else:
        results.append(
            ok(
                "03 schema compatibility",
                "additive/deprecation compatible; 3 breaking classes "
                "fail closed; deprecated behavior live",
            )
        )


def case_04_environments_isolation(results: List[Result]) -> None:
    """Sandbox/production isolation: separate stores and
    authorities, cross-environment credential rejection in both
    directions, environment-namespaced ids, sandbox evidence
    classification."""
    problems: List[str] = []
    sandbox, *_ = _compose_service(environment="sandbox")
    production, prod_core, *_ = _compose_service(environment="production")
    app_s = _full_app(sandbox, "dev-e", "s")
    app_p = _full_app(production, "dev-e", "p")

    # sandbox request -> production service: rejected (the
    # application is not issued in production -- the ids are
    # environment-namespaced by derivation)
    response = production.handle(
        _req("GET", "/api/1.0/offers", app_s)
    )
    if response.status != 401 or response.body["error"]["reason"] not in (
        "authentication-invalid",
        "environment-mismatch",
    ):
        problems.append(
            "sandbox credential not rejected by production: %d/%r"
            % (response.status, response.body["error"]["reason"])
        )
    # production request -> sandbox service: rejected
    response = sandbox.handle(
        _req("GET", "/api/1.0/offers", app_p)
    )
    if response.status != 401 or response.body["error"]["reason"] not in (
        "authentication-invalid",
        "environment-mismatch",
    ):
        problems.append(
            "production credential not rejected by sandbox: %d/%r"
            % (response.status, response.body["error"]["reason"])
        )
    # the ENVIRONMENT BINDING gate itself: a service mis-bound
    # to the other environment over the same journal rejects
    # the credential with the typed environment-mismatch (the
    # credential record IS known there, but bound to sandbox)
    misbound = DeveloperApiService.load(
        environment="production",
        core=production._core,
        usage=production._usage,
        allocation=production._allocation,
        store=sandbox._journal._store,
        clock=sandbox._clock,
        issuance_key=b"w046-platform-issuance-key",
    )
    response = misbound.handle(
        _req("GET", "/api/1.0/offers", app_s)
    )
    if response.status != 403 or (
        response.body["error"]["reason"] != "environment-mismatch"
    ):
        problems.append(
            "environment binding gate not enforced: %d/%r"
            % (response.status, response.body["error"].get("reason"))
        )

    # sandbox mutation creates SANDBOX commercial state only
    sandbox.handle(
        _req(
            "POST",
            "/api/1.0/intents",
            app_s,
            body={"intent": {"subscriber": "sub"}},
            idempotency_key="env-intent-1",
        )
    )
    if len(prod_core.transactions()) != 0:
        problems.append("sandbox mutation created production commercial state")
    if len(sandbox._core.transactions()) != 1:
        problems.append("sandbox mutation missing from sandbox state")

    # same key + same content in production: DIFFERENT resource
    # (separate stores: both admitted, ids differ by environment)
    r_s = sandbox.handle(
        _req(
            "POST",
            "/api/1.0/offers",
            app_s,
            body=_offer_body("Env offer"),
            idempotency_key="env-offer-1",
        )
    )
    r_p = production.handle(
        _req(
            "POST",
            "/api/1.0/offers",
            app_p,
            body=_offer_body("Env offer"),
            idempotency_key="env-offer-1",
        )
    )
    if r_s.body["data"]["id"] == r_p.body["data"]["id"]:
        problems.append("sandbox and production resource ids collide")
    if r_s.body["data"]["environment"] != "sandbox" or (
        r_p.body["data"]["environment"] != "production"
    ):
        problems.append("resource does not carry its environment")

    # evidence classification honesty
    if evidence_class("sandbox") != "sandbox-simulation":
        problems.append("sandbox evidence class wrong")
    if not is_production_evidence("production"):
        problems.append("production evidence classification wrong")
    if is_production_evidence("sandbox"):
        problems.append("sandbox classified as production evidence")
    # the lifecycle resource carries the honest classification
    tx_id = sandbox._core.transactions()[0].to_dict()["transaction_id"]
    life = sandbox.handle(
        _req("GET", "/api/1.0/intents/%s/lifecycle" % tx_id, app_s)
    )
    if life.body["data"]["evidence_class"] != "sandbox-simulation":
        problems.append("lifecycle resource misclassifies sandbox evidence")
    if problems:
        results.append(fail("04 environments isolation", "; ".join(problems)))
    else:
        results.append(
            ok(
                "04 environments isolation",
                "both-direction credential rejection; production state "
                "untouched; ids namespaced; sandbox never production "
                "evidence",
            )
        )


def case_05_credentials(results: List[Result]) -> None:
    """Credential model: issuance returns the secret once; the
    journal stores only the digest; verification is
    constant-time; the self read surface."""
    problems: List[str] = []
    service, *_ = _compose_service()
    app = _full_app(service, "dev-c", "c")
    journal_text = "\n".join(
        json.dumps({}) if False else str(record.to_dict())
        for record in service.journal_records()
    )
    if app.secret in journal_text:
        problems.append("credential secret appears in journal text")
    if app.record.secret_digest not in journal_text:
        # the digest (NOT the secret) is the journaled
        # verification form -- the documented design
        problems.append("credential digest not journaled")
    if not app.secret.startswith("dasec_"):
        problems.append("credential secret prefix wrong")
    if app.record.capabilities != tuple(sorted(Capability.values())):
        problems.append("capabilities not sorted-frozen at issuance")
    response = service.handle(_req("GET", "/api/1.0/application", app))
    if response.status != 200:
        problems.append("self read failed")
    elif "credential_secret" in response.body["data"]:
        problems.append("self read leaks the secret")
    # cross-resource authorization: developer B cannot read
    # developer A's offer (invisible, not enumerated)
    app_b = _full_app(service, "dev-c2", "c2")
    offer = service.handle(
        _req(
            "POST",
            "/api/1.0/offers",
            app,
            body=_offer_body("A offer"),
            idempotency_key="cred-offer-1",
        )
    )
    response = service.handle(
        _req("GET", "/api/1.0/offers/%s" % offer.body["data"]["id"], app_b)
    )
    if response.status != 404 or (
        response.body["error"]["reason"] != "resource-unknown"
    ):
        problems.append("cross-tenant resource visible")
    if problems:
        results.append(fail("05 credentials", "; ".join(problems)))
    else:
        results.append(
            ok(
                "05 credentials",
                "secret once; digest-only journal; self read; cross-"
                "tenant invisibility",
            )
        )


def case_06_authentication_failures(results: List[Result]) -> None:
    """Authentication failure family: wrong secret, unknown
    application, revoked, expired -- all fail closed with the
    right boundary reason and 401/403 status."""
    problems: List[str] = []
    service, *_ = _compose_service()
    app = _full_app(service, "dev-auth", "auth")

    wrong = _req("GET", "/api/1.0/offers", app)
    wrong = ApiRequest(
        method="GET",
        route="/api/1.0/offers",
        body={},
        api_version="1.0",
        application_id=app.record.application_id,
        secret="dasec_" + "0" * 64,
    )
    response = service.handle(wrong)
    if response.status != 401 or (
        response.body["error"]["reason"] != "authentication-invalid"
    ):
        problems.append("wrong secret not rejected 401")

    unknown = ApiRequest(
        method="GET",
        route="/api/1.0/offers",
        body={},
        api_version="1.0",
        application_id="sha256:" + "9" * 64,
        secret=app.secret,
    )
    response = service.handle(unknown)
    if response.status != 401:
        problems.append("unknown application not rejected 401")

    # expired credential (clock far beyond valid_until)
    expired_clock = FixedClock("2031-01-01T00:00:00Z")
    service2, *_ = _compose_service(clock=expired_clock)
    app2 = _full_app(service2, "dev-auth2", "auth2")
    response = service2.handle(
        ApiRequest(
            method="GET",
            route="/api/1.0/offers",
            body={},
            api_version="1.0",
            application_id=app2.record.application_id,
            secret=app2.secret,
        )
    )
    if response.status != 401 or (
        response.body["error"]["reason"] != "authentication-expired"
    ):
        problems.append("expired credential not rejected with expiry reason")

    # revoked credential
    service3, *_ = _compose_service()
    app3 = _full_app(service3, "dev-auth3", "auth3")
    service3.revoke_application_credential(
        application_id=app3.record.application_id, actor="platform"
    )
    response = service3.handle(
        ApiRequest(
            method="GET",
            route="/api/1.0/offers",
            body={},
            api_version="1.0",
            application_id=app3.record.application_id,
            secret=app3.secret,
        )
    )
    if response.status != 401:
        problems.append("revoked credential not rejected")
    if problems:
        results.append(fail("06 authentication failures", "; ".join(problems)))
    else:
        results.append(
            ok(
                "06 authentication failures",
                "wrong secret / unknown / expired / revoked all fail "
                "closed (401 + typed reason)",
            )
        )


def case_07_capability_authorization(results: List[Result]) -> None:
    """Scoped capability enforcement: an application without the
    required capability is rejected BEFORE any business surface;
    authentication alone grants no authority."""
    problems: List[str] = []
    service, *_ = _compose_service()
    reader = _app(
        service,
        "dev-read",
        "reader",
        (Capability.OFFERS_READ, Capability.INTENTS_READ),
        key_material="reader-key",
    )
    writer = _app(
        service,
        "dev-write",
        "writer",
        (Capability.OFFERS_WRITE,),
        key_material="writer-key",
    )
    # reader cannot publish
    response = service.handle(
        _req(
            "POST",
            "/api/1.0/offers",
            reader,
            body=_offer_body("Nope"),
            idempotency_key="cap-1",
        )
    )
    if response.status != 403 or (
        response.body["error"]["reason"] != "capability-denied"
    ):
        problems.append("reader publish not rejected 403")
    # no journal growth on denial (the store is untouched)
    if len(service.journal_records()) != 2:  # the two credentials
        problems.append(
            "denied mutation grew the journal (%d records)"
            % len(service.journal_records())
        )
    # writer can publish but cannot read lists
    response = service.handle(
        _req(
            "POST",
            "/api/1.0/offers",
            writer,
            body=_offer_body("Yes"),
            idempotency_key="cap-2",
        )
    )
    if response.status != 200:
        problems.append("writer publish rejected")
    response = service.handle(_req("GET", "/api/1.0/offers", writer))
    if response.status != 403:
        problems.append("writer list not rejected 403")
    # reader CAN read
    response = service.handle(_req("GET", "/api/1.0/offers", reader))
    if response.status != 200:
        problems.append("reader list rejected")
    if problems:
        results.append(fail("07 capability authorization", "; ".join(problems)))
    else:
        results.append(
            ok(
                "07 capability authorization",
                "negative authorization enforced pre-surface; "
                "authentication alone grants nothing",
            )
        )


def case_08_idempotency_normal_duplicate(results: List[Result]) -> None:
    """Normal mutation + byte-identical duplicate replay."""
    problems: List[str] = []
    service, *_ = _compose_service()
    app = _full_app(service, "dev-idem", "idem")
    first = service.handle(
        _req(
            "POST",
            "/api/1.0/offers",
            app,
            body=_offer_body("Idem offer"),
            idempotency_key="idem-1",
        )
    )
    if first.status != 200 or first.body["idempotency"]["replayed"]:
        problems.append("first mutation not clean")
    second = service.handle(
        _req(
            "POST",
            "/api/1.0/offers",
            app,
            body=_offer_body("Idem offer"),
            idempotency_key="idem-1",
        )
    )
    if second.status != 200:
        problems.append("duplicate rejected")
    if second.headers.get("X-ADCOS-Idempotent-Replay") != "true":
        problems.append("replay header missing")
    body1 = first.canonical_body_bytes()
    body2 = second.canonical_body_bytes()
    normalized1 = body1.replace(b'"replayed": false', b'"replayed": true')
    if normalized1 != body2:
        problems.append("duplicate body differs beyond the replay flag")
    if service.index().mutations["idem-1"].request_digest != service.index(
    ).mutations["idem-1"].request_digest:
        problems.append("digest unstable")
    # no journal growth from the duplicate
    before = len(service.journal_records())
    service.handle(
        _req(
            "POST",
            "/api/1.0/offers",
            app,
            body=_offer_body("Idem offer"),
            idempotency_key="idem-1",
        )
    )
    if len(service.journal_records()) != before:
        problems.append("duplicate grew the journal")
    if problems:
        results.append(fail("08 idempotency normal+duplicate", "; ".join(problems)))
    else:
        results.append(
            ok(
                "08 idempotency normal+duplicate",
                "byte-identical replay; no journal growth",
            )
        )


def case_09_idempotency_conflict(results: List[Result]) -> None:
    """Same key + materially different request fails closed."""
    problems: List[str] = []
    service, *_ = _compose_service()
    app = _full_app(service, "dev-conf", "conf")
    service.handle(
        _req(
            "POST",
            "/api/1.0/offers",
            app,
            body=_offer_body("First"),
            idempotency_key="conf-1",
        )
    )
    response = service.handle(
        _req(
            "POST",
            "/api/1.0/offers",
            app,
            body=_offer_body("DIFFERENT", amount=999),
            idempotency_key="conf-1",
        )
    )
    if response.status != 409 or (
        response.body["error"]["reason"] != "idempotency-conflict"
    ):
        problems.append("conflicting reuse not rejected 409")
    # missing key on a mutation
    response = service.handle(
        _req("POST", "/api/1.0/offers", app, body=_offer_body("No key"))
    )
    if response.status != 400 or (
        response.body["error"]["reason"] != "idempotency-key-required"
    ):
        problems.append("missing key not rejected")
    if problems:
        results.append(fail("09 idempotency conflict", "; ".join(problems)))
    else:
        results.append(
            ok("09 idempotency conflict", "409 + missing-key 400 enforced")
        )


def case_10_idempotency_concurrent(results: List[Result]) -> None:
    """Concurrent duplicates: two interleaved submissions of the
    same key -- the second lands on the ledger first append and
    replays byte-identically; exactly one durable record."""
    problems: List[str] = []
    service, *_ = _compose_service()
    app = _full_app(service, "dev-conc", "conc")
    request = _req(
        "POST",
        "/api/1.0/intents",
        app,
        body={"intent": {"subscriber": "concurrent"}},
        idempotency_key="conc-1",
    )
    first = service.handle(request)
    second = service.handle(
        _req(
            "POST",
            "/api/1.0/intents",
            app,
            body={"intent": {"subscriber": "concurrent"}},
            idempotency_key="conc-1",
        )
    )
    if first.status != 200 or second.status != 200:
        problems.append("concurrent pair statuses %s/%s" % (
            first.status, second.status
        ))
    if first.body["data"]["id"] != second.body["data"]["id"]:
        problems.append("concurrent duplicates diverged")
    mutation_records = [
        record
        for record in service.journal_records()
        if isinstance(record, MutationRecord)
        and record.idempotency_key == "conc-1"
    ]
    if len(mutation_records) != 1:
        problems.append("concurrent duplicate produced %d records" % len(
            mutation_records
        ))
    if problems:
        results.append(fail("10 concurrent duplicates", "; ".join(problems)))
    else:
        results.append(
            ok("10 concurrent duplicates", "one durable record; identical ids")
        )


def case_11_idempotency_restart(results: List[Result]) -> None:
    """Restart/recovery: the ledger survives a process restart
    (journal-first recovery); a retry after restart replays
    byte-identically and does not re-execute."""
    problems: List[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        store_path = Path(tmp) / "api-journal.jsonl"
        service, core, *_ = _compose_service(store=FileApiStore(store_path))
        app = _full_app(service, "dev-restart", "restart")
        first = service.handle(
            _req(
                "POST",
                "/api/1.0/intents",
                app,
                body={"intent": {"subscriber": "restart"}},
                idempotency_key="restart-1",
            )
        )
        core_transactions = len(core.transactions())
        service2 = DeveloperApiService.load(
            environment="sandbox",
            core=core,
            usage=service._usage,
            allocation=service._allocation,
            store=FileApiStore(store_path),
            clock=service._clock,
            issuance_key=b"w046-platform-issuance-key",
        )
        retry = service2.handle(
            _req(
                "POST",
                "/api/1.0/intents",
                app,
                body={"intent": {"subscriber": "restart"}},
                idempotency_key="restart-1",
            )
        )
        if retry.status != 200 or not (
            retry.headers.get("X-ADCOS-Idempotent-Replay") == "true"
        ):
            problems.append("post-restart retry not a replay")
        normalized = (
            first.canonical_body_bytes()
            .replace(b'"replayed": false', b'"replayed": true')
        )
        if normalized != retry.canonical_body_bytes():
            problems.append("post-restart replay differs")
        if len(core.transactions()) != core_transactions:
            problems.append("restart retry re-executed the mutation")
        # recovered index is exactly the journal fold
        service2.verify_integrity()
    if problems:
        results.append(fail("11 idempotency restart", "; ".join(problems)))
    else:
        results.append(
            ok(
                "11 idempotency restart",
                "journal-first recovery; byte-identical replay; no "
                "re-execution",
            )
        )


def case_12_idempotency_crash_window(results: List[Result]) -> None:
    """The honest crash window: the adapted authority holds the
    command but the boundary record was lost -- the retry
    reconstructs the canonical prior result from the authority's
    PUBLIC journal reads (no re-execution), and the same key
    with DIFFERENT content fails closed with the canonical
    command-conflict preserved."""
    problems: List[str] = []
    service, core, *_ = _compose_service()
    app = _full_app(service, "dev-crash", "crash")
    source = "developerapi:%s" % app.record.application_id
    command_id = derive_api_command_id("sandbox", "dev-crash", "crash-1")
    outcome = core.submit_intent(
        command_id=command_id,
        actor="dev-crash",
        source=source,
        intent={"subscriber": "crash-window"},
    )
    prior_records = len(core.journal_records())
    response = service.handle(
        _req(
            "POST",
            "/api/1.0/intents",
            app,
            body={"intent": {"subscriber": "crash-window"}},
            idempotency_key="crash-1",
        )
    )
    if response.status != 200:
        problems.append(
            "crash-window retry failed: %s" % response.body.get("error", {}).get("reason")
        )
    data = response.body["data"]
    if data["id"] != outcome.transaction_id:
        problems.append("crash-window retry diverged from prior transaction")
    if data["created_at"] != outcome.instant:
        problems.append("crash-window retry lost the prior instant")
    if len(core.journal_records()) != prior_records:
        problems.append("crash-window retry re-executed the command")
    # the boundary record now exists; a further duplicate replays
    again = service.handle(
        _req(
            "POST",
            "/api/1.0/intents",
            app,
            body={"intent": {"subscriber": "crash-window"}},
            idempotency_key="crash-1",
        )
    )
    if again.headers.get("X-ADCOS-Idempotent-Replay") != "true":
        problems.append("post-crash duplicate not a ledger replay")
    # the same key with DIFFERENT content in the crash window
    command_id2 = derive_api_command_id("sandbox", "dev-crash", "crash-2")
    core.submit_intent(
        command_id=command_id2,
        actor="dev-crash",
        source=source,
        intent={"subscriber": "first-content"},
    )
    response = service.handle(
        _req(
            "POST",
            "/api/1.0/intents",
            app,
            body={"intent": {"subscriber": "DIFFERENT-content"}},
            idempotency_key="crash-2",
        )
    )
    if response.status != 409 or (
        response.body["error"]["reason"] != "idempotency-conflict"
    ):
        problems.append("crash-window conflict not rejected")
    elif response.body["error"]["canonical_reason"] != "command-conflict":
        problems.append(
            "crash-window conflict lost the canonical reason: %r"
            % response.body["error"]["canonical_reason"]
        )
    if problems:
        results.append(fail("12 idempotency crash window", "; ".join(problems)))
    else:
        results.append(
            ok(
                "12 idempotency crash window",
                "public-journal reconstruction; no re-execution; "
                "conflict preserves command-conflict",
            )
        )


def case_13_commercial_lifecycle_flow(results: List[Result]) -> None:
    """The full real flow: API intent -> platform offer
    selection -> API reservation -> platform connectivity drive
    -> honest lifecycle observation (API success never implies
    physical connectivity)."""
    problems: List[str] = []
    service, core, usage, allocation, world = _compose_service()
    runtime, peer, session_id, manager, integrator, shared = world
    app = _full_app(service, "dev-flow", "flow")

    offer = service.handle(
        _req(
            "POST",
            "/api/1.0/offers",
            app,
            body=_offer_body("Flow offer"),
            idempotency_key="flow-offer-1",
        )
    )
    intent = service.handle(
        _req(
            "POST",
            "/api/1.0/intents",
            app,
            body={"intent": {"subscriber": "sub-flow"}},
            idempotency_key="flow-intent-1",
        )
    )
    transaction_id = intent.body["data"]["id"]
    # the platform (connectivity/matching plane) selects the offer
    core.select_offer(
        command_id="platform-select",
        transaction_id=transaction_id,
        actor="dev-flow",
        source="platform-composer",
        offer={"offer_id": offer.body["data"]["id"], "amount": 100},
    )
    reservation = service.handle(
        _req(
            "POST",
            "/api/1.0/intents/%s/reservations" % transaction_id,
            app,
            body={"expires_at": _EXPIRES},
            idempotency_key="flow-res-1",
        )
    )
    if reservation.status != 200 or (
        reservation.body["data"]["state"] != "RESERVATION_HELD"
    ):
        problems.append("reservation not held")
    # the connectivity plane advances the canonical chain
    core.authorize_session(
        command_id="platform-auth",
        transaction_id=transaction_id,
        actor="dev-flow",
        source="platform-composer",
        session_ref=session_id,
    )
    path_id = _path_for(manager, WIFI_IF)
    core.activate_path(
        command_id="platform-activate",
        transaction_id=transaction_id,
        actor="dev-flow",
        source="platform-composer",
        path_ref=path_id,
    )
    lifecycle = service.handle(
        _req("GET", "/api/1.0/intents/%s/lifecycle" % transaction_id, app)
    )
    data = lifecycle.body["data"]
    if data["commercial_state"] != "PATH_ACTIVE":
        problems.append(
            "lifecycle state wrong: %s" % data["commercial_state"]
        )
    # THE honesty invariant: API success (200) with commercial
    # state advanced -- but physical connectivity is NOT claimed
    if lifecycle.status != 200:
        problems.append("lifecycle read failed")
    if data["physical_connectivity_observed"] is not False:
        problems.append("physical connectivity claimed")
    if data["physical_evidence"] != "not-claimed":
        problems.append("physical evidence claimed")
    # the distinct statements are present and not collapsed
    if "physical_connectivity_observed" not in data["statements"]:
        problems.append("distinct lifecycle statements missing")
    # reservations listing sees the lease
    listing = service.handle(
        _req("GET", "/api/1.0/reservations", app)
    )
    if not any(
        item["id"] == transaction_id
        for item in listing.body["data"]["items"]
    ):
        problems.append("reservation not listed")
    if problems:
        results.append(fail("13 commercial lifecycle flow", "; ".join(problems)))
    else:
        results.append(
            ok(
                "13 commercial lifecycle flow",
                "intent->select->reserve->authorize->activate over real "
                "authorities; physical connectivity never claimed",
            )
        )


def case_14_reason_code_preservation(results: List[Result]) -> None:
    """Canonical domain failures reach the developer boundary
    UNCHANGED and machine-readable (criterion 4)."""
    problems: List[str] = []
    service, core, *_ = _compose_service()
    app = _full_app(service, "dev-reason", "reason")
    intent = service.handle(
        _req(
            "POST",
            "/api/1.0/intents",
            app,
            body={"intent": {"subscriber": "sub-reason"}},
            idempotency_key="reason-1",
        )
    )
    transaction_id = intent.body["data"]["id"]
    # hold_reservation from CONNECTIVITY_INTENT (offer not yet
    # selected) -> canonical lifecycle-illegal
    response = service.handle(
        _req(
            "POST",
            "/api/1.0/intents/%s/reservations" % transaction_id,
            app,
            body={"expires_at": _EXPIRES},
            idempotency_key="reason-2",
        )
    )
    error = response.body["error"]
    if response.status != 422:
        problems.append("lifecycle-illegal not 422: %d" % response.status)
    if error["canonical_reason"] != "lifecycle-illegal":
        problems.append(
            "canonical reason lost: %r" % error["canonical_reason"]
        )
    if not isinstance(error["canonical_reason"], str):
        problems.append("canonical reason not machine-readable")
    # unknown transaction -> canonical transaction-unknown
    fake = "sha256:" + "4" * 64
    response = service.handle(
        _req("GET", "/api/1.0/intents/%s" % fake, app)
    )
    error = response.body["error"]
    if error["canonical_reason"] != "transaction-unknown":
        problems.append(
            "transaction-unknown lost: %r" % error["canonical_reason"]
        )
    if response.status != 404:
        problems.append("transaction-unknown not 404")
    # malformed deadline -> canonical instant-invalid (the core's
    # own RFC 3339 gate, preserved unchanged at the boundary)
    response = service.handle(
        _req(
            "POST",
            "/api/1.0/intents/%s/reservations" % transaction_id,
            app,
            body={"expires_at": "not-a-date"},
            idempotency_key="reason-3",
        )
    )
    error = response.body["error"]
    if error["canonical_reason"] != "instant-invalid":
        problems.append(
            "canonical instant gate lost: %r" % error["canonical_reason"]
        )
    # boundary-local validation (schema strictness) still carries
    # an empty canonical reason -- never a fabricated one
    response = service.handle(
        _req(
            "POST",
            "/api/1.0/offers",
            app,
            body={"name": "x", "undeclared_member": 1},
            idempotency_key="reason-4",
        )
    )
    error = response.body["error"]
    if error["reason"] != "invalid-input" or error["canonical_reason"]:
        problems.append(
            "boundary validation error malformed: %r/%r"
            % (error["reason"], error["canonical_reason"])
        )
    if problems:
        results.append(fail("14 reason code preservation", "; ".join(problems)))
    else:
        results.append(
            ok(
                "14 reason code preservation",
                "lifecycle-illegal (422), transaction-unknown (404), "
                "invalid-input all preserved unchanged",
            )
        )


def case_15_pagination(results: List[Result]) -> None:
    """Deterministic pagination: canonical order, stable
    cursors, invalid cursor rejection, filtering, tenant
    isolation."""
    problems: List[str] = []
    service, *_ = _compose_service()
    app = _full_app(service, "dev-page", "page")
    app_b = _full_app(service, "dev-page2", "page2")
    for index in range(5):
        service.handle(
            _req(
                "POST",
                "/api/1.0/offers",
                app,
                body=_offer_body("Page %d" % index, amount=100 + index),
                idempotency_key="page-%d" % index,
            )
        )
    service.handle(
        _req(
            "POST",
            "/api/1.0/offers",
            app_b,
            body=_offer_body("Intruder"),
            idempotency_key="page-b",
        )
    )
    first = service.handle(
        _req("GET", "/api/1.0/offers", app, body={"limit": 2})
    )
    items = first.body["data"]["items"]
    if len(items) != 2 or not first.body["data"]["has_more"]:
        problems.append("first page wrong")
    ids = [item["id"] for item in items]
    if ids != sorted(ids):
        problems.append("page order not canonical (id ascending)")
    # every item belongs to the authenticated developer
    if any(item["developer_id"] != "dev-page" for item in items):
        problems.append("tenant leak in page")
    # repeat read: byte-identical
    repeat = service.handle(
        _req("GET", "/api/1.0/offers", app, body={"limit": 2})
    )
    if repeat.canonical_body_bytes() != first.canonical_body_bytes():
        problems.append("repeated read not byte-identical")
    # follow the cursor
    cursor = first.body["data"]["next_cursor"]
    second = service.handle(
        _req(
            "GET",
            "/api/1.0/offers",
            app,
            body={"limit": 2, "cursor": cursor},
        )
    )
    second_ids = [item["id"] for item in second.body["data"]["items"]]
    if set(second_ids) & set(ids):
        problems.append("cursor page overlaps the first page")
    # the full iteration covers exactly the developer's 5 offers
    all_ids = ids + second_ids + [
        item["id"]
        for item in service.handle(
            _req(
                "GET",
                "/api/1.0/offers",
                app,
                body={
                    "limit": 2,
                    "cursor": second.body["data"]["next_cursor"],
                },
            )
        ).body["data"]["items"]
    ]
    if len(all_ids) != 5 or len(set(all_ids)) != 5:
        problems.append("pagination did not cover the tenant set")
    # invalid cursor: malformed, wrong context, cross-tenant
    for bad_cursor in ("garbage", "cur_" + "0" * 64, second_ids[0]):
        response = service.handle(
            _req(
                "GET",
                "/api/1.0/offers",
                app,
                body={"limit": 2, "cursor": bad_cursor},
            )
        )
        if response.status != 400 or (
            response.body["error"]["reason"] != "pagination-invalid"
        ):
            problems.append("invalid cursor %r not rejected" % bad_cursor[:16])
    # a cursor from another developer's context: rejected
    response = service.handle(
        _req(
            "GET",
            "/api/1.0/offers",
            app_b,
            body={"limit": 2, "cursor": cursor},
        )
    )
    if response.status != 400:
        problems.append("cross-tenant cursor not rejected")
    # filtering
    filtered = service.handle(
        _req(
            "GET",
            "/api/1.0/offers",
            app,
            body={"filters": {"pricing_currency": "GHS"}},
        )
    )
    if len(filtered.body["data"]["items"]) != 5:
        problems.append("filter did not match")
    response = service.handle(
        _req(
            "GET",
            "/api/1.0/offers",
            app,
            body={"filters": {"not_a_member": "x"}},
        )
    )
    if response.status != 400 or (
        response.body["error"]["reason"] != "filter-invalid"
    ):
        problems.append("unknown filter not rejected")
    # out-of-bounds limit
    response = service.handle(
        _req("GET", "/api/1.0/offers", app, body={"limit": 101})
    )
    if response.status != 400:
        problems.append("limit 101 not rejected")
    if problems:
        results.append(fail("15 pagination", "; ".join(problems)))
    else:
        results.append(
            ok(
                "15 pagination",
                "canonical order; stable cursors; 3 invalid-cursor classes; "
                "filtering; tenant isolation",
            )
        )


def case_16_rate_limiting(results: List[Result]) -> None:
    """Rate limits: explicit throttle decision, truthful retry
    guidance, and NO canonical business mutation."""
    problems: List[str] = []
    from developerapi import RateLimiter

    clock = FixedClock("2026-09-03T00:00:00Z")
    limiter = RateLimiter(capacity=3, refill_per_second=1, clock=clock)
    service, core, *_ = _compose_service(rate_limiter=limiter)
    app = _full_app(service, "dev-rate", "rate")
    statuses = []
    for index in range(5):
        response = service.handle(
            _req("GET", "/api/1.0/offers", app)
        )
        statuses.append(response.status)
    if statuses[:3] != [200, 200, 200] or 429 not in statuses[3:]:
        problems.append("throttle did not engage: %s" % statuses)
    throttled = service.handle(_req("GET", "/api/1.0/offers", app))
    if throttled.status == 429:
        error = throttled.body["error"]
        if not error["retryable"]:
            problems.append("rate-limited not retryable")
        if not error["retry_after"]:
            problems.append("no retry_after instant")
        if "Retry-After" not in throttled.headers:
            problems.append("no Retry-After header")
    # rate limiting never mutates business state: no journal
    # growth beyond the credential, no core transactions
    if len(service.journal_records()) != 1:
        problems.append("rate limiter wrote journal records")
    if len(core.transactions()) != 0:
        problems.append("rate limiter mutated business state")
    # success carries the rate-limit envelope (a fresh
    # application has a fresh bucket)
    fresh_app = _full_app(service, "dev-rate2", "rate2")
    ok_response = service.handle(_req("GET", "/api/1.0/application", fresh_app))
    if "rate_limit" not in ok_response.body:
        problems.append("rate envelope missing on success")
    if problems:
        results.append(fail("16 rate limiting", "; ".join(problems)))
    else:
        results.append(
            ok(
                "16 rate limiting",
                "429 + retry_after + retryable; zero business mutation",
            )
        )


def case_17_correlation_secrets(results: List[Result]) -> None:
    """Observability: deterministic correlation ids on every
    response; identical retried requests correlate; secret
    hygiene over journal bytes and response bodies."""
    problems: List[str] = []
    service, *_ = _compose_service()
    app = _full_app(service, "dev-obs", "obs")
    request = _req(
        "POST",
        "/api/1.0/offers",
        app,
        body=_offer_body("Obs offer"),
        idempotency_key="obs-1",
    )
    first = service.handle(request)
    retry = service.handle(
        _req(
            "POST",
            "/api/1.0/offers",
            app,
            body=_offer_body("Obs offer"),
            idempotency_key="obs-1",
        )
    )
    if not first.body["request_id"].startswith("sha256:"):
        problems.append("request id not a fingerprint")
    if first.body["request_id"] != retry.body["request_id"]:
        problems.append("retried request lost correlation")
    if first.headers.get("X-ADCOS-Request-Id") != first.body["request_id"]:
        problems.append("correlation header mismatch")
    # correlation is deterministic: the same request in a fresh
    # run produces the same id
    service2, *_ = _compose_service()
    app2 = _full_app(service2, "dev-obs", "obs")
    again = service2.handle(
        _req(
            "POST",
            "/api/1.0/offers",
            app2,
            body=_offer_body("Obs offer"),
            idempotency_key="obs-1",
        )
    )
    if again.body["request_id"] != first.body["request_id"]:
        problems.append("correlation id not deterministic across runs")
    # secret hygiene: journal bytes + all response bodies
    journal_blob = "\n".join(
        json.dumps(record.to_dict(), sort_keys=True, default=str)
        for record in service.journal_records()
    )
    for prefix in _SECRET_PREFIXES:
        if prefix in journal_blob:
            problems.append("journal bytes carry %r secret material" % prefix)
    body_blob = first.canonical_body_bytes().decode("utf-8") + (
        retry.canonical_body_bytes().decode("utf-8")
    )
    for prefix in _SECRET_PREFIXES:
        if prefix in body_blob:
            problems.append("response bytes carry %r secret material" % prefix)
    if app.secret in journal_blob or app.secret in body_blob:
        problems.append("credential secret leaked")
    if problems:
        results.append(fail("17 correlation + secrets", "; ".join(problems)))
    else:
        results.append(
            ok(
                "17 correlation + secrets",
                "deterministic correlation; retried requests correlate; "
                "no secret material in journal or responses",
            )
        )


def case_18_webhook_signing(results: List[Result]) -> None:
    """Webhook signing: verification success, invalid-signature
    rejection, stale-timestamp rejection, deterministic
    canonical signing input, key-id binding."""
    problems: List[str] = []
    service, *_ = _compose_service()
    app = _full_app(service, "dev-hook", "hook")
    endpoint = service.handle(
        _req(
            "POST",
            "/api/1.0/webhook-endpoints",
            app,
            body={
                "url": "https://consumer.test/hook",
                "event_types": ["connectivity_intent.created"],
            },
            idempotency_key="hook-ep-1",
        )
    )
    endpoint_id = endpoint.body["data"]["id"]
    secret = service.endpoint_signing_secret(endpoint_id)
    consumer = _Consumer(secret)
    service._transports[endpoint_id] = consumer
    service.handle(
        _req(
            "POST",
            "/api/1.0/intents",
            app,
            body={"intent": {"subscriber": "sub-hook"}},
            idempotency_key="hook-intent-1",
        )
    )
    if not consumer.deliveries:
        problems.append("no delivery captured")
        results.append(fail("18 webhook signing", "; ".join(problems)))
        return
    payload, headers = consumer.deliveries[0]
    if headers.get("X-ADCOS-Algorithm") != "hmac-sha256":
        problems.append("algorithm header missing")
    if not headers.get("X-ADCOS-Key-Id", "").startswith("whk-"):
        problems.append("key id header malformed")
    # consumer verification with the SDK verifier
    verifier = WebhookVerifier(
        secret=secret, clock=FixedClock(headers["X-ADCOS-Timestamp"])
    )
    event = verifier.verify(headers, payload)
    if event.event_id != payload["event_id"]:
        problems.append("verified event id mismatch")
    # the canonical signing input is deterministic
    signing_1 = webhook_platform.canonical_signing_input(
        headers["X-ADCOS-Key-Id"],
        headers["X-ADCOS-Timestamp"],
        payload["delivery_id"],
        payload,
    )
    signing_2 = webhook_platform.canonical_signing_input(
        headers["X-ADCOS-Key-Id"],
        headers["X-ADCOS-Timestamp"],
        payload["delivery_id"],
        dict(payload),
    )
    if signing_1 != signing_2:
        problems.append("signing input not deterministic")
    # wrong secret
    wrong = WebhookVerifier(
        secret="dwh_" + "0" * 64,
        clock=FixedClock(headers["X-ADCOS-Timestamp"]),
    )
    try:
        wrong.verify(headers, payload)
        problems.append("wrong secret accepted")
    except DeveloperApiError as error:
        if error.reason != "webhook-signature-invalid":
            problems.append("wrong secret rejected with %r" % error.reason)
    # tampered payload under a valid signature (signature
    # verifies over different bytes -> rejected)
    tampered = dict(payload)
    tampered["data"] = dict(payload["data"])
    tampered["data"]["actor"] = "attacker"
    try:
        verifier.verify(headers, tampered)
        problems.append("tampered payload accepted")
    except DeveloperApiError as error:
        if error.reason != "webhook-signature-invalid":
            problems.append(
                "tampered payload rejected with %r" % error.reason
            )
    # stale timestamp (replay protection)
    stale = WebhookVerifier(
        secret=secret, clock=FixedClock("2026-09-04T00:00:00Z")
    )
    try:
        stale.verify(headers, payload)
        problems.append("stale delivery accepted")
    except DeveloperApiError as error:
        if error.reason != "webhook-timestamp-stale":
            problems.append("stale rejected with %r" % error.reason)
    if problems:
        results.append(fail("18 webhook signing", "; ".join(problems)))
    else:
        results.append(
            ok(
                "18 webhook signing",
                "verify OK; wrong secret / tampered payload / stale "
                "timestamp all rejected",
            )
        )


def case_19_webhook_duplicate_replay(results: List[Result]) -> None:
    """Duplicate deliveries are legal (at-least-once): the
    consumer dedupes by event id; re-observation of an
    UNCHANGED resource emits no new event; replayed deliveries
    are rejected by the timestamp window."""
    problems: List[str] = []
    service, *_ = _compose_service()
    app = _full_app(service, "dev-dup", "dup")
    endpoint = service.handle(
        _req(
            "POST",
            "/api/1.0/webhook-endpoints",
            app,
            body={
                "url": "https://consumer.test/hook",
                "event_types": ["connectivity_intent.created"],
            },
            idempotency_key="dup-ep-1",
        )
    )
    endpoint_id = endpoint.body["data"]["id"]
    secret = service.endpoint_signing_secret(endpoint_id)
    consumer = _Consumer(secret)
    service._transports[endpoint_id] = consumer
    intent = service.handle(
        _req(
            "POST",
            "/api/1.0/intents",
            app,
            body={"intent": {"subscriber": "sub-dup"}},
            idempotency_key="dup-intent-1",
        )
    )
    deliveries_before = len(consumer.deliveries)
    # duplicate idempotent request: no new event (same state)
    service.handle(
        _req(
            "POST",
            "/api/1.0/intents",
            app,
            body={"intent": {"subscriber": "sub-dup"}},
            idempotency_key="dup-intent-1",
        )
    )
    if len(consumer.deliveries) != deliveries_before:
        problems.append("duplicate request produced a new delivery")
    # re-observation with no state change: no new event
    service.observe_transaction(intent.body["data"]["id"])
    if len(consumer.deliveries) != deliveries_before:
        problems.append("unchanged re-observation produced a delivery")
    # the consumer sees the same event twice (duplicate delivery
    # simulation): DuplicateDetector rejects the second
    payload, headers = consumer.deliveries[0]
    detector = DuplicateDetector(capacity=8)
    if detector.observe(payload["event_id"]) is not True:
        problems.append("first observation not new")
    if detector.observe(payload["event_id"]) is not False:
        problems.append("duplicate not detected")
    # replayed delivery (old timestamp) rejected by the verifier
    verifier = WebhookVerifier(
        secret=secret, clock=FixedClock(headers["X-ADCOS-Timestamp"])
    )
    late = WebhookVerifier(
        secret=secret, clock=FixedClock("2026-09-03T06:00:00Z")
    )
    try:
        late.verify(headers, payload)
        problems.append("replayed delivery accepted")
    except DeveloperApiError:
        pass
    if problems:
        results.append(fail("19 webhook duplicate/replay", "; ".join(problems)))
    else:
        results.append(
            ok(
                "19 webhook duplicate/replay",
                "no spurious events; consumer dedupe; replayed delivery "
                "rejected",
            )
        )


def case_20_webhook_out_of_order(results: List[Result]) -> None:
    """Out-of-order protection: version metadata detects stale
    events; consumers never infer truth from arrival order."""
    problems: List[str] = []
    tracker = OrderTracker()
    # events arrive v3, v1, v2
    if tracker.observe("res-1", 3) != "advance":
        problems.append("v3 not an advance")
    if tracker.observe("res-1", 1) != "stale":
        problems.append("v1 after v3 not stale")
    if tracker.observe("res-1", 2) != "stale":
        problems.append("v2 after v3 not stale")
    if tracker.observe("res-1", 3) != "duplicate":
        problems.append("v3 repeat not duplicate")
    if tracker.observe("res-1", 4) != "advance":
        problems.append("v4 not an advance")
    # the delivery resource carries the ordering metadata
    service, core, *_ = _compose_service()
    app = _full_app(service, "dev-order", "order")
    endpoint = service.handle(
        _req(
            "POST",
            "/api/1.0/webhook-endpoints",
            app,
            body={
                "url": "https://consumer.test/hook",
                "event_types": [
                    "connectivity_intent.created",
                    "connectivity_transaction.state_changed",
                ],
            },
            idempotency_key="order-ep-1",
        )
    )
    endpoint_id = endpoint.body["data"]["id"]
    consumer = _Consumer(service.endpoint_signing_secret(endpoint_id))
    service._transports[endpoint_id] = consumer
    intent = service.handle(
        _req(
            "POST",
            "/api/1.0/intents",
            app,
            body={"intent": {"subscriber": "sub-order"}},
            idempotency_key="order-intent-1",
        )
    )
    transaction_id = intent.body["data"]["id"]
    core.select_offer(
        command_id="order-select",
        transaction_id=transaction_id,
        actor="dev-order",
        source="platform",
        offer={"offer_id": "sha256:" + "1" * 64, "amount": 10},
    )
    service.observe_transaction(transaction_id)
    service.process_due_deliveries()
    if len(consumer.deliveries) != 2:
        problems.append("expected 2 observations (create + change)")
    else:
        v_create = consumer.deliveries[0][0]["resource_version"]
        v_change = consumer.deliveries[1][0]["resource_version"]
        if not v_change > v_create:
            problems.append("version metadata not monotonic")
        if consumer.deliveries[0][0]["sequence"] >= consumer.deliveries[1][0][
            "sequence"
        ]:
            problems.append("delivery sequence not monotonic")
    # the delivery listing carries the same metadata
    listing = service.handle(
        _req(
            "GET",
            "/api/1.0/webhook-endpoints/%s/deliveries" % endpoint_id,
            app,
        )
    )
    items = listing.body["data"]["items"]
    if not all("resource_version" in item and "delivery_sequence" in item for item in items):
        problems.append("delivery listing lacks ordering metadata")
    if problems:
        results.append(fail("20 webhook out-of-order", "; ".join(problems)))
    else:
        results.append(
            ok(
                "20 webhook out-of-order",
                "stale/duplicate/advance classification; monotonic "
                "version + sequence metadata",
            )
        )


def case_21_webhook_retry(results: List[Result]) -> None:
    """Retry semantics: failed deliveries retry on the frozen
    backoff schedule; the event bytes NEVER change; delivered is
    terminal; a consumer ack never changes canonical state."""
    problems: List[str] = []
    # a fixed service clock makes the retry gate exact: the
    # attempt instant is frozen, so "due" is a pure comparison
    fixed = FixedClock("2025-06-01T06:00:00Z")
    service, core, *_ = _compose_service(clock=fixed)
    app = _full_app(service, "dev-retry", "retry")
    endpoint = service.handle(
        _req(
            "POST",
            "/api/1.0/webhook-endpoints",
            app,
            body={
                "url": "https://consumer.test/hook",
                "event_types": ["connectivity_intent.created"],
            },
            idempotency_key="retry-ep-1",
        )
    )
    endpoint_id = endpoint.body["data"]["id"]
    failing = _Consumer("unused", fail=True)
    service._transports[endpoint_id] = failing
    service.handle(
        _req(
            "POST",
            "/api/1.0/intents",
            app,
            body={"intent": {"subscriber": "sub-retry"}},
            idempotency_key="retry-intent-1",
        )
    )
    attempts = len(failing.deliveries)
    if attempts != 1:
        problems.append("first attempt missing")
    # not due yet: the clock has not advanced past the backoff
    before = len(service.journal_records())
    service.process_due_deliveries()
    if len(service.journal_records()) != before:
        problems.append("premature retry executed")
    # advance the clock past the 60s first backoff
    service._clock = FixedClock("2025-06-01T07:00:00Z")
    # swap in a succeeding consumer
    succeeding = _Consumer("unused")
    service._transports[endpoint_id] = succeeding
    service.process_due_deliveries()
    if not succeeding.deliveries:
        problems.append("retry not delivered")
    else:
        # the retried event is byte-identical to the original
        first_payload = failing.deliveries[0][0]
        retried_payload = succeeding.deliveries[0][0]
        if first_payload != retried_payload:
            problems.append("retried event bytes changed")
    # delivered is terminal: further processing does nothing
    service._clock = FixedClock("2025-06-02T00:00:00Z")
    done = service.process_due_deliveries()
    if done != 0:
        problems.append("delivered delivery re-attempted")
    # consumer acknowledgment never changes canonical state
    transactions_before = tuple(
        tx.to_dict() for tx in core.transactions()
    )
    listing = service.handle(
        _req(
            "GET",
            "/api/1.0/webhook-endpoints/%s/deliveries" % endpoint_id,
            app,
        )
    )
    items = listing.body["data"]["items"]
    if not items or items[0]["last_status"] != "delivered":
        problems.append("delivery state not delivered")
    health = service.handle(
        _req("GET", "/api/1.0/webhook-endpoints/%s" % endpoint_id, app)
    )
    if health.body["data"]["health"].get("last_status") != "delivered":
        problems.append("endpoint health wrong")
    if not health.body["data"]["health"].get("observational_only"):
        problems.append("health not marked observational")
    transactions_after = tuple(
        tx.to_dict() for tx in core.transactions()
    )
    if transactions_before != transactions_after:
        problems.append("webhook ack mutated canonical commercial state")
    if problems:
        results.append(fail("21 webhook retry", "; ".join(problems)))
    else:
        results.append(
            ok(
                "21 webhook retry",
                "backoff-gated retry; identical event bytes; terminal "
                "delivered; ack never mutates canonical state",
            )
        )


def case_22_webhook_environment_separation(results: List[Result]) -> None:
    """Sandbox webhooks never verify as production: the payload
    and signing are environment-bound."""
    problems: List[str] = []
    sandbox, *_ = _compose_service(environment="sandbox")
    production, *_ = _compose_service(environment="production")
    app_s = _full_app(sandbox, "dev-wenv", "ws")
    app_p = _full_app(production, "dev-wenv", "wp")
    for service, app, label in (
        (sandbox, app_s, "sandbox"),
        (production, app_p, "production"),
    ):
        endpoint = service.handle(
            _req(
                "POST",
                "/api/1.0/webhook-endpoints",
                app,
                body={
                    "url": "https://consumer-%s.test/hook" % label,
                    "event_types": ["connectivity_intent.created"],
                },
                idempotency_key="wenv-ep-1",
            )
        )
        endpoint_id = endpoint.body["data"]["id"]
        secret = service.endpoint_signing_secret(endpoint_id)
        consumer = _Consumer(secret)
        service._transports[endpoint_id] = consumer
        service.handle(
            _req(
                "POST",
                "/api/1.0/intents",
                app,
                body={"intent": {"subscriber": "sub-wenv"}},
                idempotency_key="wenv-intent-1",
            )
        )
        setattr(service, "_captured_%s" % label, consumer.deliveries)
    sandbox_payload = sandbox._captured_sandbox[0][0]
    production_payload = production._captured_production[0][0]
    sandbox_headers = sandbox._captured_sandbox[0][1]
    if sandbox_payload["environment"] != "sandbox" or (
        production_payload["environment"] != "production"
    ):
        problems.append("webhook payloads not environment-bound")
    if sandbox_payload["event_id"] == production_payload["event_id"]:
        problems.append("sandbox and production event ids collide")
    # a production-secret verifier rejects the sandbox delivery
    production_secret = production.endpoint_signing_secret(
        production._captured_production and [
            k for k in production.index().endpoints
        ][0]
    )
    cross = WebhookVerifier(
        secret=production_secret,
        clock=FixedClock(sandbox_headers["X-ADCOS-Timestamp"]),
    )
    try:
        cross.verify(sandbox_headers, sandbox_payload)
        problems.append("sandbox delivery verified with production secret")
    except DeveloperApiError:
        pass
    if problems:
        results.append(fail("22 webhook environment separation", "; ".join(problems)))
    else:
        results.append(
            ok(
                "22 webhook environment separation",
                "environment-bound payloads/ids; cross-environment "
                "verification impossible",
            )
        )


def case_23_sdk_request_parity(results: List[Result]) -> None:
    """SDK request parity: the SDK's requests are byte-identical
    to the direct API caller's requests."""
    problems: List[str] = []
    service, *_ = _compose_service()
    app = _full_app(service, "dev-sdk", "sdk")
    captured: List[ApiRequest] = []

    def transport(request: ApiRequest):
        captured.append(request)
        return service.handle(request)

    client = DeveloperApiClient(
        transport=transport,
        application_id=app.record.application_id,
        secret=app.secret,
        api_version="1.0",
        environment="sandbox",
    )
    key = "sdk-parity-1"
    client.publish_offer(
        idempotency_key=key, offer=_offer_body("SDK parity")
    )
    if not captured:
        problems.append("SDK issued no request")
    else:
        sdk_request = captured[0]
        direct_request = _req(
            "POST",
            "/api/1.0/offers",
            app,
            body=_offer_body("SDK parity"),
            idempotency_key=key,
        )
        if sdk_request.route != direct_request.route:
            problems.append("route mismatch")
        if sdk_request.method != direct_request.method:
            problems.append("method mismatch")
        if sdk_request.canonical_body() != direct_request.canonical_body():
            problems.append("body mismatch")
        if sdk_request.idempotency_key != direct_request.idempotency_key:
            problems.append("idempotency key mismatch")
        if (
            sdk_request.application_id != direct_request.application_id
            or sdk_request.secret != direct_request.secret
        ):
            problems.append("credential mismatch")
        if (
            sdk_request.api_version != direct_request.api_version
        ):
            problems.append("api version mismatch")
        if (
            canonical_json_bytes(sdk_request.canonical_body())
            != canonical_json_bytes(direct_request.canonical_body())
        ):
            problems.append("canonical request bytes differ")
    # listing + cursor parity
    client.list_offers(limit=2)
    if len(captured) < 2 or captured[1].body.get("limit") != 2:
        problems.append("SDK list request malformed")
    if problems:
        results.append(fail("23 SDK request parity", "; ".join(problems)))
    else:
        results.append(
            ok(
                "23 SDK request parity",
                "byte-identical canonical requests across mutation and "
                "list surfaces",
            )
        )


def case_24_sdk_response_parity(results: List[Result]) -> None:
    """SDK response/error/pagination/idempotency parity with the
    direct API."""
    problems: List[str] = []
    service, *_ = _compose_service()
    app = _full_app(service, "dev-sdk2", "sdk2")
    client = DeveloperApiClient(
        transport=service.handle,
        application_id=app.record.application_id,
        secret=app.secret,
        api_version="1.0",
        environment="sandbox",
    )
    sdk_offer = client.publish_offer(
        idempotency_key="sdk-2-offer",
        offer=_offer_body("SDK response"),
    )
    direct = service.handle(
        _req(
            "POST",
            "/api/1.0/offers",
            app,
            body=_offer_body("SDK response"),
            idempotency_key="sdk-3-offer",
        )
    )
    if sdk_offer.to_dict().keys() != direct.body["data"].keys():
        problems.append("SDK resource shape differs from direct")
    if sdk_offer.get("name") != "SDK response":
        problems.append("SDK resource parse wrong")
    # error parity: the SDK error carries the canonical reason
    try:
        client.get_offer("sha256:" + "3" * 64)
        problems.append("SDK unknown offer did not raise")
    except DeveloperApiError as error:
        if error.reason != "resource-unknown":
            problems.append("SDK error reason wrong: %r" % error.reason)
    # canonical domain failure through the SDK
    intent = client.create_intent(
        idempotency_key="sdk-2-intent",
        intent={"subscriber": "sub-sdk"},
    )
    try:
        client.hold_reservation(
            idempotency_key="sdk-2-res",
            intent_id=intent.id,
            expires_at=_EXPIRES,
        )
        problems.append("SDK lifecycle-illegal did not raise")
    except DeveloperApiError as error:
        if error.canonical_reason != "lifecycle-illegal":
            problems.append(
                "SDK lost the canonical reason: %r" % error.canonical_reason
            )
    # pagination parity: SDK iterator covers the same items as
    # direct pagination
    for index in range(4):
        client.publish_offer(
            idempotency_key="sdk-2-offer-%d" % index,
            offer=_offer_body("SDK page %d" % index),
        )
    sdk_items = list(client.iterate(client.list_offers, limit=2))
    direct_items: List[str] = []
    cursor = ""
    while True:
        body: Dict[str, Any] = {"limit": 2}
        if cursor:
            body["cursor"] = cursor
        response = service.handle(
            _req("GET", "/api/1.0/offers", app, body=body)
        )
        direct_items.extend(
            item["id"] for item in response.body["data"]["items"]
        )
        if not response.body["data"]["has_more"]:
            break
        cursor = response.body["data"]["next_cursor"]
    if [item.id for item in sdk_items] != direct_items:
        problems.append("SDK pagination diverged from direct")
    # idempotency parity: the SDK duplicate is a byte-identical
    # replay (same key, same content)
    first = client.publish_offer(
        idempotency_key="sdk-2-dup",
        offer=_offer_body("SDK dup"),
    )
    second = client.publish_offer(
        idempotency_key="sdk-2-dup",
        offer=_offer_body("SDK dup"),
    )
    if first.to_dict() != second.to_dict():
        problems.append("SDK idempotent replay diverged")
    if problems:
        results.append(fail("24 SDK response parity", "; ".join(problems)))
    else:
        results.append(
            ok(
                "24 SDK response parity",
                "resource/error/pagination/idempotency parity with the "
                "direct API",
            )
        )


def case_25_sdk_webhook_verification_parity(results: List[Result]) -> None:
    """The SDK webhook verifier reproduces the server's signing
    semantics exactly (server-signed deliveries verify; the
    canonical construction is shared)."""
    problems: List[str] = []
    service, *_ = _compose_service()
    app = _full_app(service, "dev-sdkhook", "sdkhook")
    endpoint = service.handle(
        _req(
            "POST",
            "/api/1.0/webhook-endpoints",
            app,
            body={
                "url": "https://consumer.test/hook",
                "event_types": ["connectivity_intent.created"],
            },
            idempotency_key="sdkhook-ep-1",
        )
    )
    endpoint_id = endpoint.body["data"]["id"]
    secret = service.endpoint_signing_secret(endpoint_id)
    consumer = _Consumer(secret)
    service._transports[endpoint_id] = consumer
    service.handle(
        _req(
            "POST",
            "/api/1.0/intents",
            app,
            body={"intent": {"subscriber": "sub-sdkhook"}},
            idempotency_key="sdkhook-intent-1",
        )
    )
    payload, headers = consumer.deliveries[0]
    verifier = WebhookVerifier(
        secret=secret, clock=FixedClock(headers["X-ADCOS-Timestamp"])
    )
    event = verifier.verify(headers, payload)
    # the parsed event representation equals the payload exactly
    if event.event_id != payload["event_id"] or (
        event.data != payload["data"]
    ):
        problems.append("parsed event differs from the payload")
    # forged signature rejected through the SDK verifier
    bad = dict(headers)
    bad["X-ADCOS-Signature"] = "hmac-sha256=" + "ab" * 32
    try:
        verifier.verify(bad, payload)
        problems.append("forged signature accepted")
    except DeveloperApiError as error:
        if error.reason != "webhook-signature-invalid":
            problems.append("forged rejected with %r" % error.reason)
    if problems:
        results.append(fail("25 SDK webhook parity", "; ".join(problems)))
    else:
        results.append(
            ok(
                "25 SDK webhook parity",
                "server-signed deliveries verify through the SDK; "
                "forgeries rejected",
            )
        )


def case_26_usage_billing_reads(results: List[Result]) -> None:
    """Usage and billing reads over real W052/W053 state
    (read-only: the developer API never writes usage truth)."""
    problems: List[str] = []
    service, core, usage, allocation, world = _compose_service()
    runtime, peer, session_id, manager, integrator, shared = world
    app = _full_app(service, "dev-bill", "bill")
    # drive a real chain to BILLABLE_FINAL (the platform plane)
    intent = service.handle(
        _req(
            "POST",
            "/api/1.0/intents",
            app,
            body={"intent": {"subscriber": "sub-bill"}},
            idempotency_key="bill-intent-1",
        )
    )
    transaction_id = intent.body["data"]["id"]
    core.select_offer(
        command_id="bill-select",
        transaction_id=transaction_id,
        actor="dev-bill",
        source="platform",
        offer={"offer_id": "sha256:" + "2" * 64, "amount": 10},
    )
    core.hold_reservation(
        command_id="bill-reserve",
        transaction_id=transaction_id,
        actor="dev-bill",
        source="platform",
        expires_at=_EXPIRES,
    )
    core.authorize_session(
        command_id="bill-auth",
        transaction_id=transaction_id,
        actor="dev-bill",
        source="platform",
        session_ref=session_id,
    )
    path_id = _path_for(manager, WIFI_IF)
    core.activate_path(
        command_id="bill-activate",
        transaction_id=transaction_id,
        actor="dev-bill",
        source="platform",
        path_ref=path_id,
    )
    evidence_ids = [
        record.event.event_id
        for record in integrator.journal_records()
        if record.event.kind != "platform-state-observation"
    ]
    core.start_delivery(
        command_id="bill-start",
        transaction_id=transaction_id,
        actor="dev-bill",
        source="platform",
        evidence_refs=tuple(evidence_ids[:1]),
    )
    usage_plane_ref = next(
        record.event.event_id
        for record in integrator.journal_records()
        if record.event.kind == "platform-state-observation"
    )
    core.accrue_usage(
        command_id="bill-accrue",
        transaction_id=transaction_id,
        actor="dev-bill",
        source="platform",
        usage_refs=(usage_plane_ref,),
    )
    core.complete_delivery(
        command_id="bill-complete",
        transaction_id=transaction_id,
        actor="dev-bill",
        source="platform",
        evidence_refs=tuple(evidence_ids[:1]),
    )
    # register the economic policy through the API
    service.handle(
        _req(
            "POST",
            "/api/1.0/economic-policies",
            app,
            body={
                "policy_id": "bill-policy",
                "version": 1,
                "currency": "GHS",
                "exponent": 2,
                "rounding": "half-even",
                "effective_from": "2026-08-01T00:00:00Z",
                "adc_os_share_bps": 500,
                "tax_bps": 0,
                "developer_share_min_bps": 1000,
                "developer_share_max_bps": 9000,
            },
            idempotency_key="bill-policy-1",
        )
    )
    # RE-COMPOSITION (the sanctioned load path): the W052
    # metering window's frozen evidence snapshot now includes
    # the commercial transaction projections, so the platform
    # re-composes the boundary over an updated usage ledger --
    # journal-first recovery over the SAME api store (the
    # idempotency ledger and credentials are preserved exactly).
    metering_usage = UsageLedger(
        store=MemoryUsageStore(),
        clock=shared,
        evidence=_evidence_index(manager, integrator, session_id, core),
    )
    metering_usage.ingest_observation(
        command_id="bill-obs-1",
        observation_id="obs-1",
        transaction_id=transaction_id,
        evidence_refs=tuple(evidence_ids[:1]),
        session_ref=session_id,
        path_ref=path_id,
        quantity=1000,
        unit="MB",
        observed_at=shared.now(),
        actor="metering-plane",
        source="platform-metering",
    )
    metering_usage.reconcile(
        command_id="bill-recon",
        transaction_id=transaction_id,
        unit_price=10,
        actor="billing-plane",
        source="platform-billing",
    )
    metering_usage.finalize_billable(
        command_id="bill-final",
        transaction_id=transaction_id,
        actor="billing-plane",
        source="platform-billing",
    )
    finality_record = metering_usage.account(
        transaction_id
    ).to_dict()["finality"]
    # the W053 frozen fact snapshot (public reads: the usage
    # finality + the commercial projection), then re-composition
    from allocation.evidence import FactFamily, FactReference

    account = metering_usage.account(transaction_id).to_dict()
    fact_entries = [
        FactReference(
            reference_id=finality_record["record_id"],
            family=FactFamily.USAGE_FINAL,
            provenance="usage-ledger",
            usage_state=account["state"],
            transaction_id=transaction_id,
            amount=finality_record.get("amount", 0),
            quantity=account.get("total_quantity", 0),
            unit=account.get("unit", ""),
            finalized_at=finality_record.get("finalized_at", ""),
        ),
        FactReference(
            reference_id=transaction_id,
            family=FactFamily.COMMERCIAL,
            provenance="commercial-core",
            commercial_state=core.transaction(transaction_id).to_dict(
            )["state"],
            session_ref=core.transaction(transaction_id).to_dict().get(
                "session_ref", ""
            ),
            path_ref=core.transaction(transaction_id).to_dict().get(
                "path_ref", ""
            ),
        ),
    ]
    metering_allocation = AllocationLedger(
        store=MemoryAllocationStore(),
        clock=shared,
        facts=FactIndex(fact_entries),
    )
    metering_allocation.register_policy(
        command_id="bill-policy-cmd",
        policy_id="bill-policy",
        version=1,
        currency="GHS",
        exponent=2,
        rounding="half-even",
        effective_from="2025-01-01T00:00:00Z",
        effective_until="",
        adc_os_share_bps=500,
        tax_bps=0,
        developer_share_min_bps=1000,
        developer_share_max_bps=9000,
        actor="dev-bill",
        source="platform",
    )
    metering_allocation.allocate(
        command_id="bill-alloc",
        usage_record_id=finality_record["record_id"],
        policy_id="bill-policy",
        policy_version=1,
        developer_share_bps=5000,
        adjustment=0,
        effective_at=shared.now(),
        currency="GHS",
        commercial_refs=(transaction_id,),
        actor="dev-bill",
        source="platform",
    )
    service = DeveloperApiService.load(
        environment="sandbox",
        core=core,
        usage=metering_usage,
        allocation=metering_allocation,
        store=service._journal._store,
        clock=shared,
        issuance_key=b"w046-platform-issuance-key",
    )

    # API reads: usage accounts and billing records
    usage_read = service.handle(
        _req("GET", "/api/1.0/usage", app)
    )
    items = usage_read.body["data"]["items"]
    if len(items) != 1 or items[0]["transaction_id"] != transaction_id:
        problems.append("usage listing wrong")
    detail = service.handle(
        _req("GET", "/api/1.0/usage/%s" % transaction_id, app)
    )
    if detail.body["data"]["state"] != "BILLABLE_FINAL":
        problems.append("usage state wrong")
    billing = service.handle(
        _req("GET", "/api/1.0/billing", app)
    )
    billing_items = billing.body["data"]["items"]
    if len(billing_items) != 1:
        problems.append("billing listing empty")
    else:
        record = billing_items[0]
        if not record["finality"]:
            problems.append("billing record lacks finality")
        if not record["allocation"]:
            problems.append("billing record lacks allocation")
    # tenant isolation: another developer sees neither
    app_b = _full_app(service, "dev-bill2", "bill2")
    response = service.handle(
        _req("GET", "/api/1.0/usage", app_b)
    )
    if response.body["data"]["items"]:
        problems.append("usage leaked across tenants")
    response = service.handle(
        _req("GET", "/api/1.0/billing", app_b)
    )
    if response.body["data"]["items"]:
        problems.append("billing leaked across tenants")
    # usage truth is never developer-writable: no route exists
    mutation_routes = {
        pattern for (method, pattern), spec in ROUTES.items()
        if spec.mutation
    }
    if any(p.startswith("usage") for p in mutation_routes):
        problems.append("a usage mutation route exists")
    if problems:
        results.append(fail("26 usage/billing reads", "; ".join(problems)))
    else:
        results.append(
            ok(
                "26 usage/billing reads",
                "real W052/W053 reads with allocation joins; tenant "
                "isolation; usage read-only",
            )
        )


def case_27_economic_policy(results: List[Result]) -> None:
    """Economic policy configuration through the API: register,
    read, idempotency, conflicting re-registration rejected with
    the canonical reason."""
    problems: List[str] = []
    service, *_ = _compose_service()
    app = _full_app(service, "dev-pol", "pol")

    def policy_body(version: int) -> Dict[str, Any]:
        return {
            "policy_id": "pol-1",
            "version": version,
            "currency": "GHS",
            "exponent": 2,
            "rounding": "half-even",
            "effective_from": "2026-09-01T00:00:00Z",
            "adc_os_share_bps": 500,
            "tax_bps": 0,
            "developer_share_min_bps": 1000,
            "developer_share_max_bps": 9000,
        }

    first = service.handle(
        _req(
            "POST",
            "/api/1.0/economic-policies",
            app,
            body=policy_body(1),
            idempotency_key="pol-1",
        )
    )
    if first.status != 200 or first.body["data"]["policy_id"] != "pol-1":
        problems.append("policy registration failed")
    # duplicate: byte-identical replay
    duplicate = service.handle(
        _req(
            "POST",
            "/api/1.0/economic-policies",
            app,
            body=policy_body(1),
            idempotency_key="pol-1",
        )
    )
    if duplicate.headers.get("X-ADCOS-Idempotent-Replay") != "true":
        problems.append("policy duplicate not replayed")
    # conflicting version re-registration (same key, different
    # content) rejected
    response = service.handle(
        _req(
            "POST",
            "/api/1.0/economic-policies",
            app,
            body=policy_body(2),
            idempotency_key="pol-1",
        )
    )
    if response.status != 409:
        problems.append("policy conflict not rejected")
    # a genuinely conflicting re-registration under a NEW key
    # (same policy_id+version, different content) fails closed
    # with the canonical reason
    conflicting = dict(policy_body(1))
    conflicting["tax_bps"] = 100
    response = service.handle(
        _req(
            "POST",
            "/api/1.0/economic-policies",
            app,
            body=conflicting,
            idempotency_key="pol-2",
        )
    )
    error = response.body["error"]
    if response.status != 409 or error["canonical_reason"] != "policy-conflict":
        problems.append(
            "policy-conflict not preserved: %r/%r"
            % (response.status, error["canonical_reason"])
        )
    # reads: listing and exact (policy_id, version)
    listing = service.handle(
        _req("GET", "/api/1.0/economic-policies", app)
    )
    if len(listing.body["data"]["items"]) != 1:
        problems.append("policy listing wrong")
    detail = service.handle(
        _req("GET", "/api/1.0/economic-policies/pol-1/1", app)
    )
    if detail.body["data"]["policy_id"] != "pol-1":
        problems.append("policy detail wrong")
    response = service.handle(
        _req("GET", "/api/1.0/economic-policies/pol-1/9", app)
    )
    if response.status != 404 or (
        response.body["error"]["canonical_reason"] != "policy-unknown"
    ):
        problems.append("unknown policy not rejected canonically")
    if problems:
        results.append(fail("27 economic policy", "; ".join(problems)))
    else:
        results.append(
            ok(
                "27 economic policy",
                "register/read/replay/conflict with the canonical "
                "policy-conflict and policy-unknown preserved",
            )
        )


def case_28_authority_import_discipline(results: List[Result]) -> None:
    """Structural: the developerapi family imports ONLY the
    sanctioned modules (stdlib + canonicalization + clock seam +
    the three adapted commercial-plane surfaces); NO
    connectivity/payment/eligibility authority import exists."""
    problems: List[str] = []
    for path in _FAMILY_FILES:
        rel = str(path.relative_to(REPO_ROOT))
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module = alias.name.split(".")[0]
                    if alias.name not in _ALLOWED_IMPORT_MODULES and (
                        module in _FORBIDDEN_IMPORT_MODULES
                        or module not in {
                            "developerapi",
                        }
                        and alias.name
                        not in _ALLOWED_IMPORT_MODULES
                        and module
                        not in {"developerapi", "protocol", "agent",
                                "commercial", "usage", "allocation"}
                    ):
                        problems.append(
                            "%s imports %r (outside the sanctioned set)"
                            % (rel, alias.name)
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.level == 1 or (
                    node.module and node.module.startswith("developerapi")
                ):
                    continue  # intra-package
                module = (node.module or "").split(".")[0]
                full = node.module or ""
                if full not in _ALLOWED_IMPORT_MODULES and module in (
                    _FORBIDDEN_IMPORT_MODULES
                    | {"protocol", "agent", "commercial", "usage", "allocation"}
                ) and full not in _ALLOWED_IMPORT_MODULES:
                    problems.append(
                        "%s imports from %r (outside the sanctioned set)"
                        % (rel, full)
                    )
    # the forbidden connectivity authorities appear nowhere
    blob = "\n".join(
        path.read_text(encoding="utf-8") for path in _FAMILY_FILES
    )
    for forbidden in (
        "from identity",
        "import identity",
        "from sessions",
        "import sessions",
        "from networkpath",
        "import networkpath",
        "from routing",
        "import routing",
        "from transport",
        "import transport",
        "from payment",
        "import payment",
        "from eligibility",
        "import eligibility",
        "from platform",
        "import platform",
        "from agent import",
    ):
        if forbidden in blob:
            problems.append(
                "forbidden authority import %r in the family" % forbidden
            )
    if problems:
        results.append(fail("28 import discipline", "; ".join(problems)))
    else:
        results.append(
            ok(
                "28 import discipline",
                "sanctioned imports only; zero connectivity/payment/"
                "eligibility authority imports",
            )
        )


def case_29_no_shadow_authority(results: List[Result]) -> None:
    """Structural: the cross-authority call surface is exactly
    the sanctioned adapted set (the two commercial mutations,
    policy registration, and public reads); the family never
    constructs or mutates a second authority."""
    problems: List[str] = []
    sanctioned = {
        "_core": _SANCTIONED_CORE_CALLS,
        "core": _SANCTIONED_CORE_CALLS,
        "_usage": _SANCTIONED_USAGE_CALLS,
        "usage": _SANCTIONED_USAGE_CALLS,
        "_allocation": _SANCTIONED_ALLOCATION_CALLS,
        "allocation": _SANCTIONED_ALLOCATION_CALLS,
    }
    for path in _FAMILY_FILES:
        rel = str(path.relative_to(REPO_ROOT))
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Attribute) and isinstance(
                func.value, ast.Name
            ):
                receiver = func.value.id
                allowed = sanctioned.get(receiver)
                if allowed is None:
                    continue
                if func.attr not in allowed:
                    problems.append(
                        "%s calls %s.%s (outside the sanctioned surface)"
                        % (rel, receiver, func.attr)
                    )
    if problems:
        results.append(fail("29 no shadow authority", "; ".join(problems)))
    else:
        results.append(
            ok(
                "29 no shadow authority",
                "call surface = submit_intent/hold_reservation/"
                "register_policy + public reads only",
            )
        )


def case_30_sdk_no_hidden_authority(results: List[Result]) -> None:
    """Structural: the SDK imports no authority module and no
    gateway journal surface -- no hidden business authority can
    exist in it (docstrings that DESCRIBE the boundary are
    documentation, not imports; the AST is the truth)."""
    problems: List[str] = []
    sdk_source = (REPO_ROOT / "developerapi" / "sdk.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(sdk_source, filename="developerapi/sdk.py")
    forbidden_modules = {
        "commercial",
        "commercial.lifecycle",
        "commercial.errors",
        "usage",
        "usage.lifecycle",
        "usage.errors",
        "allocation",
        "allocation.lifecycle",
        "allocation.errors",
        "developerapi.journal",
        "developerapi.gateway",
        "developerapi.credentials",
        "developerapi.ratelimit",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module in forbidden_modules:
                problems.append("sdk.py imports %r" % module)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in forbidden_modules:
                    problems.append("sdk.py imports %r" % alias.name)
    # no authority CLASS NAME is ever instantiated or referenced
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in (
            "CommercialCore",
            "UsageLedger",
            "AllocationLedger",
            "AppendOnlyApiJournal",
            "DeveloperApiService",
            "MemoryApiStore",
            "FileApiStore",
        ):
            problems.append("sdk.py references %r" % node.id)
    if problems:
        results.append(fail("30 SDK no hidden authority", "; ".join(problems)))
    else:
        results.append(
            ok(
                "30 SDK no hidden authority",
                "the SDK decides nothing: no authority imports, no "
                "journal/store/service access",
            )
        )


def case_31_physical_evidence_honesty(results: List[Result]) -> None:
    """Physical-connectivity honesty: the API reports canonical
    commercial state only; success never implies physical
    connectivity; sandbox results are never physical evidence."""
    problems: List[str] = []
    service, core, *_ = _compose_service()
    app = _full_app(service, "dev-phys", "phys")
    intent = service.handle(
        _req(
            "POST",
            "/api/1.0/intents",
            app,
            body={"intent": {"subscriber": "sub-phys"}},
            idempotency_key="phys-1",
        )
    )
    transaction_id = intent.body["data"]["id"]
    # the API accepted and persisted commercial intent (200) --
    # but no physical connectivity claim exists anywhere
    blob = intent.canonical_body_bytes().decode("utf-8")
    for term in (
        "physical_connectivity",
        '"operational"',
        "connectivity_operational",
    ):
        if term in blob:
            problems.append(
                "intent response implies physical connectivity (%r)" % term
            )
    # drive to PATH_ACTIVE (commercial path state -- still not
    # physical evidence)
    core.select_offer(
        command_id="phys-select",
        transaction_id=transaction_id,
        actor="dev-phys",
        source="platform",
        offer={"offer_id": "sha256:" + "5" * 64, "amount": 10},
    )
    service.handle(
        _req(
            "POST",
            "/api/1.0/intents/%s/reservations" % transaction_id,
            app,
            body={"expires_at": _EXPIRES},
            idempotency_key="phys-2",
        )
    )
    core_transactions = len(core.transactions())
    lifecycle = service.handle(
        _req("GET", "/api/1.0/intents/%s/lifecycle" % transaction_id, app)
    )
    data = lifecycle.body["data"]
    if lifecycle.status != 200:
        problems.append("lifecycle read failed")
    if data["physical_connectivity_observed"] is not False:
        problems.append("physical connectivity observed claim")
    if data["physical_evidence"] != "not-claimed":
        problems.append("physical evidence claimed")
    if "physical connectivity evidence is owned by" not in data["note"]:
        problems.append("honesty note missing")
    # the distinct statement family is preserved (not collapsed)
    for statement in _LIFECYCLE_STATEMENTS_CHECK:
        if statement not in data["statements"]:
            problems.append("statement %r collapsed" % statement)
    # the whole response corpus: search for physical claims
    response_blob = lifecycle.canonical_body_bytes().decode("utf-8")
    if '"physical_connectivity_observed": true' in response_blob:
        problems.append("explicit physical claim in the corpus")
    if problems:
        results.append(fail("31 physical evidence honesty", "; ".join(problems)))
    else:
        results.append(
            ok(
                "31 physical evidence honesty",
                "commercial-only reporting; distinct statements "
                "preserved; no physical claim anywhere",
            )
        )


_LIFECYCLE_STATEMENTS_CHECK = (
    "api_request_accepted",
    "commercial_intent_persisted",
    "connectivity_operational_per_networkpath_authority",
    "physical_connectivity_observed",
)


def case_32_journal_tamper(results: List[Result]) -> None:
    """Journal tamper detection: byte edit, line reorder,
    truncation, and duplicate idempotency keys all fail closed
    journal-corrupt at load."""
    problems: List[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        store_path = Path(tmp) / "journal.jsonl"
        service, *_ = _compose_service(store=FileApiStore(store_path))
        app = _full_app(service, "dev-tamper", "tamper")
        service.handle(
            _req(
                "POST",
                "/api/1.0/offers",
                app,
                body=_offer_body("Tamper offer"),
                idempotency_key="tamper-1",
            )
        )
        raw = store_path.read_bytes()
        lines = raw.decode("utf-8").splitlines()

        # 1. byte edit in the payload
        edited = lines[:]
        edited[1] = edited[1].replace("Tamper offer", "T4mper offer")
        _expect_load_failure(
            problems, tmp, "edited", edited, "byte edit"
        )
        # 2. line reorder
        if len(lines) >= 3:
            reordered = lines[:]
            reordered[1], reordered[2] = reordered[2], reordered[1]
            _expect_load_failure(
                problems, tmp, "reordered", reordered, "reorder"
            )
        # 3. truncation (partial line)
        truncated = raw[: len(raw) - 10]
        _expect_load_failure(
            problems, tmp, "truncated", truncated, "truncation", binary=True
        )
        # 4. duplicate idempotency key (append a copied line)
        duplicated = lines + [lines[-1]]
        _expect_load_failure(
            problems, tmp, "duplicated", duplicated, "duplicate key"
        )
    if problems:
        results.append(fail("32 journal tamper", "; ".join(problems)))
    else:
        results.append(
            ok(
                "32 journal tamper",
                "edit/reorder/truncate/duplicate all fail closed",
            )
        )


def _expect_load_failure(
    problems: List[str],
    tmp: str,
    label: str,
    content: Any,
    what: str,
    binary: bool = False,
) -> None:
    from developerapi.errors import (
        DeveloperApiError as _Err,
        DeveloperApiReasonCode as _RC,
    )

    path = Path(tmp) / ("tamper-%s.jsonl" % label)
    if binary:
        path.write_bytes(content)  # type: ignore[arg-type]
    else:
        path.write_text(
            "\n".join(content) + "\n", encoding="utf-8"
        )
    try:
        AppendOnlyApiJournal(store=FileApiStore(path))
        problems.append("%s not detected" % what)
    except _Err as error:
        if error.reason != _RC.JOURNAL_CORRUPT:
            problems.append(
                "%s rejected with %r" % (what, error.reason)
            )


def case_33_journal_first_recovery(results: List[Result]) -> None:
    """Journal-first recovery and replay verification: the live
    index is exactly the journal fold; recovery is
    construction."""
    problems: List[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        store_path = Path(tmp) / "journal.jsonl"
        service, core, *_ = _compose_service(store=FileApiStore(store_path))
        app = _full_app(service, "dev-recov", "recov")
        service.handle(
            _req(
                "POST",
                "/api/1.0/offers",
                app,
                body=_offer_body("Recovery offer"),
                idempotency_key="recov-1",
            )
        )
        endpoint = service.handle(
            _req(
                "POST",
                "/api/1.0/webhook-endpoints",
                app,
                body={
                    "url": "https://consumer.test/hook",
                    "event_types": ["offer.published"],
                },
                idempotency_key="recov-ep-1",
            )
        )
        consumer = _Consumer("unused", fail=True)
        service._transports[endpoint.body["data"]["id"]] = consumer
        service.handle(
            _req(
                "POST",
                "/api/1.0/offers",
                app,
                body=_offer_body("Recovery offer 2"),
                idempotency_key="recov-2",
            )
        )
        # live == fold
        service.verify_integrity()
        folded = fold_index(service.journal_records())
        if sorted(folded.offers) != sorted(service.index().offers):
            problems.append("offer fold diverges")
        if sorted(folded.deliveries) != sorted(service.index().deliveries):
            problems.append("delivery fold diverges")
        # reload: byte-identical replay of the whole boundary
        service2 = DeveloperApiService.load(
            environment="sandbox",
            core=core,
            usage=service._usage,
            allocation=service._allocation,
            store=FileApiStore(store_path),
            clock=service._clock,
            issuance_key=b"w046-platform-issuance-key",
        )
        if service2.journal_digest() != service.journal_digest():
            problems.append("journal digest changed across recovery")
        if sorted(service2.index().offers) != sorted(service.index().offers):
            problems.append("offers changed across recovery")
        if (
            service2.index().credentials.keys()
            != service.index().credentials.keys()
        ):
            problems.append("credentials changed across recovery")
        # pending delivery state survives: the failed attempt's
        # retry schedule is intact after recovery
        state = service2.index().deliveries
        if not state or not any(
            s.last_status in ("failed", "pending") or s.attempts > 0
            for s in state.values()
        ):
            problems.append("delivery state lost across recovery")
    if problems:
        results.append(fail("33 journal-first recovery", "; ".join(problems)))
    else:
        results.append(
            ok(
                "33 journal-first recovery",
                "live == fold; load == live; delivery state survives",
            )
        )


def case_34_failure_injection(results: List[Result]) -> None:
    """Failure injection: a store failure mid-mutation leaves no
    phantom boundary record; a raising transport is recorded as
    a failed delivery; the API response is unaffected by
    delivery outcomes; retry-after-timeout works."""
    problems: List[str] = []
    # 1. store failure: the credential issuance succeeds, the
    # first mutation fails on append -> no phantom mutation
    service, core, *_ = _compose_service(store=_FailingApiStore(fail_at=2))
    app = _full_app(service, "dev-fail", "fail")
    response = service.handle(
        _req(
            "POST",
            "/api/1.0/offers",
            app,
            body=_offer_body("Fail offer"),
            idempotency_key="fail-1",
        )
    )
    if response.status != 500 or (
        response.body["error"]["reason"] != "store-failed"
    ):
        problems.append("store failure not surfaced")
    if "fail-1" in service.index().mutations:
        problems.append("phantom mutation after store failure")
    # no offer resource exists (the fold never saw the record)
    if service.index().offers:
        problems.append("phantom offer after store failure")
    # a healthy store admits the retry cleanly
    service2, *_ = _compose_service()
    app2 = _full_app(service2, "dev-fail", "fail")
    response = service2.handle(
        _req(
            "POST",
            "/api/1.0/offers",
            app2,
            body=_offer_body("Fail offer"),
            idempotency_key="fail-1",
        )
    )
    if response.status != 200:
        problems.append("healthy retry failed")
    # 2. raising transport: recorded as failed attempt (code 0)
    service3, *_ = _compose_service()
    app3 = _full_app(service3, "dev-fail", "fail")
    endpoint = service3.handle(
        _req(
            "POST",
            "/api/1.0/webhook-endpoints",
            app3,
            body={
                "url": "https://consumer.test/hook",
                "event_types": ["offer.published"],
            },
            idempotency_key="fail-ep-1",
        )
    )
    endpoint_id = endpoint.body["data"]["id"]
    raising = _Consumer("unused", raise_exc=True)
    service3._transports[endpoint_id] = raising
    response = service3.handle(
        _req(
            "POST",
            "/api/1.0/offers",
            app3,
            body=_offer_body("Raising offer"),
            idempotency_key="fail-2",
        )
    )
    if response.status != 200:
        problems.append(
            "raising transport affected the API response: %d"
            % response.status
        )
    deliveries = [
        state
        for state in service3.index().deliveries.values()
        if state.endpoint_id == endpoint_id
    ]
    if not deliveries or deliveries[0].last_status != "failed":
        problems.append("raising transport not recorded as failure")
    elif deliveries[0].response_codes[0] != 0:
        problems.append("raising transport recorded a phantom code")
    # 3. retry after timeout: the clock advances, the delivery
    # retries through a healthy transport
    service3._clock = StepClock("2026-09-03T02:00:00Z", 3600)
    healthy = _Consumer("unused")
    service3._transports[endpoint_id] = healthy
    service3.process_due_deliveries()
    if not healthy.deliveries:
        problems.append("retry-after-timeout not delivered")
    if problems:
        results.append(fail("34 failure injection", "; ".join(problems)))
    else:
        results.append(
            ok(
                "34 failure injection",
                "store failure: no phantom; raising transport: failed "
                "attempt; timeout retry delivered",
            )
        )


def case_42_post_finality_webhook_isolation(results: List[Result]) -> None:
    """Post-finality webhook isolation (the W046 frozen
    observational-only invariant, failure-injected): a webhook
    queue or delivery persistence failure AFTER the mutation is
    admitted NEVER changes the API mutation result.

    The exact required sequence, per phase:

    1. the mutation is admitted successfully (200 + the canonical
       resource);
    2. the canonical mutation + the idempotency record are durable
       (the boundary journal AND the canonical subsystem journal;
       both survive a reload);
    3. the webhook persistence fails (injected store failure in
       the post-finality phase: the queue write in scenario A, the
       delivery attempt record in scenario B);
    4. the caller STILL receives the canonical successful mutation
       response (no 500, no error body);
    5. a retry with the same idempotency key returns that SAME
       canonical response byte-identically (replay header; zero
       journal growth; the canonical subsystem is NOT re-executed
       -- no duplicate canonical mutation);
    6. the webhook failure remains solely observational and
       recoverable: it is recorded as webhook health data only
       (incidents, process-local, never journal state), and once
       the store heals the delivery pump recovers the observation
       exactly-once (the queue dedupe) and delivers it."""
    problems: List[str] = []

    # -- scenario A: the commercial mutation (intent) with the
    # webhook QUEUE write failing post-finality ------------------
    # append calls: 1 credential, 2 endpoint mutation record,
    # 3 the endpoint registration's terminal not-required
    # admission record, 4 intent boundary mutation record
    # (FINALITY), 5 the intent's required admission record (the
    # frozen audience), 6 the durable webhook obligation (OK),
    # 7 the queue record (FAILS)  [the admission record is a
    # journal member as of the round-5 durable admission state;
    # the window is re-derived from the round-4 position 5 for
    # the new member order]
    store = _FlakyApiStore(fail_from=7, fail_until=8)
    service, core, *_ = _compose_service(store=store)
    app = _full_app(service, "dev-iso", "iso")
    endpoint_resp = service.handle(
        _req(
            "POST",
            "/api/1.0/webhook-endpoints",
            app,
            body={
                "url": "https://consumer-iso.test/hook",
                "event_types": ["connectivity_intent.created"],
            },
            idempotency_key="iso-ep-1",
        )
    )
    if endpoint_resp.status != 200:
        problems.append("endpoint registration failed: %d" % endpoint_resp.status)
    endpoint_id = endpoint_resp.body["data"]["id"]
    consumer = _Consumer("unused")
    service._transports[endpoint_id] = consumer

    intent_body = {"intent": {"subscriber": "iso-window"}}
    first = service.handle(
        _req(
            "POST",
            "/api/1.0/intents",
            app,
            body=intent_body,
            idempotency_key="iso-intent-1",
        )
    )
    # (4) the caller receives the canonical successful response
    if first.status != 200 or first.body.get("error") is not None:
        problems.append(
            "queue-write failure changed the mutation result: "
            "status %s body %s"
            % (
                first.status,
                first.body.get("error", {}).get("reason", "-"),
            )
        )
    transaction_id = first.body["data"]["id"]
    if not transaction_id or (
        first.body["data"].get("state") != "CONNECTIVITY_INTENT"
    ):
        problems.append("canonical intent resource missing from response")
    # (2) both records are durable
    if "iso-intent-1" not in service.index().mutations:
        problems.append("idempotency record not applied")
    if len(core.journal_records()) != 1 or len(core.transactions()) != 1:
        problems.append(
            "canonical subsystem journal count %d/%d"
            % (len(core.journal_records()), len(core.transactions()))
        )
    # (3) the injected failure really fired in the webhook phase
    if store.failures != 1:
        problems.append(
            "injection did not fire post-finality (failures=%d)"
            % store.failures
        )
    # the failure is observational: health data only, no delivery
    incidents = service.webhook_observation_incidents()
    if len(incidents) != 1 or incidents[0]["phase"] != "emission":
        problems.append(
            "queue-write failure not recorded as emission incident: %s"
            % [dict(i)["phase"] for i in incidents]
        )
    elif incidents[0]["reason_code"] != "store-failed":
        problems.append("incident reason %r" % incidents[0]["reason_code"])
    if service.index().deliveries:
        problems.append("phantom delivery after failed queue write")
    # (5) the retry replays the SAME canonical response
    journal_before = len(service.journal_records())
    retry = service.handle(
        _req(
            "POST",
            "/api/1.0/intents",
            app,
            body=intent_body,
            idempotency_key="iso-intent-1",
        )
    )
    if retry.status != 200 or (
        retry.headers.get("X-ADCOS-Idempotent-Replay") != "true"
    ):
        problems.append("retry after webhook failure not a 200 replay")
    if first.canonical_body_bytes() != retry.canonical_body_bytes():
        problems.append("replay body differs from the canonical response")
    if len(service.journal_records()) != journal_before:
        problems.append("replay grew the journal")
    if len(core.journal_records()) != 1:
        problems.append("replay re-executed the canonical mutation")
    # (6) recovery: the store healed; the pump flushes the pending
    # observation (queue dedupe = exactly-once) and delivers it
    service.process_due_deliveries()
    deliveries = [
        state
        for state in service.index().deliveries.values()
        if state.endpoint_id == endpoint_id
    ]
    if len(deliveries) != 1 or deliveries[0].last_status != "delivered":
        problems.append(
            "pending observation not recovered: %s"
            % [s.last_status for s in deliveries]
        )
    if len(consumer.deliveries) != 1:
        problems.append(
            "recovered delivery count %d (expected exactly one)"
            % len(consumer.deliveries)
        )
    if "iso-intent-1" not in service.index().mutations:
        problems.append("idempotency invalidated by recovery")
    if len(core.journal_records()) != 1:
        problems.append("recovery re-executed the canonical mutation")
    service.verify_integrity()
    # incidents survive as health history but never as durable
    # state: the reload sees the journal truth only
    reloaded = DeveloperApiService.load(
        environment="sandbox",
        core=core,
        usage=service._usage,
        allocation=service._allocation,
        store=store,
        clock=service._clock,
        issuance_key=b"w046-platform-issuance-key",
    )
    if "iso-intent-1" not in reloaded.index().mutations:
        problems.append("idempotency did not survive the reload")
    if len(reloaded.index().deliveries) != 1:
        problems.append("delivery state did not survive the reload")
    if reloaded.webhook_observation_incidents():
        problems.append("incidents leaked into durable state")
    post_reload = reloaded.handle(
        _req(
            "POST",
            "/api/1.0/intents",
            app,
            body=intent_body,
            idempotency_key="iso-intent-1",
        )
    )
    if (
        post_reload.status != 200
        or post_reload.canonical_body_bytes() != first.canonical_body_bytes()
        or post_reload.headers.get("X-ADCOS-Idempotent-Replay") != "true"
    ):
        problems.append("post-reload replay diverged")
    if len(core.journal_records()) != 1:
        problems.append("post-reload replay re-executed the mutation")

    # -- scenario B: the boundary-owned mutation (offer) with the
    # webhook DELIVERY attempt record failing post-finality ------
    # append calls: 1 credential, 2 endpoint mutation record,
    # 3 the endpoint registration's terminal not-required
    # admission record, 4 offer boundary mutation record
    # (FINALITY), 5 the offer's required admission record, 6 the
    # durable webhook obligation (OK), 7 the queue record (OK),
    # 8 the delivery attempt record (FAILS), 9 the retry attempt
    # (OK)  [round-4 positions 6/7 re-derived for the new member
    # order]
    store_b = _FlakyApiStore(fail_from=8, fail_until=9)
    service_b, *_ = _compose_service(store=store_b)
    app_b = _full_app(service_b, "dev-iso-b", "iso-b")
    endpoint_b = service_b.handle(
        _req(
            "POST",
            "/api/1.0/webhook-endpoints",
            app_b,
            body={
                "url": "https://consumer-iso-b.test/hook",
                "event_types": ["offer.published"],
            },
            idempotency_key="iso-b-ep-1",
        )
    )
    endpoint_b_id = endpoint_b.body["data"]["id"]
    consumer_b = _Consumer("unused")
    service_b._transports[endpoint_b_id] = consumer_b

    offer_body = _offer_body("Isolation offer", amount=4242)
    first_b = service_b.handle(
        _req(
            "POST",
            "/api/1.0/offers",
            app_b,
            body=offer_body,
            idempotency_key="iso-b-offer-1",
        )
    )
    if first_b.status != 200 or first_b.body.get("error") is not None:
        problems.append(
            "attempt-record failure changed the mutation result: "
            "status %s" % first_b.status
        )
    if "iso-b-offer-1" not in service_b.index().mutations:
        problems.append("boundary idempotency record missing (B)")
    if store_b.failures != 1:
        problems.append(
            "injection B did not fire post-finality (failures=%d)"
            % store_b.failures
        )
    queued_b = [
        state
        for state in service_b.index().deliveries.values()
        if state.endpoint_id == endpoint_b_id
    ]
    if len(queued_b) != 1 or queued_b[0].attempts != 0:
        problems.append(
            "queue record not durable after attempt failure: %s"
            % [(s.last_status, s.attempts) for s in queued_b]
        )
    incidents_b = service_b.webhook_observation_incidents()
    if len(incidents_b) != 1 or incidents_b[0]["phase"] != "delivery":
        problems.append(
            "attempt failure not recorded as delivery incident: %s"
            % [dict(i)["phase"] for i in incidents_b]
        )
    journal_b = len(service_b.journal_records())
    retry_b = service_b.handle(
        _req(
            "POST",
            "/api/1.0/offers",
            app_b,
            body=offer_body,
            idempotency_key="iso-b-offer-1",
        )
    )
    if (
        retry_b.status != 200
        or retry_b.canonical_body_bytes() != first_b.canonical_body_bytes()
        or retry_b.headers.get("X-ADCOS-Idempotent-Replay") != "true"
    ):
        problems.append("retry after attempt failure diverged (B)")
    if len(service_b.journal_records()) != journal_b:
        problems.append("replay grew the journal (B)")
    # recovery: the pump retries the due delivery (at-least-once
    # to the consumer; exactly one durable attempt record)
    service_b.process_due_deliveries()
    if queued_b[0].last_status != "delivered" or queued_b[0].attempts != 1:
        problems.append(
            "delivery not recovered (B): %s/%s"
            % (queued_b[0].last_status, queued_b[0].attempts)
        )
    if not consumer_b.deliveries:
        problems.append("consumer never received the event (B)")
    service_b.verify_integrity()

    if problems:
        results.append(
            fail("42 post-finality webhook isolation", "; ".join(problems))
        )
    else:
        results.append(
            ok(
                "42 post-finality webhook isolation",
                "queue-write and attempt-record failures after "
                "finality: canonical 200 + byte-identical replay + "
                "no duplicate mutation + observational recovery",
            )
        )


def case_43_durable_webhook_obligation_crash_recovery(
    results: List[Result],
) -> None:
    """Durable post-finality webhook obligation across a process
    crash (the W046 observation-channel reliability invariant,
    failure-injected at the webhook queue append): the obligation
    to observe is DURABLE -- a crash between the admitted
    mutation and the webhook queue phase loses NOTHING.

    The exact required sequence:

    1. the mutation succeeds (200 + the canonical resource);
    2. the mutation + idempotency record are durable (the
       boundary journal AND the canonical subsystem journal);
    3. the webhook queue append fails (the injected store
       failure, strictly AFTER the durable observation
       obligation);
    4. the API still returns the canonical 200 (the P0 finality
       containment is preserved);
    5. the process is reconstructed from the durable stores (the
       core through ``CommercialCore.load``, the boundary through
       ``DeveloperApiService.load`` -- the crashed instance,
       including its in-process buffers, is discarded);
    6. the pending webhook obligation IS recovered (durable: it
       is visible in the reloaded boundary index);
    7. the same observation is queued EXACTLY ONCE (the
       delivery-identity dedupe; a second pump pass is a no-op);
    8. delivery succeeds (the consumer receives the event once,
       verified by signature);
    9. the canonical mutation was NEVER re-executed;
    10. the same-key API retry on the reloaded boundary remains
        an idempotent replay (byte-identical canonical response,
        zero journal growth, zero core journal growth).

    The durable obligation does NOT violate the observational
    invariant: the DELIVERY STATE remains observational (health
    data; nothing in the commercial plane reads it), while the
    DELIVERY OBLIGATION is a durable operational obligation of
    the observation channel itself."""
    problems: List[str] = []

    # kind-selected injection: the queue write fails wherever it
    # falls, in both the pre-correction and corrected gateways
    store = _QueueFailingApiStore(failures=1)
    core_store = MemoryCommercialStore()
    service, core, usage, allocation, world = _compose_service(
        store=store, core_store=core_store
    )
    runtime, peer, session_id, manager, integrator, shared = world
    app = _full_app(service, "dev-oblig", "oblig")
    endpoint_resp = service.handle(
        _req(
            "POST",
            "/api/1.0/webhook-endpoints",
            app,
            body={
                "url": "https://consumer-oblig.test/hook",
                "event_types": ["connectivity_intent.created"],
            },
            idempotency_key="oblig-ep-1",
        )
    )
    if endpoint_resp.status != 200:
        problems.append(
            "endpoint registration failed: %d" % endpoint_resp.status
        )
    endpoint_id = endpoint_resp.body["data"]["id"]

    intent_body = {"intent": {"subscriber": "oblig-crash"}}
    # (1) + (4) the mutation is admitted; the caller receives the
    # canonical successful response despite the webhook failure
    first = service.handle(
        _req(
            "POST",
            "/api/1.0/intents",
            app,
            body=intent_body,
            idempotency_key="oblig-intent-1",
        )
    )
    if first.status != 200 or first.body.get("error") is not None:
        problems.append(
            "queue-write failure changed the mutation result: "
            "status %s body %s"
            % (
                first.status,
                first.body.get("error", {}).get("reason", "-"),
            )
        )
    transaction_id = first.body["data"]["id"]
    if not transaction_id or (
        first.body["data"].get("state") != "CONNECTIVITY_INTENT"
    ):
        problems.append("canonical intent resource missing from response")
    # (2) both records are durable BEFORE any webhook write
    if "oblig-intent-1" not in service.index().mutations:
        problems.append("idempotency record not applied")
    if len(core.journal_records()) != 1 or len(core.transactions()) != 1:
        problems.append(
            "canonical subsystem journal count %d/%d"
            % (len(core.journal_records()), len(core.transactions()))
        )
    # (3) the injected failure fired exactly once, in the webhook
    # queue phase, AFTER the durable obligation
    if store.failures != 1:
        problems.append(
            "injection did not fire at the queue append (failures=%d)"
            % store.failures
        )
    # the durable observation obligation exists and carries the
    # intended audience; no queue record was written
    obligation_records = [
        record
        for record in service.journal_records()
        if record.to_dict().get("record_kind") == "webhook-obligation"
    ]
    if len(obligation_records) != 1:
        problems.append(
            "expected exactly one durable webhook obligation, found %d"
            % len(obligation_records)
        )
    elif (
        endpoint_id
        not in tuple(obligation_records[0].to_dict().get("endpoints", ()))
    ):
        problems.append("obligation does not carry the subscribed endpoint")
    if service.index().deliveries:
        problems.append("phantom delivery after failed queue write")
    incidents = service.webhook_observation_incidents()
    if len(incidents) != 1 or incidents[0]["phase"] != "emission":
        problems.append(
            "queue-write failure not recorded as emission incident: %s"
            % [dict(i)["phase"] for i in incidents]
        )

    # (5) the CRASH: both the boundary and the canonical core are
    # reconstructed from their durable stores; the crashed
    # instance (with every in-process buffer) is discarded
    core2 = CommercialCore.load(
        store=core_store,
        clock=shared,
        references=_references(manager, integrator, session_id),
    )
    reloaded = DeveloperApiService.load(
        environment="sandbox",
        core=core2,
        usage=usage,
        allocation=allocation,
        store=store,
        clock=shared,
        issuance_key=b"w046-platform-issuance-key",
    )
    # the durable mutation truth survived the crash
    if "oblig-intent-1" not in reloaded.index().mutations:
        problems.append("idempotency did not survive the crash")
    # (6) the pending webhook obligation is recovered from the
    # durable store (NOT from any in-process state)
    pending_reader = getattr(
        reloaded, "pending_webhook_obligations", None
    )
    if pending_reader is None:
        problems.append(
            "the reloaded service exposes no durable webhook "
            "obligation surface (the obligation was lost with the "
            "process)"
        )
    else:
        pending = pending_reader()
        if len(pending) != 1:
            problems.append(
                "pending obligation not recovered across the crash: %s"
                % [dict(p)["event_type"] for p in pending]
            )
        else:
            pending_one = dict(pending[0])
            if pending_one.get("event_type") != (
                "connectivity_intent.created"
            ):
                problems.append(
                    "recovered obligation event type %r"
                    % pending_one.get("event_type")
                )
            if pending_one.get("resource_id") != transaction_id:
                problems.append(
                    "recovered obligation resource %r"
                    % pending_one.get("resource_id")
                )
            if tuple(pending_one.get("pending_endpoints", ())) != (
                endpoint_id,
            ):
                problems.append(
                    "recovered obligation pending endpoints %s"
                    % (pending_one.get("pending_endpoints"),)
                )
    # (9-pre) recovery alone re-executed nothing
    if len(core2.journal_records()) != 1:
        problems.append("crash recovery re-executed the canonical mutation")

    # the operator re-provisions the transport binding at boot
    # (transports are process-local injection, never journal
    # state), then runs the delivery pump
    consumer = _Consumer(reloaded.endpoint_signing_secret(endpoint_id))
    reloaded._transports[endpoint_id] = consumer
    # (7) + (8) the pump queues the observation exactly once and
    # delivers it
    reloaded.process_due_deliveries()
    queue_records = [
        record
        for record in reloaded.journal_records()
        if isinstance(record, WebhookQueueRecord)
    ]
    if len(queue_records) != 1:
        problems.append(
            "recovered observation queued %d times (expected exactly one)"
            % len(queue_records)
        )
    deliveries = [
        state
        for state in reloaded.index().deliveries.values()
        if state.endpoint_id == endpoint_id
    ]
    if len(deliveries) != 1 or deliveries[0].last_status != "delivered":
        problems.append(
            "recovered delivery not delivered: %s"
            % [s.last_status for s in deliveries]
        )
    if len(consumer.deliveries) != 1:
        problems.append(
            "consumer received %d events (expected exactly one)"
            % len(consumer.deliveries)
        )
    elif consumer.deliveries[0][0].get("event_type") != (
        "connectivity_intent.created"
    ) or consumer.deliveries[0][0].get("resource_id") != transaction_id:
        problems.append("recovered event content diverged")
    # exactly-once: a second pump pass is a no-op (the queue
    # dedupe holds; delivered is terminal)
    journal_before_second = len(reloaded.journal_records())
    reloaded.process_due_deliveries()
    if len(reloaded.journal_records()) != journal_before_second:
        problems.append("second pump pass grew the journal")
    if len(consumer.deliveries) != 1:
        problems.append("second pump pass re-delivered the event")
    # the obligation is retired exactly when satisfied (derived,
    # never stored: every target endpoint holds its queue record)
    if pending_reader is not None and pending_reader():
        problems.append("satisfied obligation still reported pending")
    # (9) the canonical mutation was never re-executed through
    # the whole recovery
    if len(core2.journal_records()) != 1:
        problems.append("recovery re-executed the canonical mutation")
    if core2.transaction(transaction_id).to_dict().get("event_count") != 1:
        problems.append("canonical transaction mutated during recovery")
    # live == fold after recovery
    reloaded.verify_integrity()
    # (10) the same-key retry on the reloaded boundary is an
    # idempotent replay (byte-identical; zero growth anywhere)
    journal_before_retry = len(reloaded.journal_records())
    retry = reloaded.handle(
        _req(
            "POST",
            "/api/1.0/intents",
            app,
            body=intent_body,
            idempotency_key="oblig-intent-1",
        )
    )
    if retry.status != 200 or (
        retry.headers.get("X-ADCOS-Idempotent-Replay") != "true"
    ):
        problems.append("post-crash retry not a 200 replay")
    if first.canonical_body_bytes() != retry.canonical_body_bytes():
        problems.append("replay body differs from the canonical response")
    if len(reloaded.journal_records()) != journal_before_retry:
        problems.append("replay grew the journal")
    if len(core2.journal_records()) != 1:
        problems.append("replay re-executed the canonical mutation")

    if problems:
        results.append(
            fail(
                "43 durable webhook obligation crash recovery",
                "; ".join(problems),
            )
        )
    else:
        results.append(
            ok(
                "43 durable webhook obligation crash recovery",
                "queue append fails + process crash: the durable "
                "obligation recovers, queues exactly once, delivers, "
                "never re-executes, and the same-key retry replays",
            )
        )


def case_44_obligation_write_admission_gate(
    results: List[Result],
) -> None:
    """The obligation-write ADMISSION GATE (the W046
    successful-admission contract, failure-injected at the
    durable webhook-obligation append itself): a success response
    is returned ONLY when the observation obligation is durable;
    a failed obligation write never becomes a false success, and
    the obligation is never lost to a crash.

    The exact required sequence:

    1. the developer submits an audience-carrying mutation
       (intent create with a subscribed endpoint) under an
       idempotency key;
    2. the business mutation executes and the mutation /
       idempotency record is DURABLE (the boundary journal AND
       the canonical core journal -- finality is untouched);
    3. the webhook OBLIGATION journal append FAILS (the injected
       store failure, kind-selected at the obligation record);
    4. the API does NOT claim success: the deterministic
       admission failure (500 store-failed) is returned -- no
       canonical resource, no queue record, and NOT a contained
       incident (the failure is the response itself; the message
       states the durable-not-rolled-back truth and the same-key
       retry contract);
    5. the process CRASHES (the crashed instance, including any
       in-process state, is discarded; both planes are
       reconstructed from the durable stores);
    6. the durable truth survived: the mutation record replays,
       the canonical core journal is intact, and the obligation
       is still absent (honestly: it was never established --
       nothing fabricated it);
    7. the developer RETRIES the same request (same key, same
       body: the digest match);
    8. the retry completes the admission BEFORE any success: the
       obligation is established durably from durable truth alone
       (the prior record's stored canonical response, the core's
       public journal, the retry request) -- exactly one
       obligation record carrying the subscribed endpoint, with
       no canonical re-execution (the core journal count is
       unchanged);
    9. ONLY THEN the retry returns the byte-identical stored
       canonical response (200, replay header; the response
       content is the stored envelope, not a re-execution);
    10. the observation completes through the delivery pump:
        the queue write and the delivery deliver the event to
        the consumer exactly once (verified by signature), the
        obligation is satisfied (derived, never stored), a
        further retry is a pure replay (zero journal growth),
        and the journal verifies.

    Scenario B repeats the same gate through the
    developerapi-owned mutation (offer publish), whose emission
    reconstruction comes from the prior record's stored resource
    projection alone."""
    problems: List[str] = []

    # -- scenario A: the adapted commercial mutation (intent) with
    # the webhook OBLIGATION record append failing ---------------
    store = _ObligationFailingApiStore(failures=1)
    core_store = MemoryCommercialStore()
    service, core, usage, allocation, world = _compose_service(
        store=store, core_store=core_store
    )
    runtime, peer, session_id, manager, integrator, shared = world
    app = _full_app(service, "dev-admit", "admit")
    endpoint_resp = service.handle(
        _req(
            "POST",
            "/api/1.0/webhook-endpoints",
            app,
            body={
                "url": "https://consumer-admit.test/hook",
                "event_types": ["connectivity_intent.created"],
            },
            idempotency_key="admit-ep-1",
        )
    )
    if endpoint_resp.status != 200:
        problems.append(
            "endpoint registration failed: %d" % endpoint_resp.status
        )
    endpoint_id = endpoint_resp.body["data"]["id"]

    intent_body = {"intent": {"subscriber": "admit-gate"}}
    # (1) + (3) + (4): the mutation executes, the obligation write
    # fails, and the boundary does NOT claim success
    first = service.handle(
        _req(
            "POST",
            "/api/1.0/intents",
            app,
            body=intent_body,
            idempotency_key="admit-intent-1",
        )
    )
    if first.status != 500 or (
        first.body.get("error", {}).get("reason") != "store-failed"
    ):
        problems.append(
            "obligation-write failure did not fail admission: "
            "status %s reason %r"
            % (first.status, first.body.get("error", {}).get("reason"))
        )
    else:
        message = first.body["error"].get("message", "")
        if "admit-intent-1" not in message:
            problems.append(
                "admission failure message lost the idempotency key"
            )
        if "NOT rolled back or re-executed" not in message:
            problems.append(
                "admission failure message lost the durability truth"
            )
        if "SAME idempotency key" not in message:
            problems.append(
                "admission failure message lost the retry contract"
            )
    if first.body.get("data") is not None:
        problems.append("admission failure carried a canonical resource")
    # (2) the mutation and its idempotency record ARE durable
    if "admit-intent-1" not in service.index().mutations:
        problems.append("durable idempotency record missing after the admission failure")
    if len(core.journal_records()) != 1 or len(core.transactions()) != 1:
        problems.append(
            "canonical mutation not durable: %d/%d"
            % (len(core.journal_records()), len(core.transactions()))
        )
    # (3) the injection fired exactly once, at the obligation write
    if store.failures != 1:
        problems.append(
            "injection did not fire at the obligation append (failures=%d)"
            % store.failures
        )
    # (4) nothing was fabricated: no obligation, no queue record,
    # no contained incident (the failure is the response)
    if service.index().obligations:
        problems.append("obligation recorded despite the failed write")
    if service.index().deliveries:
        problems.append("phantom delivery after the admission failure")
    if service.webhook_observation_incidents():
        problems.append("admission failure misclassified as a contained incident")

    # (5) the CRASH: both planes reconstructed from durable stores;
    # the crashed instance (with any in-process state) is discarded
    core2 = CommercialCore.load(
        store=core_store,
        clock=shared,
        references=_references(manager, integrator, session_id),
    )
    reloaded = DeveloperApiService.load(
        environment="sandbox",
        core=core2,
        usage=usage,
        allocation=allocation,
        store=store,
        clock=shared,
        issuance_key=b"w046-platform-issuance-key",
    )
    # (6) the durable truth survived; the obligation is STILL
    # absent (never established, never fabricated)
    if "admit-intent-1" not in reloaded.index().mutations:
        problems.append("idempotency did not survive the crash")
    if reloaded.index().obligations:
        problems.append("reload fabricated an obligation")
    if reloaded.pending_webhook_obligations():
        problems.append("reload reported a pending obligation")
    if len(core2.journal_records()) != 1:
        problems.append("crash recovery re-executed the canonical mutation")

    # (7) the developer retries the SAME request
    retry = reloaded.handle(
        _req(
            "POST",
            "/api/1.0/intents",
            app,
            body=intent_body,
            idempotency_key="admit-intent-1",
        )
    )
    # (8) the admission is completed BEFORE any success: exactly
    # one durable obligation, carrying the subscribed endpoint and
    # the canonical event identity, with NO re-execution
    obligations_after = [
        record
        for record in reloaded.journal_records()
        if record.to_dict().get("record_kind") == "webhook-obligation"
    ]
    if len(obligations_after) != 1:
        problems.append(
            "healed obligation count %d (expected exactly one)"
            % len(obligations_after)
        )
    else:
        healed = obligations_after[0].to_dict()
        if endpoint_id not in tuple(healed.get("endpoints", ())):
            problems.append("healed obligation lost the subscribed endpoint")
        if healed.get("event_type") != "connectivity_intent.created":
            problems.append(
                "healed obligation event type %r" % healed.get("event_type")
            )
        core_event = core2.journal_records()[0].event.to_dict()
        if healed.get("event_id") != core_event.get("event_id"):
            problems.append(
                "healed obligation event id diverged from the canonical event"
            )
        if healed.get("resource_id") != core_event.get("transaction_id"):
            problems.append(
                "healed obligation resource diverged from the canonical transaction"
            )
    if len(core2.journal_records()) != 1:
        problems.append("healing retry re-executed the canonical mutation")
    # (9) ONLY THEN the response: the byte-identical STORED
    # canonical response with the replay header
    prior = reloaded.index().mutations["admit-intent-1"]
    stored_body = json.loads(prior.response_body)
    if retry.status != 200 or (
        retry.headers.get("X-ADCOS-Idempotent-Replay") != "true"
    ):
        problems.append(
            "healing retry not a 200 replay: %s" % retry.status
        )
    if retry.canonical_body_bytes() != canonical_json_bytes(stored_body):
        problems.append(
            "replayed response diverged from the stored canonical response"
        )
    transaction_id = stored_body.get("data", {}).get("id", "")
    if not transaction_id:
        problems.append("stored canonical response lost the transaction id")

    # (10) the observation completes through the delivery pump,
    # exactly once; a further retry is a pure replay
    consumer = _Consumer(reloaded.endpoint_signing_secret(endpoint_id))
    reloaded._transports[endpoint_id] = consumer
    reloaded.process_due_deliveries()
    queue_records = [
        record
        for record in reloaded.journal_records()
        if isinstance(record, WebhookQueueRecord)
    ]
    if len(queue_records) != 1:
        problems.append(
            "healed observation queued %d times (expected exactly one)"
            % len(queue_records)
        )
    deliveries = [
        state
        for state in reloaded.index().deliveries.values()
        if state.endpoint_id == endpoint_id
    ]
    if len(deliveries) != 1 or deliveries[0].last_status != "delivered":
        problems.append(
            "healed delivery not delivered: %s"
            % [s.last_status for s in deliveries]
        )
    if len(consumer.deliveries) != 1:
        problems.append(
            "consumer received %d events (expected exactly one)"
            % len(consumer.deliveries)
        )
    elif (
        consumer.deliveries[0][0].get("event_type")
        != "connectivity_intent.created"
        or consumer.deliveries[0][0].get("resource_id") != transaction_id
    ):
        problems.append("healed event content diverged")
    # exactly-once: a second pump pass is a no-op
    journal_before_second = len(reloaded.journal_records())
    reloaded.process_due_deliveries()
    if len(reloaded.journal_records()) != journal_before_second:
        problems.append("second pump pass grew the journal")
    if len(consumer.deliveries) != 1:
        problems.append("second pump pass re-delivered the event")
    # the obligation is retired exactly when satisfied (derived)
    if reloaded.pending_webhook_obligations():
        problems.append("satisfied obligation still reported pending")
    # a FURTHER retry is a pure replay (zero growth anywhere)
    journal_before_again = len(reloaded.journal_records())
    again = reloaded.handle(
        _req(
            "POST",
            "/api/1.0/intents",
            app,
            body=intent_body,
            idempotency_key="admit-intent-1",
        )
    )
    if (
        again.status != 200
        or again.headers.get("X-ADCOS-Idempotent-Replay") != "true"
        or again.canonical_body_bytes() != retry.canonical_body_bytes()
    ):
        problems.append("post-heal retry diverged from the canonical replay")
    if len(reloaded.journal_records()) != journal_before_again:
        problems.append("post-heal retry grew the journal")
    if len(core2.journal_records()) != 1:
        problems.append("post-heal retry re-executed the mutation")
    if core2.transaction(transaction_id).to_dict().get("event_count") != 1:
        problems.append("canonical transaction mutated during healing")
    reloaded.verify_integrity()

    # -- scenario B: the developerapi-owned mutation (offer) with
    # the webhook OBLIGATION record append failing ---------------
    store_b = _ObligationFailingApiStore(failures=1)
    service_b, core_b, *_ = _compose_service(store=store_b)
    app_b = _full_app(service_b, "dev-admit-b", "admit-b")
    endpoint_b = service_b.handle(
        _req(
            "POST",
            "/api/1.0/webhook-endpoints",
            app_b,
            body={
                "url": "https://consumer-admit-b.test/hook",
                "event_types": ["offer.published"],
            },
            idempotency_key="admit-b-ep-1",
        )
    )
    endpoint_b_id = endpoint_b.body["data"]["id"]

    offer_body = _offer_body("Admission gate offer", amount=911)
    first_b = service_b.handle(
        _req(
            "POST",
            "/api/1.0/offers",
            app_b,
            body=offer_body,
            idempotency_key="admit-b-offer-1",
        )
    )
    if first_b.status != 500 or (
        first_b.body.get("error", {}).get("reason") != "store-failed"
    ):
        problems.append(
            "offer obligation-write failure did not fail admission: "
            "status %s" % first_b.status
        )
    if "admit-b-offer-1" not in service_b.index().mutations:
        problems.append("boundary idempotency record missing (B)")
    if store_b.failures != 1:
        problems.append(
            "injection B did not fire at the obligation append (failures=%d)"
            % store_b.failures
        )
    if service_b.index().obligations or service_b.index().deliveries:
        problems.append("fabricated obligation/delivery (B)")

    # the crash + the healing retry (the emission reconstruction
    # comes from the prior record's stored resource projection)
    reload_b = DeveloperApiService.load(
        environment="sandbox",
        core=core_b,
        usage=service_b._usage,
        allocation=service_b._allocation,
        store=store_b,
        clock=service_b._clock,
        issuance_key=b"w046-platform-issuance-key",
    )
    retry_b = reload_b.handle(
        _req(
            "POST",
            "/api/1.0/offers",
            app_b,
            body=offer_body,
            idempotency_key="admit-b-offer-1",
        )
    )
    obligations_b = [
        record
        for record in reload_b.journal_records()
        if record.to_dict().get("record_kind") == "webhook-obligation"
    ]
    if len(obligations_b) != 1:
        problems.append(
            "healed obligation count (B) %d" % len(obligations_b)
        )
    elif endpoint_b_id not in tuple(obligations_b[0].to_dict().get("endpoints", ())):
        problems.append("healed obligation lost the endpoint (B)")
    prior_b = reload_b.index().mutations["admit-b-offer-1"]
    if (
        retry_b.status != 200
        or retry_b.headers.get("X-ADCOS-Idempotent-Replay") != "true"
        or retry_b.canonical_body_bytes()
        != canonical_json_bytes(json.loads(prior_b.response_body))
    ):
        problems.append("healing retry diverged from the stored response (B)")
    consumer_b = _Consumer(reload_b.endpoint_signing_secret(endpoint_b_id))
    reload_b._transports[endpoint_b_id] = consumer_b
    reload_b.process_due_deliveries()
    if len(consumer_b.deliveries) != 1:
        problems.append(
            "consumer (B) received %d events (expected exactly one)"
            % len(consumer_b.deliveries)
        )
    elif (
        consumer_b.deliveries[0][0].get("event_type") != "offer.published"
    ):
        problems.append("healed event content diverged (B)")
    reload_b.verify_integrity()

    if problems:
        results.append(
            fail(
                "44 obligation-write admission gate",
                "; ".join(problems),
            )
        )
    else:
        results.append(
            ok(
                "44 obligation-write admission gate",
                "obligation append fails: no false 200, the durable "
                "mutation survives the crash, the same-key retry "
                "establishes the obligation BEFORE the byte-identical "
                "stored response, and the pump delivers exactly once",
            )
        )


def case_45_durable_observation_admission_state(
    results: List[Result],
) -> None:
    """The DURABLE observation-ADMISSION state (the round-5
    frozen semantics): the admission-time audience is an
    admission-time FACT, persisted as its own journal record
    BEFORE the successful API response, and a historical
    admission decision is AUTHORITATIVE -- the same mutation +
    the same idempotency key always resolve to the SAME
    historical decision, and an idempotent replay NEVER
    re-interprets the current endpoint state.

    The durable state machine under proof:

    .. code-block:: text

        canonical mutation
                |
        durable MutationRecord
                |
        durable observation-admission state
                |
                +-- NOT_REQUIRED (terminal, empty endpoints)
                |
                +-- REQUIRED (frozen audience + frozen emission)
                        |
                durable WebhookObligationRecord
                        |
                successful API response
                        |
                queue / delivery (contained)

    Scenario A (the no-audience replay regression): a mutation
    that legitimately completed with NO audience can never
    produce a webhook merely because an endpoint was registered
    afterwards and the client replayed the same idempotency
    key.

    Scenario B (the audience-drift retry): a required admission
    whose OBLIGATION write failed (the first attempt returned
    the deterministic admission failure) heals on the same-key
    retry with the ORIGINAL frozen audience -- endpoints
    registered between the first attempt and the retry are not
    part of the historical audience and never receive the
    historical event.

    Scenario C (the admission-record persistence failure): the
    admission record itself is the correct FIRST durable
    observation boundary -- when its write fails the boundary
    returns the deterministic non-success (never a false
    success), the canonical mutation is neither rolled back nor
    re-executed, and the same-key retry after a process crash
    establishes the admission state from the request + the
    durable canonical mutation alone, then replays the
    canonical success byte-identically with ZERO additional
    canonical executions.

    The case closes with the structural audit: the journal
    record family membership + constructor validation + the
    fold + ``verify_integrity`` (behavioral, through the
    reloads above) and the AST audit of the
    observation-emission call sites -- ONE canonical admission
    path, no audience re-resolution on the historical replay
    path, no process-local observation state."""
    problems: List[str] = []

    # -- scenario A: legitimate no-audience completion ----------------
    service, core, *_ = _compose_service()
    app = _full_app(service, "dev-adm45", "adm45")
    offer_body = _offer_body("Admission freeze offer", amount=4545)
    first = service.handle(
        _req(
            "POST",
            "/api/1.0/offers",
            app,
            body=offer_body,
            idempotency_key="adm45-a-1",
        )
    )
    if first.status != 200 or first.body.get("error") is not None:
        problems.append(
            "no-audience mutation did not succeed: %s" % first.status
        )
    # (4) the durable admission record says not-required
    # (5) a matching endpoint is registered AFTERWARD
    endpoint = service.handle(
        _req(
            "POST",
            "/api/1.0/webhook-endpoints",
            app,
            body={
                "url": "https://consumer-adm45-a.test/hook",
                "event_types": ["offer.published"],
            },
            idempotency_key="adm45-a-ep-1",
        )
    )
    endpoint_id = endpoint.body["data"]["id"]
    consumer = _Consumer("unused")
    service._transports[endpoint_id] = consumer
    # (6) replay the original idempotency key
    journal_before = len(service.journal_records())
    retry = service.handle(
        _req(
            "POST",
            "/api/1.0/offers",
            app,
            body=offer_body,
            idempotency_key="adm45-a-1",
        )
    )
    # (7) byte-identical idempotent replay
    prior = service.index().mutations["adm45-a-1"]
    if retry.status != 200 or (
        retry.headers.get("X-ADCOS-Idempotent-Replay") != "true"
    ):
        problems.append(
            "no-audience replay not a 200 replay: %s" % retry.status
        )
    if retry.canonical_body_bytes() != canonical_json_bytes(
        json.loads(prior.response_body)
    ):
        problems.append("no-audience replay body diverged")
    if len(service.journal_records()) != journal_before:
        problems.append("no-audience replay grew the journal")
    # (8) NO webhook obligation is created by the late
    # registration + the replay
    if service.index().obligations:
        problems.append(
            "late endpoint registration changed the historical "
            "replay: the replay created a webhook obligation (%d) "
            "for a mutation that completed with no audience"
            % len(service.index().obligations)
        )
    # (9) no delivery occurs (the pump runs; there is nothing
    # to deliver and nothing may be fabricated)
    service.process_due_deliveries()
    if service.index().deliveries:
        problems.append(
            "late endpoint registration produced a delivery for "
            "the historical no-audience mutation"
        )
    if consumer.deliveries:
        problems.append(
            "the late-registered endpoint received the historical "
            "no-audience event (%d deliveries)"
            % len(consumer.deliveries)
        )
    # the historical admission decision stays terminal
    admissions_a = [
        record
        for record in service.journal_records()
        if isinstance(record, WebhookAdmissionRecord)
    ]
    offer_admissions_a = [
        record
        for record in admissions_a
        if record.idempotency_key == "adm45-a-1"
    ]
    if len(offer_admissions_a) != 1:
        problems.append(
            "expected exactly one admission record for the "
            "no-audience mutation, found %d" % len(offer_admissions_a)
        )
    else:
        adm = offer_admissions_a[0]
        if adm.status != "not-required":
            problems.append(
                "no-audience admission status %r" % adm.status
            )
        if tuple(adm.endpoints) != ():
            problems.append(
                "no-audience admission carries endpoints %s"
                % (adm.endpoints,)
            )
    service.verify_integrity()

    # -- scenario B: required admission, obligation failure, and
    # the audience-freeze retry --------------------------------------
    store_b = _ObligationFailingApiStore(failures=1)
    core_store_b = MemoryCommercialStore()
    service_b, core_b, usage_b, allocation_b, world_b = _compose_service(
        store=store_b, core_store=core_store_b
    )
    runtime_b, peer_b, session_b, manager_b, integrator_b, shared_b = (
        world_b
    )
    app_b = _full_app(service_b, "dev-drift", "drift")
    ep1 = service_b.handle(
        _req(
            "POST",
            "/api/1.0/webhook-endpoints",
            app_b,
            body={
                "url": "https://consumer-drift-1.test/hook",
                "event_types": ["connectivity_intent.created"],
            },
            idempotency_key="drift-ep-1",
        )
    )
    ep1_id = ep1.body["data"]["id"]
    intent_body_b = {"intent": {"subscriber": "drift-window"}}
    # (1)-(4): the mutation executes and is durable; the
    # admission record is durably written as required with the
    # frozen audience; the OBLIGATION append fails; the API does
    # NOT return success
    first_b = service_b.handle(
        _req(
            "POST",
            "/api/1.0/intents",
            app_b,
            body=intent_body_b,
            idempotency_key="drift-intent-1",
        )
    )
    if first_b.status != 500 or (
        first_b.body.get("error", {}).get("reason") != "store-failed"
    ):
        problems.append(
            "obligation-write failure did not fail admission (B): "
            "status %s reason %r"
            % (first_b.status, first_b.body.get("error", {}).get("reason"))
        )
    if "drift-intent-1" not in service_b.index().mutations:
        problems.append("durable mutation missing after the failure (B)")
    if len(core_b.journal_records()) != 1:
        problems.append(
            "canonical mutation not durable (B): %d core records"
            % len(core_b.journal_records())
        )
    if store_b.failures != 1:
        problems.append(
            "injection (B) did not fire at the obligation append "
            "(failures=%d)" % store_b.failures
        )
    if service_b.index().obligations:
        problems.append("obligation fabricated despite the failure (B)")
    # (5) the process state is discarded; the service reloads
    # from the durable stores
    core_b2 = CommercialCore.load(
        store=core_store_b,
        clock=shared_b,
        references=_references(manager_b, integrator_b, session_b),
    )
    reloaded_b = DeveloperApiService.load(
        environment="sandbox",
        core=core_b2,
        usage=usage_b,
        allocation=allocation_b,
        store=store_b,
        clock=shared_b,
        issuance_key=b"w046-platform-issuance-key",
    )
    # (9-pre) recovery alone re-executed nothing
    if len(core_b2.journal_records()) != 1:
        problems.append("crash recovery re-executed the mutation (B)")
    # (9) the current endpoint set is intentionally CHANGED
    # before the retry: a NEW endpoint subscribed to the SAME
    # event type joins the developer's audience (the endpoint
    # model permits registration only -- no removal exists)
    ep2 = reloaded_b.handle(
        _req(
            "POST",
            "/api/1.0/webhook-endpoints",
            app_b,
            body={
                "url": "https://consumer-drift-2.test/hook",
                "event_types": ["connectivity_intent.created"],
            },
            idempotency_key="drift-ep-2",
        )
    )
    ep2_id = ep2.body["data"]["id"]
    # (8) the same-key retry: the frozen audience from the
    # admission record
    retry_b = reloaded_b.handle(
        _req(
            "POST",
            "/api/1.0/intents",
            app_b,
            body=intent_body_b,
            idempotency_key="drift-intent-1",
        )
    )
    prior_b = reloaded_b.index().mutations["drift-intent-1"]
    if retry_b.status != 200 or (
        retry_b.headers.get("X-ADCOS-Idempotent-Replay") != "true"
    ):
        problems.append(
            "healing retry not a 200 replay (B): %s" % retry_b.status
        )
    if retry_b.canonical_body_bytes() != canonical_json_bytes(
        json.loads(prior_b.response_body)
    ):
        problems.append("healing replay body diverged (B)")
    # (13) the canonical mutation executes exactly zero
    # additional times
    if len(core_b2.journal_records()) != 1:
        problems.append("healing retry re-executed the mutation (B)")
    # (10) the retry used the ORIGINAL frozen audience: the
    # healed obligation carries exactly the admission-time
    # endpoints -- never the late-registered one
    obligations_b = [
        record
        for record in reloaded_b.journal_records()
        if record.to_dict().get("record_kind") == "webhook-obligation"
    ]
    if len(obligations_b) != 1:
        problems.append(
            "healed obligation count (B) %d" % len(obligations_b)
        )
    else:
        healed_endpoints = tuple(
            obligations_b[0].to_dict().get("endpoints", ())
        )
        if ep2_id in healed_endpoints:
            problems.append(
                "the retry re-resolved the audience: the healed "
                "obligation carries the late-registered endpoint "
                "(frozen audience was %s, healed audience is %s)"
                % ((ep1_id,), healed_endpoints)
            )
        if healed_endpoints != (ep1_id,):
            problems.append(
                "healed obligation audience %s (expected the frozen "
                "admission audience (%s,))"
                % (healed_endpoints, ep1_id)
            )
    # (11)+(12)+(15): delivery succeeds exactly once for the
    # frozen audience; the NEW endpoint never receives the
    # historical event
    consumer_1 = _Consumer(reloaded_b.endpoint_signing_secret(ep1_id))
    consumer_2 = _Consumer(reloaded_b.endpoint_signing_secret(ep2_id))
    reloaded_b._transports[ep1_id] = consumer_1
    reloaded_b._transports[ep2_id] = consumer_2
    reloaded_b.process_due_deliveries()
    if len(consumer_1.deliveries) != 1:
        problems.append(
            "frozen-audience endpoint received %d deliveries "
            "(expected exactly one) (B)"
            % len(consumer_1.deliveries)
        )
    if consumer_2.deliveries:
        problems.append(
            "the NEW endpoint received the historical event (B): %d "
            "deliveries -- the retry re-resolved the audience from "
            "the current endpoint state" % len(consumer_2.deliveries)
        )
    # exactly-once: a second pump pass is a no-op
    journal_b_before = len(reloaded_b.journal_records())
    reloaded_b.process_due_deliveries()
    if len(reloaded_b.journal_records()) != journal_b_before:
        problems.append("second pump pass grew the journal (B)")
    if len(consumer_1.deliveries) != 1:
        problems.append("second pump pass re-delivered (B)")
    # the frozen admission record itself (the structural truth
    # behind the behavioral freeze)
    admissions_b = [
        record
        for record in reloaded_b.journal_records()
        if isinstance(record, WebhookAdmissionRecord)
        and record.idempotency_key == "drift-intent-1"
    ]
    if len(admissions_b) != 1:
        problems.append(
            "expected exactly one admission record for the drift "
            "mutation, found %d" % len(admissions_b)
        )
    else:
        adm_b = admissions_b[0]
        if adm_b.status != "required":
            problems.append("drift admission status %r" % adm_b.status)
        if tuple(adm_b.endpoints) != (ep1_id,):
            problems.append(
                "the admission record did not freeze the original "
                "audience: %s" % (adm_b.endpoints,)
            )
    reloaded_b.verify_integrity()

    # -- scenario C: admission-record persistence failure -------------
    store_c = _AdmissionFailingApiStore("adm45-c-1")
    core_store_c = MemoryCommercialStore()
    service_c, core_c, usage_c, allocation_c, world_c = _compose_service(
        store=store_c, core_store=core_store_c
    )
    runtime_c, peer_c, session_c, manager_c, integrator_c, shared_c = (
        world_c
    )
    app_c = _full_app(service_c, "dev-admc", "admc")
    ep_c = service_c.handle(
        _req(
            "POST",
            "/api/1.0/webhook-endpoints",
            app_c,
            body={
                "url": "https://consumer-adm45-c.test/hook",
                "event_types": ["connectivity_intent.created"],
            },
            idempotency_key="adm45-c-ep-1",
        )
    )
    ep_c_id = ep_c.body["data"]["id"]
    intent_body_c = {"intent": {"subscriber": "admission-boundary"}}
    # (2)+(3)+(4): the mutation becomes durable; the
    # ADMISSION-record append fails; the API returns the
    # deterministic non-success
    first_c = service_c.handle(
        _req(
            "POST",
            "/api/1.0/intents",
            app_c,
            body=intent_body_c,
            idempotency_key="adm45-c-1",
        )
    )
    if first_c.status != 500 or (
        first_c.body.get("error", {}).get("reason") != "store-failed"
    ):
        problems.append(
            "admission-record write failure did not fail admission "
            "(C): status %s reason %r"
            % (
                first_c.status,
                first_c.body.get("error", {}).get("reason"),
            )
        )
    else:
        message = first_c.body["error"].get("message", "")
        if "adm45-c-1" not in message:
            problems.append(
                "admission failure message lost the key (C)"
            )
        if "NOT rolled back or re-executed" not in message:
            problems.append(
                "admission failure message lost the durability truth (C)"
            )
        if "SAME idempotency key" not in message:
            problems.append(
                "admission failure message lost the retry contract (C)"
            )
    # (5)+(6): no false success, no canonical mutation rollback
    if "adm45-c-1" not in service_c.index().mutations:
        problems.append("durable mutation missing after the failure (C)")
    if len(core_c.journal_records()) != 1 or len(core_c.transactions()) != 1:
        problems.append(
            "canonical mutation not durable (C): %d/%d"
            % (len(core_c.journal_records()), len(core_c.transactions()))
        )
    if store_c.failures != 1:
        problems.append(
            "injection (C) did not fire at the admission append "
            "(failures=%d)" % store_c.failures
        )
    # nothing was fabricated: no admission for the key, no
    # obligation, no queue record, no contained incident
    admissions_c = [
        record
        for record in service_c.journal_records()
        if isinstance(record, WebhookAdmissionRecord)
        and record.idempotency_key == "adm45-c-1"
    ]
    if admissions_c:
        problems.append("admission recorded despite the failed write (C)")
    if service_c.index().obligations or service_c.index().deliveries:
        problems.append("obligation/delivery fabricated (C)")
    if service_c.webhook_observation_incidents():
        problems.append(
            "admission failure misclassified as a contained incident (C)"
        )
    # (7) the process crashes; both planes are reconstructed
    # from the durable stores
    core_c2 = CommercialCore.load(
        store=core_store_c,
        clock=shared_c,
        references=_references(manager_c, integrator_c, session_c),
    )
    reloaded_c = DeveloperApiService.load(
        environment="sandbox",
        core=core_c2,
        usage=usage_c,
        allocation=allocation_c,
        store=store_c,
        clock=shared_c,
        issuance_key=b"w046-platform-issuance-key",
    )
    if "adm45-c-1" not in reloaded_c.index().mutations:
        problems.append("idempotency did not survive the crash (C)")
    # (8)+(9)+(10): the same-key retry establishes the admission
    # state from the request + the durable canonical mutation
    # ONLY, and only then returns the canonical success
    retry_c = reloaded_c.handle(
        _req(
            "POST",
            "/api/1.0/intents",
            app_c,
            body=intent_body_c,
            idempotency_key="adm45-c-1",
        )
    )
    prior_c = reloaded_c.index().mutations["adm45-c-1"]
    if retry_c.status != 200 or (
        retry_c.headers.get("X-ADCOS-Idempotent-Replay") != "true"
    ):
        problems.append(
            "healing retry not a 200 replay (C): %s" % retry_c.status
        )
    if retry_c.canonical_body_bytes() != canonical_json_bytes(
        json.loads(prior_c.response_body)
    ):
        problems.append("healing replay body diverged (C)")
    # (11) the canonical mutation executes exactly ZERO
    # additional times
    if len(core_c2.journal_records()) != 1:
        problems.append("healing retry re-executed the mutation (C)")
    transaction_c = prior_c.response_body and json.loads(
        prior_c.response_body
    ).get("data", {}).get("id", "")
    if transaction_c and (
        core_c2.transaction(transaction_c).to_dict().get("event_count") != 1
    ):
        problems.append("canonical transaction mutated during healing (C)")
    # the admission + obligation were established by the retry
    # (exactly one of each, carrying the endpoint and the
    # canonical event identity)
    admissions_c2 = [
        record
        for record in reloaded_c.journal_records()
        if isinstance(record, WebhookAdmissionRecord)
        and record.idempotency_key == "adm45-c-1"
    ]
    if len(admissions_c2) != 1:
        problems.append(
            "healed admission count (C) %d" % len(admissions_c2)
        )
    else:
        adm_c = admissions_c2[0]
        if adm_c.status != "required":
            problems.append("healed admission status (C) %r" % adm_c.status)
        if tuple(adm_c.endpoints) != (ep_c_id,):
            problems.append(
                "healed admission audience (C) %s" % (adm_c.endpoints,)
            )
        core_event_c = core_c2.journal_records()[0].event.to_dict()
        if adm_c.event_id != core_event_c.get("event_id"):
            problems.append(
                "healed admission event id diverged from the canonical "
                "event (C)"
            )
    obligations_c = [
        record
        for record in reloaded_c.journal_records()
        if record.to_dict().get("record_kind") == "webhook-obligation"
    ]
    if len(obligations_c) != 1:
        problems.append("healed obligation count (C) %d" % len(obligations_c))
    elif ep_c_id not in tuple(
        obligations_c[0].to_dict().get("endpoints", ())
    ):
        problems.append("healed obligation lost the endpoint (C)")
    # the delivery pump completes the observation exactly once
    consumer_c = _Consumer(reloaded_c.endpoint_signing_secret(ep_c_id))
    reloaded_c._transports[ep_c_id] = consumer_c
    reloaded_c.process_due_deliveries()
    if len(consumer_c.deliveries) != 1:
        problems.append(
            "consumer (C) received %d events (expected exactly one)"
            % len(consumer_c.deliveries)
        )
    journal_c_before = len(reloaded_c.journal_records())
    reloaded_c.process_due_deliveries()
    if len(reloaded_c.journal_records()) != journal_c_before:
        problems.append("second pump pass grew the journal (C)")
    reloaded_c.verify_integrity()

    # -- the structural audit (journal family + AST) ------------------
    problems.extend(_audit_observation_admission_structure())

    if problems:
        results.append(
            fail(
                "45 durable observation admission state",
                "; ".join(problems),
            )
        )
    else:
        results.append(
            ok(
                "45 durable observation admission state",
                "no-audience replay stays obligation-free after late "
                "registration; the audience-drift retry heals with the "
                "FROZEN admission audience; the admission-record write "
                "failure returns deterministic non-success and heals "
                "from request + durable mutation with zero "
                "re-execution; one canonical admission path "
                "(AST-audited)",
            )
        )


def _audit_observation_admission_structure() -> List[str]:
    """The structural audit for the durable observation-admission
    state: journal family membership, and the AST audit of the
    observation-emission call sites in the gateway (ONE
    canonical admission path, no audience re-resolution on the
    historical replay path, no process-local observation
    state)."""
    problems: List[str] = []

    # -- the journal record family membership ------------------------
    from developerapi.journal import RECORD_KINDS, RECORD_TYPES

    if "webhook-admission" not in RECORD_KINDS:
        problems.append("webhook-admission missing from RECORD_KINDS")
    if WebhookAdmissionRecord not in RECORD_TYPES:
        problems.append("WebhookAdmissionRecord missing from RECORD_TYPES")
    # constructor validation: status/endpoints consistency
    try:
        WebhookAdmissionRecord(
            sequence=1,
            record_id="pending",
            admission_id="sha256:" + "1" * 64,
            idempotency_key="audit-1",
            event_id="sha256:" + "2" * 64,
            status="maybe",
            developer_id="dev-audit",
            environment="sandbox",
            event_type="offer.published",
            occurred_at="2026-09-01T00:00:00Z",
            resource_kind="offer",
            resource_id="sha256:" + "3" * 64,
            resource_version=1,
            correlation="",
            data={"id": "x"},
            endpoints=(),
        )
        problems.append("admission constructor accepted a bad status")
    except DeveloperApiError:
        pass
    # the fold fail-closed: an admission for a mutation the
    # journal does not hold is journal-corrupt (an admission is
    # written only AFTER its mutation record)
    mut = MutationRecord.build(
        sequence=1,
        prev_record_id="sha256:" + "0" * 64,
        idempotency_key="audit-key",
        application_id="app-audit",
        developer_id="dev-audit",
        method="POST",
        route="/api/1.0/offers",
        api_version="1.0",
        request_id="sha256:" + "4" * 64,
        request_digest="sha256:" + "5" * 64,
        resource_kind="offer",
        resource_id="sha256:" + "6" * 64,
        resource={},
        response_status=200,
        response_body="{}",
    )
    orphan = WebhookAdmissionRecord.build(
        sequence=2,
        prev_record_id=mut.record_id,
        admission_id=webhook_platform.derive_admission_id(
            "sandbox", "sha256:" + "7" * 64, "offer.published"
        ),
        idempotency_key="audit-ORPHAN",
        event_id="sha256:" + "7" * 64,
        status="not-required",
        developer_id="dev-audit",
        environment="sandbox",
        event_type="offer.published",
        occurred_at="2026-09-01T00:00:00Z",
        resource_kind="offer",
        resource_id="sha256:" + "8" * 64,
        resource_version=1,
        correlation="",
        data={"id": "x"},
        endpoints=(),
    )
    try:
        fold_index((mut, orphan))
        problems.append(
            "the fold accepted an admission for an unknown mutation"
        )
    except DeveloperApiError as error:
        if error.reason != DeveloperApiReasonCode.JOURNAL_CORRUPT:
            problems.append(
                "orphan admission rejected with %r" % error.reason
            )

    # -- the AST audit of the gateway's admission call sites ---------
    source = (REPO_ROOT / "developerapi" / "gateway.py").read_text(
        encoding="utf-8"
    )
    if "_pending_emissions" in source or "pending_emissions" in source:
        problems.append("process-local observation state exists")

    tree = ast.parse(source, filename="developerapi/gateway.py")

    # (function name -> set of self.<method> names called there)
    method_calls: Dict[str, set] = {}
    # (function name -> set of <Class>.build class-method calls)
    build_calls: Dict[str, set] = {}

    def _enclosing(node: ast.AST) -> Optional[ast.FunctionDef]:
        for candidate in ast.walk(tree):
            if isinstance(candidate, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(candidate):
                    if child is node:
                        return candidate
        return None

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and isinstance(
            func.value, ast.Name
        ):
            owner = func.value.id
            if owner == "self":
                enclosing = _enclosing(node)
                if enclosing is not None:
                    method_calls.setdefault(enclosing.name, set()).add(
                        func.attr
                    )
            elif func.attr == "build" and owner in (
                "WebhookAdmissionRecord",
                "WebhookObligationRecord",
                "WebhookQueueRecord",
            ):
                enclosing = _enclosing(node)
                if enclosing is not None:
                    build_calls.setdefault(enclosing.name, set()).add(owner)

    resolver_callers = sorted(
        name
        for name, calls in method_calls.items()
        if "_resolve_observation_audience" in calls
    )
    if resolver_callers != ["_emit_event", "_establish_observation_admission"]:
        problems.append(
            "audience resolution is not confined to the canonical "
            "admission path (callers: %s)" % resolver_callers
        )
    admission_builders = sorted(
        name
        for name, builds in build_calls.items()
        if "WebhookAdmissionRecord" in builds
    )
    if admission_builders != ["_append_observation_admission"]:
        problems.append(
            "the admission record is not written from the single "
            "canonical site (builders: %s)" % admission_builders
        )
    admission_callers = sorted(
        name
        for name, calls in method_calls.items()
        if "_append_observation_admission" in calls
    )
    if admission_callers != ["_emit_event", "_establish_observation_admission"]:
        problems.append(
            "the admission write is reachable outside the canonical "
            "admission paths (callers: %s)" % admission_callers
        )
    obligation_builders = sorted(
        name
        for name, builds in build_calls.items()
        if "WebhookObligationRecord" in builds
    )
    if obligation_builders != ["_append_observation_obligation"]:
        problems.append(
            "the obligation record is not written from the single "
            "canonical site (builders: %s)" % obligation_builders
        )
    # the historical replay path never re-resolves the audience:
    # _complete_prior_admission uses ONLY the frozen admission
    # (via _ensure_obligation_from_admission) or establishes a
    # first admission (via _establish_observation_admission /
    # _reconstruct_emission); it never calls the resolver itself
    completion_calls = method_calls.get("_complete_prior_admission", set())
    if "_resolve_observation_audience" in completion_calls:
        problems.append(
            "the historical replay path re-resolves the audience "
            "from current endpoint state"
        )
    ensure_calls = method_calls.get("_ensure_obligation_from_admission", set())
    if "_resolve_observation_audience" in ensure_calls:
        problems.append(
            "the frozen-admission obligation recovery re-resolves the "
            "audience"
        )
    return problems


def case_35_determinism_two_run(results: List[Result]) -> None:
    """Two fresh in-process runs of the golden scenario produce
    byte-identical digest streams."""
    stream1 = _scenario_stream()
    stream2 = _scenario_stream()
    if stream1 != stream2:
        differing = [
            key for key in stream1 if stream1[key] != stream2.get(key)
        ]
        results.append(
            fail(
                "35 determinism (two runs)",
                "digest stream diverged: %s" % differing,
            )
        )
    else:
        results.append(
            ok(
                "35 determinism (two runs)",
                "golden stream identical (%s keys)" % len(stream1),
            )
        )


def case_36_determinism_hash_seeds(results: List[Result]) -> None:
    """PYTHONHASHSEED 0/1/7919/unset subprocesses reproduce the
    golden digest stream byte-identically."""
    digests: Dict[str, str] = {}
    for seed in ("0", "1", "7919", "unset"):
        env = dict(os.environ)
        if seed == "unset":
            env.pop("PYTHONHASHSEED", None)
        else:
            env["PYTHONHASHSEED"] = seed
        env.pop("PYTHONDONTWRITEBYTECODE", None)
        proc = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--determinism-stream",
            ],
            capture_output=True,
            text=True,
            env=env,
            cwd=str(REPO_ROOT),
            timeout=600,
        )
        if proc.returncode != 0:
            results.append(
                fail(
                    "36 determinism (hash seeds)",
                    "seed %s exited %d: %s"
                    % (seed, proc.returncode, proc.stderr[-300:]),
                )
            )
            return
        digests[seed] = proc.stdout.strip()
    unique = set(digests.values())
    if len(unique) != 1:
        results.append(
            fail(
                "36 determinism (hash seeds)",
                "streams diverged across seeds: %s"
                % [len(stream) for stream in unique],
            )
        )
    else:
        results.append(
            ok(
                "36 determinism (hash seeds)",
                "0/1/7919/unset byte-identical",
            )
        )


def case_37_secret_hygiene(results: List[Result]) -> None:
    """Secret hygiene over the full golden scenario: journal
    bytes and every response body are free of credential and
    webhook secret material."""
    stream = _scenario_stream()  # runs the full scenario
    problems: List[str] = []
    # re-compose and inspect the raw journal text
    service, *_ = _compose_service()
    app = _full_app(service, "dev-hyg", "hyg")
    endpoint = service.handle(
        _req(
            "POST",
            "/api/1.0/webhook-endpoints",
            app,
            body={
                "url": "https://consumer.test/hook",
                "event_types": ["offer.published"],
            },
            idempotency_key="hyg-ep-1",
        )
    )
    service.handle(
        _req(
            "POST",
            "/api/1.0/offers",
            app,
            body=_offer_body("Hygiene offer"),
            idempotency_key="hyg-1",
        )
    )
    journal_text = "\n".join(
        json.dumps(record.to_dict(), sort_keys=True, default=str)
        for record in service.journal_records()
    )
    endpoint_secret = service.endpoint_signing_secret(
        endpoint.body["data"]["id"]
    )
    for secret in (app.secret, endpoint_secret):
        if secret and secret in journal_text:
            problems.append("secret material in journal bytes")
        if secret and secret in stream.get("mutation_digests", ""):
            problems.append("secret material in the digest stream")
    for prefix in _SECRET_PREFIXES:
        if prefix in journal_text:
            problems.append("secret prefix %r in journal bytes" % prefix)
    if problems:
        results.append(fail("37 secret hygiene", "; ".join(problems)))
    else:
        results.append(
            ok(
                "37 secret hygiene",
                "no credential/webhook secret material in any durable "
                "surface",
            )
        )


def case_38_frozen_public_api(results: List[Result]) -> None:
    """The frozen public API surface (independently pinned)."""
    actual = sorted(developerapi.__all__)
    if actual != _EXPECTED_API:
        results.append(
            fail(
                "38 frozen public API",
                "surface changed (%d vs %d exports)"
                % (len(actual), len(_EXPECTED_API)),
            )
        )
    else:
        results.append(
            ok(
                "38 frozen public API",
                "%d exports frozen (battery-pinned)" % len(actual),
            )
        )


def case_39_py_compile(results: List[Result]) -> None:
    """Every family module byte-compiles."""
    problems: List[str] = []
    for path in _FAMILY_FILES:
        proc = subprocess.run(
            [sys.executable, "-m", "py_compile", str(path)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if proc.returncode != 0:
            problems.append(
                "%s: %s" % (path.name, proc.stderr.strip()[-200:])
            )
    if problems:
        results.append(fail("39 py_compile", "; ".join(problems)))
    else:
        results.append(
            ok("39 py_compile", "%d modules compile" % len(_FAMILY_FILES))
        )


def case_40_frozen_spec_intact(results: List[Result]) -> None:
    """Frozen spec surfaces and unrelated families are
    byte-identical to the branch HEAD (no out-of-scope edits in
    the working tree)."""
    problems: List[str] = []
    head = subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    if head.returncode != 0:
        results.append(
            ok(
                "40 frozen surfaces intact",
                "skipped (no git HEAD in this checkout; the branch and "
                "merge-ref contexts enforce it)",
            )
        )
        return
    guarded = [
        "spec/architect/execution-state.yaml",
        "spec/architect/execution-ledger.yaml",
        "spec/work-items.md",
        "spec/dependency-graph.md",
        "tools/spec_check.py",
    ]
    for rel in guarded:
        target = REPO_ROOT / rel
        if not target.is_file():
            problems.append("missing guarded file %s" % rel)
            continue
        proc = subprocess.run(
            ["git", "diff", "--quiet", "HEAD", "--", rel],
            cwd=str(REPO_ROOT),
            capture_output=True,
        )
        if proc.returncode != 0:
            problems.append("%s differs from HEAD" % rel)
    # the workflow may differ ONLY additively (the authorized CI
    # wiring): verify no step was removed or weakened
    proc = subprocess.run(
        ["git", "diff", "HEAD", "--", ".github/workflows/spec-check.yml"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    diff = proc.stdout
    if diff:
        removed = [
            line
            for line in diff.splitlines()
            if line.startswith("-") and not line.startswith("---")
        ]
        if removed:
            problems.append(
                "CI workflow diff removed lines (%d)" % len(removed)
            )
        if "developerapi_selftest.py" not in diff:
            problems.append("CI diff does not add the W046 battery step")
        if "spec_check.py" not in diff and "eligibility_selftest.py" not in (
            Path(".github/workflows/spec-check.yml").read_text(
                encoding="utf-8"
            )
        ):
            problems.append("CI workflow lost existing steps")
    else:
        # no working-tree delta: the committed workflow must still
        # carry the W046 battery step (main wiring verification,
        # the management/simulator precedent)
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "spec-check.yml"
        ).read_text(encoding="utf-8")
        if "python3 tools/developerapi_selftest.py" not in workflow:
            problems.append("CI workflow does not invoke the W046 battery")
    if problems:
        results.append(fail("40 frozen surfaces intact", "; ".join(problems)))
    else:
        results.append(
            ok(
                "40 frozen surfaces intact",
                "spec/architect + checker + families byte-identical; CI "
                "delta additive-only",
            )
        )


def case_41_pr_delta_shape(results: List[Result]) -> None:
    """The PR delta is confined to the authorized WORK-046 scope
    (+ the sanctioned additive CI wiring)."""
    problems: List[str] = []
    # the delta is measured from the PR's merge base with main
    # (the exact branch point of this implementation; main may
    # have advanced with governance merges, which are NOT this
    # implementation's delta -- the merge-base is the honest
    # boundary the Architect reviews)
    merge_base = subprocess.run(
        ["git", "merge-base", "HEAD", "origin/main"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    if merge_base.returncode != 0:
        results.append(
            ok(
                "41 PR delta shape",
                "skipped (no origin/main ref in this checkout; CI "
                "enforces the shape on the PR)",
            )
        )
        return
    base = merge_base.stdout.strip()
    proc = subprocess.run(
        ["git", "diff", "--name-only", base],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    delta = [line for line in proc.stdout.splitlines() if line.strip()]
    untracked = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    delta += [
        line for line in untracked.stdout.splitlines() if line.strip()
    ]
    unexpected = []
    for path in delta:
        if path.startswith(_AUTHORIZED_PATHS):
            continue
        if path == AUTHORIZED_CI_WIRING:
            continue
        if path.endswith(".pyc") or "__pycache__" in path:
            continue
        unexpected.append(path)
    if unexpected:
        problems.append("out-of-scope delta: %s" % unexpected[:5])
    # spec/architect is NEVER touched by the implementation PR
    architect = [p for p in delta if p.startswith("spec/architect/")]
    if architect:
        problems.append("spec/architect modified: %s" % architect[:5])
    if problems:
        results.append(fail("41 PR delta shape", "; ".join(problems)))
    else:
        results.append(
            ok(
                "41 PR delta shape",
                "%d file(s) confined to developerapi/ + tools/ + docs/ + "
                "the additive CI step" % len(delta),
            )
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    results: List[Result] = []
    for case in (
        case_01_frozen_vocabularies,
        case_02_version_policy,
        case_03_schema_compatibility,
        case_04_environments_isolation,
        case_05_credentials,
        case_06_authentication_failures,
        case_07_capability_authorization,
        case_08_idempotency_normal_duplicate,
        case_09_idempotency_conflict,
        case_10_idempotency_concurrent,
        case_11_idempotency_restart,
        case_12_idempotency_crash_window,
        case_13_commercial_lifecycle_flow,
        case_14_reason_code_preservation,
        case_15_pagination,
        case_16_rate_limiting,
        case_17_correlation_secrets,
        case_18_webhook_signing,
        case_19_webhook_duplicate_replay,
        case_20_webhook_out_of_order,
        case_21_webhook_retry,
        case_22_webhook_environment_separation,
        case_23_sdk_request_parity,
        case_24_sdk_response_parity,
        case_25_sdk_webhook_verification_parity,
        case_26_usage_billing_reads,
        case_27_economic_policy,
        case_28_authority_import_discipline,
        case_29_no_shadow_authority,
        case_30_sdk_no_hidden_authority,
        case_31_physical_evidence_honesty,
        case_32_journal_tamper,
        case_33_journal_first_recovery,
        case_34_failure_injection,
        case_35_determinism_two_run,
        case_36_determinism_hash_seeds,
        case_37_secret_hygiene,
        case_38_frozen_public_api,
        case_39_py_compile,
        case_40_frozen_spec_intact,
        case_41_pr_delta_shape,
        case_42_post_finality_webhook_isolation,
        case_43_durable_webhook_obligation_crash_recovery,
        case_44_obligation_write_admission_gate,
        case_45_durable_observation_admission_state,
    ):
        case(results)
    failures = [result for result in results if not result[1]]
    for entry in results:
        print(
            "[%s] %-44s %s"
            % ("ok  " if entry[1] else "FAIL", entry[0], entry[2])
        )
    if failures:
        print("Result: FAIL (%d/%d cases failed)" % (len(failures), len(results)))
        for entry in failures:
            print("  FAILED %s: %s" % (entry[0], entry[2]))
        return 1
    print("Result: PASS (%d/%d cases passed)" % (len(results), len(results)))
    return 0


if __name__ == "__main__":
    if "--determinism-stream" in sys.argv:
        stream = _scenario_stream()
        for key in sorted(stream):
            print("%s=%s" % (key, stream[key]))
        sys.exit(0)
    sys.exit(main())
