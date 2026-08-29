#!/usr/bin/env python3
"""WORK-035 Android/mobile-agent battery (deterministic, stdlib only).

End-to-end verification of the mobile participation layer over the
accepted WORK-033 Linux agent:

- lifecycle: the frozen phase vocabulary and legal-transition table,
  the OS platform snapshot as explicit input (fail-closed sources),
  and the pure participation gate's totality and precedence
  (connectivity -> metered consent -> phase -> OS restriction);
- foreground/background: sends defer with typed reasons while
  backgrounded without consent, drain when consent arrives, phase
  return alone re-opens participation, and an OS background
  restriction overrides user consent (within OS limits);
- offline/online: connectivity events, access-path failure, deferred
  sends draining through the SAME session_id when connectivity
  returns (byte-identical payload delivery to the peer);
- handover: Wi-Fi -> cellular re-binding through the ordinary
  WORK-033 binding path (unchanged session_id, changed W018 IP
  binding), user-consent refusal for metered access, and unmetered
  handover needing no consent;
- user-controlled resource sharing: metered-data / background-data /
  local-discovery consent grants as INPUT (TTL expiry, explicit
  revocation, journaled), never a policy or resource authority;
- restart/recovery: the stop produces a durable secret-free snapshot,
  a stopped process refuses commands, recovery continues the journal,
  restores grants and the aging defer queue, records the session
  loss honestly, and re-establishes through the ordinary path;
- local discovery: the host-provided port participates only with the
  user's consent, and a genuine signed WORK-006 exchange flows
  through the gate (verified observations, NodeID binding, forgery
  rejection); the null default fabricates nothing;
- determinism (fresh subprocesses, PYTHONHASHSEED variations, replay
  verification), structural audits (no shadow authority, import
  discipline incl. the platform/vendor boundary, naming-token
  freedom, secret hygiene), and the frozen surfaces (API, spec/,
  PR-delta shape, CI wiring);
- the anti-faking device-evidence disclosure: software/emulated
  mobile lifecycle evidence is SUPPORTED, physical Android handset
  evidence is explicitly OPEN, and the battery asserts it stays that
  way.
"""

from __future__ import annotations

import os
import py_compile
import re
import subprocess  # noqa: S404 - deterministic child processes of this repo's own tools
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from identity.node_id import parse_node_id  # noqa: E402
from multipath import PathStatus  # noqa: E402
from policy import (  # noqa: E402
    PolicyDomain,
    PolicyRule,
)
from topology import (  # noqa: E402
    ClaimType,
    SourceClass,
    TopologyClaim,
    make_link_subject,
)

from agent import (  # noqa: E402
    AgentRuntime,
    AgentConfig,
    AgentIdentitySpec,
    InterfaceSnapshot,
    LinkMetricSpec,
    MigrationSpec,
    StaticInterfaceSource,
    StepClock,
)
from mobile import (  # noqa: E402
    MOBILE_EVIDENCE_STATUS,
    DeferReason,
    GrantScope,
    MobileAgent,
    MobileBudget,
    MobileCommand,
    MobileCommandKind,
    MobileError,
    MobileEvent,
    MobileEventType,
    MobileOutcome,
    MobilePhase,
    MobileReasonCode,
    MobileRunResult,
    MobileSnapshot,
    MobileVerdict,
    NetworkKind,
    NullDiscovery,
    ParticipationDecision,
    PeerObservation,
    PlatformSnapshot,
    PowerState,
    ShedReason,
    UserGrant,
    derive_mobile_command_id,
    derive_mobile_event_id,
    grant_active,
    mobile_event_list_digest,
    mobile_events_canonical_bytes,
    participation_gate,
    run_mobile_headless,
    transition_is_legal,
    verify_mobile_replay,
)
from mobile.discovery import (  # noqa: E402
    DiscoveryCycle,
    LocalDiscoveryPort,
)
from mobile.model import AccessPathView  # noqa: E402
from mobile.platform import (  # noqa: E402
    FailingPlatformSource,
    ScriptedPlatformSource,
    StaticPlatformSource,
)

Result = Tuple[str, bool, str]

_FAMILY_FILES = sorted((REPO_ROOT / "mobile").rglob("*.py"))

_T0 = "2025-06-01T00:00:00Z"
_FRESH = "2026-01-01T00:00:00Z"
_SECRET_A = b"mobile-battery-secret-A"
_SECRET_B = b"mobile-battery-secret-B"
_PROFILE_ID = "identity.sha256-hmac-dev.v1"
_KEY_A = b"mobile-battery-key-A"
_KEY_B = b"mobile-battery-key-B"

FG = MobilePhase.FOREGROUND
BG = MobilePhase.BACKGROUND
STOPPED = MobilePhase.STOPPED
WIFI = NetworkKind.WIFI
CELLULAR = NetworkKind.CELLULAR
NONE = NetworkKind.NONE

#: The full expected battery set wired into CI (36 prior tools +
#: this one).
_EXPECTED_TOOLS = [
    "spec_check.py", "spec_check_selftest.py", "schema_check.py",
    "schema_selftest.py", "envelope_selftest.py", "identity_selftest.py",
    "capability_selftest.py", "discovery_selftest.py",
    "topology_selftest.py", "resource_selftest.py", "intent_selftest.py",
    "policy_selftest.py", "routing_selftest.py", "session_selftest.py",
    "multipath_selftest.py", "mobility_selftest.py",
    "federation_selftest.py", "adapter_selftest.py",
    "transport_selftest.py", "ipintegration_selftest.py",
    "fivegc_selftest.py", "ran_selftest.py", "wifi_selftest.py",
    "backhaul_selftest.py", "mesh_selftest.py", "distcore_selftest.py",
    "service_selftest.py", "telemetry_selftest.py", "energy_selftest.py",
    "security_selftest.py", "upgrade_selftest.py", "management_selftest.py",
    "simulator_selftest.py", "conformance_selftest.py",
    "agent_selftest.py", "edge_selftest.py", "mobile_selftest.py",
    "appliance_selftest.py",
]

#: The frozen mobile public API surface (case_42).
_EXPECTED_API = [
    "AccessPathView",
    "DeferReason",
    "DiscoveryCycle",
    "FailingPlatformSource",
    "GrantScope",
    "LocalDiscoveryPort",
    "MOBILE_EVIDENCE_STATUS",
    "MobileAgent",
    "MobileBudget",
    "MobileCommand",
    "MobileCommandKind",
    "MobileError",
    "MobileEvent",
    "MobileEventType",
    "MobileOutcome",
    "MobilePhase",
    "MobilePlatformSource",
    "MobileReasonCode",
    "MobileRunResult",
    "MobileSnapshot",
    "MobileVerdict",
    "NetworkKind",
    "NullDiscovery",
    "ParticipationDecision",
    "PeerObservation",
    "PHASE_TRANSITIONS",
    "PlatformSnapshot",
    "PowerState",
    "ScriptedPlatformSource",
    "ShedReason",
    "StaticPlatformSource",
    "UserGrant",
    "derive_mobile_command_id",
    "derive_mobile_event_id",
    "grant_active",
    "mobile_event_list_digest",
    "mobile_events_canonical_bytes",
    "participation_gate",
    "run_mobile_headless",
    "transition_is_legal",
    "verify_mobile_replay",
]


def ok(name: str, detail: str = "") -> Result:
    return (name, True, detail)


def fail(name: str, detail: str) -> Result:
    return (name, False, detail)


# ---------------------------------------------------------------------------
# World construction
# ---------------------------------------------------------------------------


def _ids() -> Tuple[str, str]:
    """The deterministic node ids for the battery keys (derived through
    the genuine identity machinery)."""
    from identity.model import NodeIdentity
    from identity.profiles import ProfileSet

    profiles = ProfileSet.load_default()
    profile = profiles.get(_PROFILE_ID)
    identity_a = NodeIdentity.create(profile, _KEY_A, _T0)
    identity_b = NodeIdentity.create(profile, _KEY_B, _T0)
    return identity_a.node_id.text, identity_b.node_id.text


def _snapshots() -> Tuple[InterfaceSnapshot, ...]:
    """A mobile-node interface set: Wi-Fi + cellular + loopback."""
    return (
        InterfaceSnapshot(
            name="wlan0", link_kind="wireless", state_up=True, mtu=1500,
            speed_mbps=100, rx_bytes=7, tx_bytes=9, rx_errors=0,
            tx_errors=0, addresses=("fd00::a:1",),
        ),
        InterfaceSnapshot(
            name="rmnet0", link_kind="other", state_up=True, mtu=1400,
            speed_mbps=50, rx_bytes=11, tx_bytes=13, rx_errors=0,
            tx_errors=0,
        ),
        InterfaceSnapshot(
            name="lo", link_kind="loopback", state_up=True, mtu=65536,
            speed_mbps=0, rx_bytes=5, tx_bytes=5, rx_errors=0,
            tx_errors=0,
        ),
    )


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
    from management import ManagementCapability, RoleDefinition

    return (
        RoleDefinition(
            role_id="mobile-battery-operator",
            capabilities=(
                ManagementCapability.SESSION_READ,
                ManagementCapability.SESSION_CONTROL,
                ManagementCapability.POLICY_READ,
                ManagementCapability.TELEMETRY_READ,
                ManagementCapability.AUDIT_READ,
                ManagementCapability.ROLES_READ,
            ),
            description="operator role (battery fixture)",
        ),
    )


def _config(
    label: str = "mobile-node",
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
    phase: str = FG,
    network: str = WIFI,
    *,
    metered: bool = False,
    restricted: bool = False,
    power: str = PowerState.ON_BATTERY,
) -> PlatformSnapshot:
    return PlatformSnapshot(
        app_phase=phase,
        power_state=power,
        network_kind=network,
        metered=metered,
        background_restricted=restricted,
    )


def _script(*snapshots: PlatformSnapshot) -> ScriptedPlatformSource:
    return ScriptedPlatformSource(tuple(snapshots))


def _register_peers(a: AgentRuntime, b: AgentRuntime) -> None:
    cred_a = a.identity_service.active_credential(
        parse_node_id(a.node_id), "operational", now=a._now(),
    )
    cred_b = b.identity_service.active_credential(
        parse_node_id(b.node_id), "operational", now=b._now(),
    )
    a.register_peer(b.identity, cred_b, _SECRET_B)
    b.register_peer(a.identity, cred_a, _SECRET_A)


def _world(
    script: ScriptedPlatformSource,
    *,
    discovery: Optional[LocalDiscoveryPort] = None,
    budget: Optional[MobileBudget] = None,
) -> Tuple[MobileAgent, AgentRuntime]:
    """One booted mobile agent + one booted peered peer runtime.

    Both nodes read ONE shared clock (60-second steps); the read
    sequence stays deterministic for a fixed scenario.  The boot epoch
    consumes exactly ONE scripted platform observation."""
    shared = StepClock(_T0, 60)
    peer = AgentRuntime(
        _peer_config(),
        clock=shared,
        interface_source=StaticInterfaceSource(_snapshots()),
    )
    peer.boot(_SECRET_B)
    peer.expose_interfaces()
    mobile = MobileAgent(
        config=_config(),
        clock=shared,
        interface_source=StaticInterfaceSource(_snapshots()),
        platform_source=script,
        discovery=discovery,
        budget=budget,
        access_interfaces={WIFI: "wlan0", CELLULAR: "rmnet0"},
    )
    mobile.run_mobile(
        (
            MobileCommand(MobileCommandKind.BOOT, {}),
            MobileCommand(MobileCommandKind.EXPOSE_INTERFACES, {}),
        ),
        boot_secret=_SECRET_A,
    )
    _register_peers(mobile.runtime, peer)
    return mobile, peer


def _establish(mobile: MobileAgent, peer: AgentRuntime) -> str:
    """The ordinary handshake through the mobile node's runtime."""
    request = mobile.runtime.establish_session(peer.node_id)
    accept = peer.accept_session(request)
    confirm = mobile.runtime.complete_session(accept)
    peer.finalize_session(confirm)
    return confirm.session_id


def _send(sid: str, payload: bytes) -> MobileCommand:
    return MobileCommand(
        MobileCommandKind.SEND_DATAGRAM,
        {"session_id": sid, "payload_hex": payload.hex()},
    )


def _track(sid: str) -> MobileCommand:
    return MobileCommand(
        MobileCommandKind.TRACK_SESSION, {"session_id": sid},
    )


def _grant(scope: str, expires_at: str = "") -> MobileCommand:
    return MobileCommand(
        MobileCommandKind.GRANT, {"scope": scope, "expires_at": expires_at},
    )


def _revoke(scope: str) -> MobileCommand:
    return MobileCommand(MobileCommandKind.REVOKE_GRANT, {"scope": scope})


def _kinds(mobile: MobileAgent) -> List[str]:
    return [event.kind for event in mobile.mobile_events]


def _paths(mobile: MobileAgent, sid: str) -> List[Tuple[str, str]]:
    return [
        (view.access_class, view.status)
        for view in mobile.access_paths(sid)
    ]


# ---------------------------------------------------------------------------
# 1-6: value model
# ---------------------------------------------------------------------------


def case_01_frozen_vocabularies(results: List[Result]) -> None:
    name = "case_01_frozen_vocabularies"
    problems: List[str] = []
    if MobilePhase.values() != ("foreground", "background", "stopped"):
        problems.append("phase vocabulary %r" % (MobilePhase.values(),))
    if PowerState.values() != ("charging", "on-battery"):
        problems.append("power vocabulary %r" % (PowerState.values(),))
    if NetworkKind.values() != ("none", "wifi", "cellular"):
        problems.append("network vocabulary %r" % (NetworkKind.values(),))
    if GrantScope.values() != (
        "metered-data", "background-data", "local-discovery",
    ):
        problems.append("grant scopes %r" % (GrantScope.values(),))
    if MobileVerdict.values() != ("executed", "deferred", "shed"):
        problems.append("verdicts %r" % (MobileVerdict.values(),))
    if DeferReason.values() != (
        "offline", "metered-not-authorized", "background-not-authorized",
        "background-restricted", "stopped",
    ):
        problems.append("defer reasons %r" % (DeferReason.values(),))
    if ShedReason.values() != (
        "deferred-ttl-expired", "defer-queue-overflow", "session-lost",
    ):
        problems.append("shed reasons %r" % (ShedReason.values(),))
    expected_events = (
        "phase-changed", "connectivity-changed", "access-refused",
        "session-tracked", "session-bound-to-access", "handover-completed",
        "session-lost-at-restart", "send-deferred", "send-shed",
        "deferred-drained", "grant-granted", "grant-revoked",
        "grant-expired", "discovery-completed", "discovery-deferred",
        "checkpointed", "restarted",
    )
    if MobileEventType.values() != expected_events:
        problems.append("event vocabulary %r" % (MobileEventType.values(),))
    if MobileCommandKind.values() != (
        "boot", "expose-interfaces", "send-datagram", "receive-datagram",
        "track-session", "poll-discovery", "monitor", "grant",
        "revoke-grant", "checkpoint",
    ):
        problems.append("command vocabulary")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "all nine vocabularies exact and frozen"))


def case_02_platform_snapshot_validation(results: List[Result]) -> None:
    name = "case_02_platform_snapshot_validation"
    problems: List[str] = []
    snapshot = _snap(FG, WIFI)
    if snapshot.to_dict() != {
        "app_phase": "foreground", "power_state": "on-battery",
        "network_kind": "wifi", "metered": False,
        "background_restricted": False,
    }:
        problems.append("canonical dict diverged")
    if PlatformSnapshot.from_dict(snapshot.to_dict()) != snapshot:
        problems.append("round-trip diverged")
    for build_bad in (
        lambda: _snap("weird", WIFI),
        lambda: _snap(FG, "5g"),
        lambda: PlatformSnapshot(FG, "discharging", WIFI, False, False),
        lambda: PlatformSnapshot(FG, PowerState.ON_BATTERY, NONE, True, False),
        lambda: PlatformSnapshot(FG, PowerState.ON_BATTERY, WIFI, "yes", False),  # type: ignore[arg-type]
    ):
        try:
            build_bad().to_dict()
            problems.append("invalid snapshot accepted")
        except MobileError:
            pass
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "validation + round-trip; offline-never-metered enforced"),
    )


def case_03_user_grant_records(results: List[Result]) -> None:
    name = "case_03_user_grant_records"
    grant = UserGrant(
        scope=GrantScope.METERED_DATA,
        granted_at=_T0,
        expires_at="2025-06-01T00:05:00Z",
    )
    problems: List[str] = []
    if not grant.grant_id.startswith("sha256:"):
        problems.append("grant id not a digest")
    if UserGrant.from_dict(grant.to_dict()) != grant:
        problems.append("round-trip diverged")
    try:
        UserGrant("telemetry-sharing", _T0)
        problems.append("unknown scope accepted")
    except MobileError:
        pass
    grants = {GrantScope.METERED_DATA: grant}
    if not grant_active(grants, GrantScope.METERED_DATA, now=_T0):
        problems.append("grant inactive before expiry")
    if grant_active(grants, GrantScope.METERED_DATA, now="2025-06-01T00:05:00Z"):
        problems.append("grant active AT its expiry boundary")
    if grant_active(grants, GrantScope.BACKGROUND_DATA, now=_T0):
        problems.append("absent grant active")
    forever = UserGrant(scope=GrantScope.BACKGROUND_DATA, granted_at=_T0)
    if not grant_active(
        {GrantScope.BACKGROUND_DATA: forever},
        GrantScope.BACKGROUND_DATA, now="2030-01-01T00:00:00Z",
    ):
        problems.append("no-expiry grant inactive")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "content-derived ids; expires_at boundary strict; round-trip"),
    )


def case_04_participation_decision_validation(results: List[Result]) -> None:
    name = "case_04_participation_decision_validation"
    problems: List[str] = []
    base = dict(
        phase=FG, network_kind=WIFI, online=True, metered=False,
        background_restricted=False, sends_allowed=True,
        discovery_allowed=False, defer_reason="",
    )
    ParticipationDecision(**base).to_dict()
    for overrides in (
        {"phase": "alive"},
        {"network_kind": "5g"},
        {"defer_reason": "because"},
        {"sends_allowed": True, "defer_reason": DeferReason.OFFLINE},
        {"sends_allowed": False, "defer_reason": ""},
    ):
        kwargs = dict(base)
        kwargs.update(overrides)
        try:
            ParticipationDecision(**kwargs).to_dict()
            problems.append("invalid decision accepted: %r" % (overrides,))
        except MobileError:
            pass
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "frozen fields; verdict/reason consistency"))


def case_05_mobile_events_and_digests(results: List[Result]) -> None:
    name = "case_05_mobile_events_and_digests"
    event = MobileEvent(
        kind=MobileEventType.PHASE_CHANGED, sequence=1, instant=_T0,
        subject="background", detail="foreground -> background",
    )
    problems: List[str] = []
    if not event.event_id.startswith("sha256:"):
        problems.append("event id not a digest")
    if event.event_id != derive_mobile_event_id(
        event.kind, event.sequence, event.instant, event.subject,
        event.detail, event.ref,
    ):
        problems.append("id derivation diverged")
    if MobileEvent.from_dict(event.to_dict()) != event:
        problems.append("round-trip diverged")
    other = MobileEvent(
        kind=MobileEventType.GRANT_GRANTED, sequence=2, instant=_T0,
        subject="metered-data",
    )
    digest_a = mobile_event_list_digest((event, other))
    if digest_a != mobile_event_list_digest((event, other)):
        problems.append("list digest unstable")
    if mobile_events_canonical_bytes((event,)) == mobile_events_canonical_bytes(
        (other,)
    ):
        problems.append("different events share canonical bytes")
    for build_bad in (
        lambda: MobileEvent("nonsense", 1, _T0),
        lambda: MobileEvent(MobileEventType.PHASE_CHANGED, 0, _T0),
        lambda: MobileEvent(MobileEventType.PHASE_CHANGED, True, _T0),
        lambda: MobileEvent(MobileEventType.PHASE_CHANGED, 1, ""),
    ):
        try:
            build_bad().to_dict()
            problems.append("invalid event accepted")
            break
        except MobileError:
            pass
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(name, "id derivation, validation, stable digests"))


def case_06_access_path_view_w013_vocabulary(results: List[Result]) -> None:
    name = "case_06_access_path_view_w013_vocabulary"
    problems: List[str] = []
    view = AccessPathView(
        access_class=WIFI, interface_name="wlan0", status=PathStatus.ACTIVE,
    )
    if view.to_dict()["status"] != "ACTIVE":
        problems.append("status not the WORK-013 vocabulary")
    for build_bad in (
        lambda: AccessPathView("ethernet", "eth0", PathStatus.ACTIVE),
        lambda: AccessPathView(WIFI, "", PathStatus.ACTIVE),
        lambda: AccessPathView(WIFI, "wlan0", "up"),
        lambda: AccessPathView(NONE, "wlan0", PathStatus.ACTIVE),
    ):
        try:
            build_bad().to_dict()
            problems.append("invalid path view accepted")
        except MobileError:
            pass
    if AccessPathView.from_dict(view.to_dict()) != view:
        problems.append("round-trip diverged")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "WORK-013 ACTIVE/DEGRADED/FAILED vocabulary consumed as DATA"),
    )


# ---------------------------------------------------------------------------
# 7-11: lifecycle machine and platform boundary
# ---------------------------------------------------------------------------


def case_07_legal_phase_transitions(results: List[Result]) -> None:
    name = "case_07_legal_phase_transitions"
    legal = ((FG, BG), (FG, STOPPED), (BG, FG), (BG, STOPPED))
    illegal = (
        (STOPPED, BG), (STOPPED, FG), (STOPPED, STOPPED),
        (FG, FG), (BG, BG),
    )
    for previous, new in legal:
        if not transition_is_legal(previous, new):
            results.append(fail(name, "%s->%s should be legal" % (previous, new)))
            return
    for previous, new in illegal:
        if transition_is_legal(previous, new):
            results.append(fail(name, "%s->%s should be illegal" % (previous, new)))
            return
    results.append(
        ok(name, "fg<->bg, *->stopped legal; stopped terminal; "
                 "same-phase is not a transition"),
    )


def case_08_illegal_transition_fail_closed(results: List[Result]) -> None:
    name = "case_08_illegal_transition_fail_closed"
    mobile, _ = _world(_script(_snap(FG, WIFI), _snap(STOPPED, WIFI)))
    try:
        mobile.run_mobile(())
        results.append(fail(name, "stop epoch did not fail closed"))
        return
    except MobileError as error:
        if error.reason != MobileReasonCode.COMMAND_STOPPED:
            results.append(fail(name, "stop reason %r" % error.reason))
            return
    # A model in STOPPED that is fed a background observation is a
    # wiring bug: the transition table rejects it with a typed error
    # (unit-level: the refresh runs against the forced phase).
    mobile2, _ = _world(_script(_snap(BG, WIFI)))
    mobile2._phase = STOPPED
    try:
        mobile2._refresh_platform(mobile2._clock.now())
        results.append(fail(name, "stopped->background accepted"))
        return
    except MobileError as error:
        if error.reason != MobileReasonCode.LIFECYCLE_ILLEGAL:
            results.append(fail(name, "lifecycle reason %r" % error.reason))
            return
    results.append(
        ok(name, "stop fails closed COMMAND_STOPPED; illegal observations "
                 "fail closed LIFECYCLE_ILLEGAL"),
    )


def case_09_gate_totality_and_precedence(results: List[Result]) -> None:
    name = "case_09_gate_totality_and_precedence"
    problems: List[str] = []
    shapes = 0
    for phase in MobilePhase.values():
        for network in NetworkKind.values():
            for metered in (False, True):
                if network == NONE and metered:
                    continue  # structurally rejected at construction
                for restricted in (False, True):
                    platform = _snap(
                        phase, network, metered=metered, restricted=restricted,
                    )
                    for grant_shape in (0, 1, 2):
                        grants: Dict[str, UserGrant] = {}
                        if grant_shape >= 1:
                            grants[GrantScope.METERED_DATA] = UserGrant(
                                GrantScope.METERED_DATA, _T0,
                            )
                        if grant_shape >= 2:
                            grants[GrantScope.BACKGROUND_DATA] = UserGrant(
                                GrantScope.BACKGROUND_DATA, _T0,
                            )
                        decision = participation_gate(
                            phase, platform, grants, now=_T0,
                        )
                        shapes += 1
                        if network == NONE:
                            if decision.defer_reason != DeferReason.OFFLINE:
                                problems.append("offline does not dominate")
                        elif metered and grant_shape == 0:
                            if decision.defer_reason != DeferReason.METERED_NOT_AUTHORIZED:
                                problems.append("metered consent not enforced")
                        elif phase == STOPPED:
                            if decision.defer_reason != DeferReason.STOPPED:
                                problems.append("stopped not enforced")
                        elif phase == BG and grant_shape < 2:
                            if decision.defer_reason != DeferReason.BACKGROUND_NOT_AUTHORIZED:
                                problems.append("background consent not enforced")
                        elif phase == BG and restricted:
                            if decision.defer_reason != DeferReason.BACKGROUND_RESTRICTED:
                                problems.append("OS restriction not enforced")
                        elif decision.defer_reason:
                            problems.append("open gate deferred: %r" % decision.defer_reason)
                        if decision.sends_allowed == bool(decision.defer_reason):
                            problems.append("verdict/reason inconsistent")
                        if decision.discovery_allowed and not decision.sends_allowed:
                            problems.append("discovery without participation")
    expected_shapes = 3 * (4 + 1) * 2 * 3  # 90 total shapes
    if shapes != expected_shapes:
        problems.append("shape coverage %d != %d" % (shapes, expected_shapes))
    if problems:
        results.append(fail(name, "; ".join(sorted(set(problems)))))
        return
    results.append(
        ok(name, "gate total over 90 input shapes; precedence "
                 "connectivity > consent > phase > OS restriction"),
    )


def case_10_platform_sources(results: List[Result]) -> None:
    name = "case_10_platform_sources"
    snapshot = _snap(FG, WIFI)
    static = StaticPlatformSource(snapshot)
    if static.read() != snapshot or static.read() != snapshot:
        results.append(fail(name, "static source not constant"))
        return
    scripted = _script(_snap(FG, WIFI), _snap(BG, WIFI), _snap(FG, CELLULAR))
    sequence = [scripted.read() for _ in range(5)]
    if sequence[0].app_phase != FG or sequence[1].app_phase != BG:
        results.append(fail(name, "script did not advance"))
        return
    if sequence[2].network_kind != CELLULAR or sequence[3] != sequence[4]:
        results.append(fail(name, "script did not pin the last observation"))
        return
    mobile, _ = _world(_script(_snap(FG, WIFI)))
    mobile._platform_source = FailingPlatformSource()
    try:
        mobile.run_mobile(())
        results.append(fail(name, "failing source not surfaced"))
        return
    except MobileError as error:
        if error.reason != MobileReasonCode.PLATFORM_SOURCE_FAILED:
            results.append(fail(name, "reason %r" % error.reason))
            return

    class _BadSource(StaticPlatformSource):
        def read(self) -> PlatformSnapshot:  # type: ignore[override]
            return "not-a-snapshot"  # type: ignore[return-value]

    mobile2, _ = _world(_script(_snap(FG, WIFI)))
    mobile2._platform_source = _BadSource(snapshot)
    try:
        mobile2.run_mobile(())
        results.append(fail(name, "non-snapshot return not surfaced"))
        return
    except MobileError as error:
        if error.reason != MobileReasonCode.PLATFORM_SOURCE_FAILED:
            results.append(fail(name, "reason %r" % error.reason))
            return
    results.append(
        ok(name, "static/scripted deterministic; failing and non-snapshot "
                 "sources fail closed typed"),
    )


def case_11_evidence_disclosure(results: List[Result]) -> None:
    name = "case_11_evidence_disclosure"
    if MOBILE_EVIDENCE_STATUS != {
        "software_emulated_lifecycle": "supported-verified",
        "physical_device": "open",
    }:
        results.append(fail(
            name, "disclosure drifted: %r" % (MOBILE_EVIDENCE_STATUS,),
        ))
        return
    source_text = " ".join(
        (REPO_ROOT / "mobile" / "platform.py").read_text(
            encoding="utf-8",
        ).split(),
    )
    for token in (
        "software/emulated mobile lifecycle evidence",
        "physical Android handset evidence",
        "OPEN until genuinely demonstrated",
        "NEVER a physical-device PASS",
    ):
        if token not in source_text:
            results.append(fail(name, "disclosure prose missing %r" % token))
            return
    results.append(
        ok(name, "software/emulated SUPPORTED-verified; physical handset OPEN "
                 "(anti-faking disclosure battery-pinned)"),
    )


# ---------------------------------------------------------------------------
# 12-22: participation over the live agent (the golden path)
# ---------------------------------------------------------------------------


def case_12_boot_and_passthrough(results: List[Result]) -> None:
    name = "case_12_boot_and_passthrough"
    mobile, _ = _world(_script(_snap(FG, WIFI), _snap(FG, WIFI)))
    if mobile.runtime.status != "online":
        results.append(fail(name, "runtime not online after boot"))
        return
    result = mobile.run_mobile((MobileCommand(MobileCommandKind.MONITOR, {}),))
    if result.outcomes[-1].verdict != MobileVerdict.EXECUTED:
        results.append(fail(name, "monitor passthrough %r" % result.outcomes[-1].verdict))
        return
    if result.agent_event_digest != mobile.runtime.event_log_digest():
        results.append(fail(name, "agent event digest diverged"))
        return
    if not result.mobile_digest.startswith("sha256:"):
        results.append(fail(name, "mobile digest missing"))
        return
    if result.status != "online" or result.phase != FG:
        results.append(fail(name, "status/phase %r/%r" % (result.status, result.phase)))
        return
    results.append(
        ok(name, "boot/expose/monitor flow through the unchanged runtime path"),
    )


def case_13_foreground_send(results: List[Result]) -> None:
    name = "case_13_foreground_send"
    mobile, peer = _world(_script(_snap(FG, WIFI), _snap(FG, WIFI), _snap(FG, WIFI)))
    sid = _establish(mobile, peer)
    mobile.run_mobile((_track(sid),))
    result = mobile.run_mobile((_send(sid, b"foreground-payload"),))
    outcome = result.outcomes[-1]
    if outcome.verdict != MobileVerdict.EXECUTED:
        results.append(fail(name, "verdict %r" % outcome.verdict))
        return
    if "frame sha256:" not in outcome.detail:
        results.append(fail(name, "frame digest missing"))
        return
    if _paths(mobile, sid) != [(WIFI, PathStatus.ACTIVE)]:
        results.append(fail(name, "paths %r" % _paths(mobile, sid)))
        return
    if "session-tracked" not in _kinds(mobile):
        results.append(fail(name, "tracking not journaled"))
        return
    results.append(
        ok(name, "executed through the ordinary transport path; frame digested"),
    )


def case_14_foreground_to_background(results: List[Result]) -> None:
    name = "case_14_foreground_to_background"
    mobile, peer = _world(_script(_snap(FG, WIFI), _snap(FG, WIFI), _snap(BG, WIFI)))
    sid = _establish(mobile, peer)
    mobile.run_mobile((_track(sid),))
    result = mobile.run_mobile((_send(sid, b"while-backgrounded"),))
    outcome = result.outcomes[-1]
    problems: List[str] = []
    if outcome.verdict != MobileVerdict.DEFERRED:
        problems.append("verdict %r" % outcome.verdict)
    if outcome.reason != DeferReason.BACKGROUND_NOT_AUTHORIZED:
        problems.append("reason %r" % outcome.reason)
    if result.phase != BG:
        problems.append("phase %r" % result.phase)
    if result.deferred_depth != 1:
        problems.append("depth %d" % result.deferred_depth)
    session = mobile.runtime.sessions.get(sid)
    if session is None or session.state != "ESTABLISHED":
        problems.append("session state changed by backgrounding")
    kinds = _kinds(mobile)
    if "phase-changed" not in kinds or "send-deferred" not in kinds:
        problems.append("journal missing %r" % kinds)
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "send deferred background-not-authorized; session "
                 "ESTABLISHED untouched (sacred session_id)"),
    )


def case_15_background_consent_and_drain(results: List[Result]) -> None:
    name = "case_15_background_consent_and_drain"
    mobile, peer = _world(
        _script(_snap(FG, WIFI), _snap(FG, WIFI), _snap(BG, WIFI), _snap(BG, WIFI)),
    )
    sid = _establish(mobile, peer)
    mobile.run_mobile((_track(sid),))
    mobile.run_mobile((_send(sid, b"consent-drain"),))
    result = mobile.run_mobile((_grant(GrantScope.BACKGROUND_DATA),))
    if result.deferred_depth != 1:
        results.append(fail(name, "grant epoch drained early"))
        return
    result = mobile.run_mobile(())
    if result.deferred_depth != 0:
        results.append(fail(name, "queue did not drain"))
        return
    drained = [o for o in result.outcomes if o.verdict == MobileVerdict.EXECUTED]
    if not drained:
        results.append(fail(name, "no drained outcome"))
        return
    kinds = _kinds(mobile)
    if "grant-granted" not in kinds or "deferred-drained" not in kinds:
        results.append(fail(name, "journal %r" % kinds))
        return
    session = mobile.runtime.sessions.get(sid)
    if session is None or session.session_id != sid:
        results.append(fail(name, "session identity changed"))
        return
    results.append(
        ok(name, "user consent re-opens participation; deferred send drains "
                 "through the SAME session"),
    )


def case_16_background_to_foreground(results: List[Result]) -> None:
    name = "case_16_background_to_foreground"
    mobile, peer = _world(
        _script(_snap(FG, WIFI), _snap(FG, WIFI), _snap(BG, WIFI), _snap(FG, WIFI)),
    )
    sid = _establish(mobile, peer)
    mobile.run_mobile((_track(sid),))
    mobile.run_mobile((_send(sid, b"waiting-for-foreground"),))
    if mobile.deferred_depth != 1:
        results.append(fail(name, "precondition depth"))
        return
    result = mobile.run_mobile(())
    if result.phase != FG or result.deferred_depth != 0:
        results.append(fail(
            name, "phase %r depth %d" % (result.phase, result.deferred_depth),
        ))
        return
    if "phase-changed" not in _kinds(mobile):
        results.append(fail(name, "phase return not journaled"))
        return
    results.append(
        ok(name, "phase return alone re-opens participation (no consent needed)"),
    )


def case_17_os_restriction_overrides_consent(results: List[Result]) -> None:
    name = "case_17_os_restriction_overrides_consent"
    mobile, peer = _world(
        _script(
            _snap(FG, WIFI),
            _snap(BG, WIFI),
            _snap(BG, WIFI),
            _snap(BG, WIFI, restricted=True),
            _snap(BG, WIFI),
        ),
    )
    sid = _establish(mobile, peer)
    mobile.run_mobile((_track(sid),))
    mobile.run_mobile((_grant(GrantScope.BACKGROUND_DATA),))
    result = mobile.run_mobile((_send(sid, b"doze"),))
    outcome = result.outcomes[-1]
    if outcome.verdict != MobileVerdict.DEFERRED:
        results.append(fail(name, "verdict %r" % outcome.verdict))
        return
    if outcome.reason != DeferReason.BACKGROUND_RESTRICTED:
        results.append(fail(name, "reason %r" % outcome.reason))
        return
    if _paths(mobile, sid) != [(WIFI, PathStatus.DEGRADED)]:
        results.append(fail(name, "paths %r" % _paths(mobile, sid)))
        return
    # the restriction lifts: the path recovers through the legal edge
    result = mobile.run_mobile(())
    if _paths(mobile, sid) != [(WIFI, PathStatus.ACTIVE)]:
        results.append(fail(name, "recovery paths %r" % _paths(mobile, sid)))
        return
    results.append(
        ok(name, "OS doze restriction overrides user consent; path view "
                 "DEGRADED -> ACTIVE through the legal W013 edge"),
    )


def case_18_online_to_offline(results: List[Result]) -> None:
    name = "case_18_online_to_offline"
    mobile, peer = _world(
        _script(_snap(FG, WIFI), _snap(FG, WIFI), _snap(FG, NONE), _snap(FG, NONE)),
    )
    sid = _establish(mobile, peer)
    mobile.run_mobile((_track(sid),))
    result = mobile.run_mobile((_send(sid, b"during-outage"),))
    outcome = result.outcomes[-1]
    problems: List[str] = []
    if outcome.verdict != MobileVerdict.DEFERRED or outcome.reason != DeferReason.OFFLINE:
        problems.append("offline defer %r/%r" % (outcome.verdict, outcome.reason))
    if result.network_kind != NONE:
        problems.append("network %r" % result.network_kind)
    session = mobile.runtime.sessions.get(sid)
    if session is None or session.state != "ESTABLISHED":
        problems.append("offline mutated the session")
    if _paths(mobile, sid) != [(WIFI, PathStatus.FAILED)]:
        problems.append("paths %r" % _paths(mobile, sid))
    kinds = _kinds(mobile)
    if "connectivity-changed" not in kinds:
        problems.append("connectivity event missing")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "offline defers with typed reason; session ESTABLISHED; "
                 "access path FAILED (W013 terminal)"),
    )


def case_19_offline_to_online_drain(results: List[Result]) -> None:
    name = "case_19_offline_to_online_drain"
    mobile, peer = _world(
        _script(
            _snap(FG, WIFI), _snap(FG, WIFI),
            _snap(FG, NONE), _snap(FG, NONE), _snap(FG, WIFI),
        ),
    )
    sid = _establish(mobile, peer)
    mobile.run_mobile((_track(sid),))
    mobile.run_mobile((_send(sid, b"queued-1"),))
    mobile.run_mobile((_send(sid, b"queued-2"),))
    result = mobile.run_mobile(())  # wifi returns: drain executes both
    problems: List[str] = []
    if result.deferred_depth != 0:
        problems.append("queue did not drain")
    session = mobile.runtime.sessions.get(sid)
    if session is None or session.session_id != sid:
        problems.append("session identity changed")
    elif session.state != "ESTABLISHED":
        problems.append("state %r" % session.state)
    if _paths(mobile, sid) != [(WIFI, PathStatus.ACTIVE)]:
        problems.append("paths %r" % _paths(mobile, sid))
    # end-to-end delivery through the SAME session after the outage
    artifact = mobile.runtime.send_datagram(sid, b"post-recovery-probe")
    if peer.receive_datagram(artifact) != b"post-recovery-probe":
        problems.append("byte-identical delivery broken after outage")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "connectivity return drains the queue through the SAME "
                 "session_id; peer receives byte-identical payloads"),
    )


def case_20_handover_wifi_to_cellular(results: List[Result]) -> None:
    name = "case_20_handover_wifi_to_cellular"
    mobile, peer = _world(
        _script(
            _snap(FG, WIFI), _snap(FG, WIFI), _snap(FG, WIFI),
            _snap(FG, CELLULAR), _snap(FG, CELLULAR), _snap(FG, CELLULAR),
        ),
    )
    sid = _establish(mobile, peer)
    mobile.run_mobile((_track(sid),))
    binding_before = mobile.runtime.ip_manager.binding_for_session(sid)
    mobile.run_mobile((_grant(GrantScope.METERED_DATA),))
    result = mobile.run_mobile(())  # access changes to cellular
    problems: List[str] = []
    if result.network_kind != CELLULAR:
        problems.append("network %r" % result.network_kind)
    binding_after = mobile.runtime.ip_manager.binding_for_session(sid)
    if binding_after is None or binding_before is None:
        problems.append("W018 IP bindings missing")
    elif binding_after.binding_id == binding_before.binding_id:
        problems.append("IP binding did not change across handover")
    session = mobile.runtime.sessions.get(sid)
    if session is None or session.session_id != sid:
        problems.append("session identity changed across handover")
    outcome = mobile.run_mobile((_send(sid, b"after-handover"),))
    if outcome.outcomes[-1].verdict != MobileVerdict.EXECUTED:
        problems.append("post-handover send %r" % outcome.outcomes[-1].verdict)
    if _paths(mobile, sid) != [
        (CELLULAR, PathStatus.ACTIVE), (WIFI, PathStatus.FAILED),
    ]:
        problems.append("paths %r" % _paths(mobile, sid))
    if "handover-completed" not in _kinds(mobile):
        problems.append("handover event missing")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "same session_id re-bound wifi->cellular; W018 IP binding "
                 "changed; continuity view cellular ACTIVE + wifi FAILED"),
    )


def case_21_handover_refused_without_consent(results: List[Result]) -> None:
    name = "case_21_handover_refused_without_consent"
    mobile, peer = _world(
        _script(
            _snap(FG, WIFI), _snap(FG, WIFI),
            _snap(FG, CELLULAR, metered=True),
            _snap(FG, CELLULAR, metered=True),
            _snap(FG, CELLULAR, metered=True),
            _snap(FG, CELLULAR, metered=True),
        ),
    )
    sid = _establish(mobile, peer)
    mobile.run_mobile((_track(sid),))
    result = mobile.run_mobile(())  # metered cellular, no consent
    problems: List[str] = []
    if result.network_kind != CELLULAR:
        problems.append("precondition network")
    if "access-refused" not in _kinds(mobile):
        problems.append("access-refused event missing")
    if _paths(mobile, sid) != [(WIFI, PathStatus.FAILED)]:
        problems.append("paths %r" % _paths(mobile, sid))
    result = mobile.run_mobile((_send(sid, b"metered-without-consent"),))
    outcome = result.outcomes[-1]
    if outcome.verdict != MobileVerdict.DEFERRED:
        problems.append("verdict %r" % outcome.verdict)
    elif outcome.reason != DeferReason.METERED_NOT_AUTHORIZED:
        problems.append("reason %r" % outcome.reason)
    # consent arrives: the handover proceeds and the queue drains
    mobile.run_mobile((_grant(GrantScope.METERED_DATA),))
    result = mobile.run_mobile(())
    if _paths(mobile, sid) != [
        (CELLULAR, PathStatus.ACTIVE), (WIFI, PathStatus.FAILED),
    ]:
        problems.append("post-consent paths %r" % _paths(mobile, sid))
    if result.deferred_depth != 0:
        problems.append("queue did not drain after consent")
    if "handover-completed" not in _kinds(mobile):
        problems.append("handover event missing after consent")
    session = mobile.runtime.sessions.get(sid)
    if session is None or session.session_id != sid:
        problems.append("session identity changed")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "metered access refused without user consent (no attach, "
                 "typed deferral); consent -> handover + drain, same session"),
    )


def case_22_unmetered_handover_no_consent(results: List[Result]) -> None:
    name = "case_22_unmetered_handover_no_consent"
    mobile, peer = _world(
        _script(
            _snap(FG, WIFI), _snap(FG, WIFI),
            _snap(FG, CELLULAR), _snap(FG, CELLULAR),
        ),
    )
    sid = _establish(mobile, peer)
    mobile.run_mobile((_track(sid),))
    result = mobile.run_mobile(())  # unmetered cellular: no consent needed
    problems: List[str] = []
    if result.network_kind != CELLULAR:
        problems.append("network %r" % result.network_kind)
    if _paths(mobile, sid) != [
        (CELLULAR, PathStatus.ACTIVE), (WIFI, PathStatus.FAILED),
    ]:
        problems.append("paths %r" % _paths(mobile, sid))
    if "handover-completed" not in _kinds(mobile):
        problems.append("handover event missing")
    if mobile.grants:
        problems.append("consent grants were required")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "unmetered access change re-binds without any consent grant"),
    )


# ---------------------------------------------------------------------------
# 23-25: consent lifecycle and bounded queues
# ---------------------------------------------------------------------------


def case_23_grant_lifecycle(results: List[Result]) -> None:
    name = "case_23_grant_lifecycle"
    mobile, _ = _world(
        _script(*([_snap(FG, WIFI)] * 8)),
    )
    problems: List[str] = []
    # expiry: the boundary is one clock step ahead of the grant epoch
    mobile.run_mobile((
        _grant(GrantScope.BACKGROUND_DATA, expires_at="2025-06-01T00:36:30Z"),
    ))
    if not mobile.grants:
        problems.append("grant not recorded")
    mobile.run_mobile(())  # one epoch later: the sweep expires it
    if mobile.grants:
        problems.append("expired grant still present")
    if "grant-expired" not in _kinds(mobile):
        problems.append("expiry not journaled")
    # revocation
    mobile.run_mobile((_grant(GrantScope.METERED_DATA),))
    mobile.run_mobile((_revoke(GrantScope.METERED_DATA),))
    if mobile.grants:
        problems.append("revoked grant still present")
    if "grant-revoked" not in _kinds(mobile):
        problems.append("revocation not journaled")
    try:
        mobile.run_mobile((_revoke(GrantScope.METERED_DATA),))
        problems.append("double revoke accepted")
    except MobileError as error:
        if error.reason != MobileReasonCode.GRANT_INVALID:
            problems.append("revoke reason %r" % error.reason)
    # re-grant works
    mobile.run_mobile((_grant(GrantScope.METERED_DATA),))
    if not mobile.grants:
        problems.append("re-grant failed")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "grant -> TTL expiry -> revoke -> typed double-revoke -> "
                 "re-grant, all journaled"),
    )


def case_24_secret_free_consent_records(results: List[Result]) -> None:
    name = "case_24_secret_free_consent_records"
    mobile, peer = _world(_script(_snap(FG, WIFI), _snap(FG, WIFI)))
    sid = _establish(mobile, peer)
    mobile.run_mobile((_track(sid), _grant(GrantScope.BACKGROUND_DATA)))
    blob = repr(
        (mobile.mobile_events, mobile.grants, mobile.mobile_snapshot(),
         mobile.peer_observations, mobile.content_digest()),
    )
    for secret in (_SECRET_A, _SECRET_B):
        if secret in blob.encode() or secret.hex() in blob:
            results.append(fail(name, "secret material leaked into records"))
            return
    results.append(ok(name, "no secret bytes in any mobile record"))


def case_25_ttl_shed_and_overflow(results: List[Result]) -> None:
    name = "case_25_ttl_shed_and_overflow"
    # -- TTL expiry -----------------------------------------------------
    mobile, peer = _world(
        _script(_snap(FG, WIFI), _snap(FG, WIFI), _snap(BG, WIFI), _snap(BG, WIFI)),
        budget=MobileBudget(deferred_ttl_seconds=60, max_deferred_depth=32),
    )
    sid = _establish(mobile, peer)
    mobile.run_mobile((_track(sid),))
    mobile.run_mobile((_send(sid, b"short-ttl"),))  # defers (background)
    mobile.run_mobile(())  # next epoch: the 60s TTL has aged out
    shed = [
        event for event in mobile.mobile_events
        if event.kind == MobileEventType.SEND_SHED
    ]
    if not shed or shed[0].detail != "deferred-ttl-expired":
        results.append(fail(name, "ttl shed missing: %r" % (shed,)))
        return
    if mobile.deferred_depth != 0:
        results.append(fail(name, "queue not emptied by TTL shed"))
        return
    # -- overflow -------------------------------------------------------
    mobile2, peer2 = _world(
        _script(_snap(FG, WIFI), _snap(FG, WIFI), _snap(BG, WIFI), _snap(BG, WIFI)),
        budget=MobileBudget(deferred_ttl_seconds=3600, max_deferred_depth=2),
    )
    sid2 = _establish(mobile2, peer2)
    mobile2.run_mobile((_track(sid2),))
    mobile2.run_mobile((_send(sid2, b"first"), _send(sid2, b"second"),))
    result = mobile2.run_mobile((_send(sid2, b"third"),))
    overflow = [
        event for event in mobile2.mobile_events
        if event.detail == "defer-queue-overflow"
    ]
    if not overflow:
        results.append(fail(name, "overflow shed not journaled"))
        return
    if mobile2.deferred_depth != 2 or result.deferred_depth != 2:
        results.append(fail(
            name, "depth %d/%d" % (mobile2.deferred_depth, result.deferred_depth),
        ))
        return
    results.append(
        ok(name, "TTL expiry and queue overflow both shed with typed, "
                 "journaled reasons (never silent)"),
    )


# ---------------------------------------------------------------------------
# 26-28: restart/recovery
# ---------------------------------------------------------------------------


def case_26_stop_checkpoint_refusal(results: List[Result]) -> None:
    name = "case_26_stop_checkpoint_refusal"
    mobile, peer = _world(
        _script(_snap(FG, WIFI), _snap(BG, WIFI), _snap(BG, WIFI), _snap(STOPPED, WIFI)),
    )
    sid = _establish(mobile, peer)
    mobile.run_mobile((_track(sid), _grant(GrantScope.METERED_DATA),))
    mobile.run_mobile((_send(sid, b"pending-at-death"),))  # defers (background)
    try:
        mobile.run_mobile((MobileCommand(MobileCommandKind.MONITOR, {}),))
        results.append(fail(name, "stop epoch did not fail closed"))
        return
    except MobileError as error:
        if error.reason != MobileReasonCode.COMMAND_STOPPED:
            results.append(fail(name, "stop reason %r" % error.reason))
            return
    snapshot = mobile.last_snapshot
    problems: List[str] = []
    if snapshot is None or snapshot.phase != STOPPED:
        problems.append("durable snapshot missing")
    else:
        if [g.scope for g in snapshot.grants] != [GrantScope.METERED_DATA]:
            problems.append("grants not snapshotted")
        if len(snapshot.deferred) != 1:
            problems.append("deferred not snapshotted")
        if snapshot.event_sequence != len(mobile.mobile_events):
            problems.append("journal point %d vs %d" % (
                snapshot.event_sequence, len(mobile.mobile_events),
            ))
    try:
        mobile.run_mobile(())
        problems.append("post-stop run accepted")
    except MobileError as error:
        if error.reason != MobileReasonCode.COMMAND_STOPPED:
            problems.append("post-stop reason %r" % error.reason)
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "stop fails closed; durable secret-free snapshot produced; "
                 "stopped process refuses further commands"),
    )


def case_27_recovery_continuation(results: List[Result]) -> None:
    name = "case_27_recovery_continuation"
    mobile, peer = _world(
        _script(_snap(FG, WIFI), _snap(BG, WIFI), _snap(BG, WIFI), _snap(STOPPED, WIFI)),
    )
    sid = _establish(mobile, peer)
    mobile.run_mobile((_track(sid), _grant(GrantScope.METERED_DATA),))
    mobile.run_mobile((_send(sid, b"pending-at-death"),))
    try:
        mobile.run_mobile(())
    except MobileError:
        pass
    snapshot = mobile.last_snapshot
    assert snapshot is not None

    clock2 = StepClock("2025-06-01T00:10:00Z", 30)
    peer2 = AgentRuntime(
        _peer_config(), clock=clock2,
        interface_source=StaticInterfaceSource(_snapshots()),
    )
    peer2.boot(_SECRET_B)
    peer2.expose_interfaces()
    recovered = MobileAgent.recover(
        snapshot,
        config=_config(),
        clock=clock2,
        interface_source=StaticInterfaceSource(_snapshots()),
        platform_source=_script(_snap(FG, WIFI), _snap(FG, WIFI), _snap(FG, WIFI)),
        access_interfaces={WIFI: "wlan0", CELLULAR: "rmnet0"},
    )
    problems: List[str] = []
    events = recovered.mobile_events
    if not events or events[0].kind != MobileEventType.RESTARTED:
        problems.append("first recovered event not restarted")
    if events[0].sequence != snapshot.event_sequence + 1:
        problems.append("journal sequence did not continue")
    lost = [
        event for event in events
        if event.kind == MobileEventType.SESSION_LOST_AT_RESTART
    ]
    if not lost:
        problems.append("session loss not recorded")
    if [g.scope for g in recovered.grants] != [GrantScope.METERED_DATA]:
        problems.append("grants not restored")
    if recovered.deferred_depth != 1:
        problems.append("deferred not restored")
    if mobile.mobile_events[-1].sequence >= events[0].sequence:
        problems.append("sequence overlap")
    # boot + re-register + re-establish through the ordinary path
    recovered.run_mobile((
        MobileCommand(MobileCommandKind.BOOT, {}),
        MobileCommand(MobileCommandKind.EXPOSE_INTERFACES, {}),
    ), boot_secret=_SECRET_A)
    _register_peers(recovered.runtime, peer2)
    sid2 = _establish(recovered, peer2)
    if sid2 == sid:
        problems.append("re-establishment fabricated the old session id")
    result = recovered.run_mobile((_track(sid2),))
    if result.deferred_depth != 0:
        problems.append("restored entry not resolved")
    shed = [
        event for event in recovered.mobile_events
        if event.kind == MobileEventType.SEND_SHED
        and event.detail == "session-lost"
    ]
    if not shed:
        problems.append("restored deferred entry not shed as session-lost")
    if _paths(recovered, sid2) != [(WIFI, PathStatus.ACTIVE)]:
        problems.append("re-established path %r" % _paths(recovered, sid2))
    result = recovered.run_mobile((_send(sid2, b"after-restart"),))
    if result.outcomes[-1].verdict != MobileVerdict.EXECUTED:
        problems.append("post-restart send %r" % result.outcomes[-1].verdict)
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "journal continues (restarted + honest session-lost); grants "
                 "and aging queue restored; re-establishment through the "
                 "ordinary path; stale deferrals shed session-lost"),
    )


def case_28_grant_ttl_survives_restart(results: List[Result]) -> None:
    name = "case_28_grant_ttl_survives_restart"
    mobile, peer = _world(
        _script(_snap(FG, WIFI), _snap(FG, WIFI), _snap(STOPPED, WIFI)),
    )
    sid = _establish(mobile, peer)
    mobile.run_mobile((
        _track(sid),
        _grant(GrantScope.BACKGROUND_DATA, expires_at="2025-06-01T01:30:00Z"),
    ))
    try:
        mobile.run_mobile(())
    except MobileError:
        pass
    snapshot = mobile.last_snapshot
    assert snapshot is not None
    clock2 = StepClock("2025-06-01T02:00:00Z", 30)  # past the TTL boundary
    recovered = MobileAgent.recover(
        snapshot,
        config=_config(),
        clock=clock2,
        interface_source=StaticInterfaceSource(_snapshots()),
        platform_source=_script(_snap(BG, WIFI), _snap(BG, WIFI)),
        access_interfaces={WIFI: "wlan0", CELLULAR: "rmnet0"},
    )
    recovered.run_mobile((MobileCommand(MobileCommandKind.BOOT, {}),), boot_secret=_SECRET_A)
    result = recovered.run_mobile(())
    problems: List[str] = []
    if recovered.grants:
        problems.append("grant survived its TTL through restart")
    if "grant-expired" not in _kinds(recovered):
        problems.append("expiry not journaled at recovery")
    if result.phase != BG:
        problems.append("phase %r" % result.phase)
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "a grant expiring during downtime is expired at recovery "
                 "(TTLs age through process death)"),
    )


# ---------------------------------------------------------------------------
# 29-32: local discovery
# ---------------------------------------------------------------------------


class _W06BusDiscovery(LocalDiscoveryPort):
    """A genuine WORK-006 local-discovery harness behind the mobile
    port.

    The mobile node's discovery identity is provisioned over the SAME
    public key + profile the AgentConfig carries (=> the same NodeID
    as the runtime).  This is TEST WIRING: the shipped mobile/ family
    never constructs identity machinery -- it composes the runtime's
    public surface and the host-provided port only.
    """

    def __init__(
        self,
        *,
        public_key: bytes = _KEY_A,
        created_at: str = _T0,
        secret: bytes = _SECRET_A,
        peer_key: bytes = b"mobile-battery-peer-key",
        peer_secret: bytes = b"mobile-battery-peer-secret",
    ) -> None:
        from identity import (
            DevHmacSha256Provider,
            IdentityService,
            InMemoryCredentialStore,
        )
        from identity.model import NodeIdentity
        from identity.profiles import ProfileSet
        from discovery import DiscoveryService, DiscoveryStore, SourceType
        from discovery.transport import InMemoryTransportBus

        profiles = ProfileSet.load_default()
        self._identity = NodeIdentity.create(
            profiles.get(_PROFILE_ID), public_key, created_at,
        )
        self._node_id = self._identity.node_id.text
        self._seq = 1
        self._store = InMemoryCredentialStore()
        self._provider = DevHmacSha256Provider()
        ident = IdentityService(self._store, self._provider)
        self._mobile_cred = ident.provision(
            self._identity, "operational", secret, now=_T0,
        )
        ident.activate(self._mobile_cred, now=_T0)
        self._peer_identity = NodeIdentity.create(
            profiles.get(_PROFILE_ID), peer_key, created_at,
        )
        self._peer_cred = ident.provision(
            self._peer_identity, "operational", peer_secret, now=_T0,
        )
        ident.activate(self._peer_cred, now=_T0)
        peer_store = InMemoryCredentialStore()
        peer_provider = DevHmacSha256Provider()
        peer_ident = IdentityService(peer_store, peer_provider)
        peer_own = peer_ident.provision(
            self._peer_identity, "operational", peer_secret, now=_T0,
        )
        peer_ident.activate(peer_own, now=_T0)
        self._bus = InMemoryTransportBus()
        mobile_endpoint = self._bus.register(("198.18.0.10", 5353))
        peer_endpoint = self._bus.register(("198.18.0.20", 5353))
        self._mobile_service = DiscoveryService(
            sender_node_id=self._node_id, store=self._store,
            provider=self._provider, credential=self._mobile_cred,
            transport=mobile_endpoint, local_store=DiscoveryStore(),
        )
        self._peer_service = DiscoveryService(
            sender_node_id=self._peer_identity.node_id.text,
            store=peer_store, provider=peer_provider, credential=peer_own,
            transport=peer_endpoint, local_store=DiscoveryStore(),
        )
        self.last_received = None
        self.last_announced = None
        self._source_type = SourceType

    @property
    def node_id(self) -> str:
        return self._node_id

    @property
    def peer_node_id(self) -> str:
        return self._peer_identity.node_id.text

    @property
    def store(self) -> Any:
        return self._store

    @property
    def provider(self) -> Any:
        return self._provider

    @property
    def peer_credential(self) -> Any:
        return self._peer_cred

    @property
    def mobile_credential(self) -> Any:
        return self._mobile_cred

    def cycle(self, *, now: str) -> DiscoveryCycle:
        freshness = "2026-06-01T01:00:00Z"
        obs_self = self._mobile_service.build_observation(
            observed_node_id=self._peer_identity.node_id.text,
            issued_at=now, freshness_until=freshness,
            sequence=self._seq, source_type=self._source_type.LOCAL,
            observed_endpoints=(
                {"transport": "udp", "address": "198.18.0.20:5353"},
            ),
        )
        self._mobile_service.announce(obs_self, to=("198.18.0.20", 5353))
        self._seq += 1
        self.last_announced = obs_self
        obs_peer = self._peer_service.build_observation(
            observed_node_id=self._node_id,
            issued_at=now, freshness_until=freshness,
            sequence=self._seq, source_type=self._source_type.LOCAL,
            observed_endpoints=(
                {"transport": "udp", "address": "198.18.0.10:5353"},
            ),
        )
        self._peer_service.announce(obs_peer, to=("198.18.0.10", 5353))
        self._seq += 1
        results = self._mobile_service.receive(
            now=datetime.strptime(now, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc,
            ),
        )
        observations: List[PeerObservation] = []
        for result in results:
            if result.accepted:
                self.last_received = result.observation
                observations.append(
                    PeerObservation(
                        observed_by=result.observation.sender_node_id,
                        endpoints=tuple(
                            "%s:%s" % (
                                ep.get("transport", "?"),
                                ep.get("address", "?"),
                            )
                            for ep in result.observation.observed_endpoints
                        ),
                        observed_at=result.observation.issued_at,
                        freshness_until=result.observation.freshness_until,
                    )
                )
        return DiscoveryCycle(
            announced=True,
            announcement_id=obs_self.observation_id,
            observations=tuple(observations),
        )


def case_29_discovery_gating(results: List[Result]) -> None:
    name = "case_29_discovery_gating"
    # no consent: foreground + online still defers (consent-gated)
    mobile, _ = _world(
        _script(_snap(FG, WIFI), _snap(FG, WIFI), _snap(FG, WIFI)),
        discovery=_W06BusDiscovery(),
    )
    result = mobile.run_mobile((
        MobileCommand(MobileCommandKind.POLL_DISCOVERY, {}),
    ))
    outcome = result.outcomes[-1]
    if outcome.verdict != MobileVerdict.DEFERRED:
        results.append(fail(name, "foreground verdict %r" % outcome.verdict))
        return
    if outcome.reason != "local-discovery-not-granted":
        results.append(fail(name, "reason %r" % outcome.reason))
        return
    if "discovery-deferred" not in _kinds(mobile):
        results.append(fail(name, "deferral not journaled"))
        return
    if mobile.peer_observations:
        results.append(fail(name, "observations learned without consent"))
        return
    # offline: consent present still defers (connectivity first)
    mobile2, _ = _world(
        _script(_snap(FG, WIFI), _snap(FG, NONE), _snap(FG, NONE)),
        discovery=_W06BusDiscovery(),
    )
    mobile2.run_mobile((_grant(GrantScope.LOCAL_DISCOVERY),))
    result = mobile2.run_mobile((
        MobileCommand(MobileCommandKind.POLL_DISCOVERY, {}),
    ))
    if result.outcomes[-1].reason != DeferReason.OFFLINE:
        results.append(fail(name, "offline reason %r" % result.outcomes[-1].reason))
        return
    # background without background-data consent: defers
    mobile3, _ = _world(
        _script(_snap(FG, WIFI), _snap(BG, WIFI), _snap(BG, WIFI)),
        discovery=_W06BusDiscovery(),
    )
    mobile3.run_mobile((_grant(GrantScope.LOCAL_DISCOVERY),))
    result = mobile3.run_mobile((
        MobileCommand(MobileCommandKind.POLL_DISCOVERY, {}),
    ))
    if result.outcomes[-1].reason != DeferReason.BACKGROUND_NOT_AUTHORIZED:
        results.append(fail(name, "bg reason %r" % result.outcomes[-1].reason))
        return
    results.append(
        ok(name, "local discovery gated by consent in every phase, by "
                 "connectivity, and by background consent -- deferrals typed"),
    )


def case_30_discovery_genuine_w006(results: List[Result]) -> None:
    name = "case_30_discovery_genuine_w006"
    from discovery.signing import verify_observation

    harness = _W06BusDiscovery()
    mobile, _ = _world(
        _script(_snap(FG, WIFI), _snap(FG, WIFI), _snap(FG, WIFI)),
        discovery=harness,
    )
    if harness.node_id != mobile.runtime.node_id:
        results.append(fail(name, "harness NodeID is not the runtime's NodeID"))
        return
    mobile.run_mobile((_grant(GrantScope.LOCAL_DISCOVERY),))
    result = mobile.run_mobile((
        MobileCommand(MobileCommandKind.POLL_DISCOVERY, {}),
    ))
    outcome = result.outcomes[-1]
    if outcome.verdict != MobileVerdict.EXECUTED:
        results.append(fail(name, "verdict %r" % outcome.verdict))
        return
    if not mobile.peer_observations:
        results.append(fail(name, "no observations learned"))
        return
    received = harness.last_received
    announced = harness.last_announced
    if received is None or announced is None:
        results.append(fail(name, "harness exchange incomplete"))
        return
    now_dt = datetime.strptime(_T0, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc,
    ) + timedelta(minutes=5)
    if not verify_observation(
        received, store=harness.store, provider=harness.provider,
        credential=harness.peer_credential, now=now_dt,
    ):
        results.append(fail(name, "received observation fails W006 verification"))
        return
    if verify_observation(
        received, store=harness.store, provider=harness.provider,
        credential=harness.mobile_credential, now=now_dt,
    ):
        results.append(fail(name, "cross-node forgery accepted by W006"))
        return
    if received.sender_node_id != harness.peer_node_id:
        results.append(fail(name, "sender binding diverged"))
        return
    if received.observed_node_id != mobile.runtime.node_id:
        results.append(fail(name, "observed binding diverged"))
        return
    if announced.sender_node_id != mobile.runtime.node_id:
        results.append(fail(name, "announcement not sent as the mobile node"))
        return
    observation = mobile.peer_observations[0]
    if observation.observed_by != received.sender_node_id:
        results.append(fail(name, "peer observation provenance diverged"))
        return
    if "discovery-completed" not in _kinds(mobile):
        results.append(fail(name, "completion not journaled"))
        return
    results.append(
        ok(name, "genuine signed WORK-006 exchange through the gate: verified "
                 "observation, NodeID-bound sender, forgery rejected"),
    )


def case_31_null_discovery_honest(results: List[Result]) -> None:
    name = "case_31_null_discovery_honest"
    null = NullDiscovery()
    cycle = null.cycle(now=_T0)
    if cycle.announced or cycle.observations or cycle.announcement_id:
        results.append(fail(name, "null discovery fabricated %r" % (cycle,)))
        return
    mobile, _ = _world(
        _script(_snap(FG, WIFI), _snap(FG, WIFI)),
        discovery=NullDiscovery(),
    )
    mobile.run_mobile((_grant(GrantScope.LOCAL_DISCOVERY),))
    result = mobile.run_mobile((
        MobileCommand(MobileCommandKind.POLL_DISCOVERY, {}),
    ))
    if result.outcomes[-1].verdict != MobileVerdict.EXECUTED:
        results.append(fail(name, "verdict %r" % result.outcomes[-1].verdict))
        return
    if mobile.peer_observations:
        results.append(fail(name, "observations fabricated"))
        return
    results.append(
        ok(name, "the no-discovery default announces and observes nothing"),
    )


def case_32_monitor_keeps_observing(results: List[Result]) -> None:
    name = "case_32_monitor_keeps_observing"
    mobile, _ = _world(
        _script(_snap(FG, WIFI), _snap(BG, WIFI), _snap(BG, WIFI)),
    )
    result = mobile.run_mobile((MobileCommand(MobileCommandKind.MONITOR, {}),))
    if result.outcomes[-1].verdict != MobileVerdict.EXECUTED:
        results.append(fail(name, "background monitor %r" % result.outcomes[-1].verdict))
        return
    mobile._phase = STOPPED
    try:
        mobile.run_mobile((MobileCommand(MobileCommandKind.MONITOR, {}),))
        results.append(fail(name, "stopped monitor accepted"))
        return
    except MobileError as error:
        if error.reason != MobileReasonCode.COMMAND_STOPPED:
            results.append(fail(name, "reason %r" % error.reason))
            return
    results.append(
        ok(name, "monitoring keeps running in background; a stopped process "
                 "does nothing"),
    )


# ---------------------------------------------------------------------------
# 33-36: determinism
# ---------------------------------------------------------------------------


_SUBPROCESS_SCENARIO = """
import sys
sys.path.insert(0, %r)
from agent import (
    AgentConfig, AgentIdentitySpec, InterfaceSnapshot, MigrationSpec,
    StaticInterfaceSource, StepClock,
)
from mobile import (
    MobileAgent, MobileCommand, MobileCommandKind, MobilePhase,
    NetworkKind, PlatformSnapshot, PowerState, ScriptedPlatformSource,
    GrantScope,
)

_T0 = "2025-06-01T00:00:00Z"
_PROFILE_ID = "identity.sha256-hmac-dev.v1"
config = AgentConfig(
    agent_label="mobile-subprocess",
    identity=AgentIdentitySpec(
        profile_id=_PROFILE_ID, public_key=b"mobile-subprocess-key",
        created_at=_T0,
    ),
    migration=MigrationSpec(schema_id="agent.state", from_version="1.0", to_version="1.1"),
)
snapshots = (
    InterfaceSnapshot(
        name="wlan0", link_kind="wireless", state_up=True, mtu=1500,
        speed_mbps=100, rx_bytes=7, tx_bytes=9, rx_errors=0, tx_errors=0,
    ),
    InterfaceSnapshot(
        name="rmnet0", link_kind="other", state_up=True, mtu=1400,
        speed_mbps=50, rx_bytes=11, tx_bytes=13, rx_errors=0, tx_errors=0,
    ),
)

def snap(phase, network, metered=False, restricted=False):
    return PlatformSnapshot(
        app_phase=phase, power_state=PowerState.ON_BATTERY,
        network_kind=network, metered=metered,
        background_restricted=restricted,
    )

FG, BG = MobilePhase.FOREGROUND, MobilePhase.BACKGROUND
WIFI, CELL = NetworkKind.WIFI, NetworkKind.CELLULAR

mobile = MobileAgent(
    config=config, clock=StepClock(_T0, 60),
    interface_source=StaticInterfaceSource(snapshots),
    platform_source=ScriptedPlatformSource((
        snap(FG, WIFI), snap(BG, WIFI), snap(FG, WIFI),
        snap(FG, CELL, metered=True), snap(FG, CELL, metered=True),
        snap(FG, WIFI), snap(FG, WIFI),
    )),
    access_interfaces={WIFI: "wlan0", CELL: "rmnet0"},
)
r1 = mobile.run_mobile((
    MobileCommand(MobileCommandKind.BOOT, {}),
    MobileCommand(MobileCommandKind.EXPOSE_INTERFACES, {}),
), boot_secret=b"mobile-subprocess-secret")
r2 = mobile.run_mobile((
    MobileCommand(MobileCommandKind.GRANT, {"scope": GrantScope.METERED_DATA}),
    MobileCommand(MobileCommandKind.MONITOR, {}),
))
r3 = mobile.run_mobile((
    MobileCommand(MobileCommandKind.CHECKPOINT, {}),
))
print(mobile.mobile_event_digest)
print(r3.mobile_digest)
""" % (str(REPO_ROOT),)


def _determinism_stream() -> Tuple[str, str]:
    mobile, _ = _world(
        _script(
            _snap(FG, WIFI), _snap(BG, WIFI), _snap(FG, WIFI),
            _snap(FG, CELLULAR, metered=True),
            _snap(FG, CELLULAR, metered=True), _snap(FG, WIFI),
            _snap(FG, WIFI),
        ),
    )
    mobile.run_mobile((
        _grant(GrantScope.METERED_DATA),
        MobileCommand(MobileCommandKind.MONITOR, {}),
    ))
    result = mobile.run_mobile((MobileCommand(MobileCommandKind.CHECKPOINT, {}),))
    return mobile.mobile_event_digest, result.mobile_digest


def case_33_determinism_two_runs(results: List[Result]) -> None:
    name = "case_33_determinism_two_runs"
    first = _determinism_stream()
    second = _determinism_stream()
    if first != second:
        results.append(fail(name, "%r != %r" % (first, second)))
        return
    results.append(
        ok(name, "full scenario byte-identical across fresh runs "
                 "(event + mobile digests)"),
    )


def case_34_subprocess_hash_seeds(results: List[Result]) -> None:
    name = "case_34_subprocess_hash_seeds"
    digests = set()
    for seed in ("0", "1", "7919", None):
        env = dict(os.environ)
        env.pop("PYTHONHASHSEED", None)
        if seed is not None:
            env["PYTHONHASHSEED"] = seed
        run = subprocess.run(
            [sys.executable, "-c", _SUBPROCESS_SCENARIO],
            capture_output=True, text=True, env=env, cwd=str(REPO_ROOT),
        )
        if run.returncode != 0:
            results.append(fail(
                name, "seed %r failed: %s" % (seed, run.stderr.strip()[-200:]),
            ))
            return
        digests.add(tuple(run.stdout.strip().splitlines()))
    if len(digests) != 1:
        results.append(fail(name, "digests diverged across seeds"))
        return
    results.append(ok(
        name,
        "event+run digests identical across PYTHONHASHSEED 0/1/7919/None "
        "in fresh subprocesses",
    ))


def case_35_replay_verification(results: List[Result]) -> None:
    name = "case_35_replay_verification"
    commands = (
        MobileCommand(MobileCommandKind.BOOT, {}),
        MobileCommand(MobileCommandKind.EXPOSE_INTERFACES, {}),
        MobileCommand(MobileCommandKind.MONITOR, {}),
        MobileCommand(MobileCommandKind.CHECKPOINT, {}),
    )

    def make_script() -> ScriptedPlatformSource:
        return _script(
            _snap(FG, WIFI), _snap(BG, WIFI), _snap(FG, WIFI),
            _snap(FG, WIFI),
        )

    accepted, digest = verify_mobile_replay(
        _config("replay", key=b"mobile-replay-key"),
        commands,
        clock_factory=lambda: StepClock(_T0, 60),
        interface_source_factory=lambda: StaticInterfaceSource(_snapshots()),
        platform_source_factory=make_script,
        boot_secret=b"mobile-replay-secret",
        access_interfaces={WIFI: "wlan0", CELLULAR: "rmnet0"},
    )
    if not accepted or not digest.startswith("sha256:"):
        results.append(fail(name, "replay rejected: %s" % digest))
        return
    accepted2, _ = verify_mobile_replay(
        _config("replay", key=b"mobile-replay-key"),
        commands,
        clock_factory=lambda: StepClock(_T0, 60),
        interface_source_factory=lambda: StaticInterfaceSource(_snapshots()),
        platform_source_factory=make_script,
        boot_secret=b"mobile-replay-secret",
        expected_mobile_digest=digest,
        access_interfaces={WIFI: "wlan0", CELLULAR: "rmnet0"},
    )
    if not accepted2:
        results.append(fail(name, "matching digest rejected"))
        return
    accepted3, _ = verify_mobile_replay(
        _config("replay", key=b"mobile-replay-key"),
        commands,
        clock_factory=lambda: StepClock(_T0, 60),
        interface_source_factory=lambda: StaticInterfaceSource(_snapshots()),
        platform_source_factory=make_script,
        boot_secret=b"mobile-replay-secret",
        expected_mobile_digest="sha256:" + "0" * 64,
        access_interfaces={WIFI: "wlan0", CELLULAR: "rmnet0"},
    )
    if accepted3:
        results.append(fail(name, "divergent digest accepted"))
        return
    results.append(
        ok(name, "verify_mobile_replay accepts match, rejects divergence"),
    )


def case_36_canonical_round_trips(results: List[Result]) -> None:
    name = "case_36_canonical_round_trips"
    problems: List[str] = []
    events = (
        MobileEvent(MobileEventType.PHASE_CHANGED, 1, _T0, "background",
                    "foreground -> background"),
        MobileEvent(MobileEventType.GRANT_GRANTED, 2, _T0, "metered-data",
                    "expires never"),
    )
    restored = tuple(MobileEvent.from_dict(event.to_dict()) for event in events)
    if restored != events:
        problems.append("events diverged")
    if mobile_events_canonical_bytes(restored) != mobile_events_canonical_bytes(events):
        problems.append("event canonical bytes diverged")
    grant = UserGrant(GrantScope.METERED_DATA, _T0, "2025-06-01T00:05:00Z")
    if UserGrant.from_dict(grant.to_dict()) != grant:
        problems.append("grant diverged")
    snapshot = MobileSnapshot(
        phase=BG, grants=(grant,), deferred=(),
        sessions=(), event_sequence=7, event_digest="sha256:" + "1" * 64,
        produced_at=_T0,
    )
    if MobileSnapshot.from_dict(snapshot.to_dict()) != snapshot:
        problems.append("snapshot diverged")
    platform = _snap(BG, CELLULAR, metered=True, restricted=True)
    if PlatformSnapshot.from_dict(platform.to_dict()) != platform:
        problems.append("platform diverged")
    command = MobileCommand(
        MobileCommandKind.SEND_DATAGRAM,
        {"session_id": "sha256:" + "2" * 64, "payload_hex": b"ab".hex()},
    )
    if derive_mobile_command_id(command.kind, command.params) != command.command_id:
        problems.append("command id diverged")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "events, grants, snapshot, platform, commands all round-trip "
                 "byte-identically"),
    )


# ---------------------------------------------------------------------------
# 37-41: structural audits
# ---------------------------------------------------------------------------


def case_37_no_shadow_authority(results: List[Result]) -> None:
    name = "case_37_no_shadow_authority"
    forbidden_constructors = (
        "IdentityService(", "SessionStore(", "RoutingEngine(",
        "PolicyEngine(", "MultipathStore(", "TopologyGraph(",
        "ResourceStore(", "DiscoveryService(", "TransportManager(",
        "IPIntegrationManager(", "FederationStore(", "TelemetryStore(",
        "AdapterRuntime(", "NodeIdentity.create(",
    )
    problems: List[str] = []
    for path in _FAMILY_FILES:
        text = path.read_text(encoding="utf-8")
        for token in forbidden_constructors:
            if token in text:
                problems.append("%s constructs %s" % (path.name, token))
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(
        ok(name, "no authority construction in mobile/ (composition over the "
                 "one unchanged AgentRuntime only)"),
    )


#: Roots the mobile family must NEVER import (everything except the
#: consumed contracts: agent, sessions, multipath vocabulary, protocol
#: canonicalization -- plus the mobile family itself).
_FORBIDDEN_ROOTS = (
    "simulator", "mobility", "energy", "discovery",
    "intent", "services", "federation", "identity", "management",
    "policy", "resources", "routing", "topology",
    "transport", "upgrade", "capabilities", "conformance",
    "adapters", "edge", "envelope", "schema", "ipintegration",
    "fivegc", "ran", "wifi", "backhaul", "mesh", "distcore",
)
_BANNED_STDLIB = (
    "os", "socket", "time", "random", "secrets", "uuid",
    "subprocess", "urllib", "http", "ssl", "asyncio",
)


def case_38_import_discipline(results: List[Result]) -> None:
    name = "case_38_import_discipline"
    problems: List[str] = []
    for path in _FAMILY_FILES:
        relative = str(path.relative_to(REPO_ROOT))
        source = path.read_text(encoding="utf-8")
        for root in _FORBIDDEN_ROOTS:
            if re.search(r"^\s*(from|import)\s+%s\b" % root, source, re.MULTILINE):
                problems.append("%s imports forbidden root %s" % (relative, root))
        for module in _BANNED_STDLIB:
            if re.search(r"^\s*(from|import)\s+%s\b" % module, source, re.MULTILINE):
                problems.append("%s imports banned stdlib %s" % (relative, module))
        if re.search(r"\binput\s*\(", source) or "sys.stdin" in source:
            problems.append("%s touches interactive input" % relative)
        for call in ("datetime.now", "datetime.utcnow", "time.time"):
            if re.search(r"\b%s\s*\(" % call.replace(".", r"\."), source):
                problems.append("%s reads the wall clock (%s)" % (relative, call))
    if problems:
        results.append(fail(name, "; ".join(sorted(set(problems))[:6])))
        return
    results.append(
        ok(name, "forbidden families absent (platform/vendor boundary "
                 "holds); wall clock never read"),
    )


def case_39_naming_token_scan(results: List[Result]) -> None:
    name = "case_39_naming_token_scan"
    forbidden = (
        "5g", "6g", "lte", "imt-2030", "imt2030", "open5gs",
        "srsran", "wi-fi7",
    )
    problems: List[str] = []
    for path in _FAMILY_FILES:
        text = path.read_text(encoding="utf-8").lower()
        for token in forbidden:
            if token in text:
                problems.append("%s mentions %r" % (path.name, token))
    if problems:
        results.append(fail(name, "; ".join(sorted(set(problems)))))
        return
    results.append(
        ok(name, "no access-generation or vendor naming tokens in mobile/"),
    )


def case_40_secret_hygiene(results: List[Result]) -> None:
    name = "case_40_secret_hygiene"
    mobile, peer = _world(
        _script(_snap(FG, WIFI), _snap(BG, WIFI), _snap(FG, WIFI)),
    )
    sid = _establish(mobile, peer)
    mobile.run_mobile((
        _track(sid), _grant(GrantScope.METERED_DATA),
        _send(sid, b"secret-hygiene-payload"),
    ))
    mobile.checkpoint()
    blob = repr((
        mobile.mobile_events, mobile.grants, mobile.mobile_snapshot(),
        mobile.last_snapshot.to_dict() if mobile.last_snapshot else None,
        mobile.peer_observations,
    ))
    for secret in (_SECRET_A, _SECRET_B):
        if secret in blob.encode() or secret.hex() in blob:
            results.append(fail(name, "boot secret leaked"))
            return
    results.append(ok(name, "boot secrets absent from all records and events"))


def case_41_py_compile(results: List[Result]) -> None:
    name = "case_41_py_compile"
    for path in _FAMILY_FILES:
        try:
            py_compile.compile(str(path), doraise=True)
        except py_compile.PyCompileError as error:
            results.append(fail(name, "%s: %s" % (path.name, error)))
            return
    results.append(ok(name, "all %d mobile files compile" % len(_FAMILY_FILES)))


# ---------------------------------------------------------------------------
# 42-45: frozen surfaces
# ---------------------------------------------------------------------------


def case_42_frozen_api(results: List[Result]) -> None:
    name = "case_42_frozen_api"
    import mobile

    actual = set(vars(mobile).keys())
    missing = [item for item in _EXPECTED_API if item not in actual]
    unexpected_public = {
        entry for entry in actual
        if not entry.startswith("_") and entry not in _EXPECTED_API
        and callable(getattr(mobile, entry, None))
    }
    if missing or unexpected_public:
        results.append(fail(
            name, "missing %r unexpected %r" % (missing, sorted(unexpected_public)),
        ))
        return
    if len(_EXPECTED_API) != len(set(_EXPECTED_API)):
        results.append(fail(name, "duplicate exports"))
        return
    results.append(
        ok(name, "frozen public API: %d exports exact" % len(_EXPECTED_API)),
    )


def case_43_frozen_spec_intact(results: List[Result]) -> None:
    name = "case_43_frozen_spec_intact"
    status = subprocess.run(
        ["git", "status", "--porcelain", "--", "spec/"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if status.stdout.strip():
        results.append(fail(name, "uncommitted spec/ changes"))
        return
    workflow_path = REPO_ROOT / ".github" / "workflows" / "spec-check.yml"
    workflow = workflow_path.read_text(encoding="utf-8")
    ref_check = subprocess.run(
        ["git", "rev-parse", "--verify", "origin/main"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if ref_check.returncode != 0:
        # Degraded context (no origin/main ref): the committed wiring
        # must be present (the W034 case_46 precedent).
        if "python3 tools/mobile_selftest.py" in workflow:
            results.append(ok(
                name, "spec/ clean; committed CI wiring present "
                "(origin/main ref unavailable)",
            ))
        else:
            results.append(fail(name, "committed CI wiring missing"))
        return
    delta = subprocess.run(
        ["git", "diff", "--name-only", "origin/main", "HEAD"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    changed = {line for line in delta.stdout.splitlines() if line.strip()}
    if not changed:
        if "python3 tools/mobile_selftest.py" in workflow:
            results.append(ok(name, "spec/ clean on main; wiring verified"))
        else:
            results.append(fail(name, "committed CI wiring missing on main"))
        return
    spec_changed = [
        c for c in changed
        if c.startswith("spec/") and c != "spec/prompts/WORK-037.md"
        and c != "spec/prompts/WORK-038.md"
        and c != "spec/prompts/WORK-039.md"
    ]
    # (DAG-sanctioned amendment, W035 -> W037: the Architect anchored
    # the W037 execution handoff on the designated branch -- commit
    # 518c071 -- so the spec/ delta admits exactly that file.)
    # (DAG-sanctioned amendment, W035 -> W038: the Architect anchored
    # the W038 execution handoff on the designated branch -- commit
    # 0be736e -- same pattern.)
    # (DAG-sanctioned amendment, W035 -> W039: the Architect anchored
    # the W039 execution handoff on the designated branch -- commit
    # 7274384 -- same pattern.)
    if spec_changed:
        results.append(fail(name, "spec/ differs from origin/main"))
        return
    results.append(ok(name, "spec/ byte-identical to origin/main; tree clean"))


def case_44_pr_delta_shape(results: List[Result]) -> None:
    name = "case_44_pr_delta_shape"
    workflow_path = REPO_ROOT / ".github" / "workflows" / "spec-check.yml"
    workflow = workflow_path.read_text(encoding="utf-8")
    status = subprocess.run(
        ["git", "status", "--porcelain", "--", "spec/"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if status.stdout.strip():
        results.append(fail(name, "uncommitted spec/ changes"))
        return
    ref_check = subprocess.run(
        ["git", "rev-parse", "--verify", "origin/main"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if ref_check.returncode != 0:
        # Degraded context (the W034 case_46 precedent): committed
        # wiring must be present when the origin/main ref is
        # unavailable (shallow CI checkout).
        if "python3 tools/mobile_selftest.py" in workflow:
            results.append(ok(
                name, "spec/ clean; committed CI wiring present "
                "(origin/main ref unavailable)",
            ))
        else:
            results.append(fail(name, "committed CI wiring missing"))
        return
    delta = subprocess.run(
        ["git", "diff", "--name-only", "origin/main", "HEAD"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    changed = {line for line in delta.stdout.splitlines() if line.strip()}
    if not changed:
        if "python3 tools/mobile_selftest.py" in workflow:
            results.append(ok(name, "spec/ clean on main; wiring verified"))
        else:
            results.append(fail(name, "committed CI wiring missing on main"))
        return
    spec_changed = [
        c for c in changed
        if c.startswith("spec/") and c != "spec/prompts/WORK-037.md"
        and c != "spec/prompts/WORK-038.md"
        and c != "spec/prompts/WORK-039.md"
    ]
    # (DAG-sanctioned amendment, W035 -> W037: the Architect anchored
    # the W037 execution handoff on the designated branch -- commit
    # 518c071, with main's accidental publication reverted by the
    # Architect -- so the spec/ delta admits exactly that file.)
    # (DAG-sanctioned amendment, W035 -> W038: commit 0be736e, same
    # pattern.)
    if spec_changed:
        results.append(fail(name, "spec/ differs from origin/main: %s" % spec_changed))
        return
    allowed_exact = {
        "tools/mobile_selftest.py",
        # DAG-sanctioned allowlist amendments:
        # W033 -> W035 (the mobile battery extends the agent battery):
        "tools/agent_selftest.py",
        # W034 -> W035 (the mobile battery follows the edge battery in
        # work-item order; its PR-delta shape admits the successor):
        "tools/edge_selftest.py",
        "docs/WORK-035-evidence.md",
        # DAG-sanctioned allowlist amendment (W035 -> W036): the
        # appliance battery follows this one in work-item order (the
        # appliance and the mobile layer are sibling compositions
        # over the agent core), and its PR-delta shape must admit
        # the successor's files.
        "tools/appliance_selftest.py",
        "docs/WORK-036-handoff.md",
        "docs/WORK-036-evidence.md",
        # DAG-sanctioned allowlist amendment (W035 -> W037): the Open
        # RAN/Core interop-profile battery follows this one in
        # work-item order (the profile's mixed-access demonstration
        # carries the same sacred session across access legs), and
        # its PR-delta shape must admit the successor's files.
        "tools/oran_selftest.py",
        "docs/WORK-037-handoff.md",
        "docs/WORK-037-evidence.md",
        # DAG-sanctioned allowlist amendment (W035 -> W038): the
        # future-IMT profile battery follows this one in work-item
        # order (the future profile composes the same adapter SDK the
        # mobile agent hosts), and its PR-delta shape must admit the
        # successor's files.
        "tools/imt_selftest.py",
        "docs/WORK-038-handoff.md",
        "docs/WORK-038-evidence.md",
        # DAG-sanctioned allowlist amendment (W035 -> W039): the
        # federation-at-scale battery follows this one in work-item
        # order, and its PR delta shape must admit the successor's
        # files.
        "tools/scale_selftest.py",
        "docs/WORK-039-handoff.md",
        "docs/WORK-039-evidence.md",
        # DAG-sanctioned amendment (-> WORK-040): the pilot deployment
        # battery extends this one (work-item order in CI).
        "tools/pilot_selftest.py",
        "docs/WORK-040-handoff.md",
        "docs/WORK-040-evidence.md",
        # DAG-sanctioned allowlist amendment (W029 -> W038): the upgrade
        # battery's authority-boundary audit exempts the W038
        # future-IMT family as a DAG-sanctioned downstream consumer
        # (WORK-038 declares WORK-029 among its frozen dependencies;
        # imt/coexistence.py composes the real compatibility surfaces).
        "tools/upgrade_selftest.py",
        # the Architect's own branch anchor (admitted above by the
        # spec-delta check):
        "spec/prompts/WORK-037.md",
        "spec/prompts/WORK-038.md",
        "spec/prompts/WORK-039.md",
    }
    unexpected = [
        c for c in changed
        if not c.startswith("mobile/") and not c.startswith("appliance/")
        and not c.startswith("interop/") and not c.startswith("imt/")
        and not c.startswith("scale/") and not c.startswith("pilot/")
        and c not in allowed_exact
        and not c.startswith(".github/")
    ]
    if unexpected:
        results.append(fail(name, "delta beyond the sanctioned shape: %s" % unexpected))
        return
    workflow_delta = subprocess.run(
        ["git", "diff", "origin/main", "--", ".github/"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    # The wiring change must be additive for the mobile step: the
    # mobile CI step stays present and no delta line removes it.  (A
    # successor work item may append its own step further down the
    # workflow, so the mobile step need not appear inside the diff
    # context -- only never be weakened.  The W033 -> W035 agent
    # case_40 precedent, applied for the W035 -> W037 successor.)
    removed_mobile_step = any(
        line.startswith("-") and "mobile_selftest.py" in line
        for line in workflow_delta.stdout.splitlines()
    )
    if removed_mobile_step or "python3 tools/mobile_selftest.py" not in workflow:
        results.append(fail(name, ".github delta weakens or drops the mobile CI step"))
        return
    results.append(ok(
        name,
        "PR delta exactly: mobile/ + mobile battery + agent/edge allowlist "
        "amendments + evidence doc + CI step",
    ))


def case_45_ci_wiring_all_tools(results: List[Result]) -> None:
    name = "case_45_ci_wiring_all_tools"
    workflow_path = REPO_ROOT / ".github" / "workflows" / "spec-check.yml"
    workflow = workflow_path.read_text(encoding="utf-8")
    missing = [
        tool for tool in _EXPECTED_TOOLS
        if ("tools/%s" % tool) not in workflow
    ]
    if missing:
        results.append(fail(name, "batteries missing from CI: %s" % missing))
        return
    edge_index = workflow.find("python3 tools/edge_selftest.py")
    mobile_index = workflow.find("python3 tools/mobile_selftest.py")
    agent_index = workflow.find("python3 tools/agent_selftest.py")
    appliance_index = workflow.find("python3 tools/appliance_selftest.py")
    if not (agent_index < edge_index < mobile_index < appliance_index):
        results.append(fail(name, "appliance step not ordered after agent/edge/mobile"))
        return
    results.append(ok(
        name,
        "CI wired: mobile battery + all %d prior tools; mobile ordered after "
        "agent/edge, appliance after mobile (work-item order)"
        % (len(_EXPECTED_TOOLS) - 1),
    ))


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() -> int:
    results: List[Result] = []
    for case in (
        case_01_frozen_vocabularies,
        case_02_platform_snapshot_validation,
        case_03_user_grant_records,
        case_04_participation_decision_validation,
        case_05_mobile_events_and_digests,
        case_06_access_path_view_w013_vocabulary,
        case_07_legal_phase_transitions,
        case_08_illegal_transition_fail_closed,
        case_09_gate_totality_and_precedence,
        case_10_platform_sources,
        case_11_evidence_disclosure,
        case_12_boot_and_passthrough,
        case_13_foreground_send,
        case_14_foreground_to_background,
        case_15_background_consent_and_drain,
        case_16_background_to_foreground,
        case_17_os_restriction_overrides_consent,
        case_18_online_to_offline,
        case_19_offline_to_online_drain,
        case_20_handover_wifi_to_cellular,
        case_21_handover_refused_without_consent,
        case_22_unmetered_handover_no_consent,
        case_23_grant_lifecycle,
        case_24_secret_free_consent_records,
        case_25_ttl_shed_and_overflow,
        case_26_stop_checkpoint_refusal,
        case_27_recovery_continuation,
        case_28_grant_ttl_survives_restart,
        case_29_discovery_gating,
        case_30_discovery_genuine_w006,
        case_31_null_discovery_honest,
        case_32_monitor_keeps_observing,
        case_33_determinism_two_runs,
        case_34_subprocess_hash_seeds,
        case_35_replay_verification,
        case_36_canonical_round_trips,
        case_37_no_shadow_authority,
        case_38_import_discipline,
        case_39_naming_token_scan,
        case_40_secret_hygiene,
        case_41_py_compile,
        case_42_frozen_api,
        case_43_frozen_spec_intact,
        case_44_pr_delta_shape,
        case_45_ci_wiring_all_tools,
    ):
        case(results)
    failures = [r for r in results if not r[1]]
    for case_name, passed, detail in results:
        print("[%s] %-52s %s" % ("ok  " if passed else "FAIL", case_name, detail))
    print("-" * 72)
    if failures:
        print("Result: FAIL (%d/%d cases failed)" % (len(failures), len(results)))
        for case_name, _, detail in failures:
            print("  FAILED %s: %s" % (case_name, detail))
        return 1
    print("Result: PASS (%d/%d cases passed)" % (len(results), len(results)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
