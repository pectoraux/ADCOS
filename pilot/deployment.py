"""WORK-040 pilot deployment: the real multi-process conductor and the
node role implementations.

Every pilot node is a REAL OS process; every carriage is a REAL TCP
socket on the host's loopback; every protocol artifact on the wire is a
genuine WORK-003 envelope encoded and validated by the production
codec/acceptance surfaces.  The deployment plane never re-decides
anything the accepted families own:

- the appliance process boots a REAL WORK-036 ``NetworkAppliance``
  (fabric provisioned, ISOLATED upstream posture) and serves through
  its inner WORK-033 runtime;
- each device process boots a REAL WORK-033 ``AgentRuntime`` and drives
  the production session chain (establish -> accept -> complete ->
  finalize -> bind -> datagrams -> local service invocation);
- the relay process is pure carriage (the WORK-039 discipline): every
  frame it transits is validated by the production ``protocol.accept``
  under ``FORWARD_OPAQUE`` (the LOCK-014 receipt) and forwarded
  VERBATIM -- byte-identical, never re-encoded, never applied;
- failover is a REAL socket death (the appliance executes its declared
  failure plan by hard-resetting the direct access path); the device
  observes the actual transport failure, marks the primary constituent
  FAILED through the REAL WORK-018 multipath authority (admitted from
  an externally produced REAL WORK-011 route decision), re-establishes
  carriage through the relay, and continues the SAME logical session
  (session-record digest proven unchanged).

Determinism: the semantic journal (events, checks, execution records,
criterion outcomes) is derived ONLY from deterministic content.  Real
but non-deterministic observations (ports, pids, wall-clock timings,
raw socket error strings, host interface counters) live in the
operational metadata, which the run digest excludes by construction.
"""

from __future__ import annotations

import json
import os
import socket
import struct
import subprocess  # noqa: S404 - the deployment's own node processes
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from agent import (
    AgentConfig,
    AgentIdentitySpec,
    AgentRuntime,
    LinkMetricSpec,
    StepClock,
)
from appliance import ApplianceCommand, ApplianceCommandKind, NetworkAppliance
from identity.node_id import parse_node_id
from multipath import MultipathStore, PathStatus
from policy import PolicyDomain, PolicyEngine, PolicyRule
from policy.model import Operation, PolicyContext, PolicySet
from protocol import canonical_json_bytes
from resources import ResourceStore
from routing import RoutingContext, RoutingEngine
from routing.model import LinkMetrics
from topology import (
    ClaimType,
    SourceClass,
    TopologyClaim,
    TopologyGraph,
    make_link_subject,
)

from . import marshal
from .errors import PilotError, PilotReasonCode
from .model import (
    PilotCheck,
    PilotEvent,
    PilotEventKind,
    PilotRunResult,
    sha256_hex_of_bytes,
)
from .fabric import PILOT_TENANT_DOMAIN, pilot_echo_service_ref
from .topology import (
    DEVICE_CLOCK_STEP_SECONDS,
    PILOT_FRESH,
    PILOT_PROFILE_ID,
    PILOT_T0,
    PARTICIPANT_NODE_BY_LABEL,
    PilotNodeSpec,
    appliance_access_plan,
    appliance_commands,
    appliance_hardware_source,
    appliance_interface_source,
    appliance_upstream_mode,
    device_config,
    device_interface_source,
    node_identity_for,
    node_ids,
    validate_topology,
)
from .wire import (
    close_quietly,
    connect_to,
    open_listener,
    pilot_envelope,
    recv_frame,
    send_frame,
    socket_endpoint,
    validate_frame,
)

__all__ = [
    "EPOCH_ISSUED",
    "EPOCH_EXPIRES",
    "VALIDATION_NOW",
    "DEVICE_DATAGRAM_COUNT_PRIMARY",
    "DEVICE_DATAGRAM_COUNT_SECONDARY",
    "DEVICE_DATAGRAM_COUNT_LOCAL",
    "PILOT_ECHO_PAYLOADS_PRIMARY",
    "PILOT_ECHO_PAYLOADS_SECONDARY",
    "PILOT_ECHO_PAYLOADS_LOCAL",
    "PILOT_SERVICE_PAYLOAD",
    "NodeJournal",
    "run_appliance_node",
    "run_relay_node",
    "run_device_node",
    "run_pilot_deployment",
]


#: The deployment-declared envelope epoch window: every wire frame is
#: issued at the epoch origin and expires 24h later, so every node's
#: clock reads (which live strictly inside the window) validate every
#: LOCK-014 receipt in both directions.  This is the DEPLOYMENT-PLANE
#: temporal envelope; the protocol artifacts inside (offers,
#: acceptances) keep their own runtime-clock instants and gates.
EPOCH_ISSUED = PILOT_T0
EPOCH_EXPIRES = "2026-08-02T00:00:00Z"

#: The instant every receiver uses for its production acceptance
#: receipt (mid-window; deterministic).
VALIDATION_NOW = "2026-08-01T12:00:00Z"

#: The device-1 phase plan: N exchanges over the primary (direct)
#: path, then the appliance executes its declared failure plan; the
#: remaining exchanges ride the secondary (relayed) path.
DEVICE_DATAGRAM_COUNT_PRIMARY = 3
DEVICE_DATAGRAM_COUNT_SECONDARY = 3

#: The device-2 phase plan: exchanges over the relayed local-access
#: path plus one genuine local-service invocation.
DEVICE_DATAGRAM_COUNT_LOCAL = 2

#: Deterministic datagram payloads (semantic journal DATA).
PILOT_ECHO_PAYLOADS_PRIMARY = tuple(
    ("pilot-direct-datagram-%d" % (index,)).encode("utf-8")
    for index in range(1, DEVICE_DATAGRAM_COUNT_PRIMARY + 1)
)
PILOT_ECHO_PAYLOADS_SECONDARY = tuple(
    ("pilot-relay-datagram-%d" % (index,)).encode("utf-8")
    for index in range(1, DEVICE_DATAGRAM_COUNT_SECONDARY + 1)
)
PILOT_ECHO_PAYLOADS_LOCAL = tuple(
    ("pilot-local-datagram-%d" % (index,)).encode("utf-8")
    for index in range(1, DEVICE_DATAGRAM_COUNT_LOCAL + 1)
)
PILOT_SERVICE_PAYLOAD = b"pilot-service-invocation-payload"

#: The invocation-decision evaluation instant (deterministic).
_INVOCATION_INSTANT = "2026-08-01T00:30:00Z"

#: Operational-only timeouts.
_SHUTDOWN_TIMEOUT_SECONDS = 30.0
_NODE_EXIT_TIMEOUT_SECONDS = 180.0


# ---------------------------------------------------------------------------
# The per-node journal
# ---------------------------------------------------------------------------


class NodeJournal:
    """One node's deployment-plane journal (sequence + injected clock)."""

    def __init__(self, label: str, clock: StepClock) -> None:
        self._label = label
        self._clock = clock
        self._events: List[PilotEvent] = []
        self._lock = threading.Lock()

    @property
    def label(self) -> str:
        return self._label

    def append(self, kind: str, payload: Mapping[str, Any]) -> PilotEvent:
        with self._lock:
            event = PilotEvent(
                sequence=len(self._events) + 1,
                kind=kind,
                at_instant=self._clock.now(),
                payload=dict(payload),
            )
            self._events.append(event)
            return event

    def events(self) -> Tuple[PilotEvent, ...]:
        with self._lock:
            return tuple(self._events)

    def now(self) -> str:
        return self._clock.now()


# ---------------------------------------------------------------------------
# Shared wire helpers (production codec + acceptance receipts)
# ---------------------------------------------------------------------------

_CODEC = None


def _codec():
    global _CODEC
    if _CODEC is None:
        from protocol import get_codec

        _CODEC = get_codec("json-debug")
    return _CODEC


def _send_pilot_envelope(
    sock: socket.socket,
    message_type: str,
    payload: Any,
    *,
    sender: str,
) -> None:
    envelope = pilot_envelope(
        message_type,
        payload,
        sender=sender,
        issued_at=EPOCH_ISSUED,
        expires_at=EPOCH_EXPIRES,
    )
    send_frame(sock, _codec().encode(envelope))


def _recv_pilot_envelope(
    sock: socket.socket, *, timeout: float = 30.0
) -> Tuple[str, Any]:
    """Receive one pilot envelope: raw frame -> production acceptance
    receipt (LOCK-014) -> production codec decode.

    Returns ``(message_type, payload)``.
    """
    raw = recv_frame(sock, timeout=timeout)
    receipt = validate_frame(raw, now=VALIDATION_NOW)
    if not receipt["accepted"]:
        raise PilotError(
            PilotReasonCode.WIRE_INVALID,
            "frame rejected by the production acceptance surface: %s"
            % (receipt["detail"],),
        )
    envelope = _codec().decode(raw)
    return envelope.message_type, envelope.payload


def _announce_payload(
    label: str, node_id: str, credential_mapping: Mapping[str, Any]
) -> Dict[str, Any]:
    return {
        "label": label,
        "node_id": node_id,
        "credential": dict(credential_mapping),
    }


def _exchange_announce(
    sock: socket.socket,
    *,
    self_label: str,
    self_node_id: str,
    self_credential_mapping: Mapping[str, Any],
    journal: NodeJournal,
    initiate: bool,
) -> Tuple[str, str, Dict[str, Any]]:
    """The genuine identity exchange over the wire.

    ``initiate=True`` (the connecting device): send our public announce,
    then receive the peer's.  ``initiate=False`` (the access point):
    receive the peer's announce first, then respond -- the exchange is
    STRICTLY CAUSAL half-duplex, so a relay on the carriage sees a
    deterministic frame order (the deployment journal never depends on
    thread scheduling).
    """
    payload_view: Dict[str, Any] = {}

    def _send() -> None:
        _send_pilot_envelope(
            sock,
            "pilot.discovery.announce",
            _announce_payload(
                self_label, self_node_id, self_credential_mapping
            ),
            sender=self_node_id,
        )

    def _receive() -> Tuple[str, Any]:
        message_type, payload = _recv_pilot_envelope(sock)
        if message_type != "pilot.discovery.announce":
            raise PilotError(
                PilotReasonCode.WIRE_INVALID,
                "expected the peer announce, got %r" % (message_type,),
            )
        if not isinstance(payload, Mapping):
            raise PilotError(
                PilotReasonCode.WIRE_INVALID,
                "announce payload must be a mapping",
            )
        return str(payload.get("label", "")), payload

    if initiate:
        _send()
        peer_label, peer_payload = _receive()
    else:
        peer_label, peer_payload = _receive()
        _send()
    payload_view = dict(peer_payload)
    journal.append(
        PilotEventKind.DISCOVERY_ANNOUNCED,
        {"peer_label": peer_label},
    )
    return (
        peer_label,
        str(payload_view.get("node_id", "")),
        dict(payload_view.get("credential") or {}),
    )


def _active_credential_mapping(runtime: AgentRuntime) -> Dict[str, Any]:
    credential = runtime.identity_service.active_credential(
        parse_node_id(runtime.node_id), "operational", now=runtime._now()
    )
    if credential is None:
        raise PilotError(
            PilotReasonCode.NODE_FAILED,
            "no active operational credential after boot",
        )
    return marshal.credential_record_to_mapping(credential)


# ---------------------------------------------------------------------------
# The appliance node
# ---------------------------------------------------------------------------


def run_appliance_node(
    *,
    result_path: str,
    rehearsal: bool,
    bind_host: str = "127.0.0.1",
    failure_plan: bool = True,
) -> int:
    """The appliance process: boot, provision, open the two access
    points, serve every carriage connection, execute the declared
    failure plan after the primary-path exchange budget (unless the
    scenario disarms it), then shut down on stdin EOF and write the
    result document.

    ``bind_host``: which host address the access points bind (the
    default loopback keeps the delivered rehearsal byte-identical;
    the physical pilot may bind an externally reachable address).
    ``failure_plan``: the declared direct-path failure plan is
    device-1's failover demonstration; the physical participation
    scenario disarms it (its checks say so honestly)."""
    from .platform import probe_egress

    ids = node_ids()
    appliance_id = ids["appliance-1"]
    appliance = _boot_appliance()
    runtime = appliance.runtime
    journal = NodeJournal(
        "appliance-1",
        StepClock("2026-08-01T04:00:00Z", DEVICE_CLOCK_STEP_SECONDS),
    )
    journal.append(
        PilotEventKind.NODE_BOOTED,
        {"label": "appliance-1", "node_id": appliance_id},
    )
    journal.append(
        PilotEventKind.FABRIC_PROVISIONED,
        {"site": "%s-box" % (PILOT_TENANT_DOMAIN,), "services": 2},
    )

    # -- the upstream egress demonstration (an explicit probe) --------
    upstream_record: Dict[str, Any]
    if rehearsal:
        rehearsal_listener = open_listener("127.0.0.1", 0)
        rehearsal_port = socket_endpoint(rehearsal_listener)[1]
        accept_thread = threading.Thread(
            target=_accept_once, args=(rehearsal_listener,), daemon=True
        )
        accept_thread.start()
        upstream_record = probe_egress(
            ("127.0.0.1", rehearsal_port), rehearsal=True
        )
        accept_thread.join(timeout=5.0)
        close_quietly(rehearsal_listener)
    else:
        from .platform import EGRESS_PROBE_DEFAULT_TARGET

        upstream_record = probe_egress(
            EGRESS_PROBE_DEFAULT_TARGET, rehearsal=False
        )
    journal.append(
        PilotEventKind.UPSTREAM_PROBED,
        {
            "kind": str(upstream_record.get("kind", "")),
            "stage": str(upstream_record.get("stage", "")),
            "reachable": bool(upstream_record.get("reachable", False)),
            "rehearsal": bool(upstream_record.get("rehearsal", True)),
        },
    )

    # -- the two real access points ------------------------------------
    direct_listener = open_listener(bind_host, 0)
    relay_listener = open_listener(bind_host, 0)
    direct_port = socket_endpoint(direct_listener)[1]
    relay_port = socket_endpoint(relay_listener)[1]

    state: Dict[str, Any] = {
        "failed_over": False,
        "direct_served": 0,
        "announce_labels": set(),
        "appliance": appliance,
        "journal": journal,
        "direct_conns": set(),
        "direct_listener": direct_listener,
        "runtime_lock": threading.Lock(),
        "handler_errors": [],
        "lock": threading.Lock(),
    }

    direct_thread = threading.Thread(
        target=_serve_listener,
        args=(direct_listener, state, "direct",
              DEVICE_DATAGRAM_COUNT_PRIMARY if failure_plan else None),
        daemon=True,
    )
    relay_thread = threading.Thread(
        target=_serve_listener,
        args=(relay_listener, state, "relay", None),
        daemon=True,
    )
    direct_thread.start()
    relay_thread.start()

    sys.stdout.write(
        json.dumps({"direct": direct_port, "relay": relay_port}) + "\n"
    )
    sys.stdout.flush()

    # Serve until the conductor closes stdin.
    try:
        while True:
            line = sys.stdin.readline()
            if not line:
                break
    except Exception:  # noqa: BLE001 - shutdown path
        pass

    _execute_failure_plan(state)
    close_quietly(direct_listener)
    close_quietly(relay_listener)
    direct_thread.join(timeout=_SHUTDOWN_TIMEOUT_SECONDS)
    relay_thread.join(timeout=_SHUTDOWN_TIMEOUT_SECONDS)
    appliance.runtime.shutdown()

    session_document: Dict[str, Any] = {}
    sessions = appliance.runtime.sessions
    for session_id in _known_sessions(sessions):
        session = sessions.get(session_id)
        if session is None:
            continue
        session_document[session_id] = {
            "state": session.state,
            "record_digest": _session_record_digest(session),
            "last_event_sequence": session.last_event_sequence,
        }
    journal.append(
        PilotEventKind.NODE_SHUTDOWN,
        {"label": "appliance-1", "sessions": len(session_document)},
    )
    handler_errors = list(state["handler_errors"])
    _write_result(
        result_path,
        "appliance-1",
        "appliance",
        appliance_id,
        journal,
        [
            PilotCheck(
                "appliance-booted-and-provisioned",
                True,
                "NetworkAppliance booted; fabric provisioned with 2 local "
                "services; ISOLATED upstream posture",
            ),
            PilotCheck(
                "appliance-upstream-probe-recorded",
                bool(upstream_record.get("reachable", False)),
                "upstream egress probe stage=%s rehearsal=%s"
                % (
                    upstream_record.get("stage", ""),
                    upstream_record.get("rehearsal", True),
                ),
            ),
            PilotCheck(
                "appliance-failure-plan-executed"
                if failure_plan
                else "appliance-failure-plan-disarmed",
                True if not failure_plan else state["failed_over"],
                "failure plan disarmed for this scenario (the physical "
                "participation demonstration; the failover demonstration "
                "is the main deployment's device-1 scenario)"
                if not failure_plan
                else "the declared direct-path failure plan executed "
                     "(listener closed + direct connections hard-reset "
                     "after %d exchanges)" % (DEVICE_DATAGRAM_COUNT_PRIMARY,),
            ),
            PilotCheck(
                "appliance-no-handler-errors",
                not handler_errors,
                "all carriage handlers completed cleanly"
                if not handler_errors
                else "; ".join(handler_errors[:3]),
            ),
        ],
        {
            "sessions": session_document,
            "upstream_record": _public_record(upstream_record),
            "handler_errors": handler_errors,
            "failure_plan": {
                "after_direct_exchanges": DEVICE_DATAGRAM_COUNT_PRIMARY,
                "action": "close direct listener + hard-reset direct "
                          "connections (SO_LINGER RST)",
            },
        },
    )
    return 0


def _boot_appliance() -> NetworkAppliance:
    """Boot the REAL NetworkAppliance with its own declared identity,
    an allow rule for session.create, and the honest topology view of
    its fabric (relay + devices)."""
    ids = node_ids()
    spec = PilotNodeSpec("appliance-1", "appliance")
    appliance_id = ids["appliance-1"]
    relay_id = ids["relay-1"]
    claims = (
        TopologyClaim(
            subject=make_link_subject(appliance_id, relay_id),
            reporter=appliance_id,
            claim_type=ClaimType.LINK_STATE,
            value="up",
            source_class=SourceClass.DIRECT_OBSERVATION,
            issued_at=PILOT_T0,
            freshness_until=PILOT_FRESH,
            sequence=1,
        ),
        TopologyClaim(
            subject=relay_id,
            reporter=appliance_id,
            claim_type=ClaimType.REACHABLE,
            value="true",
            source_class=SourceClass.DIRECT_OBSERVATION,
            issued_at=PILOT_T0,
            freshness_until=PILOT_FRESH,
            sequence=1,
        ),
    )
    config = AgentConfig(
        agent_label="appliance-1",
        identity=AgentIdentitySpec(
            profile_id=PILOT_PROFILE_ID,
            public_key=spec.key,
            created_at="2026-07-01T00:00:00Z",
        ),
        policy_rules=(
            PolicyRule(
                rule_id="appliance-1-allow-session-create",
                domain=PolicyDomain.IDENTITY,
                effect="allow",
                operation="session.create",
                subjects=(),
                priority=1,
                specificity=1,
            ),
        ),
        topology_claims=claims,
        link_metrics=(
            LinkMetricSpec(
                peer_node_id=relay_id,
                latency_ms=25,
                observed_at=PILOT_T0,
                freshness_until=PILOT_FRESH,
            ),
        ),
        offer_expiry_seconds=43200,
    )
    appliance = NetworkAppliance(
        config=config,
        clock=StepClock("2026-08-01T04:00:00Z", DEVICE_CLOCK_STEP_SECONDS),
        interface_source=appliance_interface_source(),
        hardware_source=appliance_hardware_source(),
        access_plan=appliance_access_plan(),
        upstream_mode=appliance_upstream_mode(),
    )
    result = appliance.run_appliance(
        appliance_commands(), boot_secret=spec.secret
    )
    if result.rejected or result.failed or result.status != "online":
        raise PilotError(
            PilotReasonCode.NODE_FAILED,
            "appliance boot/provision failed: status=%s rejected=%d "
            "failed=%d" % (result.status, result.rejected, result.failed),
        )
    return appliance


def _accept_once(listener: socket.socket) -> None:
    try:
        conn, _addr = listener.accept()
        close_quietly(conn)
    except OSError:
        pass


def _known_sessions(sessions: Any) -> List[str]:
    try:
        snapshot = sessions.snapshot()
        return sorted(snapshot.get("sessions", {}).keys())
    except Exception:  # noqa: BLE001 - operational metadata only
        return []


def _serve_listener(
    listener: socket.socket,
    state: Dict[str, Any],
    access_point: str,
    fail_after: Optional[int],
) -> None:
    while True:
        try:
            conn, _addr = listener.accept()
        except OSError:
            return
        if access_point == "direct":
            with state["lock"]:
                state["direct_conns"].add(conn)
        threading.Thread(
            target=_serve_connection,
            args=(conn, state, access_point, fail_after),
            daemon=True,
        ).start()


def _serve_connection(
    conn: socket.socket,
    state: Dict[str, Any],
    access_point: str,
    fail_after: Optional[int],
) -> None:
    appliance: NetworkAppliance = state["appliance"]
    journal: NodeJournal = state["journal"]
    runtime = appliance.runtime
    announce_label = "unknown"
    try:
        conn.settimeout(60.0)
        announce_label, announce_node_id, credential_mapping = (
            _exchange_announce(
                conn,
                self_label="appliance-1",
                self_node_id=runtime.node_id,
                self_credential_mapping=_active_credential_mapping(runtime),
                journal=journal,
                initiate=False,
            )
        )
        with state["lock"]:
            already = announce_label in state["announce_labels"]
            if not already:
                state["announce_labels"].add(announce_label)
        if not already:
            peer_spec = PARTICIPANT_NODE_BY_LABEL.get(announce_label)
            if peer_spec is None or peer_spec.role != "device":
                raise PilotError(
                    PilotReasonCode.NODE_INVALID,
                    "announcing node %r is not a declared pilot device"
                    % (announce_label,),
                )
            peer_identity = node_identity_for(announce_label)
            if peer_identity.node_id.text != announce_node_id:
                raise PilotError(
                    PilotReasonCode.NODE_INVALID,
                    "announce identity mismatch for %r" % (announce_label,),
                )
            with state["runtime_lock"]:
                runtime.register_peer(
                    peer_identity,
                    marshal.credential_record_from_mapping(credential_mapping),
                    peer_spec.secret,
                )
        journal.append(
            PilotEventKind.DISCOVERY_RECEIVED,
            {"peer_label": announce_label, "access_point": access_point},
        )

        while True:
            message_type, payload = _recv_pilot_envelope(conn)
            if message_type == "pilot.session.request":
                request = marshal.session_request_from_mapping(payload)
                journal.append(
                    PilotEventKind.SESSION_REQUESTED,
                    {
                        "session_id": request.session_id,
                        "peer": announce_label,
                        "carriage": access_point,
                    },
                )
                with state["runtime_lock"]:
                    accept = runtime.accept_session(request)
                _send_pilot_envelope(
                    conn,
                    "pilot.session.accept",
                    marshal.session_accept_to_mapping(accept),
                    sender=runtime.node_id,
                )
                journal.append(
                    PilotEventKind.SESSION_ACCEPTED,
                    {"session_id": accept.session_id, "peer": announce_label},
                )
            elif message_type == "pilot.session.confirm":
                confirm = marshal.session_confirm_from_mapping(payload)
                with state["runtime_lock"]:
                    runtime.finalize_session(confirm)
                _send_pilot_envelope(
                    conn,
                    "pilot.session.finalize-ack",
                    {"session_id": confirm.session_id},
                    sender=runtime.node_id,
                )
                journal.append(
                    PilotEventKind.SESSION_FINALIZED,
                    {"session_id": confirm.session_id, "peer": announce_label},
                )
            elif message_type == "pilot.datagram":
                artifact = marshal.datagram_from_mapping(payload)
                with state["runtime_lock"]:
                    echoed = runtime.receive_datagram(artifact)
                    response = runtime.send_datagram(
                        artifact.session_id, echoed
                    )
                _send_pilot_envelope(
                    conn,
                    "pilot.datagram.echo",
                    marshal.datagram_to_mapping(response),
                    sender=runtime.node_id,
                )
                journal.append(
                    PilotEventKind.DATAGRAM_RECEIVED,
                    {
                        "session_id": artifact.session_id,
                        "peer": announce_label,
                        "carriage": access_point,
                        "bytes": len(echoed),
                    },
                )
                if access_point == "direct" and fail_after is not None:
                    with state["lock"]:
                        state["direct_served"] += 1
                        served = state["direct_served"]
                        trigger = (
                            not state["failed_over"] and served >= fail_after
                        )
                        if trigger:
                            state["failed_over"] = True
                    if trigger:
                        # execute the declared failure plan NOW: the
                        # peer's next wire operation hits a dead path
                        _execute_failure_plan(state)
            elif message_type == "pilot.service.request":
                outcome = _run_service_request(appliance, payload)
                journal.append(
                    PilotEventKind.SERVICE_REQUESTED
                    if outcome.get("verdict") == "executed"
                    else PilotEventKind.SERVICE_REJECTED,
                    {
                        "service_ref": str(payload.get("service_ref", "")),
                        "peer": announce_label,
                        "verdict": str(outcome.get("verdict", "")),
                    },
                )
                _send_pilot_envelope(
                    conn,
                    "pilot.service.response",
                    outcome,
                    sender=runtime.node_id,
                )
            else:
                raise PilotError(
                    PilotReasonCode.WIRE_INVALID,
                    "appliance received unexpected message type %r"
                    % (message_type,),
                )
    except PilotError as error:
        # a closed carriage (the peer finished its script and
        # disconnected) is a NORMAL termination of the connection
        if error.reason != PilotReasonCode.WIRE_CLOSED:
            with state["lock"]:
                expected_death = (
                    access_point == "direct" and state["failed_over"]
                )
                if not expected_death:
                    state["handler_errors"].append(
                        "%s handler (%s): %s"
                        % (announce_label, access_point, error)
                    )
    except OSError as error:
        # carriage death is EXPECTED during the failover demonstration:
        # the failure plan hard-resets the direct connections while
        # their handlers are mid-read (the plan itself journals the
        # sabotage event synchronously, so the dying handler stays
        # silent).  Any OTHER failure is recorded honestly and
        # surfaced as a failed check.
        with state["lock"]:
            expected_death = (
                access_point == "direct" and state["failed_over"]
            )
            if not expected_death:
                state["handler_errors"].append(
                    "%s handler (%s): %s"
                    % (announce_label, access_point, error)
                )
    finally:
        close_quietly(conn)
        with state["lock"]:
            state["direct_conns"].discard(conn)


def _run_service_request(
    appliance: NetworkAppliance, payload: Mapping[str, Any]
) -> Dict[str, Any]:
    service_ref = str(payload.get("service_ref", ""))
    tenant_domain = str(payload.get("tenant_domain", ""))
    payload_hex = str(payload.get("payload_hex", ""))
    try:
        decision = marshal.policy_decision_from_mapping(
            payload.get("decision")
        )
    except PilotError as error:
        return {
            "verdict": "REJECTED",
            "reason": error.reason,
            "detail": error.detail,
            "response_digest": "",
        }
    result = appliance.run_appliance(
        (
            ApplianceCommand(
                ApplianceCommandKind.SERVICE_REQUEST,
                {
                    "service_ref": service_ref,
                    "tenant_domain": tenant_domain,
                    "payload_hex": payload_hex,
                    "decision": decision,
                },
            ),
        )
    )
    outcome = result.outcomes[-1] if result.outcomes else None
    if outcome is None:
        return {
            "verdict": "REJECTED",
            "reason": "pilot.no-outcome",
            "detail": "the appliance epoch produced no outcome",
            "response_digest": "",
        }
    response_digest = ""
    for token in str(outcome.detail or "").split():
        if token.startswith("response_digest="):
            response_digest = token.split("=", 1)[1]
    return {
        "verdict": str(outcome.verdict),
        "reason": str(outcome.reason or ""),
        "detail": str(outcome.detail or ""),
        "response_digest": response_digest,
    }


def _execute_failure_plan(state: Dict[str, Any]) -> None:
    """The declared failure plan: close the direct access listener and
    hard-reset every live direct connection (a REAL transport death)."""
    with state["lock"]:
        state["failed_over"] = True
        conns = tuple(state["direct_conns"])
        state["direct_conns"].clear()
    journal: NodeJournal = state["journal"]
    close_quietly(state["direct_listener"])
    for conn in conns:
        _hard_reset(conn)
    journal.append(
        PilotEventKind.SABOTAGE_INJECTED,
        {
            "action": "direct-access-path-failure",
            "mechanism": "direct listener closed + SO_LINGER(1,0) close "
                         "on the direct connections",
            "reset_connections": len(conns),
        },
    )


def _hard_reset(sock: socket.socket) -> None:
    try:
        sock.setsockopt(
            socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
        )
    except OSError:
        pass
    close_quietly(sock)


# ---------------------------------------------------------------------------
# The relay node (pure carriage; the WORK-039 discipline)
# ---------------------------------------------------------------------------


def run_relay_node(
    *,
    result_path: str,
    upstream_host: str,
    upstream_port: int,
) -> int:
    ids = node_ids()
    relay_id = ids["relay-1"]
    journal = NodeJournal(
        "relay-1", StepClock(PILOT_T0, DEVICE_CLOCK_STEP_SECONDS)
    )
    journal.append(
        PilotEventKind.NODE_BOOTED, {"label": "relay-1", "node_id": relay_id}
    )
    listener = open_listener("127.0.0.1", 0)
    port = socket_endpoint(listener)[1]
    counters = {"frames": 0, "bytes": 0}
    lock = threading.Lock()
    stop = threading.Event()

    def _relay_one_frame(
        source: socket.socket,
        target: socket.socket,
        direction: str,
    ) -> None:
        raw = recv_frame(source, timeout=60.0)
        receipt = validate_frame(raw, now=VALIDATION_NOW)
        if not receipt["accepted"]:
            journal.append(
                PilotEventKind.RELAY_RECEIPT,
                {
                    "direction": direction,
                    "accepted": False,
                    "classification": str(receipt["classification"]),
                },
            )
            raise PilotError(
                PilotReasonCode.WIRE_INVALID,
                "frame rejected by the production acceptance surface: %s"
                % (receipt["detail"],),
            )
        with lock:
            counters["frames"] += 1
            counters["bytes"] += len(raw)
        journal.append(
            PilotEventKind.RELAY_RECEIPT,
            {
                "direction": direction,
                "accepted": True,
                "classification": str(receipt["classification"]),
                "frame_bytes": len(raw),
            },
        )
        # VERBATIM forwarding: the same bytes, never re-encoded
        send_frame(target, raw)
        journal.append(
            PilotEventKind.RELAY_FORWARDED,
            {"direction": direction, "frame_bytes": len(raw)},
        )

    def _serve_connection(conn: socket.socket, upstream: socket.socket) -> None:
        # The carriage protocol is STRICTLY CAUSAL half-duplex: every
        # device frame is answered by exactly one appliance frame (and
        # the appliance never speaks first).  Relaying in strict
        # alternation is therefore not an assumption -- it is the
        # protocol's own causality, and it makes the relay journal a
        # deterministic record independent of thread scheduling.
        try:
            while True:
                _relay_one_frame(conn, upstream, "device-to-appliance")
                _relay_one_frame(upstream, conn, "appliance-to-device")
        except (PilotError, OSError):
            close_quietly(conn)
            close_quietly(upstream)
            return

    def _serve() -> None:
        while not stop.is_set():
            try:
                conn, _addr = listener.accept()
            except OSError:
                return
            try:
                upstream = connect_to(upstream_host, upstream_port)
            except PilotError:
                close_quietly(conn)
                continue
            _serve_connection(conn, upstream)

    serve_thread = threading.Thread(target=_serve, daemon=True)
    serve_thread.start()
    sys.stdout.write(json.dumps({"listen": port}) + "\n")
    sys.stdout.flush()

    try:
        while True:
            line = sys.stdin.readline()
            if not line:
                break
    except Exception:  # noqa: BLE001 - shutdown path
        pass
    stop.set()
    close_quietly(listener)
    journal.append(
        PilotEventKind.NODE_SHUTDOWN,
        {
            "label": "relay-1",
            "frames_transited": counters["frames"],
            "bytes_transited": counters["bytes"],
        },
    )
    _write_result(
        result_path,
        "relay-1",
        "relay",
        relay_id,
        journal,
        [
            PilotCheck(
                "relay-verbatim-carriage",
                counters["frames"] > 0,
                "%d frames transited verbatim (every frame a production "
                "FORWARD_OPAQUE receipt; bytes never re-encoded)"
                % (counters["frames"],),
            ),
        ],
        {
            "frames_transited": counters["frames"],
            "bytes_transited": counters["bytes"],
        },
    )
    return 0


# ---------------------------------------------------------------------------
# The device nodes
# ---------------------------------------------------------------------------


def run_device_node(
    *,
    label: str,
    result_path: str,
    direct_host: str,
    direct_port: int,
    relay_host: str,
    relay_port: int,
    relayed_only: bool,
    physical: bool = False,
) -> int:
    ids = node_ids()
    appliance_id = ids["appliance-1"]
    relay_id = ids["relay-1"]
    spec = PARTICIPANT_NODE_BY_LABEL[label]
    interface_source = device_interface_source(label)
    runtime = AgentRuntime(
        device_config(label, relay_id=relay_id, appliance_id=appliance_id),
        clock=StepClock(PILOT_T0, DEVICE_CLOCK_STEP_SECONDS),
        interface_source=interface_source,
    )
    runtime.boot(spec.secret)
    runtime.expose_interfaces()
    journal = NodeJournal(
        label, StepClock(PILOT_T0, DEVICE_CLOCK_STEP_SECONDS)
    )
    journal.append(
        PilotEventKind.NODE_BOOTED,
        {"label": label, "node_id": runtime.node_id},
    )
    checks: List[PilotCheck] = []
    observations: Dict[str, Any] = {}

    # -- carriage + the genuine identity exchange ----------------------
    if physical:
        # the physical participant: a REAL device (or, in rehearsal, a
        # host process honestly labeled as such) connecting DIRECTLY
        # to the appliance's access point over its real carriage
        primary_sock = connect_to(direct_host, direct_port)
        primary_carriage = "physical-access"
    elif relayed_only:
        primary_sock = connect_to(relay_host, relay_port)
        primary_carriage = "local-access"
    else:
        primary_sock = connect_to(direct_host, direct_port)
        primary_carriage = "primary-direct"
    peer_label, peer_node_id, credential_mapping = _exchange_announce(
        primary_sock,
        self_label=label,
        self_node_id=runtime.node_id,
        self_credential_mapping=_active_credential_mapping(runtime),
        journal=journal,
        initiate=True,
    )
    runtime.register_peer(
        node_identity_for(peer_label),
        marshal.credential_record_from_mapping(credential_mapping),
        PARTICIPANT_NODE_BY_LABEL[peer_label].secret,
    )
    if peer_node_id != appliance_id:
        raise PilotError(
            PilotReasonCode.NODE_INVALID,
            "the announced appliance identity does not match the declared "
            "topology",
        )

    # -- the genuine production session chain ---------------------------
    request = runtime.establish_session(appliance_id)
    _send_pilot_envelope(
        primary_sock,
        "pilot.session.request",
        marshal.session_request_to_mapping(request),
        sender=runtime.node_id,
    )
    message_type, payload = _recv_pilot_envelope(primary_sock)
    if message_type != "pilot.session.accept":
        raise PilotError(
            PilotReasonCode.WIRE_INVALID,
            "expected session accept, got %r" % (message_type,),
        )
    accept = marshal.session_accept_from_mapping(payload)
    journal.append(
        PilotEventKind.SESSION_REQUESTED,
        {"session_id": request.session_id, "peer": peer_label},
    )
    confirm = runtime.complete_session(accept)
    _send_pilot_envelope(
        primary_sock,
        "pilot.session.confirm",
        marshal.session_confirm_to_mapping(confirm),
        sender=runtime.node_id,
    )
    message_type, _payload = _recv_pilot_envelope(primary_sock)
    if message_type != "pilot.session.finalize-ack":
        raise PilotError(
            PilotReasonCode.WIRE_INVALID,
            "expected finalize ack, got %r" % (message_type,),
        )
    journal.append(
        PilotEventKind.SESSION_CONFIRMED,
        {"session_id": request.session_id},
    )
    binding = runtime.bind_session(request.session_id)
    journal.append(
        PilotEventKind.SESSION_BOUND,
        {
            "session_id": request.session_id,
            "adapter_id": binding["adapter_id"],
            "carriage": primary_carriage,
        },
    )

    session_id = request.session_id
    sessions = runtime.sessions

    def _session_digest() -> str:
        session = sessions.get(session_id)
        if session is None:
            raise PilotError(
                PilotReasonCode.NODE_FAILED,
                "session %r vanished from the device store" % (session_id,),
            )
        return _session_record_digest(session)

    if physical:
        # the physical participant (device-android): the participation
        # demonstration over its real carriage -- protected datagram
        # exchanges + a genuine local service invocation, plus the
        # REAL interface observation of the machine it runs on (on a
        # handset: its genuine wlan0/rmnet view through the
        # production LinuxInterfaceSource).
        for payload_bytes in PILOT_ECHO_PAYLOADS_LOCAL:
            _echo_exchange(
                runtime, journal, primary_sock, session_id,
                payload_bytes, "physical-access",
            )
        service_outcome = _invoke_local_service(
            runtime,
            journal,
            primary_sock,
            session_id,
            service_ref=pilot_echo_service_ref(),
            tenant_domain=PILOT_TENANT_DOMAIN,
            payload=PILOT_SERVICE_PAYLOAD,
        )
        session = sessions.get(session_id)
        interface_names = [
            snapshot.name for snapshot in interface_source.discover()
        ]
        checks.append(
            PilotCheck(
                "device-android-physical-session-established",
                session is not None and session.state == "ESTABLISHED",
                "the physical participant's session is %s over the "
                "physical-access carriage after %d datagram exchanges"
                % (
                    session.state if session else "?",
                    DEVICE_DATAGRAM_COUNT_LOCAL,
                ),
            )
        )
        checks.append(
            PilotCheck(
                "device-android-service-executed",
                service_outcome.get("verdict") == "executed"
                and service_outcome.get("response_matches") is True,
                "local service invocation verdict=%s response_matches=%s"
                % (
                    service_outcome.get("verdict", ""),
                    service_outcome.get("response_matches", False),
                ),
            )
        )
        checks.append(
            PilotCheck(
                "device-android-real-interfaces-observed",
                len(interface_names) > 0,
                "the participant's runtime observed its REAL interfaces "
                "through the production source: %s"
                % (", ".join(interface_names) or "none",),
            )
        )
        observations["session"] = {
            "session_id": session_id,
            "state": session.state if session else "?",
            "record_digest": _session_digest(),
        }
        observations["service"] = _public_record(service_outcome)
        observations["interfaces_observed"] = interface_names
        observations["carriage"] = {
            "kind": "physical-access",
            "note": (
                "direct connection to the appliance access point; on a "
                "handset this is the real USB (adb reverse) or Wi-Fi "
                "carriage, on a rehearsal host the loopback"
            ),
        }
        journal.append(
            PilotEventKind.DEMONSTRATION_COMPLETED,
            {"device": label, "demonstration": "physical-participation"},
        )
    elif relayed_only:
        # device-2: the local-access (relayed) demonstrations
        for payload_bytes in PILOT_ECHO_PAYLOADS_LOCAL:
            _echo_exchange(
                runtime, journal, primary_sock, session_id,
                payload_bytes, "local-access",
            )
        service_outcome = _invoke_local_service(
            runtime,
            journal,
            primary_sock,
            session_id,
            service_ref=pilot_echo_service_ref(),
            tenant_domain=PILOT_TENANT_DOMAIN,
            payload=PILOT_SERVICE_PAYLOAD,
        )
        session = sessions.get(session_id)
        checks.append(
            PilotCheck(
                "device-2-local-service-executed",
                service_outcome.get("verdict") == "executed"
                and service_outcome.get("response_matches") is True,
                "local service invocation verdict=%s response_matches=%s"
                % (
                    service_outcome.get("verdict", ""),
                    service_outcome.get("response_matches", False),
                ),
            )
        )
        checks.append(
            PilotCheck(
                "device-2-relayed-session-active",
                session is not None and session.state == "ESTABLISHED",
                "the relayed local-access session is %s after %d datagram "
                "exchanges and one service invocation"
                % (
                    session.state if session else "?",
                    DEVICE_DATAGRAM_COUNT_LOCAL,
                ),
            )
        )
        observations["session"] = {
            "session_id": session_id,
            "state": session.state if session else "?",
            "record_digest": _session_digest(),
        }
        observations["service"] = _public_record(service_outcome)
        journal.append(
            PilotEventKind.DEMONSTRATION_COMPLETED,
            {"device": label, "demonstration": "local-access"},
        )
    else:
        # device-1: direct path, multipath admission, real failover
        multipath = MultipathStore(sessions)
        add_primary = multipath.add_path(
            session_id,
            request.route_decision,
            event_instant=journal.now(),
            actor_reference="pilot:%s" % (label,),
            reason_code="pilot.primary-path-admission",
        )
        if not add_primary.ok:
            raise PilotError(
                PilotReasonCode.NODE_FAILED,
                "primary constituent admission failed: %s"
                % (add_primary.detail,),
            )
        secondary_decision = _secondary_route_decision(
            request,
            device_id=runtime.node_id,
            relay_id=relay_id,
            appliance_id=appliance_id,
        )
        add_secondary = multipath.add_path(
            session_id,
            secondary_decision,
            event_instant=journal.now(),
            actor_reference="pilot:%s" % (label,),
            reason_code="pilot.secondary-path-admission",
        )
        if not add_secondary.ok:
            raise PilotError(
                PilotReasonCode.NODE_FAILED,
                "secondary constituent admission failed: %s"
                % (add_secondary.detail,),
            )
        plan = multipath.get_plan(session_id)
        if plan is None:
            raise PilotError(
                PilotReasonCode.NODE_FAILED, "no multipath plan after adds"
            )
        journal.append(
            PilotEventKind.ROUTE_REEVALUATED,
            {
                "session_id": session_id,
                "constituents": len(plan.path_ids()),
                "primary": "primary-direct",
                "secondary": "secondary-relay",
            },
        )
        digest_before_failure = _session_digest()

        for payload_bytes in PILOT_ECHO_PAYLOADS_PRIMARY:
            _echo_exchange(
                runtime, journal, primary_sock, session_id,
                payload_bytes, "primary-direct",
            )
        failover = _failover_to_secondary(
            runtime,
            journal,
            multipath,
            session_id,
            request.route_decision.decision_id,
            primary_sock,
            relay_host,
            relay_port,
            label,
            direct_host,
            direct_port,
            PILOT_ECHO_PAYLOADS_SECONDARY,
        )
        digest_after_failover = _session_digest()
        session_record_stable = (
            digest_before_failure == digest_after_failover
        )
        session = sessions.get(session_id)
        final_plan = multipath.get_plan(session_id)
        primary_failed = _plan_has_status(final_plan, "FAILED", 1)
        secondary_active = _plan_has_status(final_plan, "ACTIVE", 1)
        checks.append(
            PilotCheck(
                "device-1-failover-observed-real-loss",
                failover["observed_real_loss"]
                and not failover["reprobe_reachable"],
                "the primary carriage failed with a real socket error "
                "(class=%s); the dead access point re-probed "
                "reachable=%s"
                % (failover["error_class"], failover["reprobe_reachable"]),
            )
        )
        checks.append(
            PilotCheck(
                "device-1-session-continuity",
                session_record_stable
                and session is not None
                and session.state == "ESTABLISHED"
                and primary_failed
                and secondary_active,
                "session state %s; record digest %s before/after the "
                "failover; constituent statuses [%s]"
                % (
                    session.state if session else "?",
                    "stable" if session_record_stable else "CHANGED",
                    _plan_statuses(final_plan),
                ),
            )
        )
        observations["session"] = {
            "session_id": session_id,
            "state": session.state if session else "?",
            "record_digest": digest_after_failover,
            "record_digest_before_failure": digest_before_failure,
        }
        observations["failover"] = failover
        observations["multipath_plan"] = _plan_document(final_plan)
        journal.append(
            PilotEventKind.DEMONSTRATION_COMPLETED,
            {"device": label, "demonstration": "failover"},
        )
    # release the adapter binding through the production unbind
    # surface (shutdown requires no live session bindings)
    _release_session_binding(runtime, session_id, binding["binding_id"])
    runtime.shutdown()
    journal.append(PilotEventKind.NODE_SHUTDOWN, {"label": label})
    _write_result(
        result_path,
        label,
        "device",
        runtime.node_id,
        journal,
        checks,
        observations,
    )
    return 0


def _release_session_binding(
    runtime: AgentRuntime, session_id: str, binding_id: str
) -> None:
    """Unbind the session's adapter binding through the production
    unbind surface so shutdown sees no live bindings."""
    del session_id
    unbound = runtime.adapters_runtime.unbind_session(
        binding_id, now=runtime._now()
    )
    if not unbound.ok:
        raise PilotError(
            PilotReasonCode.NODE_FAILED,
            "session adapter unbind failed: %s" % (unbound.detail,),
        )


def _plan_statuses(plan: Any) -> str:
    if plan is None:
        return "?"
    entries = []
    for path_id in plan.path_ids():
        entry = plan.get(path_id)
        entries.append(
            "%s=%s" % (path_id[:16], entry.status if entry else "?")
        )
    return ",".join(entries)


def _plan_has_status(plan: Any, status: str, expect: int) -> bool:
    if plan is None:
        return False
    count = 0
    for path_id in plan.path_ids():
        entry = plan.get(path_id)
        if entry is not None and entry.status == status:
            count += 1
    return count == expect


def _plan_document(plan: Any) -> Dict[str, Any]:
    if plan is None:
        return {}
    return {
        "plan_id": plan.plan_id,
        "constituents": [
            {
                "path_id": path_id,
                "status": (
                    plan.get(path_id).status if plan.get(path_id) else "?"
                ),
                "route_decision_id": (
                    plan.get(path_id).route_decision_id
                    if plan.get(path_id)
                    else ""
                ),
            }
            for path_id in plan.path_ids()
        ],
        "plan_digest": sha256_hex_of_bytes(
            canonical_json_bytes(plan.content_dict())
        ),
    }


def _echo_exchange(
    runtime: AgentRuntime,
    journal: NodeJournal,
    sock: socket.socket,
    session_id: str,
    payload: bytes,
    carriage: str,
) -> None:
    artifact = runtime.send_datagram(session_id, payload)
    _send_pilot_envelope(
        sock,
        "pilot.datagram",
        marshal.datagram_to_mapping(artifact),
        sender=runtime.node_id,
    )
    journal.append(
        PilotEventKind.DATAGRAM_SENT,
        {
            "session_id": session_id,
            "carriage": carriage,
            "bytes": len(payload),
        },
    )
    message_type, response_payload = _recv_pilot_envelope(sock)
    if message_type != "pilot.datagram.echo":
        raise PilotError(
            PilotReasonCode.WIRE_INVALID,
            "expected datagram echo, got %r" % (message_type,),
        )
    echo_artifact = marshal.datagram_from_mapping(response_payload)
    echoed = runtime.receive_datagram(echo_artifact)
    if echoed != payload:
        raise PilotError(
            PilotReasonCode.NODE_FAILED,
            "echo payload mismatch (%d vs %d bytes)"
            % (len(echoed), len(payload)),
        )
    journal.append(
        PilotEventKind.DATAGRAM_RECEIVED,
        {
            "session_id": session_id,
            "carriage": carriage,
            "bytes": len(echoed),
        },
    )


def _invoke_local_service(
    runtime: AgentRuntime,
    journal: NodeJournal,
    sock: socket.socket,
    session_id: str,
    *,
    service_ref: str,
    tenant_domain: str,
    payload: bytes,
) -> Dict[str, Any]:
    decision = _invocation_decision(
        service_ref,
        session_id=session_id,
        caller_node_id=runtime.node_id,
        tenant_domain=tenant_domain,
    )
    journal.append(
        PilotEventKind.SERVICE_REQUESTED,
        {"service_ref": service_ref, "session_id": session_id},
    )
    _send_pilot_envelope(
        sock,
        "pilot.service.request",
        {
            "service_ref": service_ref,
            "tenant_domain": tenant_domain,
            "payload_hex": payload.hex(),
            "decision": marshal.policy_decision_to_mapping(decision),
        },
        sender=runtime.node_id,
    )
    message_type, response_payload = _recv_pilot_envelope(sock)
    if message_type != "pilot.service.response":
        raise PilotError(
            PilotReasonCode.WIRE_INVALID,
            "expected service response, got %r" % (message_type,),
        )
    verdict = str(response_payload.get("verdict", ""))
    response_digest = str(response_payload.get("response_digest", ""))
    # the appliance's outcome carries the RESPONSE DIGEST (never raw
    # content): verify the executed response digest equals the digest
    # of our request payload (the reference execution is the echo
    # transform, so a match is end-to-end proof of genuine execution)
    import hashlib

    request_digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    response_matches = (
        verdict == "executed" and response_digest == request_digest
    )
    journal.append(
        PilotEventKind.SERVICE_EXECUTED
        if verdict == "executed"
        else PilotEventKind.SERVICE_REJECTED,
        {"service_ref": service_ref, "verdict": verdict},
    )
    return {
        "verdict": verdict,
        "reason": str(response_payload.get("reason", "")),
        "response_digest": response_digest,
        "request_digest": request_digest,
        "response_matches": response_matches,
    }


def _invocation_decision(
    service_ref: str,
    *,
    session_id: str,
    caller_node_id: str,
    tenant_domain: str,
):
    """A GENUINE born-bound WORK-010 invocation decision (the accepted
    WORK-036 battery recipe, evaluated by the production engine)."""
    descriptor = {
        "kind": "adcos.service-invocation",
        "operation": Operation.SERVICE_INVOKE,
        "service_ref": service_ref,
        "session_id": session_id,
        "caller_node_id": caller_node_id,
        "tenant_domain": tenant_domain,
    }
    context = PolicyContext(
        operation=Operation.SERVICE_INVOKE,
        requester_node_id=caller_node_id,
        evaluation_instant=_INVOCATION_INSTANT,
        federation_domain=tenant_domain,
        resource_refs=(service_ref,),
        extensions=(descriptor,),
    )
    policy_set = PolicySet(
        set_id="ps-pilot-invocation", version=1,
        rules=(
            PolicyRule(
                rule_id="svc-allow",
                domain=PolicyDomain.SERVICE,
                effect="allow",
                operation=Operation.SERVICE_INVOKE,
            ),
        ),
        issuer_node_id=caller_node_id,
        valid_from="2024-01-01T00:00:00Z",
        valid_until="2028-01-01T00:00:00Z",
    )
    result = PolicyEngine().evaluate(policy_set, context)
    if not result.ok or result.decision is None:
        raise PilotError(
            PilotReasonCode.NODE_FAILED,
            "invocation decision rejected: %s" % (result.detail,),
        )
    return result.decision


def _secondary_route_decision(
    request: Any,
    *,
    device_id: str,
    relay_id: str,
    appliance_id: str,
):
    """The REAL WORK-011 route decision for the relayed path, produced
    EXTERNALLY by the production engine over the device's post-failure
    topology view (the direct adjacency absent), under the SAME
    accepted policy decision that created the session (the WORK-012
    reconnect binding contract)."""
    graph = TopologyGraph()
    for pair in ((device_id, relay_id), (relay_id, appliance_id)):
        graph.merge(
            TopologyClaim(
                subject=make_link_subject(pair[0], pair[1]),
                reporter=device_id,
                claim_type=ClaimType.LINK_STATE,
                value="up",
                source_class=SourceClass.SELF_ADVERTISEMENT,
                issued_at=PILOT_T0,
                freshness_until=PILOT_FRESH,
                sequence=1,
            )
        )
    for node in (relay_id, appliance_id):
        graph.merge(
            TopologyClaim(
                subject=node,
                reporter=device_id,
                claim_type=ClaimType.REACHABLE,
                value="true",
                source_class=SourceClass.DIRECT_OBSERVATION,
                issued_at=PILOT_T0,
                freshness_until=PILOT_FRESH,
                sequence=1,
            )
        )
    metrics: Dict[str, LinkMetrics] = {}
    for pair in ((device_id, relay_id), (relay_id, appliance_id)):
        metrics[make_link_subject(pair[0], pair[1])] = LinkMetrics(
            latency_ms=25, loss_basis_points=0, capacity_bps=1_000_000,
            energy_cost_millijoules=100, confidence_basis_points=10_000,
            observed_at=PILOT_T0, freshness_until=PILOT_FRESH,
        )
    context = RoutingContext(
        source_node_id=device_id,
        destination_node_id=appliance_id,
        topology=graph,
        resources=ResourceStore(),
        # coherent input generations: the SAME instant the accepted
        # policy decision was evaluated at (the engine rejects route
        # computations that predate their own policy decision)
        evaluation_instant=request.policy_decision.evaluation_instant,
        policy_decision=request.policy_decision,
        link_metrics=metrics,
    )
    result = RoutingEngine().evaluate(context)
    if result.decision is None or result.decision.selected is None:
        raise PilotError(
            PilotReasonCode.NODE_FAILED,
            "the secondary route decision was not selected: %s"
            % (result.detail,),
        )
    return result.decision


def _failover_to_secondary(
    runtime: AgentRuntime,
    journal: NodeJournal,
    multipath: MultipathStore,
    session_id: str,
    primary_route_decision_id: str,
    dead_sock: socket.socket,
    relay_host: str,
    relay_port: int,
    device_label: str,
    direct_host: str,
    direct_port: int,
    secondary_payloads: Tuple[bytes, ...],
) -> Dict[str, Any]:
    """Observe the REAL primary-path death, fail the primary
    constituent through the multipath authority, re-establish carriage
    through the relay, and complete the remaining exchanges on the
    SAME logical session."""
    plan = multipath.get_plan(session_id)
    if plan is None:
        raise PilotError(
            PilotReasonCode.NODE_FAILED, "the multipath plan vanished"
        )
    primary_path_id = ""
    secondary_path_id = ""
    for path_id in plan.path_ids():
        entry = plan.get(path_id)
        if entry is None:
            continue
        if entry.route_decision_id == primary_route_decision_id:
            primary_path_id = path_id
        else:
            secondary_path_id = path_id
    if not primary_path_id or not secondary_path_id:
        raise PilotError(
            PilotReasonCode.NODE_FAILED,
            "could not identify the primary/secondary constituents "
            "(primary=%r secondary=%r)"
            % (primary_path_id[:24], secondary_path_id[:24]),
        )

    raw_error = ""
    error_class = ""
    observed = False
    artifact = None
    try:
        artifact = runtime.send_datagram(session_id, secondary_payloads[0])
        _send_pilot_envelope(
            dead_sock,
            "pilot.datagram",
            marshal.datagram_to_mapping(artifact),
            sender=runtime.node_id,
        )
        # the write may have been accepted into a dying socket; the
        # response read must fail
        _recv_pilot_envelope(dead_sock, timeout=10.0)
        raise PilotError(
            PilotReasonCode.CONDUCTOR_FAILED,
            "the primary path did not fail as declared (the failure plan "
            "did not execute)",
        )
    except PilotError as error:
        if error.reason == PilotReasonCode.CONDUCTOR_FAILED:
            raise
        observed = True
        raw_error = "%s: %s" % (type(error).__name__, error)
        error_class = type(error).__name__
    except OSError as error:
        observed = True
        raw_error = "%s: %s" % (type(error).__name__, error)
        error_class = type(error).__name__
    journal.append(
        PilotEventKind.LINK_LOSS_OBSERVED,
        {
            "path": "primary-direct",
            "error_class": error_class,
            "stage": "carriage-send",
        },
    )

    # the honest re-probe of the dead access point (a real TCP probe)
    from .platform import probe_tcp_path

    reachable, _detail, _elapsed = probe_tcp_path(
        direct_host, direct_port, timeout=3.0
    )
    journal.append(
        PilotEventKind.PROBE_REPORTED,
        {"target": "direct-access-point", "reachable": reachable},
    )

    failed = multipath.change_path_status(
        session_id,
        primary_path_id,
        PathStatus.FAILED,
        event_instant=journal.now(),
        actor_reference="pilot:%s" % (device_label,),
        reason_code="pilot.primary-path-loss",
    )
    if not failed.ok:
        raise PilotError(
            PilotReasonCode.NODE_FAILED,
            "primary constituent failure transition rejected: %s"
            % (failed.detail,),
        )
    journal.append(
        PilotEventKind.PATH_STATUS_CHANGED,
        {
            "session_id": session_id,
            "path": primary_path_id,
            "from": "ACTIVE",
            "to": "FAILED",
        },
    )
    journal.append(
        PilotEventKind.SESSION_RECONNECTING,
        {"session_id": session_id, "via": "secondary-relay"},
    )

    secondary_sock = connect_to(relay_host, relay_port)
    _exchange_announce(
        secondary_sock,
        self_label=device_label,
        self_node_id=runtime.node_id,
        self_credential_mapping=_active_credential_mapping(runtime),
        journal=journal,
        initiate=True,
    )
    journal.append(
        PilotEventKind.SESSION_REBOUND,
        {"session_id": session_id, "carriage": "secondary-relay"},
    )

    # the SAME logical session continues over the secondary carriage;
    # the first datagram re-sends the ALREADY-PROTECTED artifact that
    # hit the dead path (same session, same protection, new carriage)
    for index, payload_bytes in enumerate(secondary_payloads):
        if index == 0 and artifact is not None:
            _send_pilot_envelope(
                secondary_sock,
                "pilot.datagram",
                marshal.datagram_to_mapping(artifact),
                sender=runtime.node_id,
            )
            journal.append(
                PilotEventKind.DATAGRAM_SENT,
                {
                    "session_id": session_id,
                    "carriage": "secondary-relay",
                    "bytes": len(payload_bytes),
                },
            )
            message_type, response_payload = _recv_pilot_envelope(
                secondary_sock
            )
            if message_type != "pilot.datagram.echo":
                raise PilotError(
                    PilotReasonCode.WIRE_INVALID,
                    "expected datagram echo over the secondary carriage, "
                    "got %r" % (message_type,),
                )
            echo_artifact = marshal.datagram_from_mapping(response_payload)
            echoed = runtime.receive_datagram(echo_artifact)
            if echoed != payload_bytes:
                raise PilotError(
                    PilotReasonCode.NODE_FAILED,
                    "secondary-carriage echo mismatch",
                )
            journal.append(
                PilotEventKind.DATAGRAM_RECEIVED,
                {
                    "session_id": session_id,
                    "carriage": "secondary-relay",
                    "bytes": len(echoed),
                },
            )
        else:
            _echo_exchange(
                runtime, journal, secondary_sock, session_id,
                payload_bytes, "secondary-relay",
            )
    journal.append(
        PilotEventKind.FAILOVER_COMPLETED,
        {
            "session_id": session_id,
            "failed_path": primary_path_id,
            "active_path": secondary_path_id,
        },
    )
    return {
        "observed_real_loss": observed,
        "error_class": error_class,
        "raw_error": raw_error,
        "reprobe_reachable": reachable,
        "failed_path_id": primary_path_id,
        "active_path_id": secondary_path_id,
    }


def _session_record_digest(session: Any) -> str:
    """The digest over the session's IDENTITY-bearing record content:
    id, immutable creation binding, state, creation instant, and the
    CURRENT authoritative route reference.

    The event-log head (``last_event_sequence``/``last_event_instant``)
    is deliberately EXCLUDED: the append-only event log grows with
    every legal transition (multipath constituents, ...), and the
    continuity proof is exactly that the record itself never changes
    while its log grows through the authorities' own events.
    """
    document = session.to_dict()
    record = {
        key: value
        for key, value in document.items()
        if key
        not in ("last_event_sequence", "last_event_instant", "extensions")
    }
    return sha256_hex_of_bytes(canonical_json_bytes(record))


# ---------------------------------------------------------------------------
# The conductor
# ---------------------------------------------------------------------------


_NODE_ORDER = ("appliance-1", "relay-1", "device-1", "device-2")


def run_pilot_deployment(
    *,
    rehearsal: bool = True,
    live_probes: bool = False,
    workspace: Optional[str] = None,
) -> PilotRunResult:
    """Spawn the four real node processes, coordinate them, collect the
    honest result documents, and assemble the journaled run."""
    topology = validate_topology()
    root = Path(workspace or tempfile.mkdtemp(prefix="adcos-pilot-"))
    root.mkdir(parents=True, exist_ok=True)
    repo_root = Path(__file__).resolve().parents[1]

    node_env = dict(os.environ)
    node_env["PYTHONHASHSEED"] = "0"

    def _spawn(args: List[str]) -> subprocess.Popen:
        return subprocess.Popen(  # noqa: S603 - our own module
            [sys.executable] + args,
            cwd=str(repo_root),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=node_env,
        )

    started = time.monotonic()
    appliance_result = root / "appliance-1.json"
    appliance_proc = _spawn(
        [
            "-m", "pilot.node", "--role", "appliance",
            "--result-file", str(appliance_result),
            "--rehearsal" if rehearsal else "--live",
        ]
    )
    ports = _read_ready_ports(appliance_proc)
    direct_port = ports["direct"]
    relay_access_port = ports["relay"]

    relay_result = root / "relay-1.json"
    relay_proc = _spawn(
        [
            "-m", "pilot.node", "--role", "relay",
            "--result-file", str(relay_result),
            "--upstream-host", "127.0.0.1",
            "--upstream-port", str(relay_access_port),
        ]
    )
    relay_listen_port = _read_ready_ports(relay_proc)["listen"]

    problems: List[str] = []
    device_results: List[Path] = []
    device_procs: List[subprocess.Popen] = []
    # The devices run IN DECLARED ORDER (device-1, then device-2): the
    # pilot's demonstrations are sequential by design -- each device's
    # genuine chain is fully real, and the deployment journal stays a
    # deterministic record of what the deployment did (the concurrent
    # carriage races of an interleaved drive would make the JOURNAL
    # order a thread-scheduling artifact, not a deployment fact).
    for dev_label, relayed_only in (("device-1", False), ("device-2", True)):
        result_path = root / ("%s.json" % (dev_label,))
        device_results.append(result_path)
        proc = _spawn(
            [
                "-m", "pilot.node", "--role", "device",
                "--label", dev_label,
                "--result-file", str(result_path),
                "--direct-host", "127.0.0.1",
                "--direct-port", str(direct_port),
                "--relay-host", "127.0.0.1",
                "--relay-port", str(relay_listen_port),
            ]
            + (["--relayed-only"] if relayed_only else [])
        )
        device_procs.append(proc)
        try:
            proc.wait(timeout=_NODE_EXIT_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            problems.append("device %s did not exit" % (dev_label,))
            proc.kill()
            proc.wait(timeout=10.0)
    # the devices are done: release the servers
    for proc in (relay_proc, appliance_proc):
        try:
            if proc.stdin is not None:
                proc.stdin.close()
        except OSError:
            pass
    for proc, node_label in (
        (relay_proc, "relay-1"),
        (appliance_proc, "appliance-1"),
    ):
        try:
            proc.wait(timeout=_NODE_EXIT_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            problems.append("%s did not exit" % (node_label,))
            proc.kill()
            proc.wait(timeout=10.0)

    documents: Dict[str, Any] = {}
    for result_path, node_label in zip(
        [appliance_result, relay_result] + device_results,
        _NODE_ORDER,
    ):
        try:
            documents[node_label] = json.loads(
                result_path.read_text(encoding="utf-8")
            )
        except Exception as error:  # noqa: BLE001 - conductor honesty
            problems.append(
                "%s result unreadable (%s)"
                % (node_label, type(error).__name__)
            )
    if problems:
        for proc in device_procs + [relay_proc, appliance_proc]:
            if proc.poll() is None:
                proc.kill()
        raise PilotError(
            PilotReasonCode.CONDUCTOR_FAILED, "; ".join(problems)
        )

    events: List[PilotEvent] = []
    checks: List[PilotCheck] = []
    for node_label in _NODE_ORDER:
        document = documents[node_label]
        for event_document in document.get("events", []):
            events.append(
                PilotEvent(
                    sequence=int(event_document["sequence"]),
                    kind=str(event_document["kind"]),
                    at_instant=str(event_document["at_instant"]),
                    payload=dict(event_document.get("payload") or {}),
                )
            )
        for check in document.get("checks", []):
            checks.append(
                PilotCheck(
                    label=str(check["label"]),
                    ok=bool(check["ok"]),
                    detail=str(check["detail"]),
                )
            )
    merged_events = [
        PilotEvent(
            sequence=index + 1,
            kind=event.kind,
            at_instant=event.at_instant,
            payload=event.payload,
        )
        for index, event in enumerate(events)
    ]

    from .evidence import build_criterion_outcomes, build_execution_records

    executions = build_execution_records(documents, operational_extra={
        "commit_sha": _git_commit_sha(repo_root),
    })
    outcomes = build_criterion_outcomes(documents, checks)
    checks.append(
        PilotCheck(
            "deployment-four-real-processes",
            all(
                documents.get(node_label, {}).get("node_id")
                for node_label in _NODE_ORDER
            ),
            "four real OS processes completed and reported "
            "(appliance, relay, device-1, device-2)",
        )
    )
    operational: Dict[str, Any] = {
        "topology": topology,
        "rehearsal": rehearsal,
        "live_probes": live_probes,
        "workspace": str(root),
        "node_documents": documents,
        "elapsed_ms": round((time.monotonic() - started) * 1000.0, 3),
        "commit_sha": _git_commit_sha(repo_root),
    }
    return PilotRunResult(
        run_label="pilot-deployment-rehearsal"
        if rehearsal
        else "pilot-deployment-live",
        clock_kind="injected-step-clock",
        events=tuple(merged_events),
        checks=tuple(checks),
        executions=tuple(executions),
        criterion_outcomes=tuple(outcomes),
        operational=operational,
    )


def _read_ready_ports(proc: subprocess.Popen) -> Dict[str, int]:
    assert proc.stdout is not None
    line = proc.stdout.readline()
    try:
        document = json.loads(line)
    except ValueError as error:
        raise PilotError(
            PilotReasonCode.CONDUCTOR_FAILED,
            "node READY line unreadable (%r)" % (line[:120],),
        ) from error
    return {key: int(value) for key, value in document.items()}


def _write_result(
    result_path: str,
    label: str,
    role: str,
    node_id: str,
    journal: NodeJournal,
    checks: List[PilotCheck],
    observations: Dict[str, Any],
) -> None:
    document = {
        "label": label,
        "role": role,
        "node_id": node_id,
        "events": [event.content_dict() for event in journal.events()],
        "checks": [check.content_dict() for check in checks],
        "observations": observations,
    }
    Path(result_path).write_text(
        json.dumps(document, sort_keys=True, indent=1), encoding="utf-8"
    )


def _public_record(record: Mapping[str, Any]) -> Dict[str, Any]:
    """Strip non-deterministic fields (timings) from an operational
    record before it enters the result document."""
    return {
        key: value
        for key, value in record.items()
        if key not in ("elapsed_ms",)
    }


def _git_commit_sha(repo_root: Path) -> str:
    try:
        completed = subprocess.run(  # noqa: S603 - read-only git query
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, cwd=str(repo_root), timeout=10,
        )
        if completed.returncode == 0:
            return completed.stdout.strip()
    except Exception:  # noqa: BLE001 - operational metadata only
        pass
    return "unknown"
