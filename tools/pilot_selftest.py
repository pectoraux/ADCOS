#!/usr/bin/env python3
"""WORK-040 pilot deployment battery.

The battery proves the pilot family's own discipline:

- frozen vocabularies and value records (content-derived identities);
- the deployment-plane marshalling round trips + tamper fail-closed;
- the wire framing negatives over real loopback TCP;
- the platform reconnaissance honesty (probes, lab gate, runbook);
- the FULL multi-process deployment rehearsal: four real OS processes,
  real TCP carriages, real production chains, the declared failure
  plan, and the honest criterion outcomes -- with every deployment
  check passing;
- determinism: independent rehearsals reproduce the run digest
  byte-identically, including across hash seeds;
- the structural anti-promotion rules (the 5G criterion can never be
  closed by software/operational evidence, in the model AND at the
  evidence surface);
- the WORK-040 correction cycle's physical participation path
  (cases 21-25) and its second cycle's physical HANDOVER experiment
  + the Android-agent manifest interface (cases 26-28): the handover
  rehearsal runs THREE real processes (appliance with the declared
  failure plan, relay-1, the device-android node in --physical
  --handover mode) and proves the full transition chain honestly
  (real socket death, production re-bind, SAME logical session,
  both-carriage receiver corroboration); the frozen handover evidence
  template is asserted exactly; the anti-promotion negatives never
  promote a rehearsal or LTE to a physical PASS; the Android-agent
  observation manifest loads, validates, binds by file SHA-256, and
  cross-corroborates (serial + post-technology agreement) -- never
  duplicating the Android platform authority in Python;
- no second authority, no secrets in evidence, frozen API, frozen
  spec, the sanctioned PR-delta shape, and the CI wiring.
"""

from __future__ import annotations

import json
import os
import py_compile
import subprocess  # noqa: S404 - deterministic child processes of this repo's own tools
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from pilot import (  # noqa: E402
    CriterionId,
    CriterionOutcome,
    CriterionStatus,
    ExecutionRecord,
    PilotCheck,
    PilotError,
    PilotEvent,
    PilotEventKind,
    PilotEvidenceClass,
    PilotReasonCode,
    PilotRunResult,
    PILOT_CRITERIA,
    PILOT_HARNESS_VERSION,
    attach_evidence,
    criterion_outcome_for_5g,
    evidence as pilot_evidence,
    marshal as pilot_marshal,
    pilot_event_list_digest,
    run_pilot_deployment,
    sha256_hex_of_bytes,
)
from pilot import deployment as pilot_deployment  # noqa: E402
from pilot import physical as pilot_physical  # noqa: E402
from pilot import fabric as pilot_fabric  # noqa: E402
from pilot import platform as pilot_platform  # noqa: E402
from pilot import topology as pilot_topology  # noqa: E402
from pilot import wire as pilot_wire  # noqa: E402
from protocol import canonical_json_bytes  # noqa: E402

Result = Tuple[str, bool, str]

_FAMILY_FILES = sorted((REPO_ROOT / "pilot").rglob("*.py"))

_ARCHITECT_HANDOFF = "spec/prompts/WORK-040.md"

#: The full expected battery set wired into CI (41 prior tools + this one).
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
    "appliance_selftest.py", "oran_selftest.py", "imt_selftest.py",
    "scale_selftest.py", "pilot_selftest.py",
]

_EXPECTED_EVENT_KINDS = 36
_EXPECTED_REASON_CODES = 14
# 34 at delivery; +1 for the correction cycle's `physical` submodule
_EXPECTED_EXPORTS = 35

_RUN_CACHE: dict = {}


def ok(name: str, detail: str) -> Result:
    return (name, True, detail)


def fail(name: str, detail: str) -> Result:
    return (name, False, detail)


# ---------------------------------------------------------------------------
# Shared world: the full deployment rehearsal (run once, reused)
# ---------------------------------------------------------------------------


def _full_run(label: str) -> PilotRunResult:
    if label not in _RUN_CACHE:
        _RUN_CACHE[label] = run_pilot_deployment(
            rehearsal=True,
            workspace=tempfile.mkdtemp(prefix="adcos-pilot-battery-"),
        )
    return _RUN_CACHE[label]


# ---------------------------------------------------------------------------
# 01-02: frozen vocabularies and value records
# ---------------------------------------------------------------------------


def case_01_frozen_vocabularies(results: List[Result]) -> None:
    name = "case_01_frozen_vocabularies"
    problems: List[str] = []
    if len(PilotEventKind.values()) != _EXPECTED_EVENT_KINDS:
        problems.append(
            "event kinds %d != %d"
            % (len(PilotEventKind.values()), _EXPECTED_EVENT_KINDS)
        )
    if len(PilotReasonCode.values()) != _EXPECTED_REASON_CODES:
        problems.append(
            "reason codes %d != %d"
            % (len(PilotReasonCode.values()), _EXPECTED_REASON_CODES)
        )
    if len(CriterionId.values()) != 6:
        problems.append("criteria %d != 6" % (len(CriterionId.values()),))
    if len(CriterionStatus.values()) != 4:
        problems.append("statuses %d != 4" % (len(CriterionStatus.values()),))
    if len(PilotEvidenceClass.values()) != 3:
        problems.append(
            "evidence classes %d != 3" % (len(PilotEvidenceClass.values()),)
        )
    if len(PILOT_CRITERIA) != 6:
        problems.append("criteria statements %d != 6" % (len(PILOT_CRITERIA),))
    import pilot

    if len(pilot.__all__) != _EXPECTED_EXPORTS:
        problems.append(
            "package exports %d != %d" % (len(pilot.__all__), _EXPECTED_EXPORTS)
        )
    if not PILOT_HARNESS_VERSION.startswith("pilot-harness/1."):
        problems.append("harness version %r" % (PILOT_HARNESS_VERSION,))
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name,
        "%d event kinds, %d reason codes, 6 criteria, 4 statuses, "
        "3 evidence classes, %d exports"
        % (
            _EXPECTED_EVENT_KINDS, _EXPECTED_REASON_CODES,
            _EXPECTED_EXPORTS,
        ),
    ))


def case_02_value_records(results: List[Result]) -> None:
    name = "case_02_value_records"
    problems: List[str] = []
    event = PilotEvent(
        sequence=1,
        kind=PilotEventKind.NODE_BOOTED,
        at_instant="2026-08-01T00:00:00Z",
        payload={"label": "device-1"},
    )
    if not event.event_id().startswith("sha256:"):
        problems.append("event id is not a sha256 fingerprint")
    rebuilt = PilotEvent(
        sequence=1,
        kind=PilotEventKind.NODE_BOOTED,
        at_instant="2026-08-01T00:00:00Z",
        payload={"label": "device-1"},
    )
    if rebuilt.event_id() != event.event_id():
        problems.append("event ids are not content-derived")
    tampered = PilotEvent(
        sequence=1,
        kind=PilotEventKind.NODE_BOOTED,
        at_instant="2026-08-01T00:00:00Z",
        payload={"label": "device-2"},
    )
    if tampered.event_id() == event.event_id():
        problems.append("distinct content produced identical ids")
    try:
        PilotEvent(
            sequence=1, kind="pilot.not-a-kind",
            at_instant="2026-08-01T00:00:00Z", payload={},
        )
        problems.append("unknown event kind accepted")
    except PilotError as error:
        if error.reason != PilotReasonCode.EVIDENCE_INVALID:
            problems.append("unknown kind reason %r" % (error.reason,))
    digest_a = pilot_event_list_digest((event, tampered))
    digest_b = pilot_event_list_digest((event, tampered))
    if digest_a != digest_b:
        problems.append("event-list digest not deterministic")
    # non-PASS outcomes must state requirements
    try:
        CriterionOutcome(
            criterion=CriterionId.PATH_5G,
            status=CriterionStatus.NOT_TESTABLE,
            evidence_class=PilotEvidenceClass.SOFTWARE,
            statement="x",
            requires=(),
        )
        problems.append("non-PASS outcome without requirements accepted")
    except PilotError:
        pass
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "content-derived event ids; validation fail-closed; "
              "deterministic journal digests",
    ))


# ---------------------------------------------------------------------------
# 03: marshalling round trips + tamper fail-closed
# ---------------------------------------------------------------------------


def _world_pair() -> Tuple[Any, Any, Any]:
    """Two peered runtimes over the pilot's declared device material
    (mutual claims; the batteries' standard two-agent recipe)."""
    from agent import (
        AgentConfig,
        AgentIdentitySpec,
        AgentRuntime,
        InterfaceSnapshot,
        LinkMetricSpec,
        StaticInterfaceSource,
        StepClock,
    )
    from identity.node_id import parse_node_id
    from management import RoleDefinition
    from policy import PolicyDomain, PolicyRule
    from topology import ClaimType, SourceClass, TopologyClaim, make_link_subject

    ids = pilot_topology.node_ids()
    id_a = ids["device-1"]
    id_b = ids["device-2"]

    def _config(label: str, key: bytes, self_id: str, peer_id: str) -> AgentConfig:
        roles = (
            RoleDefinition(
                role_id="pilot-battery-%s" % (label,),
                capabilities=(),
                description="pilot battery role",
            ),
        )
        return AgentConfig(
            agent_label=label,
            identity=AgentIdentitySpec(
                profile_id=pilot_topology.PILOT_PROFILE_ID,
                public_key=key,
                created_at="2026-07-01T00:00:00Z",
            ),
            policy_rules=(
                PolicyRule(
                    rule_id="%s-allow-session-create" % (label,),
                    domain=PolicyDomain.IDENTITY,
                    effect="allow",
                    operation="session.create",
                    subjects=(),
                    priority=1,
                    specificity=1,
                ),
            ),
            topology_claims=(
                TopologyClaim(
                    subject=make_link_subject(self_id, peer_id),
                    reporter=self_id,
                    claim_type=ClaimType.LINK_STATE,
                    value="up",
                    source_class=SourceClass.DIRECT_OBSERVATION,
                    issued_at=pilot_topology.PILOT_T0,
                    freshness_until=pilot_topology.PILOT_FRESH,
                    sequence=1,
                ),
                TopologyClaim(
                    subject=peer_id,
                    reporter=self_id,
                    claim_type=ClaimType.REACHABLE,
                    value="true",
                    source_class=SourceClass.DIRECT_OBSERVATION,
                    issued_at=pilot_topology.PILOT_T0,
                    freshness_until=pilot_topology.PILOT_FRESH,
                    sequence=1,
                ),
            ),
            link_metrics=(
                LinkMetricSpec(
                    peer_node_id=peer_id,
                    latency_ms=10,
                    observed_at=pilot_topology.PILOT_T0,
                    freshness_until=pilot_topology.PILOT_FRESH,
                ),
            ),
            rbac_roles=roles,
            operator_role_ids=(roles[0].role_id,),
            offer_expiry_seconds=43200,
        )

    spec_a = pilot_topology.PILOT_NODE_BY_LABEL["device-1"]
    spec_b = pilot_topology.PILOT_NODE_BY_LABEL["device-2"]
    clock = StepClock("2026-08-01T00:00:00Z", 60)
    snapshots = (
        InterfaceSnapshot(
            name="eth0", link_kind="ethernet", state_up=True, mtu=1500,
            speed_mbps=1000, rx_bytes=0, tx_bytes=0, rx_errors=0,
            tx_errors=0, addresses=("fd00::d:1",),
        ),
    )
    a = AgentRuntime(
        _config("device-1", spec_a.key, id_a, id_b),
        clock=clock,
        interface_source=StaticInterfaceSource(snapshots),
    )
    b = AgentRuntime(
        _config("device-2", spec_b.key, id_b, id_a),
        clock=clock,
        interface_source=StaticInterfaceSource(snapshots),
    )
    a.boot(spec_a.secret)
    b.boot(spec_b.secret)
    a.expose_interfaces()
    b.expose_interfaces()
    cred_a = a.identity_service.active_credential(
        parse_node_id(a.node_id), "operational", now=a._now()
    )
    cred_b = b.identity_service.active_credential(
        parse_node_id(b.node_id), "operational", now=b._now()
    )
    a.register_peer(b.identity, cred_b, spec_b.secret)
    b.register_peer(a.identity, cred_a, spec_a.secret)
    request = a.establish_session(b.node_id)
    return a, b, request


def _handshake_artifacts() -> Tuple[Any, Any, Any, Any]:
    a, b, request = _world_pair()
    accept = b.accept_session(request)
    confirm = a.complete_session(accept)
    b.finalize_session(confirm)
    datagram = a.send_datagram(request.session_id, b"battery-roundtrip")
    return request, accept, confirm, datagram


def case_03_marshal_roundtrips_and_tamper(results: List[Result]) -> None:
    name = "case_03_marshal_roundtrips_and_tamper"
    request, accept, confirm, datagram = _handshake_artifacts()
    problems: List[str] = []
    roundtrips = [
        ("session-request", pilot_marshal.session_request_to_mapping,
         pilot_marshal.session_request_from_mapping, request),
        ("session-accept", pilot_marshal.session_accept_to_mapping,
         pilot_marshal.session_accept_from_mapping, accept),
        ("session-confirm", pilot_marshal.session_confirm_to_mapping,
         pilot_marshal.session_confirm_from_mapping, confirm),
        ("datagram", pilot_marshal.datagram_to_mapping,
         pilot_marshal.datagram_from_mapping, datagram),
        ("policy-decision", pilot_marshal.policy_decision_to_mapping,
         pilot_marshal.policy_decision_from_mapping,
         request.policy_decision),
        ("route-decision", pilot_marshal.route_decision_to_mapping,
         pilot_marshal.route_decision_from_mapping, request.route_decision),
        ("transport-offer", pilot_marshal.transport_offer_to_mapping,
         pilot_marshal.transport_offer_from_mapping, request.offer),
        ("transport-acceptance", pilot_marshal.transport_acceptance_to_mapping,
         pilot_marshal.transport_acceptance_from_mapping,
         accept.acceptance),
        ("transport-confirmation",
         pilot_marshal.transport_confirmation_to_mapping,
         pilot_marshal.transport_confirmation_from_mapping,
         confirm.confirmation),
    ]
    for label, serialize, deserialize, value in roundtrips:
        try:
            rebuilt = deserialize(json.loads(json.dumps(serialize(value))))
        except Exception as error:  # noqa: BLE001
            problems.append(
                "%s roundtrip raised %s" % (label, type(error).__name__)
            )
            continue
        if serialize(rebuilt) != serialize(value):
            problems.append("%s roundtrip not stable" % (label,))
    # structural marshal tamper fail-closed negatives
    tampered_route = pilot_marshal.route_decision_to_mapping(
        request.route_decision
    )
    tampered_route["decision_id"] = "0" * 64
    try:
        pilot_marshal.route_decision_from_mapping(tampered_route)
        problems.append("tampered route decision accepted")
    except PilotError:
        pass
    tampered_policy = pilot_marshal.policy_decision_to_mapping(
        request.policy_decision
    )
    tampered_policy["decision_id"] = ""
    try:
        pilot_marshal.policy_decision_from_mapping(tampered_policy)
        problems.append("empty policy decision id accepted")
    except PilotError:
        pass
    tampered_policy = pilot_marshal.policy_decision_to_mapping(
        request.policy_decision
    )
    tampered_policy["policy_set_version"] = "not-a-number"
    try:
        pilot_marshal.policy_decision_from_mapping(tampered_policy)
        problems.append("non-integer policy set version accepted")
    except PilotError:
        pass
    # an in-transit content tamper on the policy decision is caught by
    # the RECEIVING AUTHORITY (the mirrored session create verifies the
    # decision's content binding: policy-decision-tampered)
    import agent as agent_module

    _a, responder, original_request = _world_pair()
    request_mapping = pilot_marshal.session_request_to_mapping(
        original_request
    )
    request_mapping["policy_decision"]["decision_id"] = "f" * 64
    tampered_request = pilot_marshal.session_request_from_mapping(
        request_mapping
    )
    try:
        responder.accept_session(tampered_request)
        problems.append("in-transit decision tamper accepted by the authority")
    except agent_module.AgentError as error:
        if "policy-decision-tampered" not in str(error):
            problems.append(
                "in-transit tamper reason %r" % (str(error)[:60],)
            )
    # the credential record round trip + tamper
    from agent import AgentRuntime, StaticInterfaceSource, StepClock
    from identity.node_id import parse_node_id

    runtime = AgentRuntime(
        pilot_topology.device_config(
            "device-1",
            relay_id=pilot_topology.node_ids()["relay-1"],
            appliance_id=pilot_topology.node_ids()["appliance-1"],
        ),
        clock=StepClock("2026-08-01T00:00:00Z", 60),
        interface_source=pilot_topology.device_interface_source("device-1"),
    )
    runtime.boot(pilot_topology.PILOT_NODE_BY_LABEL["device-1"].secret)
    credential = runtime.identity_service.active_credential(
        parse_node_id(runtime.node_id), "operational", now=runtime._now()
    )
    cred_mapping = pilot_marshal.credential_record_to_mapping(credential)
    rebuilt_cred = pilot_marshal.credential_record_from_mapping(
        json.loads(json.dumps(cred_mapping))
    )
    if (
        rebuilt_cred.node_id.text != credential.node_id.text
        or rebuilt_cred.status != credential.status
    ):
        problems.append("credential record roundtrip unstable")
    bad_cred = dict(cred_mapping)
    bad_cred["status"] = "not-a-state"
    try:
        pilot_marshal.credential_record_from_mapping(bad_cred)
        problems.append("tampered credential status accepted")
    except PilotError:
        pass
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "9 artifact roundtrips stable through production "
              "constructors; structural route/policy/credential tamper "
              "fail-closed at reconstruction; in-transit decision "
              "tampering caught by the receiving session authority",
    ))


# ---------------------------------------------------------------------------
# 04: wire framing over real loopback TCP
# ---------------------------------------------------------------------------


def case_04_wire_framing(results: List[Result]) -> None:
    name = "case_04_wire_framing"
    problems: List[str] = []
    listener = pilot_wire.open_listener("127.0.0.1", 0)
    port = pilot_wire.socket_endpoint(listener)[1]
    received: dict = {}

    def _serve() -> None:
        conn, _addr = listener.accept()
        try:
            envelope, raw = pilot_wire.recv_envelope(conn)
            received["type"] = envelope.message_type
            received["raw_len"] = len(raw)
            # echo the same bytes back (verbatim-forward discipline)
            pilot_wire.send_frame(conn, raw)
        finally:
            pilot_wire.close_quietly(conn)

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    sock = pilot_wire.connect_to("127.0.0.1", port)
    envelope = pilot_wire.pilot_envelope(
        "pilot.result",
        {"battery": True},
        sender="battery-node",
        issued_at=pilot_deployment.EPOCH_ISSUED,
        expires_at=pilot_deployment.EPOCH_EXPIRES,
    )
    from protocol import get_codec

    payload = get_codec("json-debug").encode(envelope)
    pilot_wire.send_frame(sock, payload)
    echoed, raw = pilot_wire.recv_envelope(sock)
    pilot_wire.close_quietly(sock)
    thread.join(timeout=5.0)
    pilot_wire.close_quietly(listener)
    if received.get("type") != "pilot.result":
        problems.append("loopback echo lost the message type")
    if raw != payload:
        problems.append("verbatim echo altered the wire bytes")
    # LOCK-014 receipt over the real frame
    receipt = pilot_wire.validate_frame(
        payload, now=pilot_deployment.VALIDATION_NOW
    )
    if not receipt["accepted"]:
        problems.append(
            "production acceptance rejected a pilot frame: %s"
            % (receipt["detail"],)
        )
    if receipt["classification"] != "unknown_optional_forwarded":
        problems.append(
            "unexpected classification %r" % (receipt["classification"],)
        )
    # oversized rejection
    listener2 = pilot_wire.open_listener("127.0.0.1", 0)
    port2 = pilot_wire.socket_endpoint(listener2)[1]

    def _serve2() -> None:
        conn, _addr = listener2.accept()
        try:
            pilot_wire.recv_frame(conn, timeout=5.0)
        except PilotError:
            pass
        finally:
            pilot_wire.close_quietly(conn)

    thread2 = threading.Thread(target=_serve2, daemon=True)
    thread2.start()
    sock2 = pilot_wire.connect_to("127.0.0.1", port2)
    try:
        pilot_wire.send_frame(sock2, b"x" * (pilot_wire.MAX_FRAME_BYTES + 1))
        problems.append("oversized frame accepted locally")
    except PilotError as error:
        if error.reason != PilotReasonCode.WIRE_OVERSIZED:
            problems.append("oversized reason %r" % (error.reason,))
    pilot_wire.close_quietly(sock2)
    thread2.join(timeout=5.0)
    pilot_wire.close_quietly(listener2)
    # oversized advertisement rejected at receive
    listener3 = pilot_wire.open_listener("127.0.0.1", 0)
    port3 = pilot_wire.socket_endpoint(listener3)[1]

    def _serve3() -> None:
        conn, _addr = listener3.accept()
        try:
            import struct

            conn.sendall(struct.pack("!I", pilot_wire.MAX_FRAME_BYTES + 1))
            time.sleep(0.2)
        except OSError:
            pass
        finally:
            pilot_wire.close_quietly(conn)

    thread3 = threading.Thread(target=_serve3, daemon=True)
    thread3.start()
    sock3 = pilot_wire.connect_to("127.0.0.1", port3)
    try:
        pilot_wire.recv_frame(sock3, timeout=5.0)
        problems.append("oversized advertisement accepted at receive")
    except PilotError as error:
        if error.reason != PilotReasonCode.WIRE_OVERSIZED:
            problems.append("advertised-oversize reason %r" % (error.reason,))
    pilot_wire.close_quietly(sock3)
    thread3.join(timeout=5.0)
    pilot_wire.close_quietly(listener3)
    # invalid envelope bytes rejected by the production codec
    try:
        get_codec("json-debug").decode(b"{not-json")
        problems.append("codec accepted malformed bytes")
    except Exception:  # noqa: BLE001
        pass
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "loopback echo verbatim byte-identical; production "
              "FORWARD_OPAQUE receipt; oversized frames fail closed on "
              "both sides",
    ))


# ---------------------------------------------------------------------------
# 05: platform reconnaissance honesty
# ---------------------------------------------------------------------------


def case_05_platform_honesty(results: List[Result]) -> None:
    name = "case_05_platform_honesty"
    problems: List[str] = []
    interfaces = pilot_platform.observe_interfaces()
    names = {snapshot.name for snapshot in interfaces}
    if "lo" not in names or "eth0" not in names:
        problems.append("real host interfaces not observed (%s)" % (sorted(names),))
    for snapshot in interfaces:
        document = snapshot.to_dict()
        if document.get("link_kind") not in ("ethernet", "loopback", "wireless"):
            problems.append("unexpected link kind %r" % (document.get("link_kind"),))
    sctp = pilot_platform.probe_sctp_support()
    if sctp.get("available") is True:
        # honest on a host WITH sctp; on this deployment host it is
        # False -- either way the record must carry a detail
        if not sctp.get("detail"):
            problems.append("sctp probe missing detail")
    lab_gate = pilot_platform.run_oran_labgate_disabled()
    if lab_gate.get("status") != "GATE_DISABLED":
        problems.append(
            "no-switch lab gate status %r (never a PASS)"
            % (lab_gate.get("status"),)
        )
    runbook = pilot_platform.five_g_required_evidence()
    if "runbook" not in runbook or not runbook["runbook"]:
        problems.append("the 5G runbook evidence requirement is absent")
    statement = runbook.get("statement", "")
    if "never be promoted" not in statement:
        problems.append("the anti-promotion statement is absent")
    host = pilot_platform.host_facts()
    for key in ("kernel", "machine", "python"):
        if not host.get(key):
            problems.append("host fact %r missing" % (key,))
    hardware = pilot_platform.observe_hardware()
    if not str(hardware.board_id):
        problems.append("hardware inventory missing board id")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "real host interfaces through LinuxInterfaceSource; honest "
              "SCTP probe; GATE_DISABLED lab gate; the frozen 5G runbook "
              "recorded verbatim",
    ))


# ---------------------------------------------------------------------------
# 06-07: topology + fabric validation
# ---------------------------------------------------------------------------


def case_06_topology_validation(results: List[Result]) -> None:
    name = "case_06_topology_validation"
    problems: List[str] = []
    document = pilot_topology.validate_topology()
    labels = [node["label"] for node in document["nodes"]]
    if labels != ["device-1", "device-2", "relay-1", "appliance-1"]:
        problems.append("unexpected node order %s" % (labels,))
    ids = pilot_topology.node_ids()
    if len(set(ids.values())) != 4:
        problems.append("node identities are not distinct")
    for path in document["paths"]:
        if len(path["hops"]) < 2:
            problems.append("path %r has < 2 hops" % (path["path_label"],))
    from pilot.topology import PilotNodeSpec

    try:
        PilotNodeSpec("device-1", "not-a-role")
        problems.append("unknown role accepted")
    except PilotError:
        pass
    try:
        PilotNodeSpec("not-a-node", "device")
        problems.append("undeclared label accepted")
    except PilotError:
        pass
    from pilot.topology import PilotPathSpec

    try:
        PilotPathSpec("bad", "x", ("device-1",), "direct")
        problems.append("single-hop path accepted")
    except PilotError:
        pass
    try:
        PilotPathSpec("bad", "x", ("device-1", "relay-1"), "not-a-kind")
        problems.append("unknown path kind accepted")
    except PilotError:
        pass
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "topology validated: 4 nodes, 4 paths, distinct real "
              "identities; spec negatives fail closed",
    ))


def case_07_fabric_provisioning(results: List[Result]) -> None:
    name = "case_07_fabric_provisioning"
    problems: List[str] = []
    from appliance import validate_manifest

    manifest = pilot_fabric.pilot_fabric_manifest()
    steps = validate_manifest(manifest)
    if len(steps) < 6:
        problems.append("manifest plan has %d steps" % (len(steps),))
    echo_ref = pilot_fabric.pilot_echo_service_ref()
    weather_ref = pilot_fabric.pilot_weather_service_ref()
    if echo_ref == weather_ref:
        problems.append("service refs collided")
    if not echo_ref.startswith("services:service:"):
        problems.append("echo ref %r not a service ref" % (echo_ref,))
    from pilot.deployment import _boot_appliance
    from appliance import ApplianceCommand, ApplianceCommandKind

    appliance = _boot_appliance()
    lookup = appliance.run_appliance(
        (ApplianceCommand(
            ApplianceCommandKind.LOOKUP_SERVICE,
            {"service_ref": echo_ref,
             "tenant_domain": pilot_fabric.PILOT_TENANT_DOMAIN},
        ),)
    )
    if lookup.outcomes[-1].verdict != "executed":
        problems.append(
            "echo service lookup refused: %s" % (lookup.outcomes[-1].detail[:80],)
        )
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "fabric manifest valid (%d steps); both service refs "
              "derive; the pilot-echo service is discoverable at the "
              "booted appliance" % (len(steps),),
    ))


# ---------------------------------------------------------------------------
# 08: the full deployment rehearsal
# ---------------------------------------------------------------------------


def case_08_full_deployment_rehearsal(results: List[Result]) -> None:
    name = "case_08_full_deployment_rehearsal"
    result = _full_run("main")
    if not result.all_checks_pass():
        failures = [
            "%s: %s" % (check.label, check.detail[:60])
            for check in result.checks if not check.ok
        ]
        results.append(fail(name, "; ".join(failures)))
        return
    statuses = {
        outcome.criterion: outcome.status
        for outcome in result.criterion_outcomes
    }
    expected = {
        CriterionId.REAL_DEVICES: CriterionStatus.PARTIAL,
        CriterionId.PATH_5G: CriterionStatus.NOT_TESTABLE,
        CriterionId.PATH_NON_CELLULAR: CriterionStatus.PASS,
        CriterionId.PATH_RELAY_BACKHAUL: CriterionStatus.PASS,
        CriterionId.RESILIENCE_FAILOVER: CriterionStatus.PASS,
        CriterionId.OPERATIONAL_EVIDENCE: CriterionStatus.PASS,
    }
    if statuses != expected:
        results.append(fail(
            name, "criterion statuses %s != %s" % (statuses, expected),
        ))
        return
    demonstrations = {
        record.demonstration: record
        for record in result.executions
    }
    for demonstration in (
        "A-real-device-participation",
        "B-five-g-access-path-honest-status",
        "C-non-cellular-access-path",
        "D-relay-backhaul-path",
        "E-resilience-failover",
    ):
        if demonstration not in demonstrations:
            results.append(fail(
                name, "execution record %r missing" % (demonstration,),
            ))
            return
    five_g = demonstrations["B-five-g-access-path-honest-status"]
    if "NOT TESTABLE" not in five_g.after_state:
        results.append(fail(
            name, "the 5G execution record is not the honest status",
        ))
        return
    failover = demonstrations["E-resilience-failover"]
    if "UNCHANGED record digest" not in failover.after_state:
        results.append(fail(
            name, "the failover record lacks the continuity proof",
        ))
        return
    node_documents = result.operational["node_documents"]
    if set(node_documents.keys()) != {
        "appliance-1", "relay-1", "device-1", "device-2"
    }:
        results.append(fail(
            name, "node documents %s" % (sorted(node_documents.keys()),),
        ))
        return
    device_1 = node_documents["device-1"]["observations"]
    if not device_1["failover"]["observed_real_loss"]:
        results.append(fail(name, "no real link loss observed"))
        return
    if device_1["failover"]["reprobe_reachable"]:
        results.append(fail(name, "the dead path re-probe connected"))
        return
    if (
        device_1["session"]["record_digest"]
        != device_1["session"]["record_digest_before_failure"]
    ):
        results.append(fail(name, "session record digest changed"))
        return
    plan_statuses = [
        entry["status"]
        for entry in device_1["multipath_plan"]["constituents"]
    ]
    if sorted(plan_statuses) != ["ACTIVE", "FAILED"]:
        results.append(fail(
            name, "constituent statuses %s" % (plan_statuses,),
        ))
        return
    device_2 = node_documents["device-2"]["observations"]
    if device_2["service"]["verdict"] != "executed":
        results.append(fail(name, "device-2 service not executed"))
        return
    if not device_2["service"]["response_matches"]:
        results.append(fail(name, "device-2 service digest mismatch"))
        return
    relay = node_documents["relay-1"]["observations"]
    if relay["frames_transited"] <= 0:
        results.append(fail(name, "relay transited no frames"))
        return
    results.append(ok(
        name,
        "4 real processes; %d journal events; %d checks; all "
        "demonstrations A/C/D/E + the honest B record; criteria "
        "[PARTIAL, NOT-TESTABLE, PASS, PASS, PASS, PASS]; %d relayed "
        "frames; failover with session-record stability"
        % (
            len(result.events), len(result.checks),
            relay["frames_transited"],
        ),
    ))


# ---------------------------------------------------------------------------
# 09-10: determinism + hashseed invariance
# ---------------------------------------------------------------------------


def case_09_determinism(results: List[Result]) -> None:
    name = "case_09_determinism"
    first = _full_run("main")
    second = _full_run("second")
    if first.run_digest() != second.run_digest():
        results.append(fail(
            name,
            "run digests diverged (%s vs %s)"
            % (first.run_digest()[:24], second.run_digest()[:24]),
        ))
        return
    results.append(ok(
        name,
        "two independent rehearsals reproduce the run digest "
        "byte-identically (%s...)" % (first.run_digest()[:19],),
    ))


def case_10_hashseed_invariance(results: List[Result]) -> None:
    name = "case_10_hashseed_invariance"
    first = _full_run("main")
    reference = first.run_digest()
    problems: List[str] = []
    for seed in ("7", "4242"):
        script = (
            "import sys; sys.path.insert(0, %r); "
            "from pilot.deployment import run_pilot_deployment; "
            "import tempfile; "
            "r = run_pilot_deployment("
            "rehearsal=True, "
            "workspace=tempfile.mkdtemp(prefix='adcos-pilot-seed-')); "
            "print(r.run_digest())" % (str(REPO_ROOT),)
        )
        completed = subprocess.run(  # noqa: S603 - this repo's own code
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=300,
            env={**os.environ, "PYTHONHASHSEED": seed},
            cwd=str(REPO_ROOT),
        )
        digest = completed.stdout.strip().splitlines()[-1] if completed.stdout else ""
        if completed.returncode != 0 or digest != reference:
            problems.append(
                "seed %s: rc=%d digest=%s..."
                % (seed, completed.returncode, digest[:19])
            )
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "run digest invariant across PYTHONHASHSEED 7 and 4242",
    ))


# ---------------------------------------------------------------------------
# 11: journal binding (replay/tamper)
# ---------------------------------------------------------------------------


def case_11_journal_binding(results: List[Result]) -> None:
    name = "case_11_journal_binding"
    result = _full_run("main")
    problems: List[str] = []
    events = result.events
    rebuilt_digest = pilot_event_list_digest(events)
    semantic = result.semantic_dict()
    if rebuilt_digest != semantic["journal_digest"]:
        problems.append("journal digest not reproducible from events")
    tampered = list(events)
    tampered[3] = PilotEvent(
        sequence=events[3].sequence,
        kind=events[3].kind,
        at_instant=events[3].at_instant,
        payload={**events[3].payload, "tampered": True},
    )
    if pilot_event_list_digest(tuple(tampered)) == semantic["journal_digest"]:
        problems.append("journal digest blind to tampering")
    for event in events:
        rebuilt = PilotEvent(
            sequence=event.sequence,
            kind=event.kind,
            at_instant=event.at_instant,
            payload=dict(event.payload),
        )
        if rebuilt.event_id() != event.event_id():
            problems.append("event id not content-derived")
            break
    document = pilot_evidence.pilot_report_document(result)
    if document["run_digest"] != result.run_digest():
        problems.append("report document digest mismatch")
    if "open_external_obligations" not in document:
        problems.append("report lacks the open obligations section")
    if "evidence_statement" not in document:
        problems.append("report lacks the evidence statement")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "journal digest reproducible + tamper-evident; the pilot "
              "report document carries the run digest, the evidence "
              "statement, and the open external obligations",
    ))


# ---------------------------------------------------------------------------
# 12: structural anti-promotion
# ---------------------------------------------------------------------------


def case_12_anti_promotion(results: List[Result]) -> None:
    name = "case_12_anti_promotion"
    problems: List[str] = []
    for evidence_class in (
        PilotEvidenceClass.SOFTWARE,
        PilotEvidenceClass.OPERATIONAL,
    ):
        try:
            attach_evidence(CriterionId.PATH_5G, evidence_class)
            problems.append(
                "attach_evidence accepted %s-class 5G evidence"
                % (evidence_class,)
            )
        except PilotError as error:
            if error.reason != PilotReasonCode.PROMOTION_FORBIDDEN:
                problems.append("refusal reason %r" % (error.reason,))
    # the model refuses a software/operational PASS for the 5G criterion
    for evidence_class in (
        PilotEvidenceClass.SOFTWARE,
        PilotEvidenceClass.OPERATIONAL,
    ):
        try:
            CriterionOutcome(
                criterion=CriterionId.PATH_5G,
                status=CriterionStatus.PASS,
                evidence_class=evidence_class,
                statement="promoted",
                requires=(),
            )
            problems.append(
                "the model accepted a %s-class PASS for the 5G criterion"
                % (evidence_class,)
            )
        except PilotError as error:
            if error.reason != PilotReasonCode.PROMOTION_FORBIDDEN:
                problems.append("model refusal reason %r" % (error.reason,))
    # the honest outcome constructor can never produce PASS
    from pilot.platform import run_oran_labgate_disabled, run_ran_env_probe

    no_infra = criterion_outcome_for_5g({
        "environment_probes": (run_ran_env_probe(),),
        "profile_lab_gate": run_oran_labgate_disabled(),
    })
    if no_infra.status not in (
        CriterionStatus.NOT_TESTABLE, CriterionStatus.OPEN
    ):
        problems.append(
            "no-infrastructure outcome %r" % (no_infra.status,)
        )
    if not no_infra.requires:
        problems.append("no-infrastructure outcome lacks requirements")
    # even with (fabricated) healthy probes the constructor yields OPEN,
    # never PASS: closing the criterion is the operator's lab run
    healthy = criterion_outcome_for_5g({
        "environment_probes": ({"kind": "ran-env-probe", "reachable": True},),
        "profile_lab_gate": {"status": "OPERATOR_RUN_PENDING"},
    })
    if healthy.status != CriterionStatus.OPEN:
        problems.append(
            "healthy-probe outcome %r (never PASS by construction)"
            % (healthy.status,)
        )
    # physical-class PASS remains constructible ONLY for real evidence
    physical = CriterionOutcome(
        criterion=CriterionId.PATH_5G,
        status=CriterionStatus.PASS,
        evidence_class=PilotEvidenceClass.PHYSICAL,
        statement="a real lab run closed every leg",
        requires=(),
    )
    if physical.status != CriterionStatus.PASS:
        problems.append("physical PASS refused (must remain possible)")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "software/operational 5G evidence refused at the attach "
              "surface AND in the model; the outcome constructor yields "
              "only NOT-TESTABLE/OPEN from real observations; a genuine "
              "PHYSICAL PASS stays constructible",
    ))


# ---------------------------------------------------------------------------
# 13: evidence classes + obligations honesty
# ---------------------------------------------------------------------------


def case_13_evidence_honesty(results: List[Result]) -> None:
    name = "case_13_evidence_honesty"
    problems: List[str] = []
    statement = pilot_evidence.evidence_statement()
    for token in ("SOFTWARE", "PHYSICAL", "OPERATIONAL", "never promoted"):
        if token not in statement:
            problems.append("statement lacks %r" % (token,))
    result = _full_run("main")
    classes = {
        outcome.criterion: outcome.evidence_class
        for outcome in result.criterion_outcomes
    }
    if classes[CriterionId.PATH_5G] == PilotEvidenceClass.PHYSICAL:
        problems.append("the 5G outcome claims physical evidence")
    if classes[CriterionId.REAL_DEVICES] == PilotEvidenceClass.PHYSICAL:
        problems.append("software participants promoted to physical")
    for record in result.executions:
        if not record.artifact_hashes and record.demonstration != (
            "D-relay-backhaul-path"
        ):
            problems.append(
                "execution record %r lacks artifact hashes"
                % (record.demonstration,)
            )
        for field in (
            "device", "interface_path", "commit_sha", "harness_version",
            "trigger", "before_state", "transition", "after_state",
            "adcos_reaction", "traffic_result", "recorded_at",
        ):
            if not getattr(record, field):
                problems.append(
                    "record %r field %r empty"
                    % (record.demonstration, field)
                )
                break
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "evidence classes honest (no physical claims); every "
              "execution record carries the full per-claim field set "
              "the WORK-040 order demands",
    ))


# ---------------------------------------------------------------------------
# 14: no second authority / import discipline
# ---------------------------------------------------------------------------


_ALLOWED_IMPORT_ROOTS = {
    # the accepted families' public contracts (composed, never re-owned)
    "protocol", "agent", "appliance", "edge", "identity", "policy",
    "routing", "resources", "topology", "multipath", "services",
    "adapters", "interop", "management", "transport",
    # stdlib the deployment plane legitimately uses (no randomness,
    # no uuid, no secrets -- those are audited separately below);
    # re/shutil joined at the correction cycle for the honest adb/path
    # detection in the physical harness (parsing framework reports,
    # locating the adb binary -- never protocol semantics)
    "__future__", "argparse", "ast", "dataclasses", "hashlib", "json",
    "os", "pathlib", "platform", "re", "shutil", "socket", "ssl",
    "struct", "subprocess", "sys", "tempfile", "threading", "time",
    "typing",
}
_FORBIDDEN_SOURCE_TOKENS = (
    "class PilotStore", "class PilotEngine", "class PilotAuthority",
)


def case_14_no_second_authority(results: List[Result]) -> None:
    name = "case_14_no_second_authority"
    problems: List[str] = []
    import ast

    for path in _FAMILY_FILES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if root not in _ALLOWED_IMPORT_ROOTS:
                        problems.append(
                            "%s imports %r" % (path.name, alias.name)
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.level > 0:
                    continue  # intra-family relative import
                root = (node.module or "").split(".")[0]
                if root and root not in _ALLOWED_IMPORT_ROOTS:
                    problems.append(
                        "%s imports from %r" % (path.name, node.module)
                    )
        source = path.read_text(encoding="utf-8")
        for token in ("import random", "import secrets", "import uuid"):
            if token in source:
                problems.append("%s contains %r" % (path.name, token))
    # the pilot never constructs protocol authorities itself
    for path in _FAMILY_FILES:
        source = path.read_text(encoding="utf-8")
        for token in ("SessionStore()", "FederationStore()"):
            if token in source:
                problems.append("%s constructs %r" % (path.name, token))
    if problems:
        results.append(fail(name, "; ".join(sorted(set(problems)))))
        return
    results.append(ok(
        name, "pilot imports only the accepted families' contracts + "
              "benign stdlib; no randomness/uuid/secrets; no second "
              "authority constructed anywhere in the family",
    ))


# ---------------------------------------------------------------------------
# 15: secrets never enter evidence
# ---------------------------------------------------------------------------


def case_15_secrets_out_of_evidence(results: List[Result]) -> None:
    name = "case_15_secrets_out_of_evidence"
    result = _full_run("main")
    blobs = [
        json.dumps(event.content_dict()).encode("utf-8")
        for event in result.events
    ]
    blobs.extend(
        json.dumps(record.content_dict()).encode("utf-8")
        for record in result.executions
    )
    blobs.extend(
        json.dumps(check.content_dict()).encode("utf-8")
        for check in result.checks
    )
    blobs.append(canonical_json_bytes(result.semantic_dict()))
    for label, spec in pilot_topology.PILOT_NODE_BY_LABEL.items():
        secret = spec.secret
        if secret.hex().encode() in blobs or any(
            secret in blob for blob in blobs
        ):
            results.append(fail(
                name, "deployment secret of %s leaked into evidence" % (label,)
            ))
            return
    results.append(ok(
        name, "no deployment-declared secret bytes in journals, checks, "
              "execution records, or the semantic digest",
    ))


# ---------------------------------------------------------------------------
# 16: frozen API surface
# ---------------------------------------------------------------------------


def case_16_frozen_api(results: List[Result]) -> None:
    name = "case_16_frozen_api"
    import pilot

    expected = set(pilot.__all__)
    actual = {
        symbol for symbol in dir(pilot)
        if not symbol.startswith("_") and symbol in pilot.__all__
    }
    missing = expected - actual
    if missing:
        results.append(fail(name, "exports missing: %s" % (sorted(missing),)))
        return
    submodules = {
        "marshal": pilot_marshal, "wire": pilot_wire,
        "topology": pilot_topology, "fabric": pilot_fabric,
        "platform": pilot_platform, "evidence": pilot_evidence,
        "deployment": pilot_deployment, "physical": pilot_physical,
    }
    for module_name, module in submodules.items():
        if not hasattr(module, "__all__"):
            results.append(fail(
                name, "submodule %s lacks a frozen __all__" % (module_name,)
            ))
            return
    results.append(ok(
        name, "%d package exports + frozen __all__ on all 8 submodules"
              % (len(expected),),
    ))


# ---------------------------------------------------------------------------
# 17: frozen spec intact
# ---------------------------------------------------------------------------


def case_17_frozen_spec_intact(results: List[Result]) -> None:
    name = "case_17_frozen_spec_intact"
    status = subprocess.run(
        ["git", "status", "--porcelain", "--", "spec/"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if status.returncode != 0 or status.stdout.strip():
        results.append(fail(
            name, "uncommitted spec/ changes: %s" % (status.stdout.strip(),)
        ))
        return
    work_items = (REPO_ROOT / "spec" / "work-items.md").read_text(
        encoding="utf-8"
    )
    if "### WORK-040 — Pilot deployment" not in work_items:
        results.append(fail(name, "the WORK-040 entry is absent"))
        return
    if "real users/devices participate" not in work_items:
        results.append(fail(name, "the frozen criteria text changed"))
        return
    results.append(ok(
        name, "spec/ clean; the frozen WORK-040 entry intact",
    ))


# ---------------------------------------------------------------------------
# 18: PR-delta shape
# ---------------------------------------------------------------------------


def case_18_pr_delta_shape(results: List[Result]) -> None:
    name = "case_18_pr_delta_shape"
    workflow_path = os.path.join(
        REPO_ROOT, ".github", "workflows", "spec-check.yml"
    )
    with open(workflow_path, encoding="utf-8") as handle:
        workflow = handle.read()
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
        if "python3 tools/pilot_selftest.py" in workflow:
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
        if "python3 tools/pilot_selftest.py" in workflow:
            results.append(ok(name, "spec/ clean on main; wiring verified"))
        else:
            results.append(fail(name, "committed CI wiring missing on main"))
        return
    allowed_exact = {
        "tools/pilot_selftest.py",
        # DAG-sanctioned allowlist amendments (work-item order): the
        # successor batteries' PR-delta shapes admit this branch's files.
        "tools/agent_selftest.py",
        "tools/edge_selftest.py",
        "tools/mobile_selftest.py",
        "tools/appliance_selftest.py",
        "tools/oran_selftest.py",
        "tools/imt_selftest.py",
        "tools/scale_selftest.py",
        "docs/WORK-040-handoff.md",
        "docs/WORK-040-evidence.md",
    }
    unexpected = [
        c for c in changed
        if not c.startswith("pilot/")
        and not c.startswith("evidence/work-040/")
        and c not in allowed_exact
        and not c.startswith(".github/")
    ]
    if unexpected:
        results.append(fail(
            name, "delta beyond the sanctioned shape: %s" % (unexpected,)
        ))
        return
    workflow_delta = subprocess.run(
        ["git", "diff", "origin/main", "--", ".github/"],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )
    if "pilot_selftest.py" not in workflow_delta.stdout:
        results.append(fail(
            name, ".github delta does not include the pilot CI step"
        ))
        return
    results.append(ok(
        name, "PR delta exactly: pilot/ + pilot battery + the seven "
              "successor-amended batteries + handoff/evidence docs + "
              "the evidence/work-040/ attempt artifacts + the CI step",
    ))


# ---------------------------------------------------------------------------
# 19: CI wiring + ordering
# ---------------------------------------------------------------------------


def case_19_ci_wiring_all_tools(results: List[Result]) -> None:
    name = "case_19_ci_wiring_all_tools"
    workflow_path = REPO_ROOT / ".github" / "workflows" / "spec-check.yml"
    workflow = workflow_path.read_text(encoding="utf-8")
    missing = [
        tool for tool in _EXPECTED_TOOLS
        if ("tools/%s" % tool) not in workflow
    ]
    if missing:
        results.append(fail(name, "batteries missing from CI: %s" % (missing,)))
        return
    scale_index = workflow.find("python3 tools/scale_selftest.py")
    pilot_index = workflow.find("python3 tools/pilot_selftest.py")
    if not (scale_index < pilot_index):
        results.append(fail(name, "pilot step not ordered after scale"))
        return
    results.append(ok(
        name, "CI wired: pilot battery + all %d prior tools; pilot "
              "ordered after scale (work-item order)"
              % (len(_EXPECTED_TOOLS) - 1),
    ))


# ---------------------------------------------------------------------------
# 20: py_compile
# ---------------------------------------------------------------------------


def case_20_py_compile(results: List[Result]) -> None:
    name = "case_20_py_compile"
    for path in _FAMILY_FILES:
        try:
            py_compile.compile(str(path), doraise=True)
        except py_compile.PyCompileError as error:
            results.append(fail(name, "%s: %s" % (path.name, error)))
            return
    results.append(ok(
        name, "all %d pilot files compile" % (len(_FAMILY_FILES),)
    ))


# ---------------------------------------------------------------------------
# 21-25: the WORK-040 correction cycle (WORK-040-CORRECTION-001)
# ---------------------------------------------------------------------------


def case_21_physical_topology_extension(results: List[Result]) -> None:
    name = "case_21_physical_topology_extension"
    problems: List[str] = []
    document = pilot_topology.validate_topology()
    labels = [node["label"] for node in document["nodes"]]
    if labels != ["device-1", "device-2", "relay-1", "appliance-1"]:
        problems.append("the CORE topology changed: %s" % (labels,))
    extension = document.get("physical_extension") or {}
    ext_nodes = extension.get("nodes") or []
    if len(ext_nodes) != 1 or ext_nodes[0]["label"] != "device-android":
        problems.append("the physical extension is not declared exactly")
    if ext_nodes and ext_nodes[0].get("role") != "device":
        problems.append("the physical extension is not a device-class node")
    # correction cycle 2: the TWO-path physical extension (the original
    # physical-access path byte-stable + the handover scenario's
    # secondary USB-tether relayed path)
    ext_paths = extension.get("paths") or []
    if len(ext_paths) != 2:
        problems.append(
            "the physical extension paths are not exactly two: %s"
            % ([p.get("path_label") for p in ext_paths],)
        )
    if ext_paths and ext_paths[0].get("path_label") != "physical-access":
        problems.append("the original physical-access path is not first")
    if ext_paths and list(ext_paths[0].get("hops") or []) != [
        "device-android", "appliance-1"
    ]:
        problems.append("the physical path hops are wrong")
    if len(ext_paths) < 2:
        problems.append("the secondary physical path is not declared")
    else:
        second = ext_paths[1]
        if second.get("path_label") != "physical-access-secondary":
            problems.append(
                "the secondary path label is %r"
                % (second.get("path_label"),)
            )
        if second.get("kind") != "physical":
            problems.append("the secondary path is not kind 'physical'")
        if list(second.get("hops") or []) != [
            "device-android", "relay-1", "appliance-1"
        ]:
            problems.append("the secondary path hops are wrong")
    all_ids = pilot_topology.participant_ids()
    if len(all_ids) != 5 or len(set(all_ids.values())) != 5:
        problems.append("participant identities are not 5 distinct ids")
    if "device-android" not in all_ids:
        problems.append("the physical participant has no identity")
    # the physical participant's config: the DIRECT physical view (no
    # relay claims) and the REAL interface source (never the declared
    # static view of the rehearsal devices); handover=True ADDS the
    # relay-leg view the handover scenario genuinely uses
    config = pilot_topology.device_config(
        "device-android",
        relay_id=all_ids["relay-1"],
        appliance_id=all_ids["appliance-1"],
    )
    subjects = [
        str(claim.subject) for claim in config.topology_claims
    ]
    if any(all_ids["relay-1"] in s for s in subjects):
        problems.append("the physical view claims relay links it does not use")
    handover_config = pilot_topology.device_config(
        "device-android",
        relay_id=all_ids["relay-1"],
        appliance_id=all_ids["appliance-1"],
        handover=True,
    )
    handover_subjects = [
        str(claim.subject) for claim in handover_config.topology_claims
    ]
    if not any(all_ids["relay-1"] in s for s in handover_subjects):
        problems.append(
            "the handover view omits the relay leg it genuinely uses"
        )
    if len(handover_config.link_metrics) != 2:
        problems.append("the handover view omits the relay-leg metric")
    source = pilot_topology.device_interface_source("device-android")
    from agent import LinuxInterfaceSource

    if not isinstance(source, LinuxInterfaceSource):
        problems.append(
            "the physical participant does not read its REAL interfaces"
        )
    try:
        pilot_topology.node_identity_for("device-android3")
        problems.append("unknown participant label accepted")
    except PilotError:
        pass
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "physical extension declared (device-android, the two-path "
              "physical-access/physical-access-secondary extension); core "
              "topology byte-stable; the plain view claims NO relay links "
              "while the handover view declares the relay leg it genuinely "
              "uses; the participant reads its REAL interfaces through the "
              "production source",
    ))


def case_22_physical_environment_honesty(results: List[Result]) -> None:
    name = "case_22_physical_environment_honesty"
    problems: List[str] = []
    environment = pilot_physical.detect_physical_environment()
    if environment.get("kind") != "physical-environment-detection":
        problems.append("wrong detection kind")
    adb = environment.get("adb_binary") or {}
    if not isinstance(adb.get("present"), bool) or not adb.get("detail"):
        problems.append("the adb probe is not an honest record")
    devices = environment.get("adb_devices") or {}
    serials = devices.get("serials")
    if not isinstance(serials, list):
        problems.append("the device serials are not a list")
    attached = environment.get("device_attached")
    if attached != bool(serials):
        problems.append(
            "device_attached %r does not match the observed serials"
            % (attached,)
        )
    if not environment.get("conclusion"):
        problems.append("no honest conclusion recorded")
    # the attempt fail-closes when (and only when) no device is attached
    if not attached:
        attempt = pilot_physical.run_physical_attempt()
        if attempt.get("kind") != "physical-environment-detection":
            problems.append("the attempt record has the wrong kind")
        cls = attempt.get("classification") or {}
        if cls.get("criterion_1_real_devices") != CriterionStatus.NOT_TESTABLE:
            problems.append(
                "criterion 1 is not honestly NOT-TESTABLE without a device"
            )
        if cls.get("criterion_2_5g") != CriterionStatus.NOT_TESTABLE:
            problems.append(
                "criterion 2 is not honestly NOT-TESTABLE without a device"
            )
        statement = str(cls.get("statement", ""))
        if "cannot be demonstrated here" not in statement:
            problems.append("the honest statement is missing")
    else:
        # a device IS attached: the attempt must run the real pilot or
        # record precisely why it could not (never fabricate)
        attempt = pilot_physical.run_physical_attempt()
        if attempt.get("kind") not in (
            "physical-environment-detection",
            "physical-participation-evidence",
        ):
            problems.append("unexpected attempt record kind")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    attached_note = (
        "a device is attached; the attempt exercised the real path"
        if attached
        else "no device reachable here; the attempt fail-closed honestly"
    )
    results.append(ok(
        name, "environment detection is honest and exhaustive; %s"
              % (attached_note,),
    ))


def case_23_physical_evidence_template(results: List[Result]) -> None:
    name = "case_23_physical_evidence_template"
    problems: List[str] = []
    required = tuple(
        field for field, _why in pilot_physical.PHYSICAL_EVIDENCE_REQUIRED
    )
    expected_fields = (
        "device_identity.model",
        "device_identity.brand",
        "device_identity.serial",
        "device_identity.android_release",
        "device_identity.observation_source",
        "access_technology.technology",
        "access_technology.observation_source",
        "host.interface_identity",
        "host.pre_transition_route",
        "adcos.access_classification",
        "adcos.device_node_id",
        "adcos.session_id",
        "adcos.bind_event",
        "adcos.sender_result",
        "adcos.receiver_result",
        "verification.validator_sha",
        "verification.artifact_hashes",
    )
    if required != expected_fields:
        problems.append("the required template drifted from the frozen list")
    five_g_fields = tuple(
        field for field, _why in pilot_physical.PHYSICAL_5G_REQUIRED
    )
    if "access_technology.is_5g" not in five_g_fields:
        problems.append("the 5G template omits the NR-only rule field")
    if "host.post_transition_route" not in five_g_fields:
        problems.append("the 5G template omits the route transition")
    # a physical document missing ANY required field fails validation
    base: dict = {
        "kind": "physical-participation-evidence",
        "schema_version": pilot_physical.PHYSICAL_EVIDENCE_SCHEMA_VERSION,
        "is_physical": True,
        "device_identity": {
            "model": "m", "brand": "b", "serial": "s",
            "android_release": "15", "observation_source": "adb getprop",
        },
        "access_technology": {
            "technology": "nr", "is_5g": True,
            "observation_source": "dumpsys telephony.registry",
        },
        "host": {
            "interface_identity": "usb0",
            "pre_transition_route": "default via 1.2.3.4 dev eth0",
            "post_transition_route": "default via 5.6.7.8 dev usb0",
        },
        "adcos": {
            "access_classification": "direct access point",
            "device_node_id": pilot_topology.node_identity_for(
                "device-android"
            ).node_id.text,
            "session_id": "sha256:ab",
            "bind_event": {"session_id": "sha256:ab"},
            "sender_result": {
                "label": "device-android",
                "observations": {"session": {"session_id": "sha256:ab"}},
            },
            "receiver_result": {
                "label": "appliance-1",
                "events": [{"kind": "pilot.session-accepted",
                            "payload": {"session_id": "sha256:ab"}}],
            },
        },
        "traffic_verification": {
            "method": "interface counters", "observation": "usb0 +1024 bytes",
        },
        "verification": {
            "validator_sha": pilot_physical.validator_sha(),
            "artifact_hashes": [["a", "sha256:" + "0" * 64]],
        },
        "classification": {},
    }
    ok_base, base_problems = pilot_physical.validate_physical_evidence(base)
    structural = [
        p for p in base_problems
        if "missing required field" not in p
        and "session id" not in p
        and "sender result does not carry" not in p
    ]
    if structural:
        problems.append("the template base has structural problems: %s"
                        % (structural[:2],))
    # the session id above is intentionally not a full digest: the
    # corroboration check must fire (a well-formed id is required)
    well_formed = json.loads(json.dumps(base))
    well_formed["adcos"]["session_id"] = "sha256:" + "c" * 64
    well_formed["adcos"]["bind_event"] = {
        "session_id": "sha256:" + "c" * 64
    }
    well_formed["adcos"]["sender_result"]["observations"]["session"] = {
        "session_id": "sha256:" + "c" * 64
    }
    well_formed["adcos"]["receiver_result"]["events"] = [
        {"kind": "pilot.session-accepted",
         "payload": {"session_id": "sha256:" + "c" * 64}}
    ]
    ok_wf, _problems_wf = pilot_physical.validate_physical_evidence(
        well_formed
    )
    if not ok_wf:
        problems.append("a complete well-formed document fails validation")
    for field in expected_fields:
        mutated = json.loads(json.dumps(well_formed))
        node = mutated
        parts = field.split(".")
        for part in parts[:-1]:
            node = node[part]
        node[parts[-1]] = None
        ok_mutated, _ = pilot_physical.validate_physical_evidence(mutated)
        if ok_mutated:
            problems.append("missing %r still validates" % (field,))
            break
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "the frozen template covers every required field (%d + %d "
              "5G-only); removing ANY field fails validation"
              % (len(required), len(five_g_fields)),
    ))


def case_24_physical_anti_promotion(results: List[Result]) -> None:
    name = "case_24_physical_anti_promotion"
    problems: List[str] = []
    rehearsal = pilot_physical.run_physical_rehearsal()
    if rehearsal.get("is_physical") is not False:
        problems.append("the rehearsal is not honestly labeled")
    cls = rehearsal.get("classification") or {}
    if cls.get("criterion_1_real_devices") not in (
        CriterionStatus.PARTIAL, CriterionStatus.NOT_TESTABLE
    ):
        problems.append("the rehearsal classified above its class")
    if cls.get("criterion_2_5g") != CriterionStatus.NOT_TESTABLE:
        problems.append("the rehearsal classified 5G above NOT-TESTABLE")

    def _rejected(mutated: dict, why: str) -> None:
        ok_mutated, _ = pilot_physical.validate_physical_evidence(mutated)
        if ok_mutated:
            problems.append(why)

    # (a) a rehearsal relabeled as a PASS
    promoted = json.loads(json.dumps(rehearsal))
    promoted["classification"]["criterion_1_real_devices"] = (
        CriterionStatus.PASS
    )
    ok_a, problems_a = pilot_physical.validate_physical_evidence(promoted)
    if ok_a or not any("rehearsal" in p for p in problems_a):
        problems.append("a rehearsal PASS is not rejected")

    # (b) cellular promoted to 5G (LTE with is_5g=true)
    lte = json.loads(json.dumps(rehearsal))
    lte["is_physical"] = True
    lte["access_technology"] = {
        "technology": "lte", "is_5g": True,
        "observation_source": "dumpsys telephony.registry",
    }
    _rejected(lte, "LTE relabeled is_5g=true is not rejected")

    # (c) 5G PASS without the route transition / traffic verification
    nr = json.loads(json.dumps(rehearsal))
    nr["is_physical"] = True
    nr["access_technology"] = {
        "technology": "nr", "is_5g": True,
        "observation_source": "dumpsys telephony.registry",
    }
    nr["classification"]["criterion_2_5g"] = CriterionStatus.PASS
    ok_c, problems_c = pilot_physical.validate_physical_evidence(nr)
    if ok_c or not any(
        "traffic verification" in p or "post-transition route" in p
        for p in problems_c
    ):
        problems.append("a 5G PASS without route/traffic evidence passes")

    # (d) the wrong participant identity
    forged = json.loads(json.dumps(rehearsal))
    forged["is_physical"] = True
    forged["adcos"]["device_node_id"] = "adcos:node:forged"
    _rejected(forged, "a forged participant node id is not rejected")

    # (e) no independent receiver corroboration
    one_sided = json.loads(json.dumps(rehearsal))
    one_sided["is_physical"] = True
    one_sided["adcos"]["receiver_result"]["events"] = []
    _rejected(one_sided, "missing receiver corroboration is not rejected")

    # (f) missing validator sha
    no_sha = json.loads(json.dumps(rehearsal))
    no_sha["is_physical"] = True
    no_sha["verification"]["validator_sha"] = "not-a-digest"
    _rejected(no_sha, "a malformed validator sha is not rejected")

    # (g) classification honesty: the derived classifiers never exceed
    # the facts (a rehearsal can never classify criterion 1 as PASS)
    if pilot_physical.classify_physical_participation(rehearsal) == (
        CriterionStatus.PASS
    ):
        problems.append("the derived classifier promotes a rehearsal")
    if pilot_physical.classify_five_g_path(rehearsal) != (
        CriterionStatus.NOT_TESTABLE
    ):
        problems.append("the derived classifier promotes 5G from rehearsal")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "anti-promotion enforced: rehearsal PASS, LTE->5G, 5G without "
              "route/traffic evidence, forged identity, one-sided evidence, "
              "and malformed digests all fail closed",
    ))


def case_25_physical_harness_rehearsal(results: List[Result]) -> None:
    name = "case_25_physical_harness_rehearsal"
    problems: List[str] = []
    document = pilot_physical.run_physical_rehearsal()
    if document.get("kind") != "physical-participation-evidence":
        problems.append("the rehearsal produced no evidence document")
        results.append(fail(name, "; ".join(problems)))
        return
    sender = document.get("adcos", {}).get("sender_result") or {}
    checks = sender.get("checks") or []
    by_label = {check.get("label"): check.get("ok") for check in checks}
    if not by_label.get("device-android-physical-session-established"):
        problems.append("the physical session was not established")
    if not by_label.get("device-android-service-executed"):
        problems.append("the local service was not executed")
    if not by_label.get("device-android-real-interfaces-observed"):
        problems.append("the real interfaces were not observed")
    session = (sender.get("observations") or {}).get("session") or {}
    if session.get("state") != "ESTABLISHED":
        problems.append("the session is not ESTABLISHED")
    receiver = document.get("adcos", {}).get("receiver_result") or {}
    events = receiver.get("events") or []
    announced = any(
        event.get("kind") == "pilot.discovery-received"
        and (event.get("payload") or {}).get("peer_label") == "device-android"
        for event in events
    )
    if not announced:
        problems.append("the appliance did not accept the participant announce")
    node_id_ok = document.get("adcos", {}).get("device_node_id") == (
        pilot_topology.node_identity_for("device-android").node_id.text
    )
    if not node_id_ok:
        problems.append("the participant identity does not match the declared")
    cls = document.get("classification") or {}
    if cls.get("validation_ok") is not True:
        problems.append(
            "the rehearsal evidence does not validate: %s"
            % (cls.get("validation_problems"),)
        )
    if cls.get("criterion_1_real_devices") != CriterionStatus.PARTIAL:
        problems.append("the rehearsal is not honestly PARTIAL")
    if cls.get("criterion_2_5g") != CriterionStatus.NOT_TESTABLE:
        problems.append("the rehearsal 5G status is not NOT-TESTABLE")
    interfaces = (sender.get("observations") or {}).get(
        "interfaces_observed"
    ) or []
    if not interfaces:
        problems.append("no real interfaces recorded")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "the full participation chain works end-to-end (announce "
              "accepted, session ESTABLISHED over the direct carriage, "
              "service executed, %d real interfaces observed) and is "
              "honestly classified PARTIAL/NOT-TESTABLE (is_physical=false)"
              % (len(interfaces),),
    ))


# ---------------------------------------------------------------------------
# 26-28: the WORK-040 correction cycle's second round (the physical
# handover experiment + the Android-agent manifest interface)
# ---------------------------------------------------------------------------


def case_26_handover_rehearsal(results: List[Result]) -> None:
    name = "case_26_handover_rehearsal"
    problems: List[str] = []
    document = pilot_physical.run_handover_rehearsal()
    if document.get("kind") != "physical-handover-evidence":
        problems.append(
            "the handover rehearsal produced no evidence document (%r)"
            % (document.get("kind"),)
        )
        results.append(fail(name, "; ".join(problems)))
        return
    if document.get("is_physical") is not False:
        problems.append("the handover rehearsal is not honestly labeled")
    session_id = document.get("adcos", {}).get("session_id")
    if not session_id:
        problems.append("no session id in the handover evidence")
    sender = document.get("adcos", {}).get("sender_result") or {}
    events = sender.get("events") or []

    def _has(kind: str, predicate=None) -> bool:
        return any(
            event.get("kind") == kind
            and (predicate is None or predicate(event.get("payload") or {}))
            for event in events
        )

    if not _has(
        "pilot.session-bound",
        lambda p: p.get("session_id") == session_id
        and p.get("carriage") == "physical-access",
    ):
        problems.append("the primary bind event (physical-access) is missing")
    for kind in (
        "pilot.link-loss-observed",
        "pilot.probe-reported",
        "pilot.path-status-changed",
        "pilot.session-reconnecting",
        "pilot.failover-completed",
    ):
        if not _has(kind):
            problems.append("the sender journal omits %s" % (kind,))
    if not _has(
        "pilot.session-rebound",
        lambda p: p.get("session_id") == session_id
        and p.get("carriage") == "physical-access-secondary",
    ):
        problems.append(
            "the rebind event does not carry the SAME session id over the "
            "physical-access-secondary carriage"
        )
    checks = {check.get("label"): check.get("ok") for check in sender.get("checks") or []}
    if not checks.get("device-android-handover-observed-real-loss"):
        problems.append("the real primary-path loss was not observed")
    if not checks.get("device-android-session-continuity"):
        problems.append("the session continuity check failed")
    if not checks.get("device-android-handover-service-executed"):
        problems.append("the service was not executed on the secondary")
    if not checks.get("device-android-real-interfaces-observed"):
        problems.append("the real interfaces were not re-observed")
    receiver = document.get("adcos", {}).get("receiver_result") or {}
    receiver_events = receiver.get("events") or []
    announced = {
        (event.get("payload") or {}).get("access_point")
        for event in receiver_events
        if event.get("kind") == "pilot.discovery-received"
        and (event.get("payload") or {}).get("peer_label") == "device-android"
    }
    if announced != {"direct", "relay"}:
        problems.append(
            "the appliance did not accept the participant announce on BOTH "
            "access points (got %s)" % (sorted(announced),)
        )
    carriages = {
        (event.get("payload") or {}).get("carriage")
        for event in receiver_events
        if event.get("kind") == "pilot.datagram-received"
        and (event.get("payload") or {}).get("session_id") == session_id
    }
    if carriages != {"direct", "relay"}:
        problems.append(
            "the receiver journal does not corroborate datagrams on BOTH "
            "access points (got %s)" % (sorted(carriages),)
        )
    if not any(
        event.get("kind") == "pilot.sabotage-injected"
        for event in receiver_events
    ):
        problems.append(
            "the rehearsal's honest artificial trigger (the declared "
            "failure plan) is not journaled by the receiver"
        )
    cls = document.get("classification") or {}
    if cls.get("validation_ok") is not True:
        problems.append(
            "the handover rehearsal evidence does not validate: %s"
            % (cls.get("validation_problems"),)
        )
    if cls.get("criterion_1_real_devices") != CriterionStatus.PARTIAL:
        problems.append("the handover rehearsal is not honestly PARTIAL")
    if cls.get("criterion_2_5g") != CriterionStatus.NOT_TESTABLE:
        problems.append("the handover rehearsal 5G status is not NOT-TESTABLE")
    if not document.get("honest_absences"):
        problems.append("the rehearsal records no honest absences")
    if document.get("adcos", {}).get("session_continuity") is not True:
        problems.append("the session-record continuity fact is missing")
    if not str(document.get("adcos", {}).get("payload_digest", "")).startswith(
        "sha256:"
    ):
        problems.append("the post-rebind payload digest is missing")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "the handover chain works end-to-end over three real processes "
              "(real socket death on the primary, production re-bind onto "
              "the secondary relayed carriage, SAME session id, "
              "session-record digest stable, service executed on the "
              "secondary, receiver corroboration on BOTH access points) and "
              "is honestly classified PARTIAL/NOT-TESTABLE (is_physical=false)",
    ))


def _synthetic_handover_document() -> dict:
    """A complete, well-formed SYNTHETIC physical handover document (the
    template's structural checks; every field explicitly present)."""
    session_id = "sha256:" + "c" * 64
    payload_digest = "sha256:" + "e" * 64
    node_id = pilot_topology.node_identity_for("device-android").node_id.text
    sender_result = {
        "label": "device-android",
        "node_id": node_id,
        "events": [
            {"kind": "pilot.session-bound",
             "payload": {"session_id": session_id,
                         "carriage": "physical-access"}},
            {"kind": "pilot.session-rebound",
             "payload": {"session_id": session_id,
                         "carriage": "physical-access-secondary"}},
        ],
        "checks": [
            {"label": "device-android-session-continuity", "ok": True},
        ],
        "observations": {
            "session": {
                "session_id": session_id,
                "state": "ESTABLISHED",
                "record_digest": "sha256:" + "d" * 64,
                "record_digest_before_transition": "sha256:" + "d" * 64,
            },
            "handover": {
                "transition_payload_digest": payload_digest,
                "session_record_stable": True,
            },
            "service": {"verdict": "executed", "response_matches": True},
        },
    }
    receiver_result = {
        "label": "appliance-1",
        "node_id": pilot_topology.node_identity_for(
            "appliance-1"
        ).node_id.text,
        "events": [
            {"kind": "pilot.discovery-received",
             "payload": {"peer_label": "device-android",
                         "access_point": "direct"}},
            {"kind": "pilot.datagram-received",
             "payload": {"session_id": session_id, "carriage": "direct"}},
            {"kind": "pilot.datagram-received",
             "payload": {"session_id": session_id, "carriage": "relay"}},
        ],
        "checks": [],
    }
    return {
        "kind": "physical-handover-evidence",
        "schema_version": pilot_physical.HANDOVER_EVIDENCE_SCHEMA_VERSION,
        "is_physical": True,
        "device_identity": {
            "model": "m", "brand": "b", "serial": "s",
            "android_release": "15", "observation_source": "adb getprop",
        },
        "access_technology_pre": {
            "technology": "lte", "is_5g": False,
            "observation_source": "dumpsys telephony.registry",
        },
        "access_technology_post": {
            "technology": "nr", "is_5g": True,
            "observation_source": "dumpsys telephony.registry",
        },
        "trigger": {
            "description": "Wi-Fi disabled on the handset at the marked step",
            "observation_source": "operator action + the agent's record",
        },
        "host": {
            "pre_transition_route": "default via 1.2.3.4 dev wlan0",
            "post_transition_route": "default via 5.6.7.8 dev usb0",
            "tether_interface": "usb0",
        },
        "adcos": {
            "access_classification": "primary direct + secondary relayed",
            "device_node_id": node_id,
            "session_id": session_id,
            "bind_event": {"session_id": session_id,
                           "carriage": "physical-access"},
            "rebind_event": {"session_id": session_id,
                             "carriage": "physical-access-secondary"},
            "sender_result": sender_result,
            "receiver_result": receiver_result,
            "payload_digest": payload_digest,
            "session_continuity": True,
        },
        "traffic_verification": {
            "method": "route + interface observation across the pilot window",
            "observation": "pre=wlan0; post=usb0; both carriages corroborated",
        },
        "verification": {
            "validator_sha": pilot_physical.validator_sha(),
            "artifact_hashes": [["a", "sha256:" + "0" * 64]],
        },
        "classification": {},
    }


def case_27_handover_evidence_template(results: List[Result]) -> None:
    name = "case_27_handover_evidence_template"
    problems: List[str] = []
    required = tuple(
        field for field, _why in pilot_physical.HANDOVER_EVIDENCE_REQUIRED
    )
    expected_fields = (
        "device_identity.model",
        "device_identity.brand",
        "device_identity.serial",
        "device_identity.android_release",
        "device_identity.observation_source",
        "access_technology_pre.technology",
        "access_technology_pre.observation_source",
        "access_technology_post.technology",
        "access_technology_post.observation_source",
        "trigger.description",
        "trigger.observation_source",
        "host.pre_transition_route",
        "host.post_transition_route",
        "host.tether_interface",
        "adcos.access_classification",
        "adcos.device_node_id",
        "adcos.session_id",
        "adcos.bind_event",
        "adcos.rebind_event",
        "adcos.sender_result",
        "adcos.receiver_result",
        "adcos.payload_digest",
        "adcos.session_continuity",
        "traffic_verification.method",
        "traffic_verification.observation",
        "verification.validator_sha",
        "verification.artifact_hashes",
    )
    if required != expected_fields:
        problems.append("the required template drifted from the frozen list")
    base = _synthetic_handover_document()
    ok_base, base_problems = pilot_physical.validate_handover_evidence(base)
    if not ok_base:
        problems.append(
            "a complete well-formed document fails validation: %s"
            % (base_problems[:3],)
        )
    elif pilot_physical.classify_handover_participation(base) != CriterionStatus.PASS:
        problems.append("the derived classifier does not PASS a complete document")
    elif pilot_physical.classify_handover_five_g(base) != CriterionStatus.PASS:
        problems.append("the derived classifier does not PASS a complete NR chain")
    for field in expected_fields:
        mutated = json.loads(json.dumps(base))
        node = mutated
        parts = field.split(".")
        for part in parts[:-1]:
            node = node[part]
        node[parts[-1]] = None
        ok_mutated, _ = pilot_physical.validate_handover_evidence(mutated)
        if ok_mutated:
            problems.append("missing %r still validates" % (field,))
            break

    def _rejected(mutated: dict, why: str) -> None:
        ok_mutated, _ = pilot_physical.validate_handover_evidence(mutated)
        if ok_mutated:
            problems.append(why)

    # (a) a rehearsal relabeled as a criterion-1 PASS
    promoted = json.loads(json.dumps(base))
    promoted["is_physical"] = False
    promoted["classification"]["criterion_1_real_devices"] = (
        CriterionStatus.PASS
    )
    _rejected(promoted, "a rehearsal criterion-1 PASS is not rejected")

    # (b) is_physical=false + NR + full route/traffic evidence relabeled
    #     as a criterion-2 PASS
    nr_promoted = json.loads(json.dumps(base))
    nr_promoted["is_physical"] = False
    nr_promoted["classification"]["criterion_2_5g"] = CriterionStatus.PASS
    _rejected(nr_promoted, "a non-physical criterion-2 PASS is not rejected")

    # (c) LTE relabeled as 5G
    lte = json.loads(json.dumps(base))
    lte["access_technology_post"] = {
        "technology": "lte", "is_5g": True,
        "observation_source": "dumpsys telephony.registry",
    }
    _rejected(lte, "LTE relabeled is_5g=true is not rejected")

    # (d) session continuity broken while criterion 1 is PASS
    broken = json.loads(json.dumps(base))
    broken["adcos"]["session_continuity"] = False
    broken["classification"]["criterion_1_real_devices"] = (
        CriterionStatus.PASS
    )
    _rejected(broken, "a broken session with a criterion-1 PASS is not rejected")

    # (e) a malformed payload digest
    no_digest = json.loads(json.dumps(base))
    no_digest["adcos"]["payload_digest"] = "not-a-digest"
    _rejected(no_digest, "a malformed payload digest is not rejected")

    # (f) no independent receiver corroboration
    one_sided = json.loads(json.dumps(base))
    one_sided["adcos"]["receiver_result"]["events"] = []
    _rejected(one_sided, "missing receiver corroboration is not rejected")

    # (g) the derived classifiers never promote a rehearsal
    rehearsal = pilot_physical.run_handover_rehearsal()
    if pilot_physical.classify_handover_participation(rehearsal) not in (
        CriterionStatus.PARTIAL, CriterionStatus.NOT_TESTABLE
    ):
        problems.append("the derived classifier promotes a handover rehearsal")
    if pilot_physical.classify_handover_five_g(rehearsal) != (
        CriterionStatus.NOT_TESTABLE
    ):
        problems.append("the derived classifier promotes 5G from a rehearsal")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "the frozen handover template covers every required field "
              "(%d); removing ANY field fails validation; rehearsal PASS, "
              "non-physical 5G PASS, LTE->5G, broken continuity, malformed "
              "digests, and one-sided evidence all fail closed"
              % (len(required),),
    ))


def case_28_android_manifest(results: List[Result]) -> None:
    name = "case_28_android_manifest"
    problems: List[str] = []
    template = pilot_physical.android_manifest_template()
    ok_template, template_problems = pilot_physical.validate_android_manifest(
        template
    )
    if not ok_template:
        problems.append(
            "the template manifest does not validate: %s"
            % (template_problems[:3],)
        )

    # the file round trip: write, load, validate
    import hashlib
    import tempfile as _tempfile

    with _tempfile.NamedTemporaryFile(
        "w", suffix=".json", delete=False
    ) as handle:
        json.dump(template, handle)
        template_path = handle.name
    try:
        loaded = pilot_physical.load_android_manifest(template_path)
        ok_loaded, _loaded_problems = (
            pilot_physical.validate_android_manifest(loaded)
        )
        if not ok_loaded:
            problems.append("the loaded template manifest does not validate")
        file_sha = "sha256:" + hashlib.sha256(
            open(template_path, "rb").read()
        ).hexdigest()
    finally:
        os.unlink(template_path)

    # a real-observation manifest built on the template, bound into a
    # handover document by its file SHA-256
    manifest = json.loads(json.dumps(template))
    manifest.pop("template", None)
    manifest.pop("usage", None)
    manifest["device_identity"]["serial"] = "s"
    manifest["apk"] = {
        "name": "android-agent.apk",
        "sha256": "sha256:" + "9" * 64,
    }
    with _tempfile.NamedTemporaryFile(
        "w", suffix=".json", delete=False
    ) as handle:
        json.dump(manifest, handle)
        manifest_path = handle.name
    try:
        bound_manifest = pilot_physical.load_android_manifest(manifest_path)
        bound_sha = "sha256:" + hashlib.sha256(
            open(manifest_path, "rb").read()
        ).hexdigest()
    finally:
        os.unlink(manifest_path)

    base = _synthetic_handover_document()
    bound = pilot_physical.assemble_handover_evidence(
        environment={"kind": "physical-environment-detection"},
        sender_result=base["adcos"]["sender_result"],
        receiver_result=base["adcos"]["receiver_result"],
        device_identity=base["device_identity"],
        access_technology_pre=base["access_technology_pre"],
        access_technology_post=base["access_technology_post"],
        trigger=base["trigger"],
        host_route=base["host"],
        carriage={
            "mode": "wifi-primary-usb-tether-secondary",
            "adcos_access_classification": "primary + secondary",
        },
        is_physical=True,
        android_manifest=bound_manifest,
        android_manifest_sha=bound_sha,
        traffic_verification=base["traffic_verification"],
    )
    hashes = [tuple(entry) for entry in bound["verification"]["artifact_hashes"]]
    if ("android-manifest", bound_sha) not in hashes:
        problems.append("the manifest file sha is not bound in artifact_hashes")
    android_obs = bound.get("android_observations") or {}
    if android_obs.get("manifest_file_sha256") != bound_sha:
        problems.append("the bound manifest sha is not recorded")
    if android_obs.get("apk_sha256") != "sha256:" + "9" * 64:
        problems.append("the apk sha256 is not recorded when present")
    ok_bound, bound_problems = pilot_physical.validate_handover_evidence(bound)
    if not ok_bound:
        problems.append(
            "a document with a properly bound manifest fails validation: %s"
            % (bound_problems[:3],)
        )

    # negatives: each FAILS closed
    # (a) a missing required field
    missing = json.loads(json.dumps(manifest))
    del missing["usb_tether"]
    if pilot_physical.validate_android_manifest(missing)[0]:
        problems.append("a manifest missing usb_tether validates")

    # (b) is_5g=true with post technology lte
    lte = json.loads(json.dumps(manifest))
    lte["network_technology"]["post"] = "lte"
    if pilot_physical.validate_android_manifest(lte)[0]:
        problems.append("a manifest with LTE relabeled is_5g=true validates")

    # (c) the serial mismatch vs the ADCOS-side observed serial
    mismatch = json.loads(json.dumps(manifest))
    mismatch["device_identity"]["serial"] = "a-different-serial"
    with _tempfile.NamedTemporaryFile(
        "w", suffix=".json", delete=False
    ) as handle:
        json.dump(mismatch, handle)
        mismatch_path = handle.name
    try:
        mismatch_manifest = pilot_physical.load_android_manifest(mismatch_path)
        mismatch_sha = "sha256:" + hashlib.sha256(
            open(mismatch_path, "rb").read()
        ).hexdigest()
    finally:
        os.unlink(mismatch_path)
    mismatched = pilot_physical.assemble_handover_evidence(
        environment={"kind": "physical-environment-detection"},
        sender_result=base["adcos"]["sender_result"],
        receiver_result=base["adcos"]["receiver_result"],
        device_identity=base["device_identity"],
        access_technology_pre=base["access_technology_pre"],
        access_technology_post=base["access_technology_post"],
        trigger=base["trigger"],
        host_route=base["host"],
        carriage={
            "mode": "wifi-primary-usb-tether-secondary",
            "adcos_access_classification": "primary + secondary",
        },
        is_physical=True,
        android_manifest=mismatch_manifest,
        android_manifest_sha=mismatch_sha,
        traffic_verification=base["traffic_verification"],
    )
    ok_mismatch, mismatch_problems = (
        pilot_physical.validate_handover_evidence(mismatched)
    )
    if ok_mismatch or not any(
        "serial" in p for p in mismatch_problems
    ):
        problems.append("a serial mismatch against the ADCOS side is not rejected")

    # (d) a malformed apk sha256
    bad_apk = json.loads(json.dumps(manifest))
    bad_apk["apk"]["sha256"] = "not-a-digest"
    if pilot_physical.validate_android_manifest(bad_apk)[0]:
        problems.append("a manifest with a malformed apk sha256 validates")

    # (e) the raw template's placeholder serial can never bind (the
    #     cross-corroboration rejects it)
    template_bound = json.loads(json.dumps(base))
    template_bound["android_observations"] = {
        "manifest": template,
        "manifest_file_sha256": file_sha,
    }
    template_bound["verification"]["artifact_hashes"].append(
        ["android-manifest", file_sha]
    )
    ok_template_bound, template_bound_problems = (
        pilot_physical.validate_handover_evidence(template_bound)
    )
    if ok_template_bound or not any(
        "serial" in p for p in template_bound_problems
    ):
        problems.append("the raw template's placeholder serial binds")
    if problems:
        results.append(fail(name, "; ".join(problems)))
        return
    results.append(ok(
        name, "the Android-agent manifest interface works end-to-end: the "
              "template loads and validates, a real-observation manifest "
              "binds by file SHA-256 into artifact_hashes (apk sha recorded "
              "when present), and missing fields, LTE->5G, serial "
              "mismatches, malformed apk digests, and the raw template's "
              "placeholders all fail closed",
    ))


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


CASES = [
    case_01_frozen_vocabularies,
    case_02_value_records,
    case_03_marshal_roundtrips_and_tamper,
    case_04_wire_framing,
    case_05_platform_honesty,
    case_06_topology_validation,
    case_07_fabric_provisioning,
    case_08_full_deployment_rehearsal,
    case_09_determinism,
    case_10_hashseed_invariance,
    case_11_journal_binding,
    case_12_anti_promotion,
    case_13_evidence_honesty,
    case_14_no_second_authority,
    case_15_secrets_out_of_evidence,
    case_16_frozen_api,
    case_17_frozen_spec_intact,
    case_18_pr_delta_shape,
    case_19_ci_wiring_all_tools,
    case_20_py_compile,
    case_21_physical_topology_extension,
    case_22_physical_environment_honesty,
    case_23_physical_evidence_template,
    case_24_physical_anti_promotion,
    case_25_physical_harness_rehearsal,
    case_26_handover_rehearsal,
    case_27_handover_evidence_template,
    case_28_android_manifest,
]


def main() -> int:
    print("WORK-040 pilot deployment battery")
    print("=" * 72)
    results: List[Result] = []
    for case in CASES:
        started = time.monotonic()
        try:
            case(results)
        except Exception as error:  # noqa: BLE001 - battery honesty
            results.append(fail(case.__name__, "raised %s: %s" % (
                type(error).__name__, error,
            )))
        elapsed = time.monotonic() - started
        name, passed, detail = results[-1]
        print(
            "[%s] %-44s %6.1fs  %s"
            % ("PASS" if passed else "FAIL", name, elapsed, detail[:90])
        )
    print("-" * 72)
    passed = sum(1 for _, ok_flag, _ in results if ok_flag)
    print("Result: %d/%d cases passed" % (passed, len(results)))
    for name, ok_flag, detail in results:
        if not ok_flag:
            print("  FAIL %s: %s" % (name, detail))
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
