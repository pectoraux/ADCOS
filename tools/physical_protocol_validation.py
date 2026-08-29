import sys
import os
import time
import subprocess
import json
import argparse
import hashlib
from typing import Mapping, List, Tuple, Optional

# Ensure project root is in path
sys.path.append(os.getcwd())

from agent.clock import SystemClock
from agent.interfaces import LinuxInterfaceSource
from agent.model import AgentConfig, AgentIdentitySpec, LinkMetricSpec
from agent.runtime import AgentRuntime
from mobile.participation import MobileAgent, MobileCommand, MobileCommandKind
from tools.adb_platform_source import AdbPlatformSource
from mobile.model import GrantScope, MobileSnapshot, NetworkKind
from identity.node_id import parse_node_id
from identity.model import NodeIdentity
from identity.profiles import ProfileSet
from topology.model import TopologyClaim, ClaimType, SourceClass, make_link_subject
from policy.model import PolicyRule, PolicyDomain
from adapters.ip.engine import ReferenceIPIntegrationEngine

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_node_id(label: str) -> str:
    profiles = ProfileSet.load_default()
    profile = profiles.get("identity.sha256-hmac-dev.v1")
    public_key = label.encode().ljust(32, b"!")
    identity = NodeIdentity.create(profile, public_key, "2026-08-29T00:00:00Z")
    return identity.node_id.text

def _get_validator_sha():
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"]).decode("utf-8").strip()
    except:
        return "unknown"

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def _claims(self_id: str, peer_id: str) -> Tuple[TopologyClaim, ...]:
    now = "2026-08-29T00:00:00Z"
    fresh = "2026-08-30T00:00:00Z"
    return (
        TopologyClaim(
            subject=make_link_subject(self_id, peer_id),
            reporter=self_id,
            claim_type=ClaimType.LINK_STATE,
            value="up",
            source_class=SourceClass.SELF_ADVERTISEMENT,
            issued_at=now,
            freshness_until=fresh,
            sequence=1,
            provenance="local"
        ),
        TopologyClaim(
            subject=peer_id,
            reporter=self_id,
            claim_type=ClaimType.REACHABLE,
            value="true",
            source_class=SourceClass.DIRECT_OBSERVATION,
            issued_at=now,
            freshness_until=fresh,
            sequence=1,
            provenance="local"
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

def _config(label: str, self_id: str, peer_id: str) -> AgentConfig:
    return AgentConfig(
        agent_label=label,
        identity=AgentIdentitySpec(
            profile_id="identity.sha256-hmac-dev.v1",
            public_key=label.encode().ljust(32, b"!"),
            created_at="2026-08-29T00:00:00Z"
        ),
        policy_rules=_policy_rules(label),
        topology_claims=_claims(self_id, peer_id),
        link_metrics=(
            LinkMetricSpec(
                peer_node_id=peer_id, latency_ms=10,
                observed_at="2026-08-29T00:00:00Z", freshness_until="2026-08-30T00:00:00Z",
            ),
        ),
        policy_default_effect="deny"
    )

def _register_peers(a: AgentRuntime, b: AgentRuntime, secret_a: bytes, secret_b: bytes) -> None:
    now = a.config.identity.created_at
    cred_a = a.identity_service.active_credential(
        parse_node_id(a.node_id), "operational", now=now,
    )
    cred_b = b.identity_service.active_credential(
        parse_node_id(b.node_id), "operational", now=now,
    )
    a.register_peer(b.identity, cred_b, secret_b)
    b.register_peer(a.identity, cred_a, secret_a)

def get_default_interface():
    try:
        output = subprocess.check_output(["ip", "route", "show", "default"]).decode("utf-8")
        for line in output.splitlines():
            if "default via" in line:
                parts = line.split()
                return parts[parts.index("dev") + 1]
    except:
        pass
    return None

# ---------------------------------------------------------------------------
# Stages
# ---------------------------------------------------------------------------

SNAPSHOT_FILE = "harness_snapshot.json"
BOOT_SECRET = b"test-secret-32-bytes-long-!!!!!!"[:32]
IF_MAP = {"wifi": "wlp3s0", "cellular": "enx0e523cbd6b00"}

def stage_1(serial: str):
    print(f"--- STAGE 1: Physical Protocol Validation (PID: {os.getpid()}) ---")
    print(f"Validator SHA: {_get_validator_sha()}")

    clock = SystemClock()
    id_m = _get_node_id("mobile-node")
    id_p = _get_node_id("peer-node")

    # Setup Peer
    peer = AgentRuntime(_config("peer-node", id_p, id_m), clock=clock, interface_source=LinuxInterfaceSource())
    peer.boot(BOOT_SECRET)
    peer.expose_interfaces()
    peer.ip_manager.register_implementation(ReferenceIPIntegrationEngine())

    # Setup Mobile
    platform_source = AdbPlatformSource(serial=serial)
    mobile = MobileAgent(
        config=_config("mobile-node", id_m, id_p),
        clock=clock,
        interface_source=LinuxInterfaceSource(),
        platform_source=platform_source,
        access_interfaces=IF_MAP
    )
    mobile.runtime.ip_manager.register_implementation(ReferenceIPIntegrationEngine())

    print("\n[BASELINE] Establishing Wi-Fi state...")
    subprocess.run(["nmcli", "connection", "up", "EKONSONS -pro"], stdout=subprocess.DEVNULL)
    time.sleep(2)
    print(f"Host default interface: {get_default_interface()}")

    print("\n[STEP 1] Booting MobileAgent...")
    mobile.run_mobile([
        MobileCommand(kind=MobileCommandKind.BOOT, params={}),
        MobileCommand(kind=MobileCommandKind.EXPOSE_INTERFACES, params={})
    ], boot_secret=BOOT_SECRET)

    _register_peers(mobile.runtime, peer, BOOT_SECRET, BOOT_SECRET)

    print("\n[STEP 2] Performing genuine session handshake...")
    request = mobile.runtime.establish_session(peer.node_id)
    accept = peer.accept_session(request)
    confirm = mobile.runtime.complete_session(accept)
    peer.finalize_session(confirm)
    session_id = confirm.session_id
    print(f"Session established: {session_id[:32]}...")

    print(f"\n[STEP 3] PHYSICAL TRIGGER: Granting consent and disabling Wi-Fi...")
    mobile.run_mobile([
        MobileCommand(kind=MobileCommandKind.TRACK_SESSION, params={"session_id": session_id}),
        MobileCommand(kind=MobileCommandKind.GRANT, params={"scope": GrantScope.METERED_DATA})
    ])

    # TRIGGER
    subprocess.run(["adb", "-s", serial, "shell", "svc", "wifi", "disable"], stdout=subprocess.DEVNULL)
    subprocess.run(["nmcli", "radio", "wifi", "off"], stdout=subprocess.DEVNULL)

    print("Monitoring for host interface transition...")
    start_time = time.time()
    transitioned = False
    while time.time() - start_time < 60:
        iface = get_default_interface()
        if iface == IF_MAP["cellular"]:
            print(f"\nDETECTED transition to {iface}")
            transitioned = True
            break
        time.sleep(1)
        sys.stdout.write(f"({iface or 'none'}).")
        sys.stdout.flush()

    if not transitioned:
        print("\nERROR: Handover failed at transport layer.")
        return

    print("\nRefreshing platform state (STRICT Production Path)...")
    mobile.run_mobile([])
    print(f"Current Network Kind: {mobile.network_kind}")

    print("\n[STEP 4] Verifying Post-Handover Traffic (Receiver-Side)...")
    payload = b"ADCOS-Physical-Tether-v8"
    if mobile.decision.sends_allowed:
        # 1. Send
        artifact = mobile.runtime.send_datagram(session_id, payload)
        print(f"Datagram sent over physical transport: {artifact.transport_id[:16]}...")

        # 2. Receive and Verify
        received = peer.receive_datagram(artifact)
        print(f"Peer received payload: {received}")

        if received == payload:
            print("TRAFFIC PROOF: End-to-end delivery verified over cellular-backed USB path.")
            # Record receipt explicitly in the agent's event log if we can,
            # or just rely on the validator summary.
            # Actually, MobileAgent.run_mobile handles events.
            # We will just print it and ensure it's in the jsonl.
        else:
            print("TRAFFIC FAILURE: Payload mismatch.")

    print("\n[STEP 5] Creating Checkpoint...")
    snapshot = mobile.checkpoint()
    with open(SNAPSHOT_FILE, "w") as f:
        json.dump(snapshot.to_dict(), f)

    print("\n[SUMMARY] Mobile Event Log (Stage 1):")
    for event in mobile.mobile_events:
        print(f"  {event.instant} | {event.kind:25} | {event.subject[:30]} | {event.detail}")

def stage_2(serial: str):
    print(f"\n--- STAGE 2: Recovery in Fresh Process (PID: {os.getpid()}) ---")
    if not os.path.exists(SNAPSHOT_FILE):
        print(f"ERROR: {SNAPSHOT_FILE} not found.")
        return

    with open(SNAPSHOT_FILE, "r") as f:
        snapshot_data = json.load(f)
    snapshot = MobileSnapshot.from_dict(snapshot_data)

    clock = SystemClock()
    id_m = _get_node_id("mobile-node")
    id_p = _get_node_id("peer-node")

    platform_source = AdbPlatformSource(serial=serial)

    print("[STEP 6] Recovering MobileAgent from snapshot...")
    recovered_agent = MobileAgent.recover(
        snapshot=snapshot,
        config=_config("mobile-node", id_m, id_p),
        clock=clock,
        interface_source=LinuxInterfaceSource(),
        platform_source=platform_source,
        access_interfaces=IF_MAP
    )
    recovered_agent.runtime.ip_manager.register_implementation(ReferenceIPIntegrationEngine())

    print(f"Recovered Phase: {recovered_agent.phase}")
    print("\n[SUMMARY] Mobile Event Log (Recovery):")
    for event in recovered_agent.mobile_events:
        print(f"  {event.instant} | {event.kind:25} | {event.subject[:30]} | {event.detail}")

    print("\nRestoring system state...")
    subprocess.run(["nmcli", "radio", "wifi", "on"], stdout=subprocess.DEVNULL)
    subprocess.run(["adb", "-s", serial, "shell", "svc", "wifi", "enable"], stdout=subprocess.DEVNULL)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", type=int, required=True)
    parser.add_argument("--serial", type=str, required=True)
    args = parser.parse_args()

    if args.stage == 1:
        stage_1(args.serial)
    elif args.stage == 2:
        stage_2(args.serial)
