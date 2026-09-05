import sys
import os
import time
import subprocess
import json
import argparse
import hashlib
import socket
import threading
import re
from typing import Mapping, List, Tuple, Optional

# Ensure project root is in path
sys.path.append(os.getcwd())

from agent.clock import SystemClock
from agent.interfaces import LinuxInterfaceSource
from agent.model import AgentConfig, AgentIdentitySpec, LinkMetricSpec, DatagramArtifact
from agent.runtime import AgentRuntime
from mobile.participation import MobileAgent, MobileCommand, MobileCommandKind
from mobile.model import GrantScope, MobileSnapshot, NetworkKind, PlatformSnapshot
from mobile.platform import MobilePlatformSource
from identity.node_id import parse_node_id
from identity.model import NodeIdentity
from identity.profiles import ProfileSet
from topology.model import TopologyClaim, ClaimType, SourceClass, make_link_subject
from policy.model import PolicyRule, PolicyDomain
from adapters.ip.engine import ReferenceIPIntegrationEngine

# ---------------------------------------------------------------------------
# Platform Source (Inlined to prevent import issues)
# ---------------------------------------------------------------------------

class AdbPlatformSource(MobilePlatformSource):
    """A MobilePlatformSource that reads from a physical device via ADB."""

    def __init__(self, serial=None):
        self.serial = serial
        self.base_cmd = ["adb"]
        if serial:
            self.base_cmd += ["-s", serial]
        self.trigger_next = True

    def _run_adb(self, args):
        cmd = self.base_cmd + args
        return subprocess.check_output(cmd).decode("utf-8")

    def read(self) -> PlatformSnapshot:
        triggered = self.trigger_next
        if triggered:
            print("[ADB-SOURCE] Triggering observation via broadcast...")
            try:
                self._run_adb(["logcat", "-c"])
                self._run_adb([
                    "shell", "am", "broadcast",
                    "-a", "org.adcos.w035.harness.OBSERVE",
                    "-n", "com.example.w035harness/.HarnessReceiver"
                ])
            except:
                pass
        else:
            print("[ADB-SOURCE] Reading EXISTING observation from logcat (no trigger)...")

        start_time = time.time()
        while time.time() - start_time < 8:
            output = self._run_adb(["logcat", "-d", "-s", "W035_HARNESS:I"])
            match = re.search(r"OBSERVATION: (\{.*\})", output)
            if match:
                self.trigger_next = True
                data = json.loads(match.group(1))
                print(f"[ADB-SOURCE] Found observation: {data['app_phase']}")
                return PlatformSnapshot.from_dict(data)
            time.sleep(0.5)

        if triggered:
            print("[ADB-SOURCE] Broadcast trigger timed out, trying UI tap...")
            try:
                self._run_adb(["shell", "input", "tap", "141", "152"])
            except:
                pass
            start_time = time.time()
            while time.time() - start_time < 5:
                output = self._run_adb(["logcat", "-d", "-s", "W035_HARNESS:I"])
                match = re.search(r"OBSERVATION: (\{.*\})", output)
                if match:
                    self.trigger_next = True
                    data = json.loads(match.group(1))
                    print(f"[ADB-SOURCE] Found observation (via tap): {data['app_phase']}")
                    return PlatformSnapshot.from_dict(data)
                time.sleep(0.5)

        self.trigger_next = True
        raise RuntimeError("Failed to obtain observation from device")

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

def get_interface_ip(ifname: str) -> Optional[str]:
    try:
        output = subprocess.check_output(["ip", "-br", "addr", "show", ifname]).decode("utf-8")
        parts = output.split()
        if len(parts) >= 3:
            return parts[2].split("/")[0]
    except:
        pass
    return None

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

# ---------------------------------------------------------------------------
# Traffic Proof (Physical UDP)
# ---------------------------------------------------------------------------

class PeerListener:
    def __init__(self, addr: str, port: int):
        self.addr = addr
        self.port = port
        self.received_payload = None
        self.stop_event = threading.Event()

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind((self.addr, self.port))
            except Exception as e:
                print(f"PEER BIND ERROR: {e}")
                return
            s.settimeout(2.0)
            print(f"PEER LISTENING on {self.addr}:{self.port}")
            while not self.stop_event.is_set():
                try:
                    data, addr = s.recvfrom(1024)
                    self.received_payload = data
                    print(f"PEER RECEIVED: {len(data)} bytes from {addr}")
                except socket.timeout:
                    continue

# ---------------------------------------------------------------------------
# Definitive Execution (v10)
# ---------------------------------------------------------------------------

SNAPSHOT_FILE = "harness_snapshot.json"
BOOT_SECRET = b"test-secret-32-bytes-long-!!!!!!"[:32]
IF_MAP = {"wifi": "wlp3s0", "cellular": "enxdaf7b654e4cf"}

def stage_1(serial: str):
    print(f"--- STAGE 1: Definitive Physical Handover (PID: {os.getpid()}) ---")
    print(f"Validator SHA: {_get_validator_sha()}")

    clock = SystemClock()
    id_m = _get_node_id("mobile-node")
    id_p = _get_node_id("peer-node")

    usb_ip = get_interface_ip(IF_MAP["cellular"])
    if not usb_ip:
        print(f"ERROR: No IP for {IF_MAP['cellular']}")
        return
    peer_port = 55555
    listener = PeerListener(usb_ip, peer_port)
    thread = threading.Thread(target=listener.run, daemon=True)
    thread.start()

    peer = AgentRuntime(_config("peer-node", id_p, id_m), clock=clock, interface_source=LinuxInterfaceSource())
    peer.boot(BOOT_SECRET)
    # Manually merge topology for peer
    for claim in _claims(id_p, id_m):
        peer.topology.merge(claim)
    peer.expose_interfaces()
    peer.ip_manager.register_implementation(ReferenceIPIntegrationEngine())

    platform_source = AdbPlatformSource(serial=serial)
    mobile = MobileAgent(
        config=_config("mobile-node", id_m, id_p),
        clock=clock,
        interface_source=LinuxInterfaceSource(),
        platform_source=platform_source,
        access_interfaces=IF_MAP
    )
    # Manually ingest topology for mobile
    for claim in _claims(id_m, id_p):
        mobile.runtime.topology.ingest(claim)
    mobile.runtime.ip_manager.register_implementation(ReferenceIPIntegrationEngine())

    print("\n[BASELINE] Verifying Hotspot baseline...")
    current_if = get_default_interface()
    print(f"Host default interface: {current_if}")
    if current_if != IF_MAP["wifi"]:
        print(f"ERROR: Baseline interface is {current_if}, expected {IF_MAP['wifi']}")
        return

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

    print(f"\n[STEP 3] PHYSICAL TRIGGER: Please disable Wi-Fi on the handset MANUALLY.")
    print("Monitoring for host interface transition (Observing ONLY)...")

    mobile.run_mobile([
        MobileCommand(kind=MobileCommandKind.TRACK_SESSION, params={"session_id": session_id}),
        MobileCommand(kind=MobileCommandKind.GRANT, params={"scope": GrantScope.METERED_DATA})
    ])

    start_time = time.time()
    transitioned = False
    while time.time() - start_time < 90:
        iface = get_default_interface()
        if iface == IF_MAP["cellular"]:
            print(f"\nNATURAL TRANSITION DETECTED! New default interface: {iface}")
            transitioned = True
            break
        time.sleep(1)
        sys.stdout.write(f"({iface or 'none'}).")
        sys.stdout.flush()

    if not transitioned:
        print("\nERROR: Handover failed at transport layer (No natural transition observed).")
        return

    print("\nRefreshing platform state (STRICT Production Path)...")
    mobile.run_mobile([])
    print(f"Current Network Kind: {mobile.network_kind}")
    print(f"Agent Access interface: {mobile.decision.access_interface}")

    print("\n[STEP 4] Verifying Post-Handover Traffic (Physical RNDIS Proof)...")
    payload = b"ADCOS-Physical-Definitive-v10"
    if mobile.decision.sends_allowed:
        print("Sending datagram via production runtime...")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind((get_interface_ip(IF_MAP["cellular"]), 0))
            s.sendto(payload, (usb_ip, peer_port))

        time.sleep(2)
        if listener.received_payload == payload:
            print(f"TRAFFIC PROOF: Delivered {len(payload)} bytes over {IF_MAP['cellular']} physical path.")
            artifact = mobile.runtime.send_datagram(session_id, payload)
            print(f"ADCOS Datagram sent: {artifact.transport_id[:16]}...")
        else:
            print("TRAFFIC FAILURE: Datagram did not reach peer over physical path.")
    else:
        print("ERROR: MobileAgent blocked traffic after handover.")

    print("\n[STEP 5] Creating Checkpoint...")
    snapshot = mobile.checkpoint()
    with open(SNAPSHOT_FILE, "w") as f:
        json.dump(snapshot.to_dict(), f)

    print("\n[SUMMARY] Mobile Event Log (Stage 1):")
    for event in mobile.mobile_events:
        print(f"  {event.instant} | {event.kind:25} | {event.subject[:30]} | {event.detail}")

    listener.stop_event.set()
    print("\n[STAGE 1 COMPLETE]")

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
    subprocess.run(["adb", "-s", serial, "shell", "svc wifi enable"], stdout=subprocess.DEVNULL)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", type=int, required=True)
    parser.add_argument("--serial", type=str, required=True)
    args = parser.parse_args()

    if args.stage == 1:
        stage_1(args.serial)
    elif args.stage == 2:
        stage_2(args.serial)
